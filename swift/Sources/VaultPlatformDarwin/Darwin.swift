#if canImport(Darwin)
	import CryptoKit
	import Darwin
	import Foundation
	import LocalAuthentication
	import Security
	import VaultCore

	// macOS platform layer (spec §15.8): process hardening, Keychain-backed unlock-key
	// store (service `dev.vault.unlock-key`, account = key id), and a
	// LocalAuthentication user-verification gate.

	public struct DarwinProcessSecurity: PlatformProcessSecurity {
		public init() {}

		public func disableCoreDumps() {
			var lim = rlimit(rlim_cur: 0, rlim_max: 0)
			setrlimit(RLIMIT_CORE, &lim)
		}

	}

	// Stores the DUK as a login-keychain generic password: service
	// `dev.vault.unlock-key`, account = id, password = base64(DUK) — the same layout
	// the Node CLI writes through /usr/bin/security, so either client can unlock.
	// At-rest protection only (unlocked at login): not per-access user verification.
	public struct DarwinKeychainKeyStore: PlatformKeyStore {
		public static let providerName = "macos-keychain"
		static let service = "dev.vault.unlock-key"

		public init() {}
		public var name: String { Self.providerName }
		public var bindingMode: String { "" }

		public func available() async -> Bool { true }

		private func query(_ id: String) -> [String: Any] {
			[
				kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.service,
				kSecAttrAccount as String: id,
			]
		}

		public func put(id: String, secret: Data) async throws {
			let value = Data(secret.base64EncodedString().utf8)
			var attrs = query(id)
			let update = [kSecValueData as String: value]
			var status = SecItemUpdate(attrs as CFDictionary, update as CFDictionary)
			if status == errSecItemNotFound {
				attrs[kSecValueData as String] = value
				status = SecItemAdd(attrs as CFDictionary, nil)
			}
			guard status == errSecSuccess else {
				throw VaultError.corrupt("keychain write failed (\(status))")
			}
		}

		public func get(id: String) async throws -> Data? {
			var q = query(id)
			q[kSecReturnData as String] = true
			q[kSecMatchLimit as String] = kSecMatchLimitOne
			var out: CFTypeRef?
			guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data,
				let s = String(data: d, encoding: .utf8)
			else { return nil }
			let raw = Data(base64: s.trimmingCharacters(in: .whitespacesAndNewlines))
			return raw.isEmpty ? nil : raw
		}

		public func delete(id: String) async throws { SecItemDelete(query(id) as CFDictionary) }
	}

	// ---- Secure Enclave ----
	//
	// The strong tier: the per-vault device unlock key (DUK) is sealed to a
	// NON-EXPORTABLE P-256 key in the Secure Enclave, gated by user presence (Touch ID,
	// passcode fallback). Sealing needs only the public key (no prompt); unsealing runs a
	// private-key operation that forces the check, and the key never leaves hardware.
	//
	// Runs IN-PROCESS (the Node CLI needed the separate `vault-helper` binary). The on-disk
	// layout is byte-compatible with that helper, so vaults sealed by either open in either:
	//   <dir>/device.sekey  enclave key blob (CryptoKit dataRepresentation), one per device
	//   <dir>/<id>.se       ephemeralPub(64) || AES-GCM combined(nonce|ct|tag)
	// CryptoKit's blob (rather than a permanent keychain SecKey) needs no entitlement.

	public enum SecureEnclaveSeal {
		static let info = Data("credvault/secure-enclave/v1".utf8)

		// ECDH(ephemeral, enclavePub) -> HKDF-SHA256 (salt = ephemeralPub) -> AES-256-GCM.
		static func key(_ shared: SharedSecret, ephemeralPub: Data) -> SymmetricKey {
			shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeralPub, sharedInfo: info, outputByteCount: 32)
		}

		public static func seal(_ secret: Data, to pub: P256.KeyAgreement.PublicKey) throws -> Data {
			let eph = P256.KeyAgreement.PrivateKey()
			let ephPub = eph.publicKey.rawRepresentation
			let shared = try eph.sharedSecretFromKeyAgreement(with: pub)
			let box = try AES.GCM.seal(secret, using: key(shared, ephemeralPub: ephPub))
			guard let combined = box.combined else { throw VaultError.corrupt("seal produced no combined box") }
			return ephPub + combined
		}

		// `agree` performs the private-key agreement (the Touch ID moment on hardware).
		public static func open(_ blob: Data, agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret) throws -> Data {
			guard blob.count > 64 else { throw VaultError.corrupt("sealed blob too short") }
			let ephPub = Data(blob.prefix(64))
			let shared = try agree(try P256.KeyAgreement.PublicKey(rawRepresentation: ephPub))
			return try AES.GCM.open(try AES.GCM.SealedBox(combined: blob.dropFirst(64)), using: key(shared, ephemeralPub: ephPub))
		}
	}

	public struct SecureEnclaveKeyStore: PlatformKeyStore {
		public static let providerName = "secure-enclave"
		let dir: URL

		public init(directory: String = (VaultPaths.configDir() as NSString).appendingPathComponent("se")) {
			dir = URL(fileURLWithPath: directory, isDirectory: true)
		}

		public var name: String { Self.providerName }
		public var bindingMode: String { "" }
		// Hardware present AND a key can actually be minted here: an unentitled or unsigned
		// host reports the enclave but refuses key creation, and must fall back to Keychain.
		// CryptoKit enclave keys are only a handle (nothing persists unless we store its
		// blob), so the probe key is simply discarded.
		public func available() async -> Bool {
			guard SecureEnclave.isAvailable, let ac = try? accessControl() else { return false }
			return (try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac, authenticationContext: nil)) != nil
		}

		private func ensureDir() throws {
			try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
		}

		private func blobURL(_ id: String) throws -> URL {
			guard !id.isEmpty, id.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) || ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "." || $0 == "_" || $0 == "-" }) else {
				throw VaultError.invalidArgument("invalid keystore id")
			}
			try ensureDir()
			return dir.appendingPathComponent(id + ".se")
		}

		private var keyURL: URL { dir.appendingPathComponent("device.sekey") }

		// Usable only while the device is unlocked, this device only, gated by user presence.
		private func accessControl() throws -> SecAccessControl {
			var e: Unmanaged<CFError>?
			guard let ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &e) else {
				throw VaultError.corrupt("could not create access control")
			}
			return ac
		}

		// Only `put` may mint the enclave key: `get` must report a lost key precisely
		// rather than silently minting one that cannot decrypt existing blobs.
		private func deviceKey(create: Bool, context: LAContext?) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
			if let blob = try? Data(contentsOf: keyURL) {
				return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
			}
			guard create else { return nil }
			try ensureDir()
			let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl(), authenticationContext: nil)
			try k.dataRepresentation.write(to: keyURL, options: .atomic)
			return k
		}

		public func put(id: String, secret: Data) async throws {
			let url = try blobURL(id)  // validate the id BEFORE minting any key
			guard let k = try deviceKey(create: true, context: nil) else { throw VaultError.keystoreUnavailable(name) }
			try SecureEnclaveSeal.seal(secret, to: k.publicKey).write(to: url, options: .atomic)
		}

		// A denied/cancelled prompt or a lost key reads as "no secret", so the engine
		// surfaces its precise "cannot unlock" error.
		public func get(id: String) async throws -> Data? {
			guard let blob = try? Data(contentsOf: try blobURL(id)) else { return nil }
			let ctx = LAContext()
			ctx.localizedReason = "Unlock your vault"
			guard let k = try? deviceKey(create: false, context: ctx) else { return nil }
			return try? SecureEnclaveSeal.open(blob) { try k.sharedSecretFromKeyAgreement(with: $0) }
		}

		public func delete(id: String) async throws { try? FileManager.default.removeItem(at: try blobURL(id)) }
	}

	public enum Platform {
		public static let processSecurity: PlatformProcessSecurity = DarwinProcessSecurity()
		// `name` pins the provider a vault was sealed under (nil: strongest available).
		// Strongest first: Secure Enclave (per-access user verification), then Keychain.
		public static func keyStore(named name: String?, mode: String? = nil) async -> PlatformKeyStore? {
			if name == nil || name == SecureEnclaveKeyStore.providerName {
				let se = SecureEnclaveKeyStore()
				if await se.available() { return se }
				if name != nil { return nil }
			}
			guard name == nil || name == DarwinKeychainKeyStore.providerName else { return nil }
			return DarwinKeychainKeyStore()
		}
	}
#endif
