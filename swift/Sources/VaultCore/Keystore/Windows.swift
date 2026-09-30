import Crypto
import Foundation

// Windows key-store ciphers. They spawn PowerShell / the signed Hello helper, so the
// code is portable Swift and testable against stubs on any OS; only the platform
// module decides when they are offered.

// DPAPI (CurrentUser scope) through PowerShell's ProtectedData. The keystore id is
// the optionalEntropy so a blob copied to another id won't unprotect. Base64 on
// stdin/stdout keeps secrets off argv and the transport binary-clean.
public struct DpapiCipher: BlobCipher {
	public static let providerName = "windows-dpapi"
	let powershell: String
	let requireWindows: Bool

	public init(powershell: String? = nil, requireWindows: Bool = true) {
		#if os(Windows)
			self.powershell = powershell ?? "powershell.exe"
		#else
			self.powershell = powershell ?? ProcessInfo.processInfo.environment["VAULT_POWERSHELL"] ?? "pwsh"
		#endif
		self.requireWindows = requireWindows
	}

	private func entropy(_ name: String) -> String {
		"[Convert]::FromBase64String('\(Data("credvault/dpapi/v1:\(name)".utf8).base64)')"
	}

	private func script(_ transform: String) -> String {
		"$ErrorActionPreference='Stop';$in=[Console]::In.ReadToEnd().Trim();$bytes=[Convert]::FromBase64String($in);"
			+ "Add-Type -AssemblyName System.Security;$out=\(transform);[Console]::Out.Write([Convert]::ToBase64String($out));"
	}

	private func run(_ transform: String, _ input: Data) async throws -> Data {
		let r = try await ProcessRunner.run(powershell, ["-NoProfile", "-NonInteractive", "-Command", script(transform)], input: Data(input.base64.utf8))
		guard r.code == 0 else { throw VaultError.corrupt("powershell exited \(r.code)") }
		return Data(base64: String(decoding: r.stdout, as: UTF8.self))
	}

	public func available() async -> Bool {
		#if !os(Windows)
			if requireWindows { return false }
		#endif
		guard let blob = try? await protect(Data([1]), name: ""), let back = try? await unprotect(blob, name: "") else { return false }
		return back == Data([1])
	}

	public func protect(_ plaintext: Data, name: String) async throws -> Data {
		try await run("[System.Security.Cryptography.ProtectedData]::Protect($bytes,\(entropy(name)),[System.Security.Cryptography.DataProtectionScope]::CurrentUser)", plaintext)
	}

	public func unprotect(_ blob: Data, name: String) async throws -> Data {
		try await run("[System.Security.Cryptography.ProtectedData]::Unprotect($bytes,\(entropy(name)),[System.Security.Cryptography.DataProtectionScope]::CurrentUser)", blob)
	}
}

// Windows Hello (spec §3.5): per-access user verification. KeyCredential can only
// SIGN, so the DUK is wrapped under a key derived from a signature:
//   wrapKey = HKDF-SHA256(sign(challenge), salt = challenge, info "credvault/hello/v1")
//   blob    = "VHW1" || challenge(32) || iv(12) || tag(16) || AES-256-GCM(wrapKey, DUK)
// with the keystore id bound as AEAD data. The blob format is fixed,
// so either client opens the other's blobs. The helper only ever sees a challenge and
// returns a signature: never the DUK, account keys, or vault plaintext (spec §15.8).
public protocol HelloSigner: Sendable {
	func available() async -> Bool
	func sign(_ challenge: Data, create: Bool) async throws -> Data
}

public struct HelperHelloSigner: HelloSigner {
	public static let credential = "dev.vault.unlock"
	let helper: String
	public init(helperPath: String) { helper = helperPath }

	public func available() async -> Bool {
		guard FileManager.default.isExecutableFile(atPath: helper),
			let r = try? await ProcessRunner.run(helper, ["available"])
		else { return false }
		return r.code == 0 && String(decoding: r.stdout, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) == "1"
	}

	public func sign(_ challenge: Data, create: Bool) async throws -> Data {
		let r = try await ProcessRunner.run(helper, ["sign"] + (create ? ["--create"] : []) + [Self.credential], input: Data(challenge.base64.utf8))
		guard r.code == 0 else {
			let e = String(decoding: r.stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
			throw VaultError.corrupt("windows-hello sign failed: \(e.isEmpty ? "exit \(r.code)" : e)")
		}
		let sig = Data(base64: String(decoding: r.stdout, as: UTF8.self))
		guard !sig.isEmpty else { throw VaultError.corrupt("windows-hello: signer returned an empty signature") }
		return sig
	}
}

public struct HelloCipher: BlobCipher {
	public static let providerName = "windows-hello"
	static let magic = Data("VHW1".utf8)
	static let info = "credvault/hello/v1"
	let signer: HelloSigner
	public init(signer: HelloSigner) { self.signer = signer }

	private func aad(_ name: String) -> Data { Data("\(Self.info):\(name)".utf8) }
	public func available() async -> Bool { await signer.available() }

	public func protect(_ plaintext: Data, name: String) async throws -> Data {
		let challenge = VaultCrypto.randomBytes(32)
		// Enrollment self-test: a randomized scheme (RSA-PSS) would yield an
		// irrecoverable wrap key, so refuse the tier rather than write a dead blob.
		let sig = try await signer.sign(challenge, create: true)
		let again = try await signer.sign(challenge, create: false)
		guard !sig.isEmpty, sig == again else {
			throw VaultError.corrupt("windows-hello: the credential signs non-deterministically; use windows-dpapi or tpm2 instead")
		}
		let wrap = VaultCrypto.hkdf(ikm: sig, salt: challenge, info: Self.info, length: 32)
		let box = try VaultCrypto.aeadEncrypt(key: wrap, plaintext: plaintext, aad: aad(name))
		return Self.magic + challenge + box.iv + box.tag + box.ct
	}

	public func unprotect(_ blob: Data, name: String) async throws -> Data {
		let b = [UInt8](blob)
		let head = Self.magic.count + 32 + 12 + 16
		guard b.count >= head, Data(b[0..<Self.magic.count]) == Self.magic else { throw VaultError.corrupt("windows-hello: not a hello-sealed blob") }
		var o = Self.magic.count
		let challenge = Data(b[o..<o + 32]); o += 32
		let iv = Data(b[o..<o + 12]); o += 12
		let tag = Data(b[o..<o + 16]); o += 16
		let ct = Data(b[o...])
		// Never create here: a fresh credential could not decrypt this blob.
		let sig = try await signer.sign(challenge, create: false)
		let wrap = VaultCrypto.hkdf(ikm: sig, salt: challenge, info: Self.info, length: 32)
		return try VaultCrypto.aeadDecrypt(key: wrap, box: AeadBox(iv: iv, ct: ct, tag: tag), aad: aad(name))
	}
}
