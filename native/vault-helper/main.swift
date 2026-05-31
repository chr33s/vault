// vault-helper — Secure Enclave KeyStore shim (plan §12a Step 2).
//
// The Node CLI's `secure-enclave` KeyStore provider (cli/keystore.ts) spawns this
// helper to satisfy the KeyStore contract (available/put/get/del). The secret it
// stores is the per-vault Device Unlock Key (DUK); the engine folds it into the
// at-rest wrap key as HKDF(accountKey, DUK). The DUK is sealed to a NON-EXPORTABLE
// P-256 key that lives in the Secure Enclave and is gated by Touch ID
// (.userPresence): sealing needs only the public key (no prompt); unsealing on
// `get` runs a private-key operation that forces a biometric/user-presence check,
// and the key material never leaves hardware. Strong tier over login-keychain —
// no passphrase to keylog, no exportable secret.
//
// Why CryptoKit (not a permanent keychain SecKey): a permanent Secure-Enclave key
// stored in the keychain (kSecAttrIsPermanent) forces the data-protection keychain,
// which needs the `keychain-access-groups` entitlement and a provisioning profile —
// neither of which a signed-but-unprofiled CLI helper has (you get errSecMissingEntitlement
// / -34018, or AMFI SIGKILLs the process). CryptoKit's SecureEnclave key instead
// hands back an opaque `dataRepresentation` blob, encrypted by THIS enclave, that we
// persist ourselves. No keychain, no entitlement — it works under plain ad-hoc signing.
//
// Wire protocol (mirrors the windows-dpapi PowerShell transport: base64 on
// stdin/stdout, the id on argv — ids are not secret):
//
//   vault-helper available        -> prints "1", exit 0 if SE usable; else exit 1
//   vault-helper put <id>         <- base64(secret) on stdin; seals to disk; exit 0
//   vault-helper get <id>         -> base64(secret) on stdout (Touch ID prompt); exit 0
//   vault-helper del <id>         removes the sealed blob; exit 0 (idempotent)
//
// On disk under $VAULT_SE_DIR (the CLI passes it, kept in sync with its config dir):
//   device.sekey   the enclave key blob (dataRepresentation), one per device, shared
//                  across vaults; safe at rest — useless without this enclave + Touch ID.
//   <id>.se        a sealed DUK: ephemeralPub(64) || AES-GCM(nonce|ct|tag).

import CryptoKit
import Foundation
import LocalAuthentication
import Security

let deviceKeyName = "device.sekey"
let hkdfInfo = Data("credvault/secure-enclave/v1".utf8)

func fail(_ message: String) -> Never {
	FileHandle.standardError.write(("vault-helper: " + message + "\n").data(using: .utf8)!)
	exit(1)
}

func storeDir() -> URL {
	guard let dir = ProcessInfo.processInfo.environment["VAULT_SE_DIR"] else {
		fail("VAULT_SE_DIR is not set")
	}
	let url = URL(fileURLWithPath: dir, isDirectory: true)
	try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
	return url
}

// Reject anything that isn't a safe filename component (matches the JS id check).
func sealedBlobURL(_ id: String) -> URL {
	guard id.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil else {
		fail("invalid keystore id")
	}
	return storeDir().appendingPathComponent(id + ".se")
}

// Access control for the enclave private key: usable only while the device is
// unlocked, this device only, gated by user presence (Touch ID, with the device
// passcode as the system fallback).
func makeAccessControl() -> SecAccessControl {
	var error: Unmanaged<CFError>?
	guard
		let ac = SecAccessControlCreateWithFlags(
			kCFAllocatorDefault,
			kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
			[.privateKeyUsage, .userPresence],
			&error
		)
	else { fail("could not create access control: \((error?.takeRetainedValue() as Error?)?.localizedDescription ?? "unknown")") }
	return ac
}

func deviceKeyURL() -> URL { storeDir().appendingPathComponent(deviceKeyName) }

// Load the device's enclave key, or nil if it was never created / the blob is gone.
// NEVER creates one: only `put` mints a key, so `get` can report a lost key
// precisely instead of silently minting a fresh key that can't decrypt existing
// blobs (which would surface as a confusing "unseal failed"). The auth context is
// attached for the decrypt path so the Touch ID reason string is shown.
func loadDeviceKey(context: LAContext?) -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
	guard let blob = try? Data(contentsOf: deviceKeyURL()) else { return nil }
	do {
		return try SecureEnclave.P256.KeyAgreement.PrivateKey(
			dataRepresentation: blob, authenticationContext: context)
	} catch {
		fail("device key blob is unreadable: \(error.localizedDescription)")
	}
}

// Mint and persist the device's enclave key. Creating it does not prompt — only
// USING the private key (the `get` decrypt path) does.
func createDeviceKey() -> SecureEnclave.P256.KeyAgreement.PrivateKey {
	do {
		let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
			accessControl: makeAccessControl(), authenticationContext: nil)
		try key.dataRepresentation.write(to: deviceKeyURL(), options: .atomic)
		return key
	} catch {
		fail("could not create Secure Enclave key: \(error.localizedDescription)")
	}
}

func readStdinBase64() -> Data {
	let raw = FileHandle.standardInput.readDataToEndOfFile()
	let text = String(decoding: raw, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
	guard let data = Data(base64Encoded: text) else { fail("stdin was not valid base64") }
	return data
}

func writeStdoutBase64(_ data: Data) {
	FileHandle.standardOutput.write((data.base64EncodedString() + "\n").data(using: .utf8)!)
}

// ECDH(ephemeral, enclavePub) -> HKDF-SHA256 -> AES-256-GCM key. The ephemeral
// public key is unique per seal, so it doubles as the HKDF salt; both sides have it.
func deriveKey(_ shared: SharedSecret, ephemeralPub: Data) -> SymmetricKey {
	shared.hkdfDerivedSymmetricKey(
		using: SHA256.self, salt: ephemeralPub, sharedInfo: hkdfInfo, outputByteCount: 32)
}

// ---- caller authentication ----
//
// Closes the keystore's biggest gap. By itself, CryptoKit's `.userPresence` gate
// authenticates the *human* (Touch ID) but NOT the *calling code*: any process
// running as this user could spawn the helper and, on a single reflexive tap,
// unseal the DUK. Here we additionally require the parent process — the one that
// spawned us — to be signed by the same Apple Developer Team as this helper. Under
// real (Developer ID) signing that restricts the unseal to our own CLI/app; code
// signed by a different identity, or unsigned malware, is rejected before the
// Touch ID prompt is ever shown.
//
// Tradeoffs (deliberate):
//   * Binds to Team, not a single binary — any of our own signed code qualifies,
//     which is fine for a personal vault. Tighten to `identifier "…"` if you ever
//     want to pin one executable.
//   * getppid()+SecCode has a theoretical PID-reuse TOCTOU; sound here because the
//     parent is alive awaiting our exit for the whole call.
//   * Ad-hoc/unsigned helpers carry no Team identity to bind to, so enforcement is
//     only possible under real signing. An unsigned helper therefore fails OPEN
//     (preserving the supported "Sign to Run Locally" / `swift build` dev flow)
//     UNLESS VAULT_SE_STRICT is set, which makes an unsigned helper fail CLOSED.
//     => For the guarantee to hold in production, ship the CLI and helper
//        Developer-ID signed (build.sh does this when CODESIGN_ID is set).

func signingInfo(_ staticCode: SecStaticCode) -> [String: Any]? {
	var info: CFDictionary?
	guard
		SecCodeCopySigningInformation(
			staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
		let dict = info as? [String: Any]
	else { return nil }
	return dict
}

func selfTeamIdentifier() -> String? {
	var selfCode: SecCode?
	guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let code = selfCode else { return nil }
	var staticCode: SecStaticCode?
	guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let sc = staticCode else {
		return nil
	}
	return signingInfo(sc)?[kSecCodeInfoTeamIdentifier as String] as? String
}

// The calling code's signing identifier (e.g. "vault", "chr33s.dev.vault"). Only
// read after SecCodeCheckValidity has confirmed the caller is our own signed code,
// so the value is trustworthy — safe to surface in the Touch ID prompt.
func callerIdentifier(_ code: SecCode) -> String? {
	var staticCode: SecStaticCode?
	guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let sc = staticCode else {
		return nil
	}
	return signingInfo(sc)?[kSecCodeInfoIdentifier as String] as? String
}

// Verifies the parent process is signed by our Team; returns its (verified) code
// signing identifier so callers like `get` can name the requester in the biometric
// prompt. Returns nil when this helper is unsigned/dev (no identity to bind to) —
// fails closed in that case only if VAULT_SE_STRICT is set.
@discardableResult
func verifyCaller() -> String? {
	guard let team = selfTeamIdentifier() else {
		if ProcessInfo.processInfo.environment["VAULT_SE_STRICT"] != nil {
			fail("caller verification required (VAULT_SE_STRICT) but this helper is unsigned")
		}
		return nil  // ad-hoc / dev build: no code identity to bind the caller to
	}
	let reqString = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
	var requirement: SecRequirement?
	guard
		SecRequirementCreateWithString(reqString as CFString, [], &requirement) == errSecSuccess,
		let req = requirement
	else { fail("could not build caller code requirement") }

	let attrs = [kSecGuestAttributePid as String: NSNumber(value: getppid())] as CFDictionary
	var callerCode: SecCode?
	guard
		SecCodeCopyGuestWithAttributes(nil, attrs, [], &callerCode) == errSecSuccess,
		let caller = callerCode
	else { fail("could not inspect the calling process") }

	guard SecCodeCheckValidity(caller, [], req) == errSecSuccess else {
		fail("caller is not authorized to use the Secure Enclave keystore")
	}
	return callerIdentifier(caller)
}

// ---- commands ----

// `available`: is the Secure Enclave usable here? CryptoKit answers directly and
// without side effects (no key minted, no prompt).
func cmdAvailable() {
	guard SecureEnclave.isAvailable else { exit(1) }
	FileHandle.standardOutput.write("1\n".data(using: .utf8)!)
	exit(0)
}

// `put <id>`: seal the DUK from stdin to the enclave public key, store on disk.
// Uses only the public key, so it never prompts for Touch ID.
func cmdPut(_ id: String) {
	let secret = readStdinBase64()
	let enclavePub = (loadDeviceKey(context: nil) ?? createDeviceKey()).publicKey
	do {
		let eph = P256.KeyAgreement.PrivateKey()
		let ephPub = eph.publicKey.rawRepresentation
		let shared = try eph.sharedSecretFromKeyAgreement(with: enclavePub)
		let box = try AES.GCM.seal(secret, using: deriveKey(shared, ephemeralPub: ephPub))
		guard let combined = box.combined else { fail("seal produced no combined box") }
		try (ephPub + combined).write(to: sealedBlobURL(id), options: .atomic)
	} catch { fail("seal failed: \(error.localizedDescription)") }
}

// `get <id>`: read the sealed blob, decrypt with the enclave private key. The
// private-key key-agreement is what triggers the Touch ID / user-presence prompt.
func cmdGet(_ id: String, caller: String?) {
	guard let blob = try? Data(contentsOf: sealedBlobURL(id)), blob.count > 64 else {
		fail("no sealed secret for id")  // missing/short -> JS get() returns undefined
	}
	let ephPub = blob.prefix(64)
	let combined = blob.suffix(from: blob.startIndex + 64)
	let context = LAContext()
	// Name the verified requester so the human has a second signal beyond Touch ID
	// (the identifier is trustworthy — it came from a signature we just validated).
	context.localizedReason = caller.map { "Unlock your vault — requested by \($0)" }
		?? "Unlock your vault"
	guard let priv = loadDeviceKey(context: context) else {
		// Blob present but the device key is gone -> this device lost its keystore
		// factor. Report it; don't mint a new key (that could never decrypt this blob).
		fail("Secure Enclave device key is missing on this device — re-enroll to recover")
	}
	do {
		let ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: ephPub)
		let shared = try priv.sharedSecretFromKeyAgreement(with: ephemeral)
		let sealed = try AES.GCM.SealedBox(combined: combined)
		let plain = try AES.GCM.open(sealed, using: deriveKey(shared, ephemeralPub: Data(ephPub)))
		writeStdoutBase64(plain)
	} catch { fail("unseal failed (denied or wrong device): \(error.localizedDescription)") }
}

// `del <id>`: remove the sealed blob. Idempotent; the shared enclave key stays.
func cmdDel(_ id: String) {
	try? FileManager.default.removeItem(at: sealedBlobURL(id))
}

// ---- dispatch ----

let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: vault-helper <available|put|get|del> [id]") }
let command = args[1]

func requireId() -> String {
	guard args.count >= 3 else { fail("usage: vault-helper \(command) <id>") }
	return args[2]
}

switch command {
case "available":
	cmdAvailable()
case "put":
	verifyCaller()
	cmdPut(requireId())
case "get":
	let caller = verifyCaller()
	cmdGet(requireId(), caller: caller)
case "del":
	verifyCaller()
	cmdDel(requireId())
default:
	fail("unknown command: \(command)")
}
