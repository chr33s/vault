import Foundation

// TPM 2.0 key store over the `tpm2-tools` CLI (tpm2_createprimary / tpm2_create /
// tpm2_load / tpm2_unseal). The tools own ALL TPM marshalling, sessions and transport
// (`/dev/tpmrm0`, `swtpm`, or whatever `TPM2TOOLS_TCTI` names); this type only drives
// them. That replaces the retired hand-written TPM2 codec, which could only be verified
// against an emulator.
//
// The device unlock key (DUK) is SEALED to a data object under a primary key derived
// from the owner hierarchy (deterministic for a fixed template, so it is simply
// recreated on every call and nothing about it is persisted). The object is created
// `fixedtpm|fixedparent|userwithauth`, i.e. it cannot leave this TPM, and WITHOUT
// `noda`, so an auth value (the PIN) is protected by the TPM's dictionary-attack
// lockout. With `$VAULT_TPM2_PIN` set this is per-access user verification; without it,
// at-rest TPM binding.
//
// Secrets never touch argv: the DUK goes over stdin, the PIN through a 0600 file in a
// private 0700 work dir that is removed afterwards. Blob (persisted by BlobKeyStore):
//   "VTP1" || u32be(len pub) || TPM2B_PUBLIC || TPM2B_PRIVATE
// The sealed payload is sha256(name) || secret, so a blob copied to another keystore id
// is refused even though the TPM would unseal it.

public struct Tpm2ToolsCipher: BlobCipher {
	public static let providerName = "tpm2"
	static let magic = Data("VTP1".utf8)

	let pin: String?
	let binDir: String?
	let extraEnv: [String: String]
	let requirePin: Bool

	// `binDir` prefixes the tool names (tests, non-PATH installs). `requirePin` is set
	// when the vault was sealed with a PIN, so unlock fails clearly instead of trying an
	// empty auth value (which would burn a dictionary-attack attempt).
	public init(pin: String? = ProcessInfo.processInfo.environment["VAULT_TPM2_PIN"], requirePin: Bool = false, binDir: String? = nil, environment: [String: String] = [:]) {
		self.pin = (pin?.isEmpty == false) ? pin : nil
		self.requirePin = requirePin
		self.binDir = binDir
		self.extraEnv = environment
	}

	// Recorded in vault meta so unlock knows a PIN is needed.
	public var bindingMode: String { pin != nil ? "pin" : "" }

	private func tool(_ n: String) -> String { binDir.map { ($0 as NSString).appendingPathComponent(n) } ?? n }
	private var env: [String: String] { ProcessInfo.processInfo.environment.merging(extraEnv) { $1 } }

	private func run(_ name: String, _ args: [String], input: Data = Data()) async throws -> Data {
		// Exit codes only: tool stderr can carry object handles and is not useful to echo.
		let r = try await ProcessRunner.run(tool(name), args, input: input, environment: env)
		// Each tool leaves its transient objects loaded. Behind a resource manager
		// (/dev/tpmrm0, tpm2-abrmd) they die with the connection; on a raw TPM (/dev/tpm0,
		// a bare swtpm) they pile up until the ~3 object slots run out. The context files
		// reload them for the next step, so flushing after every call is always safe.
		if name != "tpm2_getrandom" { _ = try? await ProcessRunner.run(tool("tpm2_flushcontext"), ["-t"], environment: env) }
		guard r.code == 0 else { throw VaultError.corrupt("\(name) failed (exit \(r.code))") }
		return r.stdout
	}

	public func available() async -> Bool {
		guard ProcessRunner.resolve(tool("tpm2_createprimary")) != nil, ProcessRunner.resolve(tool("tpm2_getrandom")) != nil else { return false }
		// A real round trip: the tools exist AND a TPM answers.
		return (try? await run("tpm2_getrandom", ["1"]))?.count == 1
	}

	private func withWorkdir<T>(_ body: (String) async throws -> T) async throws -> T {
		let dir = NSTemporaryDirectory() + "vault-tpm2-\(UUID().uuidString)"
		try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
		defer { try? FileManager.default.removeItem(atPath: dir) }
		return try await body(dir)
	}

	private func primary(_ dir: String) async throws -> String {
		let ctx = dir + "/primary.ctx"
		_ = try await run("tpm2_createprimary", ["-C", "o", "-g", "sha256", "-G", "ecc", "-c", ctx])
		return ctx
	}

	// `-p file:` keeps the PIN off argv (visible via `ps`).
	private func authArgs(_ dir: String) throws -> [String] {
		guard let pin else { return [] }
		let f = dir + "/pin"
		guard FileManager.default.createFile(atPath: f, contents: Data(pin.utf8), attributes: [.posixPermissions: 0o600]) else {
			throw VaultError.corrupt("cannot stage the TPM PIN")
		}
		return ["-p", "file:\(f)"]
	}

	private func nameTag(_ name: String) -> Data { VaultCrypto.sha256("credvault/tpm2/v1:\(name)") }

	public func protect(_ plaintext: Data, name: String) async throws -> Data {
		try await withWorkdir { dir in
			let ctx = try await primary(dir)
			let pub = dir + "/sealed.pub", priv = dir + "/sealed.priv"
			// DA protection stays ON (no `noda`): the TPM locks out repeated bad PINs.
			_ = try await run(
				"tpm2_create",
				["-C", ctx, "-i", "-", "-u", pub, "-r", priv, "-a", "fixedtpm|fixedparent|userwithauth"] + (try authArgs(dir)),
				input: nameTag(name) + plaintext)
			guard let p = FileManager.default.contents(atPath: pub), let r = FileManager.default.contents(atPath: priv) else {
				throw VaultError.corrupt("tpm2_create produced no object")
			}
			var len = UInt32(p.count).bigEndian
			return Self.magic + Data(bytes: &len, count: 4) + p + r
		}
	}

	public func unprotect(_ blob: Data, name: String) async throws -> Data {
		let b = [UInt8](blob)
		guard b.count > 8, Data(b[0..<4]) == Self.magic else { throw VaultError.corrupt("tpm2: not a tpm2-sealed blob") }
		let pl = Int(UInt32(b[4]) << 24 | UInt32(b[5]) << 16 | UInt32(b[6]) << 8 | UInt32(b[7]))
		guard pl > 0, 8 + pl < b.count else { throw VaultError.corrupt("tpm2: truncated blob") }
		// Refuse before touching the TPM: a missing PIN would burn a lockout attempt.
		if requirePin && pin == nil { throw VaultError.invalidArgument("this vault's TPM key needs $VAULT_TPM2_PIN") }
		return try await withWorkdir { dir in
			let ctx = try await primary(dir)
			guard FileManager.default.createFile(atPath: dir + "/sealed.pub", contents: Data(b[8..<8 + pl])),
				FileManager.default.createFile(atPath: dir + "/sealed.priv", contents: Data(b[(8 + pl)...]))
			else { throw VaultError.corrupt("cannot stage the sealed object") }
			let obj = dir + "/obj.ctx"
			_ = try await run("tpm2_load", ["-C", ctx, "-u", dir + "/sealed.pub", "-r", dir + "/sealed.priv", "-c", obj])
			let out = try await run("tpm2_unseal", ["-c", obj] + (try authArgs(dir)))
			guard out.count >= 32 else { throw VaultError.corrupt("tpm2: unsealed data too short") }
			var diff: UInt8 = 0
			let tag = nameTag(name)
			for i in 0..<32 { diff |= out[out.startIndex + i] ^ tag[tag.startIndex + i] }
			guard diff == 0 else { throw VaultError.corrupt("tpm2: blob belongs to a different keystore id") }
			return out.dropFirst(32)
		}
	}
}
