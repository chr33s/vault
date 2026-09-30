import Foundation

// Linux `systemd-creds` as a BlobCipher: the DPAPI analog.
// Raw bytes on stdin/stdout; only --name/--with-key ride argv. `--with-key=host` is
// machine-scoped software; "auto"/"tpm2" binds the DUK to the TPM at rest. The
// keystore id becomes the credential --name so a blob can't be reused under another id.

public struct SystemdCredsCipher: BlobCipher {
	public static let providerName = "systemd-creds"
	let binary: String
	let mode: String?
	let requireLinux: Bool

	// `binary` is overridable (env VAULT_SYSTEMD_CREDS) for tests and custom installs.
	public init(keyMode: String? = nil, binary: String? = nil, requireLinux: Bool = true, environment: [String: String] = ProcessInfo.processInfo.environment) {
		self.binary = binary ?? environment["VAULT_SYSTEMD_CREDS"] ?? "systemd-creds"
		self.mode = keyMode
		self.requireLinux = requireLinux
		self.env = environment
	}
	private let env: [String: String]

	// The mode NEW seals use: $VAULT_SYSTEMD_CREDS_KEY, default "host".
	public var keyMode: String { mode ?? env["VAULT_SYSTEMD_CREDS_KEY"] ?? "host" }
	public var bindingMode: String { keyMode }

	private func run(_ args: [String], _ input: Data) async throws -> Data {
		let r = try await ProcessRunner.run(binary, args, input: input)
		guard r.code == 0 else { throw VaultError.corrupt("systemd-creds exited \(r.code)") }
		return r.stdout
	}

	public func available() async -> Bool {
		#if !os(Linux)
			if requireLinux { return false }
		#endif
		// Round-trip a probe byte: also confirms host-key access (root-only by default).
		guard let blob = try? await protect(Data([1]), name: "vault-probe"), let back = try? await unprotect(blob, name: "vault-probe") else { return false }
		return back == Data([1])
	}

	public func protect(_ plaintext: Data, name: String) async throws -> Data {
		try await run(["encrypt", "--name=\(name)", "--with-key=\(keyMode)", "-", "-"], plaintext)
	}

	public func unprotect(_ blob: Data, name: String) async throws -> Data {
		try await run(["decrypt", "--name=\(name)", "-", "-"], blob)
	}
}
