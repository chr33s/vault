// The bridge to the SEA CLI. Every action the app takes is a `vault --json
// --passphrase-stdin <cmd>` invocation: structured output in, vault secrets (the
// passphrase, item passwords) over stdin only — never argv/env — per the §12a
// Step-1 machine contract. Relay credentials are the one exception, crossing via
// `extraEnv` because they gate reachability/metadata (§8.3), not confidentiality.
// The app holds no crypto and no engine state — the CLI is the engine.

import Foundation

struct CLIError: LocalizedError {
	let message: String
	var errorDescription: String? { message }
}

// The success/failure envelope shared by every --json response.
private nonisolated struct Envelope: Decodable {
	let ok: Bool
	let error: String?
}

final class VaultCLI {
	let binaryURL: URL
	let seHelperURL: URL?
	var vaultName: String?

	init(binaryURL: URL, seHelperURL: URL?, vaultName: String? = nil) {
		self.binaryURL = binaryURL
		self.seHelperURL = seHelperURL
		self.vaultName = vaultName
	}

	// Resolve the bundled CLI + Secure-Enclave helper from Contents/Resources,
	// with env overrides ($VAULT_BIN / $VAULT_HELPER) for Xcode-run dev use.
	static func bundled() -> VaultCLI {
		let env = ProcessInfo.processInfo.environment
		let resources = Bundle.main.resourceURL
		func resolve(_ key: String, _ name: String) -> URL? {
			if let p = env[key] { return URL(fileURLWithPath: p) }
			if let r = resources?.appendingPathComponent(name),
				FileManager.default.isExecutableFile(atPath: r.path)
			{
				return r
			}
			return nil
		}
		let bin = resolve("VAULT_BIN", "vault") ?? URL(fileURLWithPath: "/usr/local/bin/vault")
		return VaultCLI(binaryURL: bin, seHelperURL: resolve("VAULT_HELPER", "vault-helper"))
	}

	// Run a command and return the single JSON line as Data (throws on ok:false or
	// a non-zero exit with no JSON). Passphrases are written to stdin, one line
	// each, in the order the command prompts (account passphrase first). `extraEnv`
	// carries non-argv credentials (e.g. relay tokens) into the child environment.
	private func raw(_ args: [String], passphrases: [String], extraEnv: [String: String]) async throws
		-> Data
	{
		try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
			let process = Process()
			process.executableURL = binaryURL
			var full = ["--json", "--passphrase-stdin"]
			if let v = vaultName { full += ["--vault", v] }
			process.arguments = full + args

			var environment = ProcessInfo.processInfo.environment
			if let helper = seHelperURL { environment["VAULT_HELPER"] = helper.path }
			for (k, v) in extraEnv { environment[k] = v }
			process.environment = environment

			let stdin = Pipe()
			let stdout = Pipe()
			let stderr = Pipe()
			process.standardInput = stdin
			process.standardOutput = stdout
			process.standardError = stderr

			process.terminationHandler = { _ in
				let outData = stdout.fileHandleForReading.readDataToEndOfFile()
				let errData = stderr.fileHandleForReading.readDataToEndOfFile()
				guard
					let firstLine = String(data: outData, encoding: .utf8)?
						.split(separator: "\n", omittingEmptySubsequences: true).first
				else {
					let msg = String(data: errData, encoding: .utf8) ?? ""
					cont.resume(
						throwing: CLIError(message: msg.isEmpty ? "vault produced no output" : msg.trimmed))
					return
				}
				let lineData = Data(firstLine.utf8)
				do {
					let env = try JSONDecoder().decode(Envelope.self, from: lineData)
					if env.ok { cont.resume(returning: lineData) } else {
						cont.resume(throwing: CLIError(message: env.error ?? "unknown error"))
					}
				} catch {
					cont.resume(throwing: CLIError(message: "could not parse vault output"))
				}
			}

			do { try process.run() } catch {
				cont.resume(throwing: error)
				return
			}
			let h = stdin.fileHandleForWriting
			for p in passphrases { h.write(Data((p + "\n").utf8)) }
			try? h.close()
		}
	}

	// Typed command: decode the JSON envelope (which carries the payload at top
	// level alongside "ok") into a Decodable result.
	func run<T: Decodable>(
		_ args: [String], passphrases: [String] = [], extraEnv: [String: String] = [:], as type: T.Type
	) async throws -> T {
		let data = try await raw(args, passphrases: passphrases, extraEnv: extraEnv)
		return try JSONDecoder().decode(T.self, from: data)
	}

	// Command whose success we only need to confirm (add/edit/rm).
	func run(_ args: [String], passphrases: [String] = [], extraEnv: [String: String] = [:]) async throws
	{
		_ = try await raw(args, passphrases: passphrases, extraEnv: extraEnv)
	}
}

extension String {
	fileprivate nonisolated var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
