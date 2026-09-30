// The bridge to the vault engine. Every action the app takes is a
// `vault --json --passphrase-stdin <cmd>` command — but it now runs IN-PROCESS:
// the app links VaultCommands (and through it VaultCore) directly instead of
// spawning a Node SEA subprocess. That removes the passphrase IPC boundary
// entirely: secrets (the account passphrase, item passwords) are handed over as
// values, never through a pipe, argv or the environment. The structured JSON
// envelope stays as the app/engine contract so the views and models are unchanged.
// Relay credentials still cross via `extraEnv` (an overlay for this one command, not
// the process environment) because they gate reachability/metadata (§8.3), not
// confidentiality.

import Foundation
import VaultCommands

struct CLIError: LocalizedError {
	let message: String
	var errorDescription: String? { message }
}

// The success/failure envelope shared by every --json response.
private struct Envelope: Decodable {
	let ok: Bool
	let error: String?
}

final class VaultCLI {
	var vaultName: String?

	init(vaultName: String? = nil) {
		self.vaultName = vaultName
	}

	static func bundled() -> VaultCLI { VaultCLI() }

	// Run a command and return the single JSON line as Data (throws on ok:false or
	// no JSON). Passphrases are consumed one per prompt, in the order the command
	// asks (account passphrase first).
	private func raw(_ args: [String], passphrases: [String], extraEnv: [String: String]) async throws
		-> Data
	{
		var full = ["--json", "--passphrase-stdin"]
		if let v = vaultName { full += ["--vault", v] }
		let result = await VaultCommands.execute(full + args, secrets: passphrases, environment: extraEnv)
		guard
			let firstLine = result.stdout.split(separator: "\n", omittingEmptySubsequences: true).first
		else {
			let msg = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
			throw CLIError(message: msg.isEmpty ? "vault produced no output" : msg)
		}
		let lineData = Data(firstLine.utf8)
		let env: Envelope
		do { env = try JSONDecoder().decode(Envelope.self, from: lineData) } catch {
			throw CLIError(message: "could not parse vault output")
		}
		guard env.ok else { throw CLIError(message: env.error ?? "unknown error") }
		return lineData
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
