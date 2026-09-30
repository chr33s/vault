import Foundation
import VaultCore

// `vault run` (spec §15.13): resolve `.env` declarations from the local vault and
// inject them at child launch only. Nothing resolved is written to disk; the child
// never inherits the vault's own credentials; failure to resolve aborts before spawn.

private let vaultSecretEnv: Set<String> = [
	"VAULT_PASSPHRASE", "VAULT_ORG_KEY", "VAULT_RELAY_TOKEN", "VAULT_RELAY_TOKENS", "VAULT_PEER_TOKEN",
	"VAULT_TPM2_PIN", "CF_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_SECRET",
]

// process env minus the vault's own credentials (case-insensitive, like Windows).
func childBaseEnv() -> [String: String] {
	envVars().filter { !vaultSecretEnv.contains($0.key.uppercased()) }
}

func runChild(_ e: VaultEngine, _ a: ParsedArgs, _ cmd: String, _ args: [String]) async throws -> Int32 {
	let (env, missing) = try await e.resolveEnv(envFile: a.value("env") ?? "./.env", openVault: a.value("vault") ?? defaultVault)
	if !missing.isEmpty {
		let msg = "unresolved variables: \(missing.joined(separator: ", "))"
		if !a.flag("allow-missing") { throw VaultError.invalidArgument("\(msg) (use --allow-missing to proceed)") }
		writeErr("warning: \(msg)\n")
	}
	if !env.isEmpty {
		// Per-access audit line: names, never values.
		writeErr("audit: \(ISO8601DateFormatter().string(from: Date())) injected [\(env.map(\.0).joined(separator: ", "))] -> \(cmd)\n")
	}
	guard let exe = ProcessRunner.resolve(cmd) else { throw VaultError.invalidArgument("command not found: \(cmd)") }

	var merged = childBaseEnv()
	for (k, v) in env { merged[k] = v }  // declared variables win, even over stripped names

	let p = Process()
	p.executableURL = exe
	p.arguments = args
	p.environment = merged

	let scrubber = Scrubber()
	var drainJobs: [@Sendable () -> Void] = []
	if a.flag("mask") {
		for (_, v) in env { scrubber.register(v) }
		let out = Pipe(), err = Pipe()
		p.standardOutput = out
		p.standardError = err
		for (pipe, sink) in [(out, FileHandle.standardOutput), (err, FileHandle.standardError)] {
			let stream = scrubber.stream()
			drainJobs.append { [stream] in
				while true {
					let d = pipe.fileHandleForReading.availableData
					if d.isEmpty { break }
					sink.write(stream.feed(d))
				}
				sink.write(stream.flush())
			}
		}
	}
	let exited: AsyncStream<Void>
	do { exited = try p.start() } catch { throw VaultError.invalidArgument("cannot launch \(cmd): \(error.localizedDescription)") }
	// Blocking reads run on dispatch threads, not the cooperative pool.
	await withTaskGroup(of: Void.self) { g in
		for j in drainJobs { g.addTask { await blocking(j) } }
		g.addTask { for await _ in exited {} }
	}
	return p.terminationReason == .uncaughtSignal ? 128 + p.terminationStatus : p.terminationStatus
}
