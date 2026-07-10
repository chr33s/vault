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
private struct Envelope: Decodable {
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
		// Prefer an explicit $VAULT_BIN (dev) or the signed binary bundled in
		// Contents/Resources. Do NOT fall back to a fixed path like
		// /usr/local/bin/vault: on a Homebrew Mac that directory is admin-writable
		// without root, so a planted binary there would receive the account
		// passphrase on stdin. A missing bundled binary instead yields a clear spawn
		// error against the in-bundle path.
		let bin =
			resolve("VAULT_BIN", "vault")
			?? resources?.appendingPathComponent("vault")
			?? URL(fileURLWithPath: "vault")
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

			// Drain stdout/stderr on background queues that start BEFORE the process
			// exits. Reading only inside terminationHandler deadlocks: a child whose
			// output exceeds the ~64KB pipe buffer blocks in write(2) and never
			// terminates, so the handler never fires and this continuation hangs
			// forever. Concurrent reads keep both pipes flowing regardless of size.
			var outData = Data()
			var errData = Data()
			let ioGroup = DispatchGroup()
			ioGroup.enter()
			DispatchQueue.global().async {
				outData = stdout.fileHandleForReading.readDataToEndOfFile()
				ioGroup.leave()
			}
			ioGroup.enter()
			DispatchQueue.global().async {
				errData = stderr.fileHandleForReading.readDataToEndOfFile()
				ioGroup.leave()
			}

			process.terminationHandler = { _ in
				// Both reads have completed (EOF at child exit); safe to read the vars.
				ioGroup.notify(queue: DispatchQueue.global()) {
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
			}

			do { try process.run() } catch {
				// No child inherited these descriptors, so Process will not close the
				// parent-side writers for us. Closing them releases both background EOF
				// readers instead of retaining a blocked task after every failed launch.
				try? stdin.fileHandleForWriting.close()
				try? stdout.fileHandleForWriting.close()
				try? stderr.fileHandleForWriting.close()
				cont.resume(throwing: error)
				return
			}
			// Write secrets to stdin with the throwing API inside do/catch: the legacy
			// FileHandle.write(_:) raises an UNCATCHABLE ObjC exception on a broken
			// pipe (child exited early — bad --vault, wrong binary), crashing the whole
			// app. write(contentsOf:) throws a Swift error we can swallow; the child's
			// exit code/output is authoritative.
			let h = stdin.fileHandleForWriting
			do {
				for p in passphrases { try h.write(contentsOf: Data((p + "\n").utf8)) }
			} catch {
				// Child closed stdin before we finished writing; ignore and let its
				// output/exit drive the result.
			}
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
