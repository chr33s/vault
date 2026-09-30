import Foundation

// Where a command reads secrets/environment from and writes results to. The
// executable uses the process-wide context (real stdin/stdout/env); an embedding
// app (Vault.app) runs commands in-process with its own context, so passphrases are
// handed over as values, never through a pipe, argv or the environment. The context
// travels in a task-local, so concurrent in-process commands do not interfere.

public final class CommandContext: @unchecked Sendable {
	private let lock = NSLock()
	private var _json = false
	private var _stdinSecrets = false
	private var _queue: [String]?

	let environment: [String: String]
	let out: @Sendable (String) -> Void
	let err: @Sendable (String) -> Void
	// The process context talks to a real terminal; embedded contexts never do.
	let isProcess: Bool

	init(environment: [String: String], isProcess: Bool, secrets: [String]?, out: @escaping @Sendable (String) -> Void, err: @escaping @Sendable (String) -> Void) {
		self.environment = environment
		self.isProcess = isProcess
		self._queue = secrets
		self.out = out
		self.err = err
	}

	var json: Bool {
		get { lock.withLock { _json } }
		set { lock.withLock { _json = newValue } }
	}
	var stdinSecrets: Bool {
		get { lock.withLock { _stdinSecrets } }
		set { lock.withLock { _stdinSecrets = newValue } }
	}
	// In-process secrets, consumed one per prompt in the order a command asks.
	func nextSecret() -> String? {
		lock.withLock {
			guard _queue != nil else { return nil }
			return _queue!.isEmpty ? "" : _queue!.removeFirst()
		}
	}
	var hasQueue: Bool { lock.withLock { _queue != nil } }
	func queueExhausted() -> Bool { lock.withLock { _queue?.isEmpty ?? false } }

	static let process = CommandContext(
		environment: ProcessInfo.processInfo.environment, isProcess: true, secrets: nil,
		out: { FileHandle.standardOutput.write(Data($0.utf8)) }, err: { FileHandle.standardError.write(Data($0.utf8)) })

	@TaskLocal static var current: CommandContext = .process
}

func envVars() -> [String: String] { CommandContext.current.environment }
