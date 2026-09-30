import Foundation

// Child-process driver shared by every helper-backed keystore transport
// (systemd-creds, PowerShell/DPAPI, the Hello helper). Secrets ride stdin/stdout,
// never argv. A non-zero exit is reported via the code; only a launch failure throws.

public struct ProcessResult: Sendable {
	public var code: Int32
	public var stdout: Data
	public var stderr: Data
}

public func blocking<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
	await withCheckedContinuation { c in DispatchQueue.global().async { c.resume(returning: work()) } }
}

public enum ProcessRunner {
	public static func resolve(_ cmd: String, environment env: [String: String] = ProcessInfo.processInfo.environment) -> URL? {
		if cmd.contains("/") || cmd.contains("\\") { return FileManager.default.isExecutableFile(atPath: cmd) ? URL(fileURLWithPath: cmd) : nil }
		#if os(Windows)
			let sep: Character = ";"
			let names = [cmd, cmd + ".exe"]
		#else
			let sep: Character = ":"
			let names = [cmd]
		#endif
		for dir in (env["PATH"] ?? "").split(separator: sep) {
			for n in names {
				let p = (String(dir) as NSString).appendingPathComponent(n)
				if FileManager.default.isExecutableFile(atPath: p) { return URL(fileURLWithPath: p) }
			}
		}
		return nil
	}

	public static func run(_ bin: String, _ args: [String], input: Data = Data(), environment: [String: String]? = nil) async throws -> ProcessResult {
		guard let exe = resolve(bin) else { throw VaultError.invalidArgument("command not found: \(bin)") }
		let p = Process()
		p.executableURL = exe
		p.arguments = args
		if let environment { p.environment = environment }
		let inp = Pipe(), out = Pipe(), err = Pipe()
		p.standardInput = inp
		p.standardOutput = out
		p.standardError = err
		let exited: AsyncStream<Void>
		do { exited = try p.start() } catch { throw VaultError.invalidArgument("cannot launch \(bin): \(error.localizedDescription)") }
		// Feed stdin and drain both outputs concurrently so a chatty child cannot
		// deadlock on a full pipe. Blocking I/O runs on dispatch threads, never the
		// cooperative pool (blocking it would starve unrelated async work). A child
		// that exits before draining stdin is fine: its exit code is authoritative.
		async let writer: Void = blocking {
			try? inp.fileHandleForWriting.write(contentsOf: input)
			try? inp.fileHandleForWriting.close()
		}
		async let o: Data = blocking { out.fileHandleForReading.readDataToEndOfFile() }
		async let e: Data = blocking { err.fileHandleForReading.readDataToEndOfFile() }
		let (stdout, stderr, _) = await (o, e, writer)
		for await _ in exited {}
		// A signal-killed child must read as failure, never success.
		return ProcessResult(code: p.terminationReason == .uncaughtSignal ? 128 + p.terminationStatus : p.terminationStatus, stdout: stdout, stderr: stderr)
	}
}

extension Process {
	// Launches the process; the returned stream finishes when it exits. Use this, never
	// `waitUntilExit()`: that polls the calling thread's run loop, and on a bare dispatch
	// thread (Swift 6.4, macOS 27) it can miss the exit and block forever. The handler is
	// set before launch and the stream buffers, so an early exit is never lost.
	public func start() throws -> AsyncStream<Void> {
		let (exited, exit) = AsyncStream<Void>.makeStream()
		terminationHandler = { _ in exit.finish() }
		try run()
		return exited
	}
}
