#if !os(Windows)  // macOS + Linux only (see Package.swift)
import Foundation
import VaultCore
import VaultNet

// `vault proxy` (spec §13). Core dumps are disabled at process start (Main), so the
// resolved secrets held here cannot end up in a crash image.

func runProxy(_ e: VaultEngine, _ a: ParsedArgs, _ files: [String], _ childArgv: [String]) async throws -> Int32 {
	let scrubber = Scrubber()
	let policies = try await ProxyPolicies.load(files: files, engine: e, openVault: a.value("vault") ?? defaultVault, scrubber: scrubber)
	guard let port = Int(a.value("port") ?? String(ProxyPolicies.defaultPort)), (0...65535).contains(port) else {
		throw VaultError.invalidArgument("invalid --port")
	}

	// CONNECT mode mints an in-memory ephemeral CA; only its public certificate is
	// written to disk (for the child to trust), for this session only.
	var ca: CertificateAuthority?
	var caFile: String?
	if a.flag("connect") {
		let c = try CertificateAuthority()
		ca = c
		let path = NSTemporaryDirectory() + "vault-proxy-ca-\(ProcessInfo.processInfo.processIdentifier)-\(Int(Date().timeIntervalSince1970)).pem"
		guard FileManager.default.createFile(atPath: path, contents: Data(c.certPEM.utf8), attributes: [.posixPermissions: 0o600]) else {
			throw VaultError.invalidArgument("cannot write the CA certificate")
		}
		caFile = path
	}
	defer { if let caFile { try? FileManager.default.removeItem(atPath: caFile) } }

	let server = try await ProxyServer.start(policies: policies, ca: ca, scrubber: scrubber, port: port)
	let proxyURL = "http://127.0.0.1:\(server.port)"
	writeErr("vault proxy listening on \(proxyURL) (loopback only\(a.flag("connect") ? "; CONNECT/HTTPS_PROXY mode" : ""))\n")

	var extra = ProxyPolicies.childEnv(policies, proxyURL: proxyURL)
	if !extra.knownSDK {
		writeErr("note: no known base-URL env var for the configured upstream(s); point the agent's SDK at \(proxyURL) (VAULT_PROXY_URL) manually\n")
	}
	if let caFile { extra.env.merge(ProxyPolicies.connectEnv(proxyURL: proxyURL, caFile: caFile)) { $1 } }

	guard let cmd = childArgv.first else {
		// Foreground: run until signalled, for an agent launched separately.
		for (k, v) in extra.env.sorted(by: { $0.key < $1.key }) { writeErr("  export \(k)=\(v)\n") }
		await waitForTermination()
		await server.stop()
		return 0
	}

	// Spawn the agent with the proxy preset and the real secret absent from its env.
	guard let exe = ProcessRunner.resolve(cmd) else {
		await server.stop()
		throw VaultError.invalidArgument("command not found: \(cmd)")
	}
	let p = Process()
	p.executableURL = exe
	p.arguments = Array(childArgv.dropFirst())
	p.environment = childBaseEnv().merging(extra.env) { $1 }
	let exited: AsyncStream<Void>
	do { exited = try p.start() } catch {
		await server.stop()
		throw VaultError.invalidArgument("cannot launch \(cmd): \(error.localizedDescription)")
	}
	for await _ in exited {}
	await server.stop()  // tear the proxy down when the agent exits
	return p.terminationReason == .uncaughtSignal ? 128 + p.terminationStatus : p.terminationStatus
}
#endif
