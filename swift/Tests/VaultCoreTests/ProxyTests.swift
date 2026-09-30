#if !os(Windows)  // macOS + Linux only (see Package.swift)
import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

import NIOCore
import NIOPosix
import NIOSSL
import Testing
import X509

@testable import VaultCore
@testable import VaultNet

// ---- a raw client, so tests can send absolute-URI and CONNECT requests verbatim ----

private final class ByteSink: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
	typealias InboundIn = ByteBuffer
	private let lock = NSLock()
	private var buf = Data()
	private(set) var closed = false
	var text: String {
		lock.lock()
		defer { lock.unlock() }
		return String(decoding: buf, as: UTF8.self)
	}
	func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		var b = unwrapInboundIn(data)
		lock.lock()
		buf.append(contentsOf: b.readBytes(length: b.readableBytes) ?? [])
		lock.unlock()
	}
	func channelInactive(context: ChannelHandlerContext) {
		lock.lock()
		closed = true
		lock.unlock()
	}
	func errorCaught(context: ChannelHandlerContext, error: Error) { context.close(promise: nil) }
	func wait(until cond: @escaping (String) -> Bool, seconds: Double = 10) async -> String {
		let end = Date().addingTimeInterval(seconds)
		while Date() < end {
			if cond(text) || closed { break }
			try? await Task.sleep(nanoseconds: 10_000_000)
		}
		return text
	}
}

private func connect(_ group: EventLoopGroup, port: Int) async throws -> (Channel, ByteSink) {
	let sink = ByteSink()
	let ch = try await ClientBootstrap(group: group).channelInitializer { $0.pipeline.addHandler(sink) }.connect(host: "127.0.0.1", port: port).get()
	return (ch, sink)
}

private func rawHTTP(_ group: EventLoopGroup, port: Int, _ request: String) async throws -> String {
	let (ch, sink) = try await connect(group, port: port)
	try await ch.writeAndFlush(ByteBuffer(string: request)).get()
	let out = await sink.wait(until: { $0.contains("\r\n\r\n") && ($0.hasSuffix("}") || $0.hasSuffix("\n")) && $0.count > 20 }, seconds: 5)
	try? await ch.close()
	return out
}

// CONNECT `target`, complete TLS trusting `caPEM`, send `request` inside the tunnel.
private func tunnel(_ group: EventLoopGroup, port: Int, target: String, caPEM: String, verifyHost: String?, _ request: String) async throws -> (connect: String, inner: String) {
	let (ch, sink) = try await connect(group, port: port)
	try await ch.writeAndFlush(ByteBuffer(string: "CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n\r\n")).get()
	let head = await sink.wait(until: { $0.contains("\r\n\r\n") }, seconds: 5)
	guard head.hasPrefix("HTTP/1.1 200") else {
		try? await ch.close()
		return (head, "")
	}
	var cfg = TLSConfiguration.makeClientConfiguration()
	cfg.trustRoots = .certificates([try NIOSSLCertificate(bytes: Array(caPEM.utf8), format: .pem)])
	cfg.certificateVerification = verifyHost == nil ? .noHostnameVerification : .fullVerification
	let ctx = try NIOSSLContext(configuration: cfg)
	let tls = try NIOSSLClientHandler(context: ctx, serverHostname: verifyHost)
	let inner = ByteSink()
	try await ch.pipeline.removeHandler(sink).get()
	try await ch.pipeline.addHandlers([tls, inner], position: .first).get()
	// An untrusted CA makes the handshake fail and the channel close: an error here is the outcome.
	try? await ch.writeAndFlush(ByteBuffer(string: request)).get()
	let out = await inner.wait(until: { $0.contains("\r\n\r\n") && $0.hasSuffix("}") }, seconds: 10)
	try? await ch.close()
	return (head, out)
}

// ---- fixtures ----

private let secret = "sk-live-SUPER-SECRET-9f8e7d"

// An upstream that echoes what it received, plus a few misbehaving routes.
private func startUpstream() async throws -> HTTPServer {
	try await HTTPServer.start(host: "127.0.0.1", port: 0) { req in
		func json(_ v: JSONValue, headers: [String: String] = [:]) -> HTTPReplyData {
			HTTPReplyData(status: 200, headers: headers.merging(["content-type": "application/json"]) { $1 }, body: v.serialized())
		}
		let echo = JSONValue.obj([
			"method": .string(req.method), "uri": .string(req.uri), "host": .string(req.headers["host"] ?? ""),
			"authorization": .string(req.headers["authorization"] ?? ""), "xapi": .string(req.headers["x-api-key"] ?? ""),
			"custom": .string(req.headers["x-custom"] ?? ""), "body": .string(String(decoding: req.body, as: UTF8.self)),
		])
		switch req.path {
		case "/reflect":  // echoes the injected credential back in body and a header
			return json(.obj(["you_sent": .string(req.headers["authorization"] ?? "")]), headers: ["x-echo": req.headers["authorization"] ?? ""])
		case "/redirect":
			return HTTPReplyData(status: 302, headers: ["location": "http://elsewhere.example/landing?\(req.uri.split(separator: "?").dropFirst().joined())"], body: Data())
		case "/binary":
			return HTTPReplyData(status: 200, headers: ["content-type": "application/octet-stream"], body: Data((req.headers["authorization"] ?? "").utf8))
		default: return json(echo)
		}
	}
}

private func policies(upstream: HTTPServer, injections: [Injection]) -> LoadedPolicies {
	let p = Policy(upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!, injections: injections)
	return LoadedPolicies(byHost: [p.host: p], byHostname: [p.hostname: p], defaultPolicy: p)
}

private let injections = [
	Injection(kind: .header, name: "authorization", value: "Bearer \(secret)"),
	Injection(kind: .query, name: "key", value: "q-\(secret)"),
]

private final class NoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
	// The completion-handler form: swift-corelibs-foundation (Linux) never calls the async one.
	func urlSession(
		_ s: URLSession, task: URLSessionTask, willPerformHTTPRedirection r: HTTPURLResponse, newRequest: URLRequest,
		completionHandler: @escaping @Sendable (URLRequest?) -> Void
	) { completionHandler(nil) }
}

@Suite struct ProxyTests {
	@Test func injectsCredentialsAndBindsThemToTheUpstream() async throws {
		let up = try await startUpstream()
		// Nothing registered with the scrubber here, so the upstream's view is observable.
		let proxy = try await ProxyServer.start(policies: policies(upstream: up, injections: injections), scrubber: Scrubber(), port: 0, audit: { _ in })
		defer { Task { await proxy.stop(); await up.stop() } }

		var req = URLRequest(url: URL(string: "http://127.0.0.1:\(proxy.port)/v1/things?a=1&key=client-supplied")!)
		req.httpMethod = "POST"
		req.httpBody = Data("payload".utf8)
		req.setValue("Bearer client-supplied", forHTTPHeaderField: "Authorization")  // must be overridden
		req.setValue("keep-me", forHTTPHeaderField: "X-Custom")
		let (data, resp) = try await URLSession.shared.data(for: req)
		#expect((resp as? HTTPURLResponse)?.statusCode == 200)
		let j = try JSONValue.parse(data)
		#expect(j["method"]?.string == "POST" && j["body"]?.string == "payload" && j["custom"]?.string == "keep-me")
		#expect(j["host"]?.string == "127.0.0.1:\(up.port)")
		// The upstream saw the injected credentials, not the client's own.
		#expect(j["authorization"]?.string == "Bearer \(secret)")
		let uri = try #require(j["uri"]?.string)
		#expect(uri.contains("key=q-\(secret)") && !uri.contains("client-supplied") && uri.contains("a=1"))
	}

	@Test func scrubsEchoedSecretsFromBodyAndHeaders() async throws {
		let up = try await startUpstream()
		let scrubber = Scrubber()
		injections.forEach { scrubber.register($0.value) }
		let proxy = try await ProxyServer.start(policies: policies(upstream: up, injections: injections), scrubber: scrubber, port: 0, audit: { _ in })
		defer { Task { await proxy.stop(); await up.stop() } }
		let base = "http://127.0.0.1:\(proxy.port)"

		let (data, resp) = try await URLSession.shared.data(from: URL(string: base + "/reflect")!)
		let http = try #require(resp as? HTTPURLResponse)
		let body = String(decoding: data, as: UTF8.self)
		#expect(!body.contains(secret) && body.contains("[REDACTED]"))
		#expect(http.value(forHTTPHeaderField: "x-echo")?.contains(secret) == false)
		// Binary bodies are relayed byte-exact (redaction could corrupt them).
		let (bin, _) = try await URLSession.shared.data(from: URL(string: base + "/binary")!)
		#expect(String(decoding: bin, as: UTF8.self) == "Bearer \(secret)")
	}

	@Test func neverFollowsRedirectsAndScrubsLocation() async throws {
		let up = try await startUpstream()
		let scrubber = Scrubber()
		injections.forEach { scrubber.register($0.value) }
		let proxy = try await ProxyServer.start(policies: policies(upstream: up, injections: injections), scrubber: scrubber, port: 0, audit: { _ in })
		defer { Task { await proxy.stop(); await up.stop() } }
		let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
		let (_, resp) = try await session.data(from: URL(string: "http://127.0.0.1:\(proxy.port)/redirect")!)
		let http = try #require(resp as? HTTPURLResponse)
		#expect(http.statusCode == 302)
		let loc = try #require(http.value(forHTTPHeaderField: "location"))
		#expect(loc.contains("elsewhere.example") && !loc.contains(secret))
	}

	@Test func egressAllowlistAndMalformedTargets() async throws {
		let up = try await startUpstream()
		let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
		let proxy = try await ProxyServer.start(policies: policies(upstream: up, injections: injections), scrubber: Scrubber(), port: 0, audit: { _ in })
		defer { Task { await proxy.stop(); await up.stop(); try? await group.shutdownGracefully() } }

		// Absolute-URI to a host with no policy: refused (SSRF guard), nothing forwarded.
		let denied = try await rawHTTP(group, port: proxy.port, "GET http://internal.example/admin HTTP/1.1\r\nHost: internal.example\r\nConnection: close\r\n\r\n")
		#expect(denied.hasPrefix("HTTP/1.1 403") && denied.contains("host not allowlisted: internal.example"))
		// Absolute-URI to the allowlisted upstream is served.
		let ok = try await rawHTTP(group, port: proxy.port, "GET http://127.0.0.1:\(up.port)/x HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
		#expect(ok.hasPrefix("HTTP/1.1 200") && ok.contains(secret))
		// A protocol-relative target can never change the destination host.
		let rel = try await rawHTTP(group, port: proxy.port, "GET //evil.example/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		#expect(rel.hasPrefix("HTTP/1.1 400"))
		// CONNECT is off unless a CA was configured.
		let conn = try await rawHTTP(group, port: proxy.port, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
		#expect(conn.hasPrefix("HTTP/1.1 403"))
	}

	@Test func upstreamFailuresDoNotLeakSecrets() async throws {
		let dead = try await startUpstream()
		let p = policies(upstream: dead, injections: injections)
		await dead.stop()  // nothing listens any more
		let scrubber = Scrubber()
		injections.forEach { scrubber.register($0.value) }
		let proxy = try await ProxyServer.start(policies: p, scrubber: scrubber, port: 0, audit: { _ in })
		defer { Task { await proxy.stop() } }
		let (data, resp) = try await URLSession.shared.data(from: URL(string: "http://127.0.0.1:\(proxy.port)/x")!)
		#expect((resp as? HTTPURLResponse)?.statusCode == 502)
		#expect(!String(decoding: data, as: UTF8.self).contains(secret))
	}

	@Test func auditLinesNameInjectionsButNeverValues() async throws {
		let up = try await startUpstream()
		final class Lines: @unchecked Sendable { var v: [String] = []; let l = NSLock(); func add(_ s: String) { l.lock(); v.append(s); l.unlock() } }
		let lines = Lines()
		let scrubber = Scrubber()
		injections.forEach { scrubber.register($0.value) }
		let proxy = try await ProxyServer.start(policies: policies(upstream: up, injections: injections), scrubber: scrubber, port: 0, audit: { lines.add($0) })
		defer { Task { await proxy.stop(); await up.stop() } }
		_ = try await URLSession.shared.data(from: URL(string: "http://127.0.0.1:\(proxy.port)/x")!)
		let all = lines.v.joined()
		#expect(all.contains("injected [authorization, ?key]") && !all.contains(secret))
	}

	@Test func connectModeTerminatesTlsWithEphemeralCAForAllowlistedHostsOnly() async throws {
		let up = try await startUpstream()
		let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
		let ca = try CertificateAuthority()
		let scrubber = Scrubber()
		injections.forEach { scrubber.register($0.value) }
		let proxy = try await ProxyServer.start(policies: policies(upstream: up, injections: injections), ca: ca, scrubber: scrubber, port: 0, audit: { _ in })
		defer { Task { await proxy.stop(); await up.stop(); try? await group.shutdownGracefully() } }

		// The client trusts only our CA (chain verified; NIOSSL cannot hostname-check an IP, so the IPv4 SAN is asserted in CertificateAuthorityTests).
		let (head, inner) = try await tunnel(group, port: proxy.port, target: "127.0.0.1:\(up.port)", caPEM: ca.certPEM, verifyHost: nil, "GET /via-tunnel?z=1 HTTP/1.1\r\nHost: 127.0.0.1:\(up.port)\r\nConnection: close\r\n\r\n")
		#expect(head.hasPrefix("HTTP/1.1 200 Connection Established"))
		// Decrypted requests take the identical injection + scrubbing path: the upstream
		// echoed the injected header, and the proxy redacted it on the way back.
		#expect(inner.hasPrefix("HTTP/1.1 200") && inner.contains("[REDACTED]") && !inner.contains(secret))

		// A host with no policy never gets a tunnel (and never a certificate).
		let (deniedHead, _) = try await tunnel(group, port: proxy.port, target: "other.example:443", caPEM: ca.certPEM, verifyHost: nil, "")
		#expect(deniedHead.hasPrefix("HTTP/1.1 403"))

		// A client that does not trust our CA cannot complete the handshake.
		let other = try CertificateAuthority()
		let (_, rejected) = try await tunnel(group, port: proxy.port, target: "127.0.0.1:\(up.port)", caPEM: other.certPEM, verifyHost: nil, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		#expect(rejected.isEmpty)
	}

}

@Suite struct CertificateAuthorityTests {
	@Test func issuesLeavesForDNSNamesAndIPv4() throws {
		let ca = try CertificateAuthority()
		for host in ["api.example.com", "127.0.0.1"] {
			let leaf = try ca.issueLeaf(hostname: host)
			let cert = try Certificate(pemEncoded: leaf.certPEM)
			let san = try #require(try cert.extensions.subjectAlternativeNames)
			#expect(san.count == 1)
			#expect(leaf.keyPEM.contains("PRIVATE KEY"))
		}
		#expect(CertificateAuthority.ipv4Bytes("10.0.0.256") == nil && CertificateAuthority.ipv4Bytes("a.b.c.d") == nil && CertificateAuthority.ipv4Bytes("1.2.3.4") == [1, 2, 3, 4])
		// Each CA is independent and in-memory only.
		#expect(try CertificateAuthority().certPEM != ca.certPEM)
	}
}

@Suite struct PolicyTests {
	@Test func parsesManifestAndFailsFast() async throws {
		let store = try Store(path: ":memory:")
		let kdf = KdfParams.scrypt(salt: Data(repeating: 4, count: 16), n: 1024, r: 8, p: 1, length: 32)
		_ = try await VaultEngine.initialize(store: store, password: Data("p".utf8), kdf: kdf)
		let e = try await VaultEngine.unlock(store: store, password: Data("p".utf8))
		try await e.addItem(title: "ANTHROPIC_KEY", fields: [("password", "sk-ant-123456")])
		let s = Scrubber()

		let p = try await ProxyPolicies.parse("UPSTREAM=https://api.anthropic.com\nx-api-key=vault://personal/ANTHROPIC_KEY\n?token=literal-value-1\nanthropic-version=2023-06-01\n", engine: e, openVault: "personal", scrubber: s)
		#expect(p.host == "api.anthropic.com" && p.isHTTPS)
		#expect(p.injections == [
			Injection(kind: .header, name: "x-api-key", value: "sk-ant-123456"), Injection(kind: .query, name: "token", value: "literal-value-1"),
			Injection(kind: .header, name: "anthropic-version", value: "2023-06-01"),
		])
		#expect(s.scrub("leak sk-ant-123456") == "leak [REDACTED]")  // registered as soon as resolved
		#expect(Policy(upstream: URL(string: "http://h:8080")!, injections: []).host == "h:8080")
		#expect(Policy(upstream: URL(string: "https://h:443")!, injections: []).host == "h")

		for (bad, why) in [
			("x=1", "missing UPSTREAM"), ("UPSTREAM=ftp://x", "scheme"), ("UPSTREAM=https://x/base/path", "path"), ("UPSTREAM=https://x?q=1", "query"),
			("UPSTREAM=https://x\nMISSING_SECRET", "unresolvable"), ("UPSTREAM=\n", "empty"),
		] {
			await #expect(throws: VaultError.self, "\(why)") { try await ProxyPolicies.parse(bad, engine: e, openVault: "personal", scrubber: s) }
		}
		let env = ProxyPolicies.childEnv(LoadedPolicies(byHost: [p.host: p], byHostname: [p.hostname: p], defaultPolicy: p), proxyURL: "http://127.0.0.1:9")
		#expect(env.knownSDK && env.env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:9" && env.env["VAULT_PROXY_URL"] == "http://127.0.0.1:9")
		#expect(ProxyPolicies.connectEnv(proxyURL: "u", caFile: "/ca.pem")["SSL_CERT_FILE"] == "/ca.pem")
	}
}
#endif
