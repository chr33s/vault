#if !os(Windows)  // macOS + Linux only (see Package.swift)
import Foundation
import NIOCore
import NIOPosix
import Testing

@testable import VaultCore
@testable import VaultNet

private final class Hits: @unchecked Sendable {
	private let l = NSLock()
	private var n = 0
	func bump() { l.lock(); n += 1; l.unlock() }
	var count: Int { l.lock(); defer { l.unlock() }; return n }
}

private final class Sink: ChannelInboundHandler, @unchecked Sendable {
	typealias InboundIn = ByteBuffer
	private let l = NSLock()
	private(set) var closed = false
	func channelInactive(context: ChannelHandlerContext) { l.lock(); closed = true; l.unlock() }
	func channelRead(context: ChannelHandlerContext, data: NIOAny) {}
	var isClosed: Bool { l.lock(); defer { l.unlock() }; return closed }
}

private func open(_ group: EventLoopGroup, _ port: Int) async throws -> (Channel, Sink) {
	let s = Sink()
	return (try await ClientBootstrap(group: group).channelInitializer { $0.pipeline.addHandler(s) }.connect(host: "127.0.0.1", port: port).get(), s)
}

private func waitClosed(_ s: Sink, seconds: Double) async -> Bool {
	let end = Date().addingTimeInterval(seconds)
	while Date() < end {
		if s.isClosed { return true }
		try? await Task.sleep(nanoseconds: 20_000_000)
	}
	return s.isClosed
}

@Suite struct ReviewFix2Tests {
	@Test func relayClientNeverFollowsRedirectsWithCredentials() async throws {
		let hits = Hits()
		let attacker = try await HTTPServer.start(host: "127.0.0.1", port: 0) { _ in
			hits.bump()
			return .json(200, Data("{}".utf8))
		}
		let relay = try await HTTPServer.start(host: "127.0.0.1", port: 0) { _ in
			HTTPReplyData(status: 307, headers: ["location": "http://127.0.0.1:\(attacker.port)/steal"], body: Data())
		}
		defer { Task { await attacker.stop(); await relay.stop() } }
		let url = URL(string: "http://127.0.0.1:\(relay.port)/sync")!
		await #expect(throws: RelayError.self) {
			try await RelayClient.post(url, .obj([:]), auth: RelayAuth(token: "secret-token", accessId: "id", accessSecret: "secret"), timeout: 10)
		}
		try await Task.sleep(nanoseconds: 300_000_000)
		#expect(hits.count == 0)  // the credentials never reached the redirect target
	}

	@Test func slowAndIdleClientsAreDroppedAndConnectionsAreCapped() async throws {
		let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
		let server = try await HTTPServer.start(host: "127.0.0.1", port: 0, maxConnections: 2, idleSeconds: 1, requestSeconds: 1) { _ in .json(200, Data("{}".utf8)) }
		defer { Task { await server.stop(); try? await group.shutdownGracefully() } }

		// An idle connection that never sends a byte is closed.
		let (_, idle) = try await open(group, server.port)
		#expect(await waitClosed(idle, seconds: 5))

		// Slowloris: a request head that never completes is closed within the request limit.
		let (slow, slowSink) = try await open(group, server.port)
		try await slow.writeAndFlush(ByteBuffer(string: "POST /sync HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial")).get()
		#expect(await waitClosed(slowSink, seconds: 5))

		// Connection cap: with two held open, a third is refused.
		let (_, a) = try await open(group, server.port)
		let (_, b) = try await open(group, server.port)
		let (_, c) = try await open(group, server.port)
		#expect(await waitClosed(c, seconds: 0.8) && !a.isClosed && !b.isClosed)
	}

	@Test func aProxyThatFailsToBindShutsItsClientDownInsteadOfCrashing() async throws {
		let up = try await HTTPServer.start(host: "127.0.0.1", port: 0) { _ in .json(200, Data("{}".utf8)) }
		defer { Task { await up.stop() } }
		let p = Policy(upstream: URL(string: "http://127.0.0.1:\(up.port)")!, injections: [])
		let pol = LoadedPolicies(byHost: [p.host: p], byHostname: [p.hostname: p], defaultPolicy: p)
		// `up.port` is already bound: the second bind fails after the HTTP client exists.
		await #expect(throws: Error.self) { _ = try await ProxyServer.start(policies: pol, scrubber: Scrubber(), port: up.port, audit: { _ in }) }
	}

	@Test func aFixableConfigErrorIsNotFlattenedIntoDenied() async throws {
		struct Cipher: BlobCipher {
			let error: Error
			func available() async -> Bool { true }
			func protect(_ p: Data, name: String) async throws -> Data { Data([1]) }
			func unprotect(_ b: Data, name: String) async throws -> Data { throw error }
		}
		let root = NSTemporaryDirectory() + "vault-bks-\(UUID().uuidString)"
		defer { try? FileManager.default.removeItem(atPath: root) }
		func ks(_ e: Error) -> BlobKeyStore { BlobKeyStore(name: "x", subdir: "x", ext: "x", cipher: Cipher(error: e), root: root) }
		try await ks(VaultError.noCurrentKey).put(id: "k", secret: Data([9]))
		await #expect(throws: VaultError.invalidArgument("needs $VAULT_TPM2_PIN")) { try await ks(VaultError.invalidArgument("needs $VAULT_TPM2_PIN")).get(id: "k") }
		#expect(try await ks(VaultError.corrupt("wrong machine")).get(id: "k") == nil)  // wrong machine/key stays "no secret"
		#expect(try await ks(VaultCryptoError.authenticationFailed).get(id: "k") == nil)
	}

	@Test func concurrentJwtRequestsShareOneJwksFetch() async throws {
		final class Count: @unchecked Sendable { let l = NSLock(); var n = 0; func bump() { l.lock(); n += 1; l.unlock() } }
		let count = Count()
		var cfg = AccessConfig(teamDomain: "team.cloudflareaccess.com", audience: "aud")
		cfg.fetchJWKS = { _ in
			count.bump()
			try await Task.sleep(nanoseconds: 300_000_000)  // a slow certs endpoint
			return Data(#"{"keys":[]}"#.utf8)
		}
		let v = AccessVerifier(cfg)
		let hdr = #"{"alg":"RS256","kid":"k"}"#.data(using: .utf8)!.base64.replacingOccurrences(of: "=", with: "")
		let pay = #"{"aud":"aud","iss":"https://team.cloudflareaccess.com","exp":9999999999}"#.data(using: .utf8)!.base64.replacingOccurrences(of: "=", with: "")
		let jwt = "\(hdr).\(pay).AAAA"
		await withTaskGroup(of: Void.self) { g in
			for _ in 0..<20 { g.addTask { _ = await v.authorize(["cf-access-jwt-assertion": jwt]) } }
		}
		#expect(count.n == 1)  // not one fetch per request
	}
}
#endif
