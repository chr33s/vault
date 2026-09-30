#if !os(Windows)  // VaultNet is empty on Windows (see Package.swift)
import AsyncHTTPClient
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS
import VaultCore

// `vault proxy` (spec §13): let an agent USE a secret without SEEING
// it. The proxy injects on egress, only on requests bound for the policy's
// upstream; the agent points its SDK base URL at us.
//
// Two ingress shapes: the default base-URL / reverse-proxy form (no TLS
// interception), and the opt-in `--connect` forward-proxy form for clients that
// only honor HTTPS_PROXY, where we terminate TLS with a leaf from an ephemeral
// in-memory CA and run the decrypted request through the identical path.
//
// Security (§13.2): loopback only; each secret bound to its upstream host; egress
// allowlist (unconfigured hosts rejected); redirects are never followed (a credential
// cannot cross hosts); values are never logged; every resolved value is registered
// with the scrubber, which also redacts error text, relayed headers and textual bodies.

public final class ProxyServer: @unchecked Sendable {
	private let group: MultiThreadedEventLoopGroup
	private let channel: Channel
	fileprivate let core: ProxyCore
	public var port: Int { channel.localAddress?.port ?? 0 }

	init(group: MultiThreadedEventLoopGroup, channel: Channel, core: ProxyCore) {
		self.group = group
		self.channel = channel
		self.core = core
	}

	// Loopback only: never reachable off this host.
	public static func start(policies: LoadedPolicies, ca: CertificateAuthority? = nil, scrubber: Scrubber, port: Int, audit: @escaping @Sendable (String) -> Void = { writeStderr($0) }) async throws -> ProxyServer {
		let core = ProxyCore(policies: policies, ca: ca, scrubber: scrubber, audit: audit)
		let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
		do {
			let ch = try await ServerBootstrap(group: group)
				.serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
				.childChannelInitializer { channel in
					let enc = HTTPResponseEncoder()
					let dec = ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes))
					let handler = ProxyHandler(core: core, encoder: enc, decoder: dec)
					return channel.pipeline.addHandlers([enc, dec, handler])
				}
				.bind(host: "127.0.0.1", port: port).get()
			return ProxyServer(group: group, channel: ch, core: core)
		} catch {
			try? await core.client.shutdown()  // AsyncHTTPClient must be shut down before deinit
			try? await group.shutdownGracefully()
			throw error
		}
	}

	public func stop() async {
		try? await channel.close()
		try? await core.client.shutdown()
		try? await group.shutdownGracefully()
	}
}

public func writeStderr(_ s: String) { FileHandle.standardError.write(Data(s.utf8)) }

// Shared, immutable proxy state.
final class ProxyCore: Sendable {
	let policies: LoadedPolicies
	let scrubber: Scrubber
	let audit: @Sendable (String) -> Void
	let leafCache: LeafContextCache?
	let connectEnabled: Bool
	let client: HTTPClient

	init(policies: LoadedPolicies, ca: CertificateAuthority?, scrubber: Scrubber, audit: @escaping @Sendable (String) -> Void) {
		self.policies = policies
		self.scrubber = scrubber
		self.audit = audit
		self.leafCache = ca.map { LeafContextCache(ca: $0) }
		self.connectEnabled = ca != nil
		var cfg = HTTPClient.Configuration()
		cfg.redirectConfiguration = .disallow  // a credential must never cross to another host
		cfg.decompression = .disabled  // relay bodies byte-exact
		// Idle-based, not a total deadline: a long SSE/LLM stream must not be cut mid-body.
		cfg.timeout = .init(connect: .seconds(15), read: .seconds(300))
		self.client = HTTPClient(eventLoopGroupProvider: .singleton, configuration: cfg)
	}

	func auditLine(_ names: [String], _ host: String) {
		guard !names.isEmpty else { return }
		audit(scrubber.scrub("audit: \(ISO8601DateFormatter().string(from: Date())) injected [\(names.joined(separator: ", "))] -> \(host)\n"))
	}

	// Hop-by-hop / rewritten request headers never forwarded verbatim. Framing
	// headers are dropped because the body is re-framed for the upstream leg.
	static let stripRequest: Set<String> = ["host", "connection", "proxy-connection", "proxy-authorization", "keep-alive", "te", "trailer", "upgrade", "transfer-encoding", "content-length"]
	static let stripResponse: Set<String> = ["connection", "keep-alive", "transfer-encoding", "proxy-connection", "upgrade"]

	// Only mask a body that is textual and uncompressed: a compressed or binary body
	// cannot be scrubbed without risking corruption, and a secret is not present as
	// plaintext there anyway. Header scrubbing still covers an echoed Location/query.
	static let textual = try! NSRegularExpression(pattern: #"^(?:text/|application/(?:json|xml|x-www-form-urlencoded|[\w.-]+\+(?:json|xml)))"#, options: .caseInsensitive)
	static func isScrubbable(_ h: HTTPHeaders) -> Bool {
		if let enc = h.first(name: "content-encoding")?.trimmingCharacters(in: .whitespaces).lowercased(), !enc.isEmpty, enc != "identity" { return false }
		guard let ct = h.first(name: "content-type") else { return false }
		return textual.firstMatch(in: ct, range: NSRange(location: 0, length: (ct as NSString).length)) != nil
	}
}

struct ProxyRequest: Sendable {
	var method: HTTPMethod
	var uri: String
	var headers: HTTPHeaders
	var body: Data
	var keepAlive: Bool
}

final class ProxyHandler: ChannelInboundHandler, @unchecked Sendable {
	typealias InboundIn = HTTPServerRequestPart
	typealias OutboundOut = HTTPServerResponsePart

	static let maxBody = 64 * 1024 * 1024
	static let handshakeTimeout: TimeAmount = .seconds(10)

	let core: ProxyCore
	var encoder: HTTPResponseEncoder
	var decoder: ByteToMessageHandler<HTTPRequestDecoder>
	var head: HTTPRequestHead?
	var body = Data()
	var tooLarge = false
	var queue: [ProxyRequest] = []
	var busy = false
	var tunneled = false
	var handshaken = false

	init(core: ProxyCore, encoder: HTTPResponseEncoder, decoder: ByteToMessageHandler<HTTPRequestDecoder>) {
		self.core = core
		self.encoder = encoder
		self.decoder = decoder
	}

	func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		switch unwrapInboundIn(data) {
		case .head(let h):
			head = h
			body = Data()
			tooLarge = false
		case .body(let b):
			guard !tooLarge else { return }
			if body.count + b.readableBytes > Self.maxBody {
				tooLarge = true
				body = Data()
			} else {
				body.append(contentsOf: b.readableBytesView)
			}
		case .end:
			guard let h = head else { return }
			head = nil
			if h.method == .CONNECT {
				connect(context, h)
				return
			}
			if tooLarge {
				simple(context.channel, 413, "payload too large", keepAlive: false)
				return
			}
			queue.append(ProxyRequest(method: h.method, uri: h.uri, headers: h.headers, body: body, keepAlive: h.isKeepAlive))
			body = Data()
			pump(context.channel)
		}
	}

	func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		if let e = event as? TLSUserEvent, case .handshakeCompleted = e { handshaken = true }
		context.fireUserInboundEventTriggered(event)
	}

	func errorCaught(context: ChannelHandlerContext, error: Error) { context.close(promise: nil) }

	// MARK: - responses

	// A short text reply. Client-visible error text is always scrubbed: the agent
	// prints what we send it, so a secret in an error here would leak via its logging.
	func simple(_ channel: Channel, _ status: Int, _ text: String, keepAlive: Bool) {
		let payload = Data(core.scrubber.scrub(text).utf8)
		var h = HTTPHeaders()
		h.add(name: "content-type", value: "text/plain")
		h.add(name: "content-length", value: String(payload.count))
		if !keepAlive { h.add(name: "connection", value: "close") }
		channel.write(NIOAny(HTTPServerResponsePart.head(HTTPResponseHead(version: .http1_1, status: HTTPResponseStatus(statusCode: status), headers: h))), promise: nil)
		var buf = channel.allocator.buffer(capacity: payload.count)
		buf.writeBytes(payload)
		channel.write(NIOAny(HTTPServerResponsePart.body(.byteBuffer(buf))), promise: nil)
		channel.writeAndFlush(NIOAny(HTTPServerResponsePart.end(nil))).whenComplete { _ in
			if !keepAlive { channel.close(promise: nil) }
		}
	}

	private func pump(_ channel: Channel) {
		guard !busy, !queue.isEmpty else { return }
		busy = true
		let req = queue.removeFirst()
		let tunneled = self.tunneled
		Task {
			let keep = await self.forward(req, tunneled: tunneled, channel: channel)
			channel.eventLoop.execute {
				self.busy = false
				if keep { self.pump(channel) } else { channel.close(promise: nil) }
			}
		}
	}

	// MARK: - policy selection

	// Origin-form / base-URL ingress. An absolute request-URI names a host
	// explicitly and MUST be allowlisted; an origin-form path uses the default policy.
	private func policy(for req: ProxyRequest, tunneled: Bool) -> (Policy, String)? {
		if tunneled {
			// The client TLS-terminated against us: the Host header names the upstream.
			let hostname = (req.headers.first(name: "host") ?? "").replacingOccurrences(of: #":\d+$"#, with: "", options: .regularExpression).lowercased()
			return core.policies.byHostname[hostname].map { ($0, req.uri) }
		}
		if req.uri.lowercased().hasPrefix("http://") || req.uri.lowercased().hasPrefix("https://") {
			guard let c = URLComponents(string: req.uri), let host = c.host else { return nil }
			let https = c.scheme?.lowercased() == "https"
			let key = Policy.hostKey(host: host.lowercased(), port: c.port, https: https)
			guard let p = core.policies.byHost[key] else { return nil }
			var path = c.percentEncodedPath.isEmpty ? "/" : c.percentEncodedPath
			if let q = c.percentEncodedQuery { path += "?" + q }
			return (p, path)
		}
		return (core.policies.defaultPolicy, req.uri)
	}

	// MARK: - forwarding

	// Inject the policy's secrets, forward to the upstream over a real connection, and
	// relay the (scrubbed) response. Shared by both ingress shapes so the host-binding,
	// redirect and scrubbing guarantees are identical. Returns whether the connection
	// may be kept alive.
	private func forward(_ req: ProxyRequest, tunneled: Bool, channel: Channel) async -> Bool {
		if !tunneled, req.uri.lowercased().hasPrefix("http") {
			guard policy(for: req, tunneled: false) != nil else {
				let host = URLComponents(string: req.uri)?.host ?? "?"
				self.simple(channel, 403, "host not allowlisted: \(host)", keepAlive: false)  // egress allowlist (SSRF guard)
				return false
			}
		}
		guard let (pol, path) = policy(for: req, tunneled: tunneled) else {
			let hostname = req.headers.first(name: "host") ?? ""
			self.simple(channel, 403, "host not allowlisted: \(hostname)", keepAlive: false)
			return false
		}
		// A protocol-relative or otherwise malformed request target is a 400, never a
		// host change.
		guard path.hasPrefix("/"), !path.hasPrefix("//"), var comps = URLComponents(string: pol.upstream.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path) else {
			self.simple(channel, 400, "bad request target", keepAlive: false)
			return false
		}
		// Host-binding: the secret is attached only to its upstream. By construction we
		// forward to policy.upstream; assert it so a refactor cannot silently break it.
		guard Policy.hostKey(host: (comps.host ?? "").lowercased(), port: comps.port, https: comps.scheme == "https") == pol.host else {
			self.simple(channel, 403, "host-binding violation", keepAlive: false)
			return false
		}

		var headers = HTTPHeaders()
		for (k, v) in req.headers where !ProxyCore.stripRequest.contains(k.lowercased()) { headers.add(name: k, value: v) }
		var injected: [String] = []
		for inj in pol.injections {
			switch inj.kind {
			case .header:
				headers.replaceOrAdd(name: inj.name, value: inj.value)  // overrides any client-sent value
				injected.append(inj.name)
			case .query:
				// Build the query by hand: URLComponents.queryItems leaves '+' unencoded, so a
				// base64-style secret would reach the upstream with '+' decoded as a space.
				// Strict RFC 3986 encoding of both name and value is unambiguous everywhere.
				var pairs = (comps.percentEncodedQuery ?? "").split(separator: "&", omittingEmptySubsequences: true).map(String.init)
				let mine = Self.encodeQueryComponent(inj.name) + "=" + Self.encodeQueryComponent(inj.value)
				let existing = pairs.map { ($0.split(separator: "=", maxSplits: 1).first.map(String.init) ?? "").removingPercentEncoding ?? "" }
				if let first = existing.firstIndex(of: inj.name) {
					pairs[first] = mine  // replace in place, dropping any client-supplied duplicates
					pairs = pairs.enumerated().filter { $0.offset == first || existing[$0.offset] != inj.name }.map(\.element)
				} else {
					pairs.append(mine)
				}
				comps.percentEncodedQuery = pairs.joined(separator: "&")
				injected.append("?\(inj.name)")
			}
		}
		core.auditLine(injected, pol.host)

		guard let url = comps.url else {
			self.simple(channel, 400, "bad request target", keepAlive: false)
			return false
		}
		var out = HTTPClientRequest(url: url.absoluteString)
		out.method = req.method
		out.headers = headers
		if !req.body.isEmpty { out.body = .bytes(req.body) }
		do {
			let resp = try await core.client.execute(out, timeout: .hours(12))
			return await relay(resp, method: req.method, keepAlive: req.keepAlive, channel: channel)
		} catch {
			// Never propagate the raw error: it can reference request options (injected
			// headers included). Re-wrap minimally and scrub.
			self.simple(channel, 502, "proxy error: upstream \(type(of: error))", keepAlive: false)
			return false
		}
	}

	static func encodeQueryComponent(_ s: String) -> String {
		let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
		return s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? s
	}

	// Relay the upstream response. Redirects are not followed (AsyncHTTPClient is
	// configured `.disallow`), and headers are scrubbed on every status: a Location can
	// echo an injected query param.
	private func relay(_ resp: HTTPClientResponse, method: HTTPMethod, keepAlive: Bool, channel: Channel) async -> Bool {
		let status = Int(resp.status.code)
		var headers = HTTPHeaders()
		for (k, v) in resp.headers where !ProxyCore.stripResponse.contains(k.lowercased()) { headers.add(name: k, value: core.scrubber.scrub(v)) }
		let bodyless = method == .HEAD || status == 204 || status == 304 || status < 200
		let scrub = !bodyless && ProxyCore.isScrubbable(resp.headers)
		// Redaction changes the body length: drop content-length and re-chunk.
		if scrub || (!bodyless && headers.first(name: "content-length") == nil) {
			headers.remove(name: "content-length")
			headers.replaceOrAdd(name: "transfer-encoding", value: "chunked")
		}
		if !keepAlive { headers.replaceOrAdd(name: "connection", value: "close") }
		do {
			try await channel.writeAndFlush(NIOAny(HTTPServerResponsePart.head(HTTPResponseHead(version: .http1_1, status: resp.status, headers: headers)))).get()
			if !bodyless {
				let stream = core.scrubber.stream()
				for try await chunk in resp.body {
					if scrub {
						let d = stream.feed(Data(chunk.readableBytesView))
						if !d.isEmpty { try await channel.writeAndFlush(NIOAny(HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: d))))).get() }
					} else {
						try await channel.writeAndFlush(NIOAny(HTTPServerResponsePart.body(.byteBuffer(chunk)))).get()
					}
				}
				if scrub {
					let tail = stream.flush()
					if !tail.isEmpty { try await channel.writeAndFlush(NIOAny(HTTPServerResponsePart.body(.byteBuffer(ByteBuffer(bytes: tail))))).get() }
				}
			}
			try await channel.writeAndFlush(NIOAny(HTTPServerResponsePart.end(nil))).get()
			return keepAlive
		} catch {
			return false  // headers already sent: the status cannot change; drop the connection
		}
	}

	// MARK: - CONNECT

	// Forward-proxy ingress for clients that only honor HTTPS_PROXY. We only ever open
	// tunnels to — and mint certs for — allowlisted hosts, so the egress boundary and
	// host-binding hold exactly as in the reverse-proxy path.
	private func connect(_ context: ChannelHandlerContext, _ h: HTTPRequestHead) {
		let channel = context.channel
		let hostname = h.uri.replacingOccurrences(of: #":\d+$"#, with: "", options: .regularExpression).lowercased()
		guard core.connectEnabled, let cache = core.leafCache, core.policies.byHostname[hostname] != nil else {
			// Refuse to open the tunnel (and never present a cert) for a host we hold no
			// policy for, so the agent's secret-bearing TLS session never starts.
			simple(channel, 403, "host not allowlisted: \(hostname)\n", keepAlive: false)
			return
		}
		Task {
			do {
				let ctx = try await cache.context(for: hostname)
				channel.eventLoop.execute { self.upgrade(channel, ctx) }
			} catch {
				channel.close(promise: nil)  // cert minting failed: drop the tunnel
			}
		}
	}

	private func upgrade(_ channel: Channel, _ sslContext: NIOSSLContext) {
		guard channel.isActive else { return }
		let pipeline = channel.pipeline
		let ssl = NIOSSLServerHandler(context: sslContext)
		let sslBox = NIOLoopBound(ssl, eventLoop: channel.eventLoop)
		// Handlers are not Sendable; the chain below runs on this channel's loop.
		let enc2 = HTTPResponseEncoder()
		let dec2 = ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes))
		let enc2Box = NIOLoopBound(enc2, eventLoop: channel.eventLoop)
		let dec2Box = NIOLoopBound(dec2, eventLoop: channel.eventLoop)
		// Swap the plaintext HTTP codec for TLS + a fresh inner HTTP codec; this handler
		// stays last and keeps serving decrypted requests in `tunneled` mode.
		pipeline.removeHandler(decoder).flatMap { pipeline.removeHandler(self.encoder) }
			.flatMap { () -> EventLoopFuture<Void> in
				// On this channel's loop: the synchronous pipeline API needs no Sendable handlers.
				do {
					let ops = pipeline.syncOperations
					try ops.addHandler(sslBox.value, position: .first)
					try ops.addHandlers([enc2Box.value, dec2Box.value], position: .after(sslBox.value))
					let ctx = try ops.context(handler: sslBox.value)
					self.tunneled = true
					self.encoder = enc2Box.value
					self.decoder = dec2Box.value
					// Written from the TLS handler's context so it bypasses encryption.
					var buf = channel.allocator.buffer(capacity: 64)
					buf.writeString("HTTP/1.1 200 Connection Established\r\n\r\n")
					return ctx.writeAndFlush(NIOAny(buf))
				} catch {
					return channel.eventLoop.makeFailedFuture(error)
				}
			}
			.whenFailure { _ in channel.close(promise: nil) }
		// Bound the handshake: a tunnel told "200" that never completes TLS (a stalled or
		// cert-pinning client) must not linger.
		channel.eventLoop.scheduleTask(in: Self.handshakeTimeout) {
			if !self.handshaken { channel.close(promise: nil) }
		}
	}
}
#endif
