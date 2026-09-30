#if !os(Windows)  // VaultNet is empty on Windows (see Package.swift)
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

// A small buffered HTTP/1.1 server on SwiftNIO: the transport for the direct peer
// server. Requests are read fully (bounded), handed to an async handler, and the
// reply is written back. Keep-alive and sequential pipelining are honored.

public struct HTTPRequestData: Sendable {
	public var method: String
	public var uri: String
	public var headers: [String: String]  // lowercased names
	public var body: Data
	public var path: String { URLComponents(string: uri)?.path ?? uri }
}

public struct HTTPReplyData: Sendable {
	public var status: Int
	public var headers: [String: String]
	public var body: Data

	public static func json(_ status: Int, _ body: JSONBody) -> HTTPReplyData {
		HTTPReplyData(status: status, headers: ["content-type": "application/json"], body: body)
	}
	public typealias JSONBody = Data
}

public final class HTTPServer: @unchecked Sendable {
	private let group: MultiThreadedEventLoopGroup
	private let channel: Channel

	public var port: Int { channel.localAddress?.port ?? 0 }

	init(group: MultiThreadedEventLoopGroup, channel: Channel) {
		self.group = group
		self.channel = channel
	}

	// Slow-client defenses (the Node http.Server this replaces had header/request timeouts): an
	// idle keep-alive connection is closed after `idleSeconds`, a request must finish arriving
	// within `requestSeconds` of its first byte (slowloris), and at most `maxConnections` sockets
	// are served at once, so trickling clients cannot exhaust memory or descriptors.
	public static func start(
		host: String, port: Int, maxBodyBytes: Int = 16 * 1024 * 1024, maxConnections: Int = 512, idleSeconds: Int64 = 60, requestSeconds: Int64 = 30,
		handler: @escaping @Sendable (HTTPRequestData) async -> HTTPReplyData
	) async throws -> HTTPServer {
		let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
		let limiter = ConnectionLimiter(max: maxConnections)
		do {
			let ch = try await ServerBootstrap(group: group)
				.serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
				.childChannelInitializer { channel in
					guard limiter.admit() else { return channel.eventLoop.makeFailedFuture(ConnectionLimitReached()) }
					channel.closeFuture.whenComplete { _ in limiter.release() }
					return channel.pipeline.configureHTTPServerPipeline().flatMap {
						channel.pipeline.addHandler(BufferedHandler(maxBody: maxBodyBytes, idle: .seconds(idleSeconds), request: .seconds(requestSeconds), handler: handler))
					}
				}
				.bind(host: host, port: port).get()
			return HTTPServer(group: group, channel: ch)
		} catch {
			try? await group.shutdownGracefully()
			throw error
		}
	}

	public func stop() async {
		try? await channel.close()
		try? await group.shutdownGracefully()
	}
}

struct ConnectionLimitReached: Error {}

final class ConnectionLimiter: @unchecked Sendable {
	private let lock = NSLock()
	private var n = 0
	let max: Int
	init(max: Int) { self.max = max }
	func admit() -> Bool {
		lock.lock()
		defer { lock.unlock() }
		guard n < max else { return false }
		n += 1
		return true
	}
	func release() {
		lock.lock()
		n -= 1
		lock.unlock()
	}
}

private final class BufferedHandler: ChannelInboundHandler, @unchecked Sendable {
	typealias InboundIn = HTTPServerRequestPart
	typealias OutboundOut = HTTPServerResponsePart

	struct Pending {
		var request: HTTPRequestData
		var keepAlive: Bool
	}

	let maxBody: Int
	let idle: TimeAmount
	let requestLimit: TimeAmount
	let handler: @Sendable (HTTPRequestData) async -> HTTPReplyData
	var idleTimer: Scheduled<Void>?
	var requestTimer: Scheduled<Void>?
	var head: HTTPRequestHead?
	var body = Data()
	var tooLarge = false
	var queue: [Pending] = []
	var busy = false

	init(maxBody: Int, idle: TimeAmount, request: TimeAmount, handler: @escaping @Sendable (HTTPRequestData) async -> HTTPReplyData) {
		self.maxBody = maxBody
		self.idle = idle
		self.requestLimit = request
		self.handler = handler
	}

	private func armIdle(_ channel: Channel) {
		idleTimer?.cancel()
		idleTimer = channel.eventLoop.scheduleTask(in: idle) { channel.close(promise: nil) }
	}

	func channelActive(context: ChannelHandlerContext) {
		armIdle(context.channel)
		context.fireChannelActive()
	}

	func channelInactive(context: ChannelHandlerContext) {
		idleTimer?.cancel()
		requestTimer?.cancel()
		context.fireChannelInactive()
	}

	func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		switch unwrapInboundIn(data) {
		case .head(let h):
			// A request is in flight: no idle timeout, but it must finish arriving promptly.
			idleTimer?.cancel()
			if requestTimer == nil {
				let ch = context.channel
				requestTimer = ch.eventLoop.scheduleTask(in: requestLimit) { ch.close(promise: nil) }
			}
			head = h
			body = Data()
			tooLarge = false
		case .body(let b):
			guard !tooLarge else { return }
			if body.count + b.readableBytes > maxBody {
				tooLarge = true
				body = Data()
			} else {
				body.append(contentsOf: b.readableBytesView)
			}
		case .end:
			requestTimer?.cancel()
			requestTimer = nil
			guard let h = head else { return }
			head = nil
			if tooLarge {
				write(context.channel, HTTPReplyData(status: 413, headers: ["content-type": "application/json"], body: Data(#"{"error":"payload too large"}"#.utf8)), keepAlive: false)
				return
			}
			var headers: [String: String] = [:]
			for (k, v) in h.headers { headers[k.lowercased()] = headers[k.lowercased()].map { $0 + ", " + v } ?? v }
			queue.append(Pending(request: HTTPRequestData(method: h.method.rawValue, uri: h.uri, headers: headers, body: body), keepAlive: h.isKeepAlive))
			body = Data()
			pump(context.channel)
		}
	}

	// Requests on one connection are served strictly in order.
	private func pump(_ channel: Channel) {
		guard !busy, !queue.isEmpty else { return }
		busy = true
		let p = queue.removeFirst()
		let handler = self.handler
		Task {
			let reply = await handler(p.request)
			channel.eventLoop.execute {
				self.write(channel, reply, keepAlive: p.keepAlive)
				self.busy = false
				if self.queue.isEmpty { self.armIdle(channel) }
				self.pump(channel)
			}
		}
	}

	private func write(_ channel: Channel, _ reply: HTTPReplyData, keepAlive: Bool) {
		var headers = HTTPHeaders()
		for (k, v) in reply.headers { headers.add(name: k, value: v) }
		headers.replaceOrAdd(name: "content-length", value: String(reply.body.count))
		if !keepAlive { headers.replaceOrAdd(name: "connection", value: "close") }
		channel.write(NIOAny(HTTPServerResponsePart.head(HTTPResponseHead(version: .http1_1, status: HTTPResponseStatus(statusCode: reply.status), headers: headers))), promise: nil)
		var buf = channel.allocator.buffer(capacity: reply.body.count)
		buf.writeBytes(reply.body)
		channel.write(NIOAny(HTTPServerResponsePart.body(.byteBuffer(buf))), promise: nil)
		channel.writeAndFlush(NIOAny(HTTPServerResponsePart.end(nil))).whenComplete { _ in
			if !keepAlive { channel.close(promise: nil) }
		}
	}

	func errorCaught(context: ChannelHandlerContext, error: Error) { context.close(promise: nil) }
}
#endif
