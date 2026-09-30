import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

// Relay sync client (spec §15.12): one anti-entropy round against
// the always-on hub. The relay only ever sees opaque envelopes plus cleartext
// membership/epoch metadata, and is treated as untrusted: everything pulled is
// re-verified before it is stored.

public struct RelayAuth: Sendable, Equatable {
	public var token: String?
	public var accessId: String?
	public var accessSecret: String?
	public init(token: String? = nil, accessId: String? = nil, accessSecret: String? = nil) {
		self.token = token
		self.accessId = accessId
		self.accessSecret = accessSecret
	}

	// App-layer token as `cf-access-token`; a Cloudflare Access service token as the
	// edge-authenticated client-id/secret pair.
	var headers: [String: String] {
		var h: [String: String] = [:]
		if let token, !token.isEmpty { h["cf-access-token"] = token }
		if let id = accessId, let secret = accessSecret, !id.isEmpty, !secret.isEmpty {
			h["CF-Access-Client-Id"] = id
			h["CF-Access-Client-Secret"] = secret
		}
		return h
	}
}

public struct SyncStats: Sendable, Equatable {
	public var pulled = 0
	public var pushed = 0
	public var authPulled = 0
	public var rotationsPulled = 0
}

public struct RelayError: Error, Sendable, CustomStringConvertible {
	public let description: String
	public init(description: String) { self.description = description }
}

// Collects a response while enforcing the size cap AS BYTES ARRIVE: a compromised relay
// or peer must not be able to make us buffer an unbounded body before a check runs.
private final class CappedFetch: NSObject, URLSessionDataDelegate, @unchecked Sendable {
	let cap: Int
	private(set) var data = Data()
	private(set) var response: URLResponse?
	private(set) var exceeded = false
	var continuation: CheckedContinuation<Error?, Never>?

	init(cap: Int) { self.cap = cap }

	// Never follow redirects: URLSession would re-send our custom credential headers
	// (`cf-access-token`, `CF-Access-Client-Secret`) to whatever host a compromised or
	// misconfigured relay names. The 3xx then surfaces as an ordinary non-2xx error.
	func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
		completionHandler(nil)
	}

	func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
		self.response = response
		if response.expectedContentLength > Int64(cap) {
			exceeded = true
			completionHandler(.cancel)
		} else {
			completionHandler(.allow)
		}
	}

	func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
		guard !exceeded else { return }
		if data.count + chunk.count > cap {
			exceeded = true
			data = Data()
			dataTask.cancel()
			return
		}
		data.append(chunk)
	}

	func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
		continuation?.resume(returning: error)
		continuation = nil
	}
}

public enum RelayClient {
	// A compromised relay must not OOM a syncing client with an unbounded body.
	public static let maxResponseBytes = 64 * 1024 * 1024

	static func post(_ url: URL, _ body: JSONValue, auth: RelayAuth, timeout: TimeInterval?, maxBytes: Int = maxResponseBytes) async throws -> JSONValue {
		var req = URLRequest(url: url)
		req.httpMethod = "POST"
		req.setValue("application/json", forHTTPHeaderField: "content-type")
		for (k, v) in auth.headers { req.setValue(v, forHTTPHeaderField: k) }
		req.httpBody = body.serialized()
		if let timeout { req.timeoutInterval = timeout }
		let cfg = URLSessionConfiguration.ephemeral  // no cookies/cache/credentials on disk
		cfg.httpShouldSetCookies = false
		let fetch = CappedFetch(cap: maxBytes)
		let session = URLSession(configuration: cfg, delegate: fetch, delegateQueue: nil)
		defer { session.finishTasksAndInvalidate() }
		let task = session.dataTask(with: req)
		let failure: Error? = await withCheckedContinuation { c in
			fetch.continuation = c
			task.resume()
		}
		if fetch.exceeded { throw RelayError(description: "relay response exceeded \(maxBytes) bytes") }
		if let failure { throw RelayError(description: "relay unreachable: \(failure.localizedDescription)") }
		let status = (fetch.response as? HTTPURLResponse)?.statusCode ?? 0
		guard (200..<300).contains(status) else {
			throw RelayError(description: "relay \(status): \(String(decoding: fetch.data.prefix(512), as: UTF8.self))")
		}
		guard let j = try? JSONValue.parse(fetch.data.isEmpty ? Data("{}".utf8) : fetch.data) else { throw RelayError(description: "relay returned malformed JSON") }
		return j
	}
}

extension VaultEngine {
	func verifiedRotationIds(_ m: Membership) throws -> [String] {
		try signatureVerifiedRotations(m).map { Rotation.id(epoch: $0.epoch, deviceId: $0.deviceId) }
	}

	public func savedRelay() throws -> RelayInfo? { try Self.savedRelay(store) }

	// Relays keep the first grant per (principal, keyVersion), so a filled slot is
	// "held" whatever its contents.
	private static func grantKey(_ g: GrantRow) -> String { "\(g.principal)\u{0}\(g.keyVersion)" }

	// Well under the peer server's 16 MiB request limit.
	public static let pushBatchBytes = 4 * 1024 * 1024

	@discardableResult
	public func syncWithRelay(url relayURL: String, auth: RelayAuth = RelayAuth(), timeout: TimeInterval? = nil, pushBatchBytes: Int = VaultEngine.pushBatchBytes) async throws -> SyncStats {
		var base = relayURL
		while base.hasSuffix("/") { base.removeLast() }
		guard let syncURL = URL(string: base + "/sync"), let pushURL = URL(string: base + "/push"), ["http", "https"].contains(syncURL.scheme) else {
			throw VaultError.invalidArgument("invalid relay URL: \(relayURL)")
		}
		let before = try membership()
		let verifiedIds = try verifiedRotationIds(before)

		let reqBody = SyncRequest(teamId: vaultId, vector: try store.versionVector(), authHashes: try store.authHashes(), rotationIds: verifiedIds).json
		guard let resp = SyncResponse(json: try await RelayClient.post(syncURL, reqBody, auth: auth, timeout: timeout)) else {
			throw RelayError(description: "relay returned a malformed sync response")
		}

		// Membership first: a device's first ops arrive in the same round as the
		// add-device entry that authorizes them.
		let imported = try importAuth(resp.authLog, resp.rotations, prior: before)
		let m = imported.membership
		var stats = SyncStats()
		stats.authPulled = imported.auth
		stats.rotationsPulled = imported.rotations

		// The relay is only a transport: store an op only if the device it names
		// signed it (ops are UNIQUE(device_id, seq), so a forged one would otherwise
		// occupy the genuine op's slot for good). Historical keys count.
		let authentic = resp.ops.filter { op in m.deviceKeys[op.deviceId].map { WireProtocol.verifyEnvelope(op, signPub: $0) } ?? false }
		stats.pulled = try store.putOps(WireProtocol.acceptContiguous(authentic) { (try? self.store.maxSeq(for: $0)) ?? 0 })
		for g in resp.grants where WireProtocol.grantAuthentic(teamId: vaultId, g, m) { try store.putGrant(teamId: vaultId, g) }

		// Push only what the relay lacks AND would accept (active devices only).
		let toPush = try store.opsSince(resp.vector).filter { AuthLog.deviceSignKey(m, $0.deviceId) != nil }
		let lacksAuth = Set(resp.lacksAuth), lacksRot = Set(resp.lacksRotations)
		let relayGrants = Set(resp.grants.map(Self.grantKey))
		let rotations = try store.rotations().filter { raw in
			guard let r = RotationRecord.parse(raw), lacksRot.contains(Rotation.id(epoch: r.epoch, deviceId: r.deviceId)) else { return false }
			return Rotation.authentic(r, m)
		}
		let grants = try store.allGrants(teamId: vaultId).filter { !relayGrants.contains(Self.grantKey($0)) && WireProtocol.grantAuthentic(teamId: vaultId, $0, m) }
		// Ops go in bounded batches, in order (the receiver keeps each device's run
		// gap-free): a large backlog must not exceed the server's request-size limit and
		// be refused forever. The first request also carries the small metadata.
		let meta = (try store.authLog().filter { lacksAuth.contains($0.hash) }, rotations, grants)
		var batches: [[OpEnvelope]] = [[]]
		var size = 0
		for op in toPush {
			let cost = op.payload.utf8.count + 400
			if size + cost > pushBatchBytes, !batches[batches.count - 1].isEmpty {
				batches.append([])
				size = 0
			}
			batches[batches.count - 1].append(op)
			size += cost
		}
		for (i, ops) in batches.enumerated() {
			let push = i == 0
				? PushRequest(teamId: vaultId, ops: ops, authLog: meta.0, rotations: meta.1, grants: meta.2)
				: PushRequest(teamId: vaultId, ops: ops)
			_ = try await RelayClient.post(pushURL, push.json, auth: auth, timeout: timeout)
		}
		stats.pushed = toPush.count

		// One membership is threaded through the whole round: replaying the DAG is the
		// expensive step and the log is unchanged since `m` unless entries were imported.
		try rebuildSession(membership: m)
		try contributeRecovery(membership: m)
		return stats
	}
}
