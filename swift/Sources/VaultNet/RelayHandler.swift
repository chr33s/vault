#if !os(Windows)  // VaultNet is empty on Windows (see Package.swift)
import Foundation
import VaultCore

// Transport-agnostic relay request handler. One
// store-and-forward implementation backs the direct peer server (and could back a
// self-hosted relay): storage, authorization and op/rotation/grant verification are
// injected. The relay is untrusted for confidentiality; clients re-verify everything.

public struct RelayRequest: Sendable {
	public var method: String
	public var path: String
	public var headers: [String: String]  // lowercased names
	public var body: Data
	public init(method: String, path: String, headers: [String: String], body: Data) {
		self.method = method
		self.path = path
		self.headers = headers
		self.body = body
	}
}

public struct RelayResponse: Sendable {
	public var status: Int
	public var body: JSONValue
}

public struct RelayDeps: Sendable {
	public var authorize: @Sendable ([String: String]) async -> Bool
	// An op is accepted only if the author device's key in the auth log signed it:
	// otherwise a writer could pre-claim another device's (deviceId, seq) slot.
	public var verifyOp: @Sendable (OpEnvelope, String) -> Bool
	public var verifyRotation: @Sendable (RotationRecord, String) -> Bool
	// Unauthenticated grants can make a client seal its identity to an attacker's
	// key, so the secure default is reject.
	public var verifyGrant: @Sendable (GrantRow, String) -> Bool

	public init(
		authorize: @escaping @Sendable ([String: String]) async -> Bool, verifyOp: @escaping @Sendable (OpEnvelope, String) -> Bool = { _, _ in true },
		verifyRotation: @escaping @Sendable (RotationRecord, String) -> Bool = { _, _ in true },
		verifyGrant: @escaping @Sendable (GrantRow, String) -> Bool = { _, _ in false }
	) {
		self.authorize = authorize
		self.verifyOp = verifyOp
		self.verifyRotation = verifyRotation
		self.verifyGrant = verifyGrant
	}
}

// The single body returned for an unexpected server error: an echoed message could
// carry an access token.
public let generic500 = JSONValue.obj(["error": "internal error"])

public enum RelayHandler {
	private static func strings(_ v: JSONValue?) -> [String] { v?.array?.compactMap { $0.string } ?? [] }

	public static func handle(_ req: RelayRequest, store: RelayStorage, deps: RelayDeps) async -> RelayResponse {
		if req.method == "GET" && req.path == "/health" { return RelayResponse(status: 200, body: .obj(["ok": .bool(true)])) }
		guard req.method == "POST" else { return RelayResponse(status: 405, body: .obj(["error": "method not allowed"])) }
		guard await deps.authorize(req.headers) else { return RelayResponse(status: 403, body: .obj(["error": "forbidden"])) }
		do {
			guard let body = try? JSONValue.parse(req.body.isEmpty ? Data("{}".utf8) : req.body) else {
				return RelayResponse(status: 500, body: generic500)
			}
			switch req.path {
			case "/sync": return try sync(body, store)
			case "/push": return try push(body, store, deps)
			default: return RelayResponse(status: 404, body: .obj(["error": "not found"]))
			}
		} catch {
			return RelayResponse(status: 500, body: generic500)
		}
	}

	private static func sync(_ body: JSONValue, _ store: RelayStorage) throws -> RelayResponse {
		guard let team = body["teamId"]?.string, !team.isEmpty else {
			return RelayResponse(status: 400, body: .obj(["error": "teamId required"]))
		}
		let vector = body["vector"].flatMap { VersionVector(vectorJSON: $0) } ?? [:]
		let authHashes = strings(body["authHashes"]), rotIds = strings(body["rotationIds"])
		let resp = SyncResponse(
			ops: try store.opsSince(team, vector), vector: try store.vector(team),
			authLog: try store.authExcept(team, Set(authHashes)), rotations: try store.rotationsExcept(team, Set(rotIds)),
			grants: try store.allGrants(team), lacksAuth: try store.authLacking(team, authHashes),
			lacksRotations: try store.rotationsLacking(team, rotIds))
		return RelayResponse(status: 200, body: resp.json)
	}

	private static func push(_ body: JSONValue, _ store: RelayStorage, _ deps: RelayDeps) throws -> RelayResponse {
		guard let team = body["teamId"]?.string, !team.isEmpty, let opsJ = body["ops"]?.array else {
			return RelayResponse(status: 400, body: .obj(["error": "teamId and ops required"]))
		}
		// Membership/rotations/grants first: a device's first ops travel in the same
		// push as the add-device entry that authorizes them.
		var authBatch: [LogEntry] = []
		for j in body["authLog"]?.array ?? [] {
			guard let entry = LogEntry(json: j) else { continue }  // malformed: dropped, not fatal
			if entry.body.type == "genesis" {
				// A genesis is self-authorizing: pin the first well-scoped root.
				guard entry.body.str("vaultId") == team, entry.parents.isEmpty, try store.pinGenesis(team, entry) else { continue }
			}
			authBatch.append(entry)
		}
		// Admitted only if it verifies: an open peer must not let anyone grow the log.
		try store.putAuthBatch(team, authBatch)
		for raw in strings(body["rotations"]) {
			guard let r = RotationRecord.parse(raw), deps.verifyRotation(r, team) else { continue }
			try store.putRotation(team, r)
		}
		for j in body["grants"]?.array ?? [] {
			if let g = GrantRow(json: j), deps.verifyGrant(g, team) { try store.putGrant(team, g) }
		}
		let verified = opsJ.compactMap { OpEnvelope(json: $0) }.filter { deps.verifyOp($0, team) }
		var held: [String: Int] = [:]
		for id in Set(verified.map(\.deviceId)) { held[id] = try store.maxSeq(team, id) }
		var accepted = 0
		for op in WireProtocol.acceptContiguous(verified, maxSeq: { held[$0] ?? 0 }) where try store.putOp(team, op) { accepted += 1 }
		return RelayResponse(status: 200, body: .obj(["accepted": .int(Int64(accepted))]))
	}

	// Constant-time membership test for the service-token allowlist: every candidate
	// is compared and the loop never short-circuits, so timing is independent of
	// which token (if any) matched.
	public static func tokenAllowed(_ tokens: Set<String>, _ presented: String) -> Bool {
		let want = Array(presented.utf8)
		var ok = false
		for t in tokens {
			let c = Array(t.utf8)
			var diff = UInt8(c.count == want.count ? 0 : 1)
			for i in 0..<min(c.count, want.count) { diff |= c[i] ^ want[i] }
			ok = ok || diff == 0
		}
		return ok
	}
}
#endif
