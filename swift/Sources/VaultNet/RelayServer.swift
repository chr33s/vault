#if !os(Windows)  // VaultNet is empty on Windows (see Package.swift)
import Foundation
import VaultCore

// The self-hosted relay (spec §15.14): a dumb zero-knowledge store-and-forward
// hub over the shared relay handler. Ops are authenticated against each team's own auth log,
// so a hostile writer cannot pre-claim another device's (deviceId, seq) slot or flood the
// store with synthetic rotations, grants or membership entries.

public enum RelayServer {
	public static let defaultPort = 8731

	public static func deps(store: RelayStore, access: AccessVerifier) -> RelayDeps {
		RelayDeps(
			authorize: { await access.authorize($0) },
			verifyOp: { op, team in
				guard let m = store.membershipFor(team), let key = AuthLog.deviceSignKey(m, op.deviceId) else { return false }
				return WireProtocol.verifyEnvelope(op, signPub: key)
			},
			// A rotation advances the current epoch only if signed by an active owner/admin
			// device; historical keys are deliberately not enough.
			verifyRotation: { rec, team in store.membershipFor(team).map { Rotation.authentic(rec, $0) } ?? false },
			verifyGrant: { g, team in store.membershipFor(team).map { WireProtocol.grantAuthentic(teamId: team, g, $0) } ?? false })
	}

	public static func start(dbPath: String, host: String, port: Int, access: AccessConfig) async throws -> (server: HTTPServer, store: RelayStore) {
		let store = try RelayStore(path: dbPath)
		let verifier = AccessVerifier(access)
		let deps = deps(store: store, access: verifier)
		let server = try await HTTPServer.start(host: host, port: port) { req in
			let r = await RelayHandler.handle(RelayRequest(method: req.method, path: req.path, headers: req.headers, body: req.body), store: store, deps: deps)
			return .json(r.status, r.body.serialized())  // never echo error text: it could carry an Access token
		}
		return (server, store)
	}
}
#endif
