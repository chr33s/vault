#if !os(Windows)  // VaultNet is empty on Windows (see Package.swift)
import Foundation
import VaultCore

// HTTP peer server for the direct tailnet path: exposes this
// device's local replica through the same relay handler, backed by a PeerStore. It
// holds no keys and runs while the vault is locked. The caller binds it to the
// Tailscale interface (the access gate); an optional shared token adds a second gate.
// Confidentiality never rests on either: ops stay end-to-end encrypted and signed.

public enum PeerServer {
	public static func start(store: Store, vaultId: String, host: String, port: Int, token: String? = nil, maxBodyBytes: Int = 16 * 1024 * 1024) async throws -> HTTPServer {
		let peer = try PeerStore(store: store, vaultId: vaultId)
		let tokens: Set<String> = token.map { [$0] } ?? []
		// A token makes the server fail-closed; none leaves it open to the tailnet.
		let deps = RelayDeps(
			authorize: { headers in
				tokens.isEmpty ? true : headers["cf-access-token"].map { RelayHandler.tokenAllowed(tokens, $0) } ?? false
			},
			// Authenticate authorship against this device's own auth log, so a tailnet
			// peer can't censor a device's (deviceId, seq) slot or flood the store.
			verifyOp: { op, _ in
				guard let m = peer.membership(), let key = AuthLog.deviceSignKey(m, op.deviceId) else { return false }
				return WireProtocol.verifyEnvelope(op, signPub: key)
			},
			verifyRotation: { rec, _ in peer.membership().map { Rotation.authentic(rec, $0) } ?? false },
			verifyGrant: { g, team in
				guard team == vaultId, let m = peer.membership() else { return false }
				return WireProtocol.grantAuthentic(teamId: team, g, m)
			})
		return try await HTTPServer.start(host: host, port: port, maxBodyBytes: maxBodyBytes) { req in
			let r = await RelayHandler.handle(
				RelayRequest(method: req.method, path: req.path, headers: req.headers, body: req.body), store: peer, deps: deps)
			// Never echo error text: it could carry the request's token.
			return .json(r.status, r.body.serialized())
		}
	}
}
#endif
