#if !os(Windows)  // macOS + Linux only (see Package.swift)
import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

import Testing

@testable import VaultCore
@testable import VaultNet

private let kdf = KdfParams.scrypt(salt: Data(repeating: 5, count: 16), n: 1024, r: 8, p: 1, length: 32)
private let pass = Data("pw".utf8)

@Suite struct TailnetTests {
	@Test func parsesStatusAndSkipsOfflinePeers() throws {
		let json = """
			{"Self":{"TailscaleIPs":["fd7a::1","100.64.0.1"]},
			 "Peer":{"a":{"TailscaleIPs":["100.64.0.2","fd7a::2"],"DNSName":"laptop.tail.ts.net.","Online":true},
			         "b":{"TailscaleIPs":["100.64.0.3"],"HostName":"off","Online":false},
			         "c":{"TailscaleIPs":["fd7a::9"],"HostName":"v6only","Online":true},
			         "d":{"TailscaleIPs":["100.64.0.4"],"HostName":"phone","Online":true}}}
			"""
		let s = try Tailnet.parseStatus(json)
		#expect(s.selfIP == "100.64.0.1")
		#expect(s.peers == [Tailnet.Peer(name: "laptop.tail.ts.net", ip: "100.64.0.2"), Tailnet.Peer(name: "phone", ip: "100.64.0.4")])
	}

	@Test func missingCliIsAClearError() async {
		await #expect(throws: VaultError.self) { try await Tailnet.status(binaries: ["/nonexistent/tailscale"]) }
	}
}

@Suite struct PeerServerTests {
	// Owner replica A (served) and an enrolled second device B (client).
	private func pair() async throws -> (a: Store, b: Store, owner: VaultEngine, dev: VaultEngine) {
		let sa = try Store(path: ":memory:"), sb = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: sa, password: pass, kdf: kdf)
		let owner = try await VaultEngine.unlock(store: sa, password: pass)
		try await owner.addItem(title: "gh", fields: [("password", "pw1")])
		let t = try VaultEngine.authNewDevice(store: sb, password: pass, kdf: kdf)
		_ = try await VaultEngine.deviceConfirm(store: sb, password: pass, token: try await owner.deviceAdd(t))
		return (sa, sb, owner, try await VaultEngine.unlock(store: sb, password: pass))
	}

	@Test func replicasConvergeThroughAKeylessPeerServer() async throws {
		let (sa, _, owner, dev) = try await pair()
		let server = try await PeerServer.start(store: sa, vaultId: try await owner.vaultId, host: "127.0.0.1", port: 0)
		defer { Task { await server.stop() } }
		let url = "http://127.0.0.1:\(server.port)"

		// B pulls the owner's ops and publishes its own proof-of-device + edits.
		try await dev.syncWithRelay(url: url)
		#expect(await dev.item(title: "gh")?.passwords == ["pw1"])
		try await dev.editItem(title: "gh", fields: [("username", "from-device")])
		try await dev.syncWithRelay(url: url)
		try await owner.importAuthAndRotations(try sa.authLog(), [])
		try await owner.rebuildSession()
		#expect(await owner.item(title: "gh")?.fields["username"] == "from-device")
		// The peer server never held a key: it only ever stored ciphertext envelopes.
		#expect(try sa.allOps().allSatisfy { !String(decoding: Data(base64: $0.payload), as: UTF8.self).contains("from-device") })
	}

	@Test func tokenGatesTheServerAndFailsClosed() async throws {
		let (sa, _, owner, dev) = try await pair()
		let server = try await PeerServer.start(store: sa, vaultId: try await owner.vaultId, host: "127.0.0.1", port: 0, token: "s3cret-peer-token")
		defer { Task { await server.stop() } }
		let url = "http://127.0.0.1:\(server.port)"
		await #expect(throws: Error.self) { try await dev.syncWithRelay(url: url) }
		await #expect(throws: Error.self) { try await dev.syncWithRelay(url: url, auth: RelayAuth(token: "wrong")) }
		try await dev.syncWithRelay(url: url, auth: RelayAuth(token: "s3cret-peer-token"))
		#expect(await dev.item(title: "gh") != nil)
	}

	@Test func otherVaultsAreRefusedAndForgedOpsRejected() async throws {
		let (sa, _, owner, _) = try await pair()
		let vid = try await owner.vaultId
		let peer = try PeerStore(store: sa, vaultId: vid)
		let deps = RelayDeps(authorize: { _ in true }, verifyOp: { _, _ in false })
		func call(_ path: String, _ body: JSONValue, method: String = "POST") async -> RelayResponse {
			await RelayHandler.handle(RelayRequest(method: method, path: path, headers: [:], body: body.serialized()), store: peer, deps: deps)
		}
		#expect(await call("/health", .null, method: "GET").status == 200)
		#expect(await call("/sync", .null, method: "GET").status == 405)
		#expect(await call("/nope", .obj([:])).status == 404)
		#expect(await call("/sync", .obj([:])).status == 400)
		// A different team id sees nothing.
		let other = await call("/sync", .obj(["teamId": "other-vault", "vector": .obj([:])]))
		#expect(other.body["ops"]?.array?.isEmpty == true && other.body["authLog"]?.array?.isEmpty == true)
		// Our own team returns data.
		#expect(await call("/sync", .obj(["teamId": .string(vid), "vector": .obj([:])])).body["ops"]?.array?.isEmpty == false)
		// Ops failing verification are not stored.
		let forged = OpEnvelope(deviceId: "x", seq: 1, hash: "h", sig: "s", payload: "p")
		#expect(await call("/push", .obj(["teamId": .string(vid), "ops": .array([forged.json])])).body["accepted"]?.int == 0)
		// A rival genesis for the same vault cannot displace the pinned root.
		let rivalKey = VaultCrypto.generateEd25519()
		let rival = try AuthLog.makeEntry(parents: [], body: .genesis(vaultId: vid, userId: "u", userSignPub: rivalKey.publicKey.base64, userEncPub: ""), signerId: "u", signerKind: .user, signerPriv: rivalKey.privateKey)
		let before = try sa.authHashes().count
		_ = await call("/push", .obj(["teamId": .string(vid), "ops": .array([]), "authLog": .array([rival.json])]))
		#expect(try sa.authHashes().count == before)
		// Malformed body -> generic 500, never echoing input.
		let bad = await RelayHandler.handle(RelayRequest(method: "POST", path: "/sync", headers: [:], body: Data("{not json".utf8)), store: peer, deps: deps)
		#expect(bad.status == 500 && bad.body == generic500)
	}

	@Test func constantTimeTokenCompare() {
		#expect(RelayHandler.tokenAllowed(["abc", "defg"], "defg"))
		#expect(!RelayHandler.tokenAllowed(["abc"], "abd") && !RelayHandler.tokenAllowed(["abc"], "abcd") && !RelayHandler.tokenAllowed([], "x"))
	}

	@Test func oversizedBodiesAreRejected() async throws {
		let server = try await HTTPServer.start(host: "127.0.0.1", port: 0, maxBodyBytes: 1024) { _ in .json(200, Data("{}".utf8)) }
		defer { Task { await server.stop() } }
		var req = URLRequest(url: URL(string: "http://127.0.0.1:\(server.port)/x")!)
		req.httpMethod = "POST"
		req.httpBody = Data(repeating: 65, count: 5000)
		let (_, resp) = try await URLSession.shared.data(for: req)
		#expect((resp as? HTTPURLResponse)?.statusCode == 413)
	}
}
#endif
