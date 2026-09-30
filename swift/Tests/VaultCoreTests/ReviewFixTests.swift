#if !os(Windows)  // macOS + Linux only (see Package.swift)
import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

import Testing

@testable import VaultCore
@testable import VaultNet

private let kdf = KdfParams.scrypt(salt: Data(repeating: 6, count: 16), n: 1024, r: 8, p: 1, length: 32)
private let pass = Data("pw".utf8)

private func junkEntry(_ i: Int) throws -> LogEntry {
	let k = VaultCrypto.generateEd25519()
	return try AuthLog.makeEntry(parents: [], body: .removeUser(userId: "victim\(i)"), signerId: "nobody", signerKind: .device, signerPriv: k.privateKey)
}

@Suite struct ReviewFixTests {
	@Test func unauthenticatedAuthEntriesAreNeverPersisted() async throws {
		let store = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: store, password: pass, kdf: kdf)
		let e = try await VaultEngine.unlock(store: store, password: pass)
		let before = try store.authHashes().count
		let junk = try (0..<200).map(junkEntry)
		// Via a sync pull...
		#expect(try await e.importAuthAndRotations(junk, []).auth == 0)
		// ...and via an OPEN peer server push.
		let peer = try PeerStore(store: store, vaultId: try await e.vaultId)
		try peer.putAuthBatch(try await e.vaultId, junk)
		#expect(try store.authHashes().count == before)

		// A forged entry of an unknown (future) type is rejected too; a genuinely signed one is kept
		// opaquely so upgraded clients can still exchange it through this replica.
		let m = try await e.membership()
		let owner = try #require(m.members.values.first)
		_ = owner
		let forgedFuture = try AuthLog.makeEntry(parents: [], body: EntryBody(raw: .obj(["type": "future-thing", "x": .int(1)])), signerId: "nobody", signerKind: .device, signerPriv: VaultCrypto.generateEd25519().privateKey)
		try peer.putAuthBatch(try await e.vaultId, [forgedFuture])
		#expect(try store.authHashes().count == before)
	}

	@Test func aDeviceWithAnUnusableEncryptionKeyCannotBlockRotation() async throws {
		let store = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: store, password: pass, kdf: kdf)
		let e = try await VaultEngine.unlock(store: store, password: pass)
		let sign = VaultCrypto.generateEd25519()
		// The auth log only checks a device's SIGNING key, so a member can register any encPub.
		let (userId, deviceId, devPriv) = await (e.userId, e.deviceId, e.priv.deviceSign.data)
		let entry = try AuthLog.makeEntry(
			parents: AuthLog.heads(try store.authLog()),
			body: .addDevice(userId: userId, deviceId: AuthLog.deviceId(ofSignPub: sign.publicKey.base64), deviceSignPub: sign.publicKey.base64, deviceEncPub: "AAAA"),
			signerId: deviceId, signerKind: .device, signerPriv: devPriv)
		try store.appendAuthEntry(entry)
		try await e.rebuildSession()
		#expect(try await e.rotate() == 2)  // previously threw invalidKey and aborted revocations
		try await e.addItem(title: "after", fields: [])
		#expect(await e.item(title: "after") != nil)
	}

	@Test func enrollmentDeletesPreEnrollmentPrivateKeys() async throws {
		let s1 = try Store(path: ":memory:"), s2 = try Store(path: ":memory:"), s3 = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: s1, password: pass, kdf: kdf)
		let owner = try await VaultEngine.unlock(store: s1, password: pass)
		let a = try VaultEngine.authNewDevice(store: s2, password: pass, kdf: kdf)
		#expect(try s2.meta("pendingPriv") != nil)
		_ = try await VaultEngine.deviceConfirm(store: s2, password: pass, token: try await owner.deviceAdd(a))
		#expect(try s2.meta("pendingPriv") == nil)
		let inv = try VaultEngine.inviteInit(store: s3, password: pass, kdf: kdf)
		#expect(try s3.meta("pendingInvitePriv") != nil)
		_ = try await VaultEngine.joinConfirm(store: s3, password: pass, token: try await owner.shareVault(inv))
		#expect(try s3.meta("pendingInvitePriv") == nil)
	}

	@Test func concurrentWritersOnOneDatabaseLoseNothing() async throws {
		let path = NSTemporaryDirectory() + "vault-race-\(UUID().uuidString).db"
		defer { for s in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + s) } }
		let s0 = try Store(path: path)
		_ = try await VaultEngine.initialize(store: s0, password: pass, kdf: kdf)
		// Two engines (as the CLI and the app would be) on the same database file.
		let a = try await VaultEngine.unlock(store: try Store(path: path), password: pass)
		let b = try await VaultEngine.unlock(store: try Store(path: path), password: pass)
		await withThrowingTaskGroup(of: Void.self) { g in
			for i in 0..<10 {
				g.addTask { try await (i % 2 == 0 ? a : b).addItem(title: "item-\(i)", fields: []) }
			}
			try? await g.waitForAll()
		}
		let fresh = try await VaultEngine.unlock(store: try Store(path: path), password: pass)
		#expect(await fresh.listItems().count == 10)  // every reported success is really persisted
		let seqs = try s0.allOps().map(\.seq)
		#expect(Set(seqs).count == seqs.count)
	}

	@Test func responsesAreCappedWhileStreaming() async throws {
		let server = try await HTTPServer.start(host: "127.0.0.1", port: 0) { _ in
			HTTPReplyData(status: 200, headers: ["content-type": "application/json"], body: Data(repeating: 32, count: 2_000_000))
		}
		defer { Task { await server.stop() } }
		let url = URL(string: "http://127.0.0.1:\(server.port)/x")!
		await #expect(throws: RelayError.self) { try await RelayClient.post(url, .obj([:]), auth: RelayAuth(), timeout: 10, maxBytes: 100_000) }
	}

	@Test func largeBacklogsPushInBoundedBatches() async throws {
		let sa = try Store(path: ":memory:"), sb = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: sa, password: pass, kdf: kdf)
		let owner = try await VaultEngine.unlock(store: sa, password: pass)
		let a = try VaultEngine.authNewDevice(store: sb, password: pass, kdf: kdf)
		_ = try await VaultEngine.deviceConfirm(store: sb, password: pass, token: try await owner.deviceAdd(a))
		let dev = try await VaultEngine.unlock(store: sb, password: pass)
		// The peer refuses requests over 300 KB; the device's backlog is ~1 MB.
		let server = try await PeerServer.start(store: sa, vaultId: try await owner.vaultId, host: "127.0.0.1", port: 0, maxBodyBytes: 300_000)
		defer { Task { await server.stop() } }
		let big = String(repeating: "x", count: 50_000)
		for i in 0..<16 { try await dev.addItem(title: "i\(i)", fields: [("notes", big)]) }
		try await dev.syncWithRelay(url: "http://127.0.0.1:\(server.port)", pushBatchBytes: 100_000)
		try await owner.importAuthAndRotations(try sa.authLog(), [])
		try await owner.rebuildSession()
		#expect(await owner.listItems().count == 16)
	}
}

@Suite struct ProxyQueryEncodingTests {
	@Test func secretsWithReservedCharactersReachTheUpstreamIntact() async throws {
		let value = "ab+cd/ef=gh&i j%41~"
		let up = try await HTTPServer.start(host: "127.0.0.1", port: 0) { req in
			.json(200, JSONValue.obj(["uri": .string(req.uri)]).serialized())
		}
		let p = Policy(upstream: URL(string: "http://127.0.0.1:\(up.port)")!, injections: [Injection(kind: .query, name: "k y", value: value)])
		let pol = LoadedPolicies(byHost: [p.host: p], byHostname: [p.hostname: p], defaultPolicy: p)
		let proxy = try await ProxyServer.start(policies: pol, scrubber: Scrubber(), port: 0, audit: { _ in })
		defer { Task { await proxy.stop(); await up.stop() } }
		let (data, _) = try await URLSession.shared.data(from: URL(string: "http://127.0.0.1:\(proxy.port)/p?a=1&k%20y=client&b=2&k%20y=dup")!)
		let uri = try #require(try JSONValue.parse(data)["uri"]?.string)
		// '+' is %2B (never a space), and client-supplied duplicates of the injected name are gone.
		#expect(uri == "/p?a=1&k%20y=ab%2Bcd%2Fef%3Dgh%26i%20j%2541~&b=2")
		let decoded = URLComponents(string: "http://x" + uri)?.queryItems?.first { $0.name == "k y" }?.value
		#expect(decoded == value)
		// The scrubber recognises the exact wire form, so an upstream echo is redacted.
		let s = Scrubber()
		s.register(value)
		#expect(s.scrub("echo ab%2Bcd%2Fef%3Dgh%26i%20j%2541~ end") == "echo [REDACTED] end")
	}
}
#endif
