import Foundation
import Testing

@testable import VaultCore

@Suite struct ProtocolVectorTests {
	let v = try! Vectors.load("protocol.json")
	let a = try! Vectors.load("auth.json")

	@Test func envelopesAreByteIdentical() throws {
		let od = v.at("signPubs").members![0].key
		for e in v.at("envelopes").items {
			let env = try WireProtocol.makeEnvelope(
				deviceId: e.str("deviceId"), seq: Int(e.at("seq").int!), payload: b64(e.str("payload")),
				signPriv: b64(v.at("signPrivs").str(od)))
			let ref = OpEnvelope(json: e.at("env"))!
			// Hash and payload are deterministic; signatures are randomized but must verify.
			#expect(env.hash == ref.hash && env.payload == ref.payload && env.seq == ref.seq)
			#expect(WireProtocol.verifyEnvelope(env, signPub: b64(v.at("signPubs").str(od))))
			#expect(WireProtocol.verifyEnvelope(ref, signPub: b64(v.at("signPubs").str(od))))
			var tampered = ref
			tampered.seq += 1
			#expect(!WireProtocol.verifyEnvelope(tampered, signPub: b64(v.at("signPubs").str(od))))
		}
	}

	@Test func grantsMatchReference() throws {
		let m = try AuthLog.replay(a.at("entries").items.map { LogEntry(json: $0)! }, expectedVaultId: a.str("vaultId"))
		let team = v.str("teamId")
		for info in v.at("grants").items {
			let g = GrantRow(json: info.at("grant"))!
			let bytes = WireProtocol.grantBytes(
				teamId: team, principal: g.principal, keyVersion: g.keyVersion, wrapped: g.wrapped, signerId: g.signerId)
			#expect(bytes.base64 == info.str("bytes"))
			#expect(WireProtocol.grantAuthentic(teamId: team, g, m) == (info["authentic"] == .bool(true)), "\(g.principal)")
			#expect(WireProtocol.grantVerifiable(teamId: team, g, m) == (info["verifiable"] == .bool(true)), "\(g.principal)")
			#expect(GrantRow(json: g.json) == g)
		}
	}

	@Test func contiguousAcceptance() {
		let c = v.at("contiguous")
		let ops = c.at("input").items.map {
			OpEnvelope(deviceId: $0.str("deviceId"), seq: Int($0.at("seq").int!), hash: "", sig: "", payload: "")
		}
		var maxSeq: [String: Int] = [:]
		for m in c.at("maxSeq").members! { maxSeq[m.key] = Int(m.value.int!) }
		let accepted = WireProtocol.acceptContiguous(ops) { maxSeq[$0] ?? 0 }
		let expected = c.at("accepted").items.map { ($0.str("deviceId"), Int($0.at("seq").int!)) }
		#expect(accepted.map { $0.deviceId } == expected.map(\.0))
		#expect(accepted.map { $0.seq } == expected.map(\.1))
	}

	@Test func syncMessagesRoundTrip() throws {
		let req = SyncRequest(teamId: "t", vector: ["b": 2, "a": 1], authHashes: ["h"], rotationIds: ["1:d"])
		#expect(req.json.stringify() == #"{"teamId":"t","vector":{"a":1,"b":2},"authHashes":["h"],"rotationIds":["1:d"]}"#)
		let entry = LogEntry(json: a.at("entries").items[0])!
		let resp = SyncResponse(
			json: .obj([
				"ops": .array([]), "vector": .obj(["a": .int(3)]),
				"authLog": .array([entry.json, .obj(["parents": "junk"])]), "rotations": .array([]),
				"grants": .array([]), "lacksAuth": .array(["x"]), "lacksRotations": .array([]),
			]))!
		#expect(resp.vector == ["a": 3])
		#expect(resp.authLog == [entry])  // malformed entry dropped, not fatal
		#expect(resp.lacksAuth == ["x"])
		let push = PushRequest(teamId: "t", ops: [], authLog: [entry])
		#expect(push.json["authLog"]?.array?.count == 1)
		#expect(push.json["rotations"] == nil)
	}
}

@Suite struct StoreTests {
	let expected = try! Vectors.load("store/expected.json")

	private func tempDB() -> String {
		FileManager.default.temporaryDirectory.appendingPathComponent("vault-\(UUID().uuidString).db").path
	}

	@Test func readsTheReferenceDatabaseFixture() throws {
		let copy = tempDB()
		try FileManager.default.copyItem(at: Vectors.url("store/ts-replica.db"), to: URL(fileURLWithPath: copy))
		defer { try? FileManager.default.removeItem(atPath: copy) }
		let store = try Store(path: copy)
		#expect(try store.authHashes().sorted() == expected.at("authHashes").strings)
		#expect(try store.authLog().count == expected.at("authHashes").strings.count)
		#expect(try store.rotations().count == Int(expected.at("rotationCount").int!))
		#expect(try store.allOps().count == Int(expected.at("totalOps").int!))
		let vec = try store.versionVector()
		#expect(vec == VersionVector(vectorJSON: expected.at("vector")))
		let since = try store.opsSince(VersionVector(vectorJSON: expected.at("opsSinceVector"))!)
		#expect(since.count == Int(expected.at("opsSinceCount").int!))
		#expect(try store.allGrants(teamId: expected.str("teamId")).count == Int(expected.at("grantCount").int!))
		#expect(try store.meta("vaultId") == expected.at("meta").str("vaultId"))
		#expect(try store.meta("note") == expected.at("meta").str("note"))
		#expect(try store.meta("absent") == nil)
		// The replica replays to the same membership the reference computed.
		let m = try AuthLog.replay(try store.authLog(), expectedVaultId: expected.str("vaultId"))
		#expect(m.members.count == 3)
	}

	@Test func opsRoundTripDedupeAndVectors() throws {
		let store = try Store(path: ":memory:")
		let a = OpEnvelope(deviceId: "a", seq: 1, hash: "h1", sig: "s", payload: "p")
		let a2 = OpEnvelope(deviceId: "a", seq: 2, hash: "h2", sig: "s", payload: "p")
		let b = OpEnvelope(deviceId: "b", seq: 1, hash: "h3", sig: "s", payload: "p")
		#expect(try store.putOp(a))
		#expect(try !store.putOp(a))  // dedupe by hash
		#expect(try store.putOps([a, a2, b]) == 2)
		#expect(try store.versionVector() == ["a": 2, "b": 1])
		#expect(try store.maxSeq(for: "a") == 2 && store.maxSeq(for: "zz") == 0)
		#expect(try store.opsSince(["a": 1]).map(\.hash) == ["h2", "h3"])
		#expect(try store.opsSince([:]).count == 3)
		#expect(try store.opsSince(["a": 2, "b": 1]).isEmpty)
	}

	@Test func authLogIsIdempotentByRecomputedHashAndSkipsCorruptRows() throws {
		let a = try Vectors.load("auth.json")
		let entries = a.at("entries").items.map { LogEntry(json: $0)! }
		let store = try Store(path: ":memory:")
		for var e in entries {
			e.hash = "lies"  // a spoofed hash must not choose the storage slot
			try store.appendAuthEntry(e)
			try store.appendAuthEntry(e)
		}
		#expect(try store.authHashes().sorted() == a.at("hashes").strings.sorted())
		#expect(try store.authLog().count == entries.count)
	}

	@Test func transactionsRollBack() throws {
		let store = try Store(path: ":memory:")
		struct Boom: Error {}
		#expect(throws: Boom.self) {
			try store.transaction {
				try store.setMeta("k", "v")
				throw Boom()
			}
		}
		#expect(try store.meta("k") == nil)
		try store.transaction { try store.setMeta("k", "v") }
		#expect(try store.meta("k") == "v")
	}

	@Test func grantsAndRotationsPersist() throws {
		let store = try Store(path: ":memory:")
		let g = GrantRow(principal: "orgPublicKey", keyVersion: 0, wrapped: "w", signerId: "s", sig: "g")
		try store.putGrant(teamId: "t", g)
		#expect(try store.getGrant(teamId: "t", principal: "orgPublicKey", keyVersion: 0) == g)
		#expect(try store.getGrant(teamId: "t", principal: "x", keyVersion: 0) == nil)
		try store.putRotation(epoch: 2, deviceId: "d", record: "r2")
		try store.putRotation(epoch: 1, deviceId: "d", record: "r1")
		try store.putRotation(epoch: 1, deviceId: "d", record: "r1b")  // replace
		#expect(try store.rotations() == ["r1b", "r2"])
	}

	@Test(.disabled(if: onWindows, "POSIX permissions")) func databaseFileIsOwnerOnly() throws {
		let path = tempDB()
		defer { try? FileManager.default.removeItem(atPath: path) }
		_ = try Store(path: path)
		let perms = try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? Int
		#expect(perms == 0o600)
	}
}
