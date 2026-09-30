import Foundation
import Testing

@testable import VaultCore

private func loadEntries(_ v: JSONValue) -> [LogEntry] {
	v.at("entries").items.map { LogEntry(json: $0)! }
}

private func summary(_ m: Membership) -> JSONValue {
	.obj([
		"vaultId": .string(m.vaultId),
		"members": .array(
			m.members.values.map { mem in
				.obj([
					"userId": .string(mem.userId), "role": .string(mem.role.rawValue), "active": .bool(mem.active),
					"devices": .array(mem.devices.keys.map { .string($0) }),
					"pending": .array(mem.pendingDevices.keys.map { .string($0) }),
					"hasEverHadDevice": .bool(mem.hasEverHadDevice),
					"addedByDeviceId": mem.addedByDeviceId.map { .string($0) } ?? .null,
				])
			}),
		"deviceKeys": .array(m.deviceKeys.keys.sorted().map { .string($0) }),
		"deviceOwners": .array(m.deviceOwners.sorted { $0.key < $1.key }.map { .array([.string($0.key), .string($0.value)]) }),
		"applied": .array(m.appliedHashes.sorted().map { .string($0) }),
	])
}

private func jsonEqual(_ a: JSONValue, _ b: JSONValue) -> Bool { a.stringify() == b.stringify() }

@Suite struct AuthVectorTests {
	let v = try! Vectors.load("auth.json")

	@Test func hashesHeadsAndOrderAreIdentical() {
		let entries = loadEntries(v)
		#expect(entries.map(AuthLog.entryHash) == v.at("hashes").strings)
		#expect(entries.map(\.hash) == v.at("hashes").strings)
		#expect(AuthLog.heads(entries) == v.at("heads").strings)
		#expect(AuthLog.linearize(entries).map(AuthLog.entryHash) == v.at("linearized").strings)
	}

	@Test func entryRoundTripsByteForByte() {
		for j in v.at("entries").items {
			let e = LogEntry(json: j)!
			#expect(e.json.stringify() == j.stringify())
		}
	}

	@Test func replayMatchesReference() throws {
		let entries = loadEntries(v)
		let m = try AuthLog.replay(entries, expectedVaultId: v.str("vaultId"))
		#expect(jsonEqual(summary(m), v.at("membership")), "\(summary(m).stringify())")
		let rev = try AuthLog.replay(entries.reversed(), expectedVaultId: v.str("vaultId"))
		#expect(jsonEqual(summary(rev), v.at("membershipShuffled")))
		var rng = SystemRandomNumberGenerator()
		for _ in 0..<10 {
			let s = try AuthLog.replay(entries.shuffled(using: &rng), expectedVaultId: v.str("vaultId"))
			#expect(jsonEqual(summary(s), v.at("membership")))
		}
	}

	@Test func rivalGenesisCannotHijackPinnedRoot() throws {
		let entries = loadEntries(v)
		#expect(throws: Error.self) { try AuthLog.replay(entries, expectedVaultId: "nope") }
		let m = try AuthLog.replay(entries, expectedVaultId: v.str("vaultId"))
		#expect(m.vaultId == v.str("vaultId"))
	}

	@Test func validRootGenesis() {
		let entries = loadEntries(v)
		let g = entries[0]
		#expect(AuthLog.validRootGenesis(g, expectedVaultId: v.str("vaultId")))
		#expect(!AuthLog.validRootGenesis(g, expectedVaultId: "other"))
		var forged = g
		forged.sig = Data(count: 64).base64
		#expect(!AuthLog.validRootGenesis(forged, expectedVaultId: v.str("vaultId")))
		#expect(!AuthLog.validRootGenesis(entries[1], expectedVaultId: v.str("vaultId")))
	}

	@Test func swiftReproducesSignedEntryBytes() throws {
		// The reference derives every key from sha256("vault-vector/<label>").
		let signSeed = VaultCrypto.sha256("vault-vector/owner-user/sign")
		let signPub = try VaultCrypto.ed25519PublicKey(fromSeed: signSeed)
		let encPub = try VaultCrypto.x25519PublicKey(fromSeed: VaultCrypto.sha256("vault-vector/owner-user/enc"))
		let uid = AuthLog.deviceId(ofSignPub: signPub.base64)
		let genesis = try AuthLog.makeEntry(
			parents: [],
			body: .genesis(vaultId: v.str("vaultId"), userId: uid, userSignPub: signPub.base64, userEncPub: encPub.base64),
			signerId: uid, signerKind: .user, signerPriv: signSeed)
		let ref = LogEntry(json: v.at("entries").items[0])!
		#expect(genesis.hash == ref.hash)
		#expect(genesis.body == ref.body && genesis.parents == ref.parents)
		// Signatures are randomized in swift-crypto: assert both verify over the same bytes.
		let bytes = AuthLog.canonicalBytes(parents: [], body: ref.body, signerId: uid, signerKind: .user)
		#expect(VaultCrypto.verify(bytes, pub: signPub, sig: Data(base64: genesis.sig)))
		#expect(VaultCrypto.verify(bytes, pub: signPub, sig: Data(base64: ref.sig)))
	}

	@Test func malformedEntriesAreRejectedAtParse() {
		let bad: [String] = [
			#"{"parents":"x","body":{"type":"remove-user","userId":"u"},"signerId":"s","signerKind":"user","sig":"x"}"#,
			#"{"parents":[],"body":{"type":"genesis","vaultId":"v","userId":"u","userSignPub":"a","userEncPub":"b","role":"admin"},"signerId":"s","signerKind":"user","sig":"x"}"#,
			#"{"parents":[],"body":{"type":"add-device","userId":"u"},"signerId":"s","signerKind":"device","sig":"x"}"#,
			#"{"parents":[],"body":{"type":"remove-user","userId":"u"},"signerId":"s","signerKind":"robot","sig":"x"}"#,
			#"{"parents":[1],"body":{"type":"remove-user","userId":"u"},"signerId":"s","signerKind":"user","sig":"x"}"#,
		]
		for b in bad { #expect(LogEntry(json: try! JSONValue.parse(b)) == nil, "\(b)") }
		// A future entry type is kept opaquely, not rejected.
		let future = #"{"parents":[],"body":{"type":"future","x":1},"signerId":"s","signerKind":"user","sig":"x"}"#
		#expect(LogEntry(json: try! JSONValue.parse(future)) != nil)
	}
}

@Suite struct RotationVectorTests {
	let r = try! Vectors.load("rotation.json")
	let a = try! Vectors.load("auth.json")

	private func membership() throws -> Membership {
		try AuthLog.replay(loadEntries(a), expectedVaultId: a.str("vaultId"))
	}

	@Test func recordsSerializeAndVerifyIdentically() throws {
		let m = try membership()
		for info in r.at("records").items {
			let rec = RotationRecord(json: info.at("record"))!
			#expect(rec.serialized == info.str("serialized"))
			#expect(rec.signedBytes.base64 == info.str("bytes"))
			#expect(Rotation.authentic(rec, m) == (info["authentic"] == .bool(true)))
			#expect(Rotation.verifiable(rec, m) == (info["verifiable"] == .bool(true)))
			#expect(RotationRecord.parse(info.str("serialized")) == rec)
		}
	}

	@Test func winnerMatchesReference() throws {
		let m = try membership()
		let recs = r.at("records").items.map { RotationRecord(json: $0.at("record"))! }
		let authentic = recs.filter { Rotation.authentic($0, m) }
		let win = Rotation.winner(authentic)!
		#expect(win.epoch == Int(r.at("winner").at("epoch").int!))
		#expect(win.deviceId == r.at("winner").str("deviceId"))
		#expect(win.keyCommit == r.at("winner").str("keyCommit"))
		let e2 = Rotation.winner(authentic.filter { $0.epoch == 2 })!
		#expect(e2.deviceId == r.at("winnerEpoch2").str("deviceId"))
		// Order independence.
		var rng = SystemRandomNumberGenerator()
		for _ in 0..<20 { #expect(Rotation.winner(authentic.shuffled(using: &rng))?.keyCommit == win.keyCommit) }
	}

	@Test func catchUpRule() throws {
		let recs = r.at("records").items.map { RotationRecord(json: $0.at("record"))! }
		let removals = r.at("catchUp").at("removalHashes").strings
		#expect(Rotation.needsCatchUp(recs[0], removalHashes: []) == (r.at("catchUp")["winnerObservedAll"] == .bool(true)))
		#expect(Rotation.needsCatchUp(recs[0], removalHashes: removals) == (r.at("catchUp")["needsWithEarly"] == .bool(true)))
		#expect(!Rotation.needsCatchUp(nil, removalHashes: removals))
	}

	@Test func typeScriptGrantsUnsealToTheRightKeys() throws {
		let recs = r.at("records").items.map { RotationRecord(json: $0.at("record"))! }
		let devs = r.at("encPriv").members!
		var checked = 0
		for rec in recs where ["e1", "e2-admin", "e2-owner"].contains(where: { Rotation.keyCommit(b64(r.at("keys").str($0))) == rec.keyCommit }) {
			for d in devs {
				let pub = r.at("encPub").str(d.key)
				let g = rec.grants[pub]!
				let key = try SealedBoxes.unseal(g.sealedBox, priv: b64(d.value.string!), pub: b64(pub))
				#expect(Rotation.keyCommit(key) == rec.keyCommit)
				checked += 1
			}
		}
		#expect(checked == 9)
	}

	@Test func malformedRecordsAreRejected() {
		for bad in [
			#"{"epoch":0,"baseEpoch":-1,"hlc":"h","deviceId":"d","keyCommit":"k","grants":{},"observed":[],"signerId":"d","sig":"s"}"#,
			#"{"epoch":2,"baseEpoch":0,"hlc":"h","deviceId":"d","keyCommit":"k","grants":{},"observed":[],"signerId":"d","sig":"s"}"#,
			#"{"epoch":1,"baseEpoch":0,"hlc":"h","deviceId":"d","keyCommit":"k","grants":null,"observed":[],"signerId":"d","sig":"s"}"#,
			#"{"epoch":1,"baseEpoch":0,"hlc":"h","deviceId":"d","keyCommit":"k","grants":{"p":{"ephPub":"x"}},"observed":[],"signerId":"d","sig":"s"}"#,
			"garbage",
		] { #expect(RotationRecord.parse(bad) == nil, "\(bad)") }
	}
}
