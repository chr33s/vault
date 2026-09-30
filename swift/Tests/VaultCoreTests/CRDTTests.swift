import Foundation
import Testing

@testable import VaultCore

@Suite struct CRDTVectorTests {
	let v = try! Vectors.load("crdt.json")

	@Test func hlcEncodingAndOrder() throws {
		let h = v.at("hlc")
		for (raw, enc) in zip(h.at("hlcs").items, h.at("encoded").strings) {
			let hlc = HLC(millis: raw.at("millis").int!, counter: raw.at("counter").int!, deviceId: raw.str("deviceId"))
			#expect(try HLCCodec.encode(hlc) == enc)
			#expect(HLCCodec.decode(enc) == hlc)
		}
		for c in h.at("compare").items {
			#expect(HLCCodec.compareEncoded(c.str("a"), c.str("b")) == Int(c.at("cmp").int!))
		}
		#expect(throws: HLCError.self) { try HLCCodec.encode(HLC(millis: 10_000_000_000_000_000, counter: 0, deviceId: "x")) }
	}

	@Test func clockMatchesReference() {
		final class Box: @unchecked Sendable { var t: Int64 = 0 }
		let box = Box()
		var clock = Clock(deviceId: "dev", now: { box.t })
		for s in v.at("hlc").at("clockSteps").items {
			box.t = s.at("now").int!
			let r: HLC
			if s.str("kind") == "tick" {
				r = clock.tick()
			} else {
				let rm = s.at("remote")
				r = clock.observe(HLC(millis: rm.at("millis").int!, counter: rm.at("counter").int!, deviceId: rm.str("deviceId")))
			}
			#expect(try! HLCCodec.encode(r) == s.str("result"))
		}
	}

	@Test func counterOverflowCarriesIntoMillis() {
		var clock = Clock(deviceId: "d", now: { 100 })
		var last = clock.tick()
		for _ in 0..<1_000_005 {
			let n = clock.tick()
			#expect(HLCCodec.compare(n, last) > 0)
			last = n
		}
		#expect(last.counter <= HLCCodec.counterMax)
		#expect(last.millis > 100)
	}

	private func ops() -> [FieldOp] { v.at("ops").items.map { FieldOp(json: $0)! } }

	private func views(_ st: VaultState, ids: [String]) -> [ItemView?] { ids.map { st.materialize($0) } }

	@Test func fieldOpSerializationIsByteIdentical() {
		for (op, expected) in zip(ops(), v.at("opJson").strings) {
			#expect(op.json.stringify() == expected)
		}
	}

	private func assertView(_ view: ItemView?, _ j: JSONValue) {
		if j.isNull {
			#expect(view == nil)
			return
		}
		guard let view else {
			Issue.record("missing item \(j.str("itemId"))")
			return
		}
		#expect(view.itemId == j.str("itemId"))
		#expect(view.itemType.rawValue == j.str("itemType"))
		#expect(view.deleted == (j["deleted"] == .bool(true)))
		#expect(view.lastHlc == j.str("lastHlc"))
		#expect(view.passwords == j.at("passwords").strings)
		var fields: [String: String] = [:]
		for m in j.at("fields").members! { fields[m.key] = m.value.string! }
		#expect(view.fields == fields)
	}

	@Test func convergesToReferenceState() {
		var st = VaultState()
		st.applyAll(ops())
		let ids = ["item-a", "item-b", "item-c", "item-eq"]
		for (view, j) in zip(views(st, ids: ids), v.at("materialized").items) { assertView(view, j) }
		let list = st.list()
		let expected = v.at("list").items
		#expect(list.count == expected.count)
		for (view, j) in zip(list, expected) { assertView(view, j) }
		for id in ids {
			#expect(st.livePasswordHlcs(id) == v.at("livePasswordHlcs").at(id).strings)
		}
	}

	@Test func orderIndependentAndIdempotent() {
		var base = VaultState()
		base.applyAll(ops())
		let expected = views(base, ids: ["item-a", "item-b", "item-c", "item-eq"])
		var rng = SystemRandomNumberGenerator()
		for round in 0..<40 {
			var shuffled = ops()
			shuffled.shuffle(using: &rng)
			if round % 2 == 0 { shuffled += ops().prefix(20) }  // duplicates
			var st = VaultState()
			st.applyAll(shuffled)
			#expect(views(st, ids: ["item-a", "item-b", "item-c", "item-eq"]) == expected)
		}
	}

	@Test func passwordEquivocationResolvesDeterministically() {
		let a = FieldOp(itemId: "i", field: "password", value: "aaa", hlc: "h")
		let b = FieldOp(itemId: "i", field: "password", value: "bbb", hlc: "h")
		var s1 = VaultState(), s2 = VaultState()
		s1.applyAll([a, b])
		s2.applyAll([b, a])
		#expect(s1.materialize("i")?.passwords == ["bbb"])
		#expect(s2.materialize("i")?.passwords == ["bbb"])
	}

	@Test func concurrentPasswordsSurfaceThenConverge() {
		var st = VaultState()
		let hA = "000001700000000001:000000:aa"
		let hB = "000001700000000001:000000:bb"
		st.applyAll([
			FieldOp(itemId: "i", field: "password", value: "one", hlc: hA, replaces: []),
			FieldOp(itemId: "i", field: "password", value: "two", hlc: hB, replaces: []),
		])
		#expect(st.materialize("i")?.passwords == ["one", "two"])
		st.apply(FieldOp(itemId: "i", field: "password", value: "merged", hlc: "000001700000000002:000000:aa", replaces: st.livePasswordHlcs("i")))
		#expect(st.materialize("i")?.passwords == ["merged"])
	}

	@Test func tombstoneAndTypeFallback() {
		var st = VaultState()
		st.applyAll([
			FieldOp(itemId: "i", field: "title", value: "t", hlc: "000000000000001:000000:a"),
			FieldOp(itemId: "i", field: CRDTFields.itemType, value: "bogus", hlc: "000000000000002:000000:a"),
			ItemOps.delete(itemId: "i", hlc: "000000000000003:000000:a"),
		])
		#expect(st.materialize("i")?.deleted == true)
		#expect(st.materialize("i")?.itemType == .login)
		#expect(st.list().isEmpty)
	}
}
