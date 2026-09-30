import Foundation

// Field-level CRDT (spec §7.1, §15.10). Ordinary fields are LWW
// registers keyed by HLC; `password` is a multi-value register so concurrent
// edits surface; deletes are tombstones. Apply is idempotent and
// order-independent.

public enum CRDTFields {
	public static let password = "password"
	public static let deleted = "__deleted__"
	public static let itemType = "__type__"
}

public enum ItemType: String, Sendable, CaseIterable {
	case login, note, card, identity
	public static let `default`: ItemType = .login
}

// A single field mutation. `value == nil` clears the field.
public struct FieldOp: Sendable, Equatable {
	public var itemId: String
	public var field: String
	public var value: String?
	public var hlc: String
	public var replaces: [String]?

	public init(itemId: String, field: String, value: String?, hlc: String, replaces: [String]? = nil) {
		self.itemId = itemId
		self.field = field
		self.value = value
		self.hlc = hlc
		self.replaces = replaces
	}

	// Key order matches `JSON.stringify(op)` in the reference.
	public var json: JSONValue {
		var m: [JSONMember] = [
			JSONMember("itemId", .string(itemId)), JSONMember("field", .string(field)),
			JSONMember("value", value.map { .string($0) } ?? .null), JSONMember("hlc", .string(hlc)),
		]
		if let r = replaces { m.append(JSONMember("replaces", .array(r.map { .string($0) }))) }
		return .object(m)
	}

	public init?(json: JSONValue) {
		guard let itemId = json["itemId"]?.string, let field = json["field"]?.string,
			let hlc = json["hlc"]?.string
		else { return nil }
		let value: String?
		switch json["value"] {
		case .some(.string(let s)): value = s
		case .some(.null), .none: value = nil
		default: return nil
		}
		self.init(
			itemId: itemId, field: field, value: value, hlc: hlc,
			replaces: json["replaces"]?.array?.compactMap { $0.string })
	}
}

public struct ItemView: Sendable, Equatable {
	public var itemId: String
	public var itemType: ItemType
	public var fields: [String: String]
	public var passwords: [String]  // more than one => unresolved concurrent edits
	public var deleted: Bool
	public var lastHlc: String

	public var title: String? { fields["title"] }
}

public struct VaultState: Sendable {
	private struct Reg: Sendable {
		var value: String?
		var hlc: String
	}
	private struct Acc: Sendable {
		var lww: [String: Reg] = [:]
		var pwValues: [String: String?] = [:]
		var pwSuperseded: Set<String> = []
		var lastHlc = ""
	}

	private var items: [String: Acc] = [:]

	public init() {}

	public mutating func apply(_ op: FieldOp) {
		var a = items[op.itemId] ?? Acc()
		defer { items[op.itemId] = a }
		if jsLess(a.lastHlc, op.hlc) { a.lastHlc = op.hlc }

		if op.field == CRDTFields.password {
			// An author equivocating two values at one HLC resolves deterministically
			// (larger value wins) so the merge stays order-independent.
			if let prev = a.pwValues[op.hlc] {
				if op.value == nil || (prev != nil && jsLess(prev!, op.value!)) {
					a.pwValues[op.hlc] = .some(op.value)
				}
			} else {
				a.pwValues[op.hlc] = .some(op.value)
			}
			for r in op.replaces ?? [] { a.pwSuperseded.insert(r) }
			return
		}

		if let cur = a.lww[op.field], HLCCodec.compareEncoded(op.hlc, cur.hlc) <= 0 { return }
		a.lww[op.field] = Reg(value: op.value, hlc: op.hlc)
	}

	public mutating func applyAll<S: Sequence>(_ ops: S) where S.Element == FieldOp {
		for op in ops { apply(op) }
	}

	private func liveEntries(_ a: Acc) -> [(hlc: String, value: String)] {
		var live: [(hlc: String, value: String)] = []
		for (hlc, value) in a.pwValues {
			guard !a.pwSuperseded.contains(hlc), let v = value else { continue }
			live.append((hlc, v))
		}
		live.sort { HLCCodec.compareEncoded($0.hlc, $1.hlc) < 0 }
		return live
	}

	// HLCs of currently-live password writes: pass as `replaces` on the next edit.
	public func livePasswordHlcs(_ itemId: String) -> [String] {
		items[itemId].map { liveEntries($0).map(\.hlc) } ?? []
	}

	public func materialize(_ itemId: String) -> ItemView? {
		guard let a = items[itemId] else { return nil }
		var fields: [String: String] = [:]
		var deleted = false
		var type = ItemType.default
		for name in Array(a.lww.keys).jsSorted() {
			let reg = a.lww[name]!
			if name == CRDTFields.deleted {
				deleted = reg.value != nil
				continue
			}
			if name == CRDTFields.itemType {
				if let v = reg.value, let t = ItemType(rawValue: v) { type = t }
				continue
			}
			if let v = reg.value { fields[name] = v }
		}
		return ItemView(
			itemId: itemId, itemType: type, fields: fields,
			passwords: liveEntries(a).map(\.value), deleted: deleted, lastHlc: a.lastHlc)
	}

	public func list() -> [ItemView] {
		items.keys.jsSortedKeys().compactMap { id in
			guard let v = materialize(id), !v.deleted else { return nil }
			return v
		}
	}
}

extension Dictionary.Keys where Key == String {
	fileprivate func jsSortedKeys() -> [String] { Array(self).jsSorted() }
}

public enum ItemOps {
	// Ops to create/update an item's fields, minting one HLC per field.
	public static func build(
		itemId: String, fields: [(String, String?)], nextHlc: () throws -> String,
		livePasswordHlcs: [String] = []
	) rethrows -> [FieldOp] {
		try fields.map { (field, value) in
			FieldOp(
				itemId: itemId, field: field, value: value, hlc: try nextHlc(),
				replaces: field == CRDTFields.password ? livePasswordHlcs : nil)
		}
	}

	public static func delete(itemId: String, hlc: String) -> FieldOp {
		FieldOp(itemId: itemId, field: CRDTFields.deleted, value: "1", hlc: hlc)
	}
}
