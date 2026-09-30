import Foundation

// Order-preserving JSON model. The wire protocol signs and hashes
// `JSON.stringify(...)` output from the original implementation, so member order and
// the exact escaping rules are part of the format (spec §15.5); Foundation's
// JSONSerialization/Codable do not guarantee either.

public struct JSONMember: Sendable, Equatable {
	public var key: String
	public var value: JSONValue
	public init(_ key: String, _ value: JSONValue) {
		self.key = key
		self.value = value
	}
}

public enum JSONValue: Sendable, Equatable {
	case null
	case bool(Bool)
	case int(Int64)
	case double(Double)
	case string(String)
	case array([JSONValue])
	case object([JSONMember])

	public static func obj(_ members: KeyValuePairs<String, JSONValue>) -> JSONValue {
		.object(members.map { JSONMember($0.key, $0.value) })
	}

	public subscript(key: String) -> JSONValue? {
		guard case .object(let m) = self else { return nil }
		return m.first { $0.key == key }?.value
	}

	public var string: String? {
		if case .string(let s) = self { return s }
		return nil
	}
	public var int: Int64? {
		switch self {
		case .int(let i): return i
		case .double(let d) where d == d.rounded() && abs(d) < 9.007199254740992e15: return Int64(d)
		default: return nil
		}
	}
	public var array: [JSONValue]? {
		if case .array(let a) = self { return a }
		return nil
	}
	public var members: [JSONMember]? {
		if case .object(let m) = self { return m }
		return nil
	}
	public var isNull: Bool {
		if case .null = self { return true }
		return false
	}

	// Equivalent of `JSON.stringify(value)`.
	public func stringify() -> String {
		var out = ""
		write(to: &out)
		return out
	}

	public func serialized() -> Data { Data(stringify().utf8) }

	func write(to out: inout String) {
		switch self {
		case .null: out += "null"
		case .bool(let b): out += b ? "true" : "false"
		case .int(let i): out += String(i)
		case .double(let d):
			if !d.isFinite { out += "null" } else if d == d.rounded(), abs(d) < 1e21 {
				out += String(Int64(d))
			} else {
				out += "\(d)"
			}
		case .string(let s): JSONValue.writeString(s, to: &out)
		case .array(let a):
			out += "["
			for (i, v) in a.enumerated() {
				if i > 0 { out += "," }
				v.write(to: &out)
			}
			out += "]"
		case .object(let m):
			out += "{"
			for (i, kv) in m.enumerated() {
				if i > 0 { out += "," }
				JSONValue.writeString(kv.key, to: &out)
				out += ":"
				kv.value.write(to: &out)
			}
			out += "}"
		}
	}

	// JSON.stringify string escaping: quote, backslash, \b\f\n\r\t, other C0 as
	// lowercase \u00xx; everything else (including U+2028/9 and DEL) verbatim.
	static func writeString(_ s: String, to out: inout String) {
		out += "\""
		for u in s.unicodeScalars {
			switch u {
			case "\"": out += "\\\""
			case "\\": out += "\\\\"
			case "\u{08}": out += "\\b"
			case "\u{0C}": out += "\\f"
			case "\n": out += "\\n"
			case "\r": out += "\\r"
			case "\t": out += "\\t"
			default:
				if u.value < 0x20 {
					let h = String(u.value, radix: 16)
					out += "\\u" + String(repeating: "0", count: 4 - h.count) + h
				} else {
					out.unicodeScalars.append(u)
				}
			}
		}
		out += "\""
	}

	// Equivalent of `JSON.parse`. Duplicate keys: last value wins, first position
	// kept (JS object semantics).
	public static func parse(_ text: String) throws -> JSONValue {
		try parse(Array(text.utf8))
	}

	public static func parse(_ data: Data) throws -> JSONValue { try parse(Array(data)) }

	static func parse(_ bytes: [UInt8]) throws -> JSONValue {
		var p = JSONParser(bytes: bytes)
		let v = try p.value(depth: 0)
		p.skipWS()
		guard p.i == bytes.count else { throw JSONError.syntax }
		return v
	}
}

public enum JSONError: Error, Sendable { case syntax }

private struct JSONParser {
	let bytes: [UInt8]
	var i = 0
	init(bytes: [UInt8]) { self.bytes = bytes }

	mutating func skipWS() {
		while i < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[i]) { i += 1 }
	}

	mutating func value(depth: Int) throws -> JSONValue {
		guard depth < 512 else { throw JSONError.syntax }
		skipWS()
		guard i < bytes.count else { throw JSONError.syntax }
		switch bytes[i] {
		case UInt8(ascii: "{"):
			i += 1
			var members: [JSONMember] = []
			var index: [String: Int] = [:]
			skipWS()
			if i < bytes.count, bytes[i] == UInt8(ascii: "}") {
				i += 1
				return .object([])
			}
			while true {
				skipWS()
				let k = try string()
				skipWS()
				guard i < bytes.count, bytes[i] == UInt8(ascii: ":") else { throw JSONError.syntax }
				i += 1
				let v = try value(depth: depth + 1)
				if let at = index[k] {
					members[at].value = v
				} else {
					index[k] = members.count
					members.append(JSONMember(k, v))
				}
				skipWS()
				guard i < bytes.count else { throw JSONError.syntax }
				if bytes[i] == UInt8(ascii: ",") {
					i += 1
					continue
				}
				if bytes[i] == UInt8(ascii: "}") {
					i += 1
					return .object(members)
				}
				throw JSONError.syntax
			}
		case UInt8(ascii: "["):
			i += 1
			var items: [JSONValue] = []
			skipWS()
			if i < bytes.count, bytes[i] == UInt8(ascii: "]") {
				i += 1
				return .array([])
			}
			while true {
				items.append(try value(depth: depth + 1))
				skipWS()
				guard i < bytes.count else { throw JSONError.syntax }
				if bytes[i] == UInt8(ascii: ",") {
					i += 1
					continue
				}
				if bytes[i] == UInt8(ascii: "]") {
					i += 1
					return .array(items)
				}
				throw JSONError.syntax
			}
		case UInt8(ascii: "\""):
			return .string(try string())
		case UInt8(ascii: "t"): try literal("true"); return .bool(true)
		case UInt8(ascii: "f"): try literal("false"); return .bool(false)
		case UInt8(ascii: "n"): try literal("null"); return .null
		default: return try number()
		}
	}

	mutating func literal(_ s: String) throws {
		let u = Array(s.utf8)
		guard i + u.count <= bytes.count, Array(bytes[i..<i + u.count]) == u else {
			throw JSONError.syntax
		}
		i += u.count
	}

	mutating func number() throws -> JSONValue {
		let start = i
		if i < bytes.count, bytes[i] == UInt8(ascii: "-") { i += 1 }
		var digits = 0
		var isInt = true
		while i < bytes.count, (0x30...0x39).contains(bytes[i]) {
			i += 1
			digits += 1
		}
		guard digits > 0 else { throw JSONError.syntax }
		if i < bytes.count, bytes[i] == UInt8(ascii: ".") {
			isInt = false
			i += 1
			var f = 0
			while i < bytes.count, (0x30...0x39).contains(bytes[i]) {
				i += 1
				f += 1
			}
			guard f > 0 else { throw JSONError.syntax }
		}
		if i < bytes.count, bytes[i] == UInt8(ascii: "e") || bytes[i] == UInt8(ascii: "E") {
			isInt = false
			i += 1
			if i < bytes.count, bytes[i] == UInt8(ascii: "+") || bytes[i] == UInt8(ascii: "-") { i += 1 }
			var e = 0
			while i < bytes.count, (0x30...0x39).contains(bytes[i]) {
				i += 1
				e += 1
			}
			guard e > 0 else { throw JSONError.syntax }
		}
		let text = String(decoding: bytes[start..<i], as: UTF8.self)
		if isInt, let n = Int64(text) { return .int(n) }
		guard let d = Double(text) else { throw JSONError.syntax }
		return .double(d)
	}

	mutating func hex4() throws -> UInt32 {
		guard i + 4 <= bytes.count else { throw JSONError.syntax }
		var v: UInt32 = 0
		for _ in 0..<4 {
			let c = bytes[i]
			i += 1
			let d: UInt32
			switch c {
			case 0x30...0x39: d = UInt32(c) - 0x30
			case 0x61...0x66: d = UInt32(c) - 0x61 + 10
			case 0x41...0x46: d = UInt32(c) - 0x41 + 10
			default: throw JSONError.syntax
			}
			v = v << 4 | d
		}
		return v
	}

	mutating func string() throws -> String {
		guard i < bytes.count, bytes[i] == UInt8(ascii: "\"") else { throw JSONError.syntax }
		i += 1
		var out: [UInt8] = []
		while true {
			guard i < bytes.count else { throw JSONError.syntax }
			let c = bytes[i]
			i += 1
			switch c {
			case UInt8(ascii: "\""):
				return String(decoding: out, as: UTF8.self)
			case UInt8(ascii: "\\"):
				guard i < bytes.count else { throw JSONError.syntax }
				let e = bytes[i]
				i += 1
				switch e {
				case UInt8(ascii: "\""): out.append(0x22)
				case UInt8(ascii: "\\"): out.append(0x5C)
				case UInt8(ascii: "/"): out.append(0x2F)
				case UInt8(ascii: "b"): out.append(0x08)
				case UInt8(ascii: "f"): out.append(0x0C)
				case UInt8(ascii: "n"): out.append(0x0A)
				case UInt8(ascii: "r"): out.append(0x0D)
				case UInt8(ascii: "t"): out.append(0x09)
				case UInt8(ascii: "u"):
					var cp = try hex4()
					if (0xD800...0xDBFF).contains(cp), i + 1 < bytes.count, bytes[i] == 0x5C,
						bytes[i + 1] == UInt8(ascii: "u")
					{
						let save = i
						i += 2
						let lo = try hex4()
						if (0xDC00...0xDFFF).contains(lo) {
							cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
						} else {
							i = save
						}
					}
					// Lone surrogates cannot be represented in a Swift String.
					let scalar = Unicode.Scalar(cp) ?? "\u{FFFD}"
					out.append(contentsOf: Array(String(Character(scalar)).utf8))
				default: throw JSONError.syntax
				}
			case 0..<0x20:
				throw JSONError.syntax
			default:
				out.append(c)
			}
		}
	}
}

extension JSONValue: ExpressibleByStringLiteral {
	public init(stringLiteral value: String) { self = .string(value) }
}
