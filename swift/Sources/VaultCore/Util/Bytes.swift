import Foundation

private let hexDigits = Array("0123456789abcdef".utf8)

extension Data {
	public var hex: String {
		var out = [UInt8]()
		out.reserveCapacity(count * 2)
		for b in self {
			out.append(hexDigits[Int(b >> 4)])
			out.append(hexDigits[Int(b & 15)])
		}
		return String(decoding: out, as: UTF8.self)
	}

	public init?(hex: String) {
		let u = Array(hex.utf8)
		guard u.count % 2 == 0 else { return nil }
		func nib(_ c: UInt8) -> UInt8? {
			switch c {
			case 0x30...0x39: return c - 0x30
			case 0x61...0x66: return c - 0x61 + 10
			case 0x41...0x46: return c - 0x41 + 10
			default: return nil
			}
		}
		var out = Data()
		var i = 0
		while i < u.count {
			guard let h = nib(u[i]), let l = nib(u[i + 1]) else { return nil }
			out.append(h << 4 | l)
			i += 2
		}
		self = out
	}

	public var base64: String { base64EncodedString() }

	// Lenient base64 decode matching Node's `Buffer.from(s, "base64")`: accepts the
	// standard and URL-safe alphabets, ignores whitespace/unknown characters,
	// tolerates missing padding, and stops at the first `=`.
	public init(base64 s: String) {
		var out = [UInt8]()
		var acc: UInt32 = 0
		var bits = 0
		for c in s.utf8 {
			if c == 0x3D { break }
			let v: UInt32
			switch c {
			case 0x41...0x5A: v = UInt32(c) - 0x41
			case 0x61...0x7A: v = UInt32(c) - 0x61 + 26
			case 0x30...0x39: v = UInt32(c) - 0x30 + 52
			case 0x2B, 0x2D: v = 62
			case 0x2F, 0x5F: v = 63
			default: continue
			}
			acc = acc << 6 | v
			bits += 6
			if bits >= 8 {
				bits -= 8
				out.append(UInt8((acc >> UInt32(bits)) & 0xFF))
			}
		}
		self = Data(out)
	}
}

// JavaScript compares strings by UTF-16 code unit. Sort orders that feed hashes
// and CRDT tie-breaks must use this, not Swift's Unicode-aware `<`.
@inlinable public func jsLess(_ a: String, _ b: String) -> Bool {
	a.utf16.lexicographicallyPrecedes(b.utf16)
}

extension Array where Element == String {
	public func jsSorted() -> [String] { sorted(by: jsLess) }
}

// Insertion-ordered dictionary (JS `Map` iteration semantics). Membership replay
// depends on iteration order, so a plain Dictionary is not enough.
public struct OrderedMap<Key: Hashable & Sendable, Value: Sendable>: Sendable, Sequence {
	public private(set) var keys: [Key] = []
	private var storage: [Key: Value] = [:]

	public init() {}

	public var count: Int { keys.count }
	public var isEmpty: Bool { keys.isEmpty }
	public var values: [Value] { keys.map { storage[$0]! } }

	public subscript(key: Key) -> Value? {
		get { storage[key] }
		set {
			if let v = newValue {
				if storage.updateValue(v, forKey: key) == nil { keys.append(key) }
			} else if storage.removeValue(forKey: key) != nil {
				keys.removeAll { $0 == key }
			}
		}
	}

	public func has(_ key: Key) -> Bool { storage[key] != nil }

	public mutating func removeAll() {
		keys.removeAll()
		storage.removeAll()
	}

	public mutating func update(_ key: Key, _ body: (inout Value) -> Void) {
		guard var v = storage[key] else { return }
		body(&v)
		storage[key] = v
	}

	public func makeIterator() -> AnyIterator<(key: Key, value: Value)> {
		var it = keys.makeIterator()
		return AnyIterator {
			guard let k = it.next() else { return nil }
			return (k, storage[k]!)
		}
	}
}

extension OrderedMap: Equatable where Value: Equatable {
	public static func == (a: Self, b: Self) -> Bool {
		a.keys == b.keys && a.keys.allSatisfy { a[$0] == b[$0] }
	}
}
