import Foundation

// Last-line-of-defense secret redaction. The primary rule stays
// "never put a secret in a message"; this is the backstop for output we don't
// author (a child that echoes an injected value). Best-effort: exotic encodings
// and values shorter than `minLength` pass through.

public final class Scrubber: @unchecked Sendable {
	public static let redaction = "[REDACTED]"
	static let minLength = 6

	private let lock = NSLock()
	private var patterns: [[UInt8]] = []
	private var seen = Set<[UInt8]>()

	public init() {}

	private func add(_ s: String) {
		let b = Array(s.utf8)
		guard !b.isEmpty, seen.insert(b).inserted else { return }
		patterns.append(b)
	}

	private static func percentEncode(_ s: String, keep: String, spaceAsPlus: Bool) -> String {
		var out = ""
		for byte in s.utf8 {
			let c = Character(Unicode.Scalar(byte))
			if byte < 0x80, c.isASCII, c.isLetter || c.isNumber || keep.contains(c) {
				out.append(c)
			} else if spaceAsPlus && byte == 0x20 {
				out.append("+")
			} else {
				out += "%" + String(format: "%02X", byte)
			}
		}
		return out
	}

	// Register a value plus the encodings it commonly travels under.
	public func register(_ value: String) {
		guard value.count >= Self.minLength else { return }
		lock.lock()
		defer { lock.unlock() }
		add(value)
		add(Self.percentEncode(value, keep: "-_.!~*'()", spaceAsPlus: false))  // encodeURIComponent
		add(Self.percentEncode(value, keep: "*-._", spaceAsPlus: true))  // x-www-form-urlencoded
		add(Self.percentEncode(value, keep: "-._~", spaceAsPlus: false))  // strict RFC 3986 (the proxy's query form)
		add(String(JSONValue.string(value).stringify().dropFirst().dropLast()))  // JSON-escaped
		add(Data(value.utf8).base64)  // Basic-auth form
	}

	private static func replaceAll(_ hay: [UInt8], _ needle: [UInt8]) -> [UInt8] {
		guard !needle.isEmpty, hay.count >= needle.count else { return hay }
		var out: [UInt8] = []
		out.reserveCapacity(hay.count)
		let marker = Array(redaction.utf8)
		var i = 0
		while i < hay.count {
			if i + needle.count <= hay.count, hay[i] == needle[0], hay[i..<i + needle.count].elementsEqual(needle) {
				out += marker
				i += needle.count
			} else {
				out.append(hay[i])
				i += 1
			}
		}
		return out
	}

	private func redact(_ bytes: [UInt8]) -> [UInt8] {
		patterns.reduce(bytes) { Self.replaceAll($0, $1) }
	}

	// Scrub a short string (error messages, audit lines).
	public func scrub(_ text: String) -> String {
		lock.lock()
		defer { lock.unlock() }
		return patterns.isEmpty ? text : String(decoding: redact(Array(text.utf8)), as: UTF8.self)
	}

	// Streaming, binary-safe form: holds back only the tail that could begin a
	// not-yet-complete match.
	public final class Stream: @unchecked Sendable {
		private let owner: Scrubber
		private var carry: [UInt8] = []
		init(_ o: Scrubber) { owner = o }

		public func feed(_ chunk: Data) -> Data {
			owner.lock.lock()
			defer { owner.lock.unlock() }
			if owner.patterns.isEmpty && carry.isEmpty { return chunk }
			let redacted = owner.redact(carry + Array(chunk))
			let maxLen = owner.patterns.map(\.count).max() ?? 0
			let firsts = Set(owner.patterns.compactMap(\.first))
			let keep = maxLen > 1 ? maxLen - 1 : 0
			var cut = redacted.count
			var i = max(0, redacted.count - keep)
			while i < redacted.count {
				if firsts.contains(redacted[i]) {
					cut = i
					break
				}
				i += 1
			}
			carry = Array(redacted[cut...])
			return Data(redacted[..<cut])
		}

		public func flush() -> Data {
			let out = Data(carry)
			carry = []
			return out
		}
	}

	public func stream() -> Stream { Stream(self) }
}
