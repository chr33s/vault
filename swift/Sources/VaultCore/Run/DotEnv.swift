import Foundation

// `.env` as a secret-free manifest of required variables.

public struct EnvDecl: Sendable, Equatable {
	public var key: String
	// nil: bare `KEY` (resolve by name); "": `KEY=` (resolve by name);
	// "vault://…": explicit reference; other: literal passthrough.
	public var value: String?
}

public struct VaultRef: Sendable, Equatable {
	public var vault: String
	public var item: String
	public var field: String?
}

public enum DotEnv {
	private static let line = try! NSRegularExpression(
		pattern: #"^\s*(?:export\s+)?(\??[A-Za-z_][A-Za-z0-9_.-]*)\s*(=(.*))?\s*$"#)

	// Strip a trailing ` #…` comment, but not a `#` inside a quoted value.
	static func stripComment(_ s: String) -> String {
		let chars = Array(s)
		var i = 0
		while i < chars.count {
			let ch = chars[i]
			let prev: Character? = i == 0 ? nil : chars[i - 1]
			let valueLeading = i == 0 || prev == "=" || prev!.isWhitespace
			if (ch == "'" || ch == "\"") && valueLeading, let close = chars[(i + 1)...].firstIndex(of: ch) {
				i = close + 1
				continue
			}
			if ch == "#" && (i == 0 || prev!.isWhitespace) { return String(chars[..<i]) }
			i += 1
		}
		return s
	}

	static func unquote(_ raw: String) -> String {
		let v = raw.trimmingCharacters(in: .whitespaces)
		if v.count >= 2, let f = v.first, let l = v.last, f == l, f == "\"" || f == "'" { return String(v.dropFirst().dropLast()) }
		return v
	}

	public static func parse(_ text: String) throws -> [EnvDecl] {
		var out: [EnvDecl] = []
		for raw in text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
			let l = stripComment(String(raw))
			if l.trimmingCharacters(in: .whitespaces).isEmpty { continue }
			let ns = l as NSString
			// A non-empty line that isn't a valid declaration must fail loudly: silently
			// dropping it would bypass the "unresolved variables" guard.
			guard let m = line.firstMatch(in: l, range: NSRange(location: 0, length: ns.length)) else {
				throw VaultError.invalidArgument("malformed .env line: \(l.trimmingCharacters(in: .whitespaces))")
			}
			let key = ns.substring(with: m.range(at: 1))
			if m.range(at: 2).location == NSNotFound {
				out.append(EnvDecl(key: key, value: nil))
			} else {
				let v = m.range(at: 3).location == NSNotFound ? "" : ns.substring(with: m.range(at: 3))
				out.append(EnvDecl(key: key, value: unquote(v)))
			}
		}
		return out
	}

	// vault://<vault>/<item>[/<field>]
	public static func parseRef(_ value: String) -> VaultRef? {
		guard value.hasPrefix("vault://") else { return nil }
		let parts = value.dropFirst("vault://".count).split(separator: "/").map(String.init)
		guard parts.count >= 2 else { return nil }
		return VaultRef(vault: parts[0], item: parts[1], field: parts.count > 2 ? parts[2] : nil)
	}
}
