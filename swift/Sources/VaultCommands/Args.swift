import VaultCore

// Minimal strict argument parser (the TS CLI uses node:util parseArgs in strict
// mode). Flags may appear before or after the command; `--` ends flag parsing.

struct ParsedArgs {
	var values: [String: [String]] = [:]
	var flags: Set<String> = []
	var positionals: [String] = []

	func flag(_ n: String) -> Bool { flags.contains(n) }
	func value(_ n: String) -> String? { values[n]?.last }
	func all(_ n: String) -> [String] { values[n] ?? [] }
}

private let booleanFlags: Set<String> = ["json", "passphrase-stdin", "password", "keychain", "allow-missing", "mask", "tailnet", "tailnet-only", "connect"]
private let valueFlags: Set<String> = [
	"db", "vault", "field", "type", "field-stdin", "name", "device", "user", "token", "token-file", "relay",
	"relay-token-file", "access-id", "access-secret-file", "role", "org-key-file", "env", "with-key", "port",
	"peer-token-file", "peer", "config", "host",
]

func parseArgs(_ argv: [String]) throws -> ParsedArgs {
	var out = ParsedArgs()
	var i = 0
	while i < argv.count {
		let a = argv[i]
		i += 1
		if a == "--" {
			out.positionals += argv[i...]
			break
		}
		guard a.hasPrefix("--") else {
			out.positionals.append(a)
			continue
		}
		var name = String(a.dropFirst(2))
		var inline: String?
		if let eq = name.firstIndex(of: "=") {
			inline = String(name[name.index(after: eq)...])
			name = String(name[..<eq])
		}
		if booleanFlags.contains(name) {
			guard inline == nil else { throw VaultError.invalidArgument("option --\(name) does not take a value") }
			out.flags.insert(name)
		} else if valueFlags.contains(name) {
			if let v = inline {
				out.values[name, default: []].append(v)
			} else {
				guard i < argv.count else { throw VaultError.invalidArgument("option --\(name) requires a value") }
				out.values[name, default: []].append(argv[i])
				i += 1
			}
		} else {
			throw VaultError.invalidArgument("unknown option: --\(name)")
		}
	}
	return out
}
