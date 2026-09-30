import Foundation
import VaultCore

#if canImport(VaultPlatformDarwin)
	import VaultPlatformDarwin
#elseif canImport(VaultPlatformLinux)
	import VaultPlatformLinux
#elseif canImport(VaultPlatformWindows)
	import VaultPlatformWindows
#endif

let version = "0.5.0-swift"

let help = """
	vault \(version) — end-to-end encrypted, local-first credential vault (Swift client)

	Usage: vault <command> [options]

	Vault & items
	  init [--keychain]            Create a vault + personal keys; bootstrap the auth log
	  add <title> [--type login|note|card|identity] [--field k=v ...] [--password]
	  get <title> [--field name]   Show an item (or one field)
	  list                         List item titles
	  edit <title> [--type <t>] [--field k=v...]   Update fields and/or the item type
	  rm <title>                   Delete (tombstone) an item
	  totp <title> [--name <field>]  Print the current RFC-6238 TOTP code

	Vaults & keys
	  vaults                       List local vaults
	  rotate                       Issue a new key epoch (conflict-free)
	  device-remove (--device <id> | --user <id>)   Revoke a device or a person, then rotate

	Global: --vault <name> selects a vault (default "\(defaultVault)"); --db <path> overrides the file.
	  --json                       Emit one JSON object per command (machine contract).
	  --passphrase-stdin           Read each passphrase as a line from stdin (one secret per line).
	Passphrase: prompted, or read from $VAULT_PASSPHRASE for non-interactive use.

	Sync
	  sync [--relay <url>] [--relay-token-file <path>] [--access-id <id>] [--access-secret-file <path>]
	                               Anti-entropy round with the relay (env: VAULT_RELAY_TOKEN,
	                               CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET; defaults to the saved relay)

	Devices (token handshake)
	  auth                         New device: generate keys, print Token A
	  device-add --token <A> [--relay <url>]   Authorized device: seal grants, print Token B
	  device-confirm --token <B>   New device: unseal vault key, build replica

	Sharing with other people
	  invite                       Joiner: generate a user identity, print Invite Token
	  share --token <invite> [--role member|admin] [--relay <url>]   Admin: print Join Token
	  join --token <join>          Joiner: validate, add own device, build replica

	Recovery escrow / keystore / secrets
	  recovery-enable              Owner: create the org escrow key; print the org private key
	  recover --user <id> (--org-key-file <path> | VAULT_ORG_KEY) [--token <A>] [--relay <url>]
	                               Owner: with the member's Token A, enroll their new device (prints Token B);
	                               without it, print the recovered identity keys
	  keystore (status|enable|disable)   OS-keychain second factor for at-rest keys
	  run [--env <file>] [--allow-missing] [--mask] -- <cmd> [args...]

	Self-hosted relay
	  relay [--host <ip>] [--port <n>] [--db <file>]   Zero-knowledge store-and-forward hub.
	                               Env: PORT, RELAY_DB, VAULT_RELAY_TOKENS (comma-separated),
	                               CF_ACCESS_TEAM_DOMAIN + CF_ACCESS_AUD, REQUIRE_ACCESS=1 (fail closed)

	Direct peer sync (tailnet)
	  serve [--host <ip>] [--port <n>] [--peer-token-file <path>]   Always-on replica peer
	  sync --tailnet | --tailnet-only [--port <n>] [--peer <name|ip> ...] [--peer-token-file <path>]

	Credential-injecting proxy
	  proxy --config <file> [--config <file> ...] [--port <n>] [--connect] [-- <cmd> [args...]]
	                               Loopback proxy so an agent USES a secret without SEEING it. The
	                               .env-format policy has a reserved UPSTREAM= line plus header and
	                               ?query lines (same vault:// refs as run). With -- <cmd>, spawns the
	                               agent pointed at the proxy (secret absent from its env). --connect
	                               also enables HTTPS_PROXY/CONNECT mode (ephemeral in-memory CA).

	"""

func openStore(_ a: ParsedArgs) throws -> Store {
	try Store(path: a.value("db") ?? dbPath(a.value("vault") ?? defaultVault))
}

func keyStore(for store: Store) async throws -> PlatformKeyStore? {
	guard let provider = try store.meta("keystoreProvider"), !provider.isEmpty else { return nil }
	// Resolve in the persisted binding (e.g. systemd-creds --with-key mode).
	let mode = try store.meta("keystoreKeyMode").flatMap { $0.isEmpty ? nil : $0 }
	return await Platform.keyStore(named: provider, mode: mode)
}

func withEngine(_ a: ParsedArgs, _ body: (VaultEngine) async throws -> Void) async throws {
	let store = try openStore(a)
	defer { store.close() }
	guard try VaultEngine.isInitialized(store) else { throw VaultError.notInitialized }
	var pass = try readPassphrase()
	defer { SecureBytes.wipe(&pass) }
	let engine = try await VaultEngine.unlock(store: store, password: pass, keystore: try await keyStore(for: store))
	try await body(engine)
}

func parseItemType(_ v: String?) throws -> ItemType? {
	guard let v else { return nil }
	guard let t = ItemType(rawValue: v) else {
		throw VaultError.invalidArgument("invalid --type \"\(v)\" (expected \(ItemType.allCases.map(\.rawValue).joined(separator: "|")))")
	}
	return t
}

// `k=v` pairs; a repeated key overwrites the value but keeps its first position.
func collectFields(_ raw: [String]) throws -> ItemFields {
	var out: ItemFields = []
	for f in raw {
		guard let eq = f.firstIndex(of: "=") else { throw VaultError.invalidArgument("bad --field \"\(f)\" (expected key=value)") }
		out.append((String(f[..<eq]), String(f[f.index(after: eq)...])))
	}
	return out
}

// `--field-stdin <n>`: n `KEY=VALUE` lines after the passphrase, so a wrapper can
// pass secret values without exposing them on argv.
func readStdinFields(_ a: ParsedArgs, into fields: inout ItemFields) throws {
	guard let raw = a.value("field-stdin") else { return }
	guard let n = Int(raw), n >= 0 else { throw VaultError.invalidArgument("--field-stdin expects a non-negative count") }
	for _ in 0..<n {
		let line = try readStdinLine()
		guard let eq = line.firstIndex(of: "="), eq != line.startIndex else {
			throw VaultError.invalidArgument("bad --field-stdin line (expected KEY=VALUE)")
		}
		fields.append((String(line[..<eq]), String(line[line.index(after: eq)...])))
	}
}

func otpJSON(_ o: TotpResult) -> JSONValue {
	.obj([
		"code": .string(o.code), "expiresIn": .int(Int64(o.expiresInSec)), "period": .int(Int64(o.period)),
		"digits": .int(Int64(o.digits)), "algorithm": .string(o.algorithm.rawValue),
	])
}

func run(_ argv: [String]) async throws -> Int32 {
	if argv.isEmpty || ["help", "--help", "-h"].contains(argv[0]) {
		writeOut(help)
		return 0
	}
	if ["version", "--version", "-v"].contains(argv[0]) {
		writeOut("\(version)\n")
		return 0
	}
	let a = try parseArgs(argv)
	if a.flag("json") { jsonOutput = true }
	if a.flag("passphrase-stdin") { passphraseFromStdin = true }
	guard let command = a.positionals.first else {
		writeErr(help)
		return 2
	}
	let rest = Array(a.positionals.dropFirst())

	switch command {
	case "init":
		let store = try openStore(a)
		defer { store.close() }
		guard try !VaultEngine.isInitialized(store) else { throw VaultError.alreadyInitialized }
		var pass = try readPassphrase("New passphrase: ")
		defer { SecureBytes.wipe(&pass) }
		var ks: PlatformKeyStore?
		ks = try await requestedKeyStore(a)
		let r = try await VaultEngine.initialize(store: store, password: pass, keystore: ks)
		emit(
			"Initialized vault \(r.vaultId)\n  user:   \(r.userId)\n  device: \(r.deviceId)\n",
			[JSONMember("vaultId", .string(r.vaultId)), JSONMember("userId", .string(r.userId)), JSONMember("deviceId", .string(r.deviceId))])

	case "add":
		guard let title = rest.first else {
			throw VaultError.invalidArgument("usage: vault add <title> [--type login|note|card|identity] [--field k=v ...] [--password]")
		}
		var fields = try collectFields(a.all("field"))
		let type = try parseItemType(a.value("type"))
		try await withEngine(a) { e in
			// stdin order: passphrase, --field-stdin lines, then the item password.
			try readStdinFields(a, into: &fields)
			if a.flag("password") {
				var pw = try readPassphrase("Item password: ", useEnv: false)
				fields.append(("password", String(decoding: pw, as: UTF8.self)))
				SecureBytes.wipe(&pw)
			}
			let id = try await e.addItem(title: title, fields: fields, itemType: type ?? .default)
			emit(
				"Added \((type ?? .default).rawValue) \"\(title)\" (\(id))\n",
				[JSONMember("title", .string(title)), JSONMember("itemId", .string(id)), JSONMember("itemType", .string((type ?? .default).rawValue))])
		}

	case "get":
		guard let title = rest.first else { throw VaultError.invalidArgument("usage: vault get <title> [--field name]") }
		try await withEngine(a) { e in
			guard let item = await e.item(title: title) else { throw VaultError.noSuchItem(title) }
			if let field = a.value("field") {
				guard let v = field == "password" ? (item.passwords.isEmpty ? nil : item.passwords.joined(separator: "\n")) : item.fields[field]
				else { throw VaultError.noSuchField(field) }
				emit("\(v)\n", [JSONMember("title", .string(title)), JSONMember("field", .string(field)), JSONMember("value", .string(v))])
				return
			}
			var text = "type: \(item.itemType.rawValue)\n"
			let names = Array(item.fields.keys).jsSorted()
			for k in names { text += "\(k): \(item.fields[k]!)\n" }
			if item.passwords.count == 1 {
				text += "password: \(item.passwords[0])\n"
			} else if item.passwords.count > 1 {
				text += "password: <\(item.passwords.count) conflicting values: \(item.passwords.joined(separator: " | "))>\n"
			}
			// A malformed secret simply omits the derived line rather than failing `get`.
			let otp = item.fields["totp"].flatMap { try? TOTP.generate($0) }
			if let otp { text += "otp: \(otp.code) (expires in \(otp.expiresInSec)s)\n" }
			var data: [JSONMember] = [
				JSONMember("title", .string(title)), JSONMember("itemId", .string(item.itemId)),
				JSONMember("itemType", .string(item.itemType.rawValue)),
				JSONMember("fields", .object(names.map { JSONMember($0, .string(item.fields[$0]!)) })),
				JSONMember("passwords", .array(item.passwords.map { .string($0) })),
			]
			if let otp { data.append(JSONMember("otp", otpJSON(otp))) }
			emit(text, data)
		}

	case "list":
		try await withEngine(a) { e in
			let items = await e.listItems()
			emit(
				items.map { "\($0.title ?? $0.itemId)\n" }.joined(),
				[
					JSONMember(
						"items",
						.array(
							items.map {
								.obj(["itemId": .string($0.itemId), "title": $0.title.map { .string($0) } ?? .null, "itemType": .string($0.itemType.rawValue)])
							}))
				])
		}

	case "edit":
		guard let title = rest.first else {
			throw VaultError.invalidArgument("usage: vault edit <title> [--type <t>] [--field k=v ...]")
		}
		let type = try parseItemType(a.value("type"))
		var fields = try collectFields(a.all("field"))
		try await withEngine(a) { e in
			try readStdinFields(a, into: &fields)
			if fields.isEmpty && type == nil {
				throw VaultError.invalidArgument("nothing to update: pass --field k=v ... and/or --type <t>")
			}
			try await e.editItem(title: title, fields: fields, itemType: type)
			var data = [JSONMember("title", .string(title))]
			if let type { data.append(JSONMember("itemType", .string(type.rawValue))) }
			emit("Updated \"\(title)\"\n", data)
		}

	case "rm":
		guard let title = rest.first else { throw VaultError.invalidArgument("usage: vault rm <title>") }
		try await withEngine(a) { e in
			try await e.removeItem(title: title)
			emit("Removed \"\(title)\"\n", [JSONMember("title", .string(title))])
		}

	case "totp":
		guard let title = rest.first else { throw VaultError.invalidArgument("usage: vault totp <title> [--name <field>]") }
		try await withEngine(a) { e in
			guard let item = await e.item(title: title) else { throw VaultError.noSuchItem(title) }
			let name = a.value("name") ?? "totp"
			guard let secret = item.fields[name] else {
				throw VaultError.invalidArgument("item \"\(title)\" has no \"\(name)\" field (store a base32 secret or otpauth:// URI)")
			}
			// Unlike `get`, a malformed secret surfaces as an error here.
			let otp: TotpResult
			do { otp = try TOTP.generate(secret) } catch let e as TotpError { throw VaultError.invalidArgument(e.description) }
			if !jsonOutput { writeErr("(expires in \(otp.expiresInSec)s)\n") }
			emit(
				"\(otp.code)\n",
				[JSONMember("title", .string(title))] + (otpJSON(otp).members ?? []))
		}

	case "vaults":
		let names = try listVaultNames()
		emit(names.map { "\($0)\n" }.joined(), [JSONMember("vaults", .array(names.map { .string($0) }))])

	case "rotate":
		try await withEngine(a) { e in
			let epoch = try await e.rotate()
			emit("Rotated to epoch \(epoch)\n", [JSONMember("epoch", .int(Int64(epoch)))])
		}

	case "device-remove":
		try await withEngine(a) { e in
			if let d = a.value("device") {
				let epoch = try await e.removeDevice(d)
				emit("Removed device \(d); rotated to epoch \(epoch)\n", [JSONMember("removedDevice", .string(d)), JSONMember("epoch", .int(Int64(epoch)))])
			} else if let u = a.value("user") {
				let epoch = try await e.removeUser(u)
				emit("Removed user \(u); rotated to epoch \(epoch)\n", [JSONMember("removedUser", .string(u)), JSONMember("epoch", .int(Int64(epoch)))])
			} else {
				throw VaultError.invalidArgument("usage: vault device-remove (--device <id> | --user <id>)")
			}
		}

	default:
		if let code = try await runExtended(command, a, rest) { return code }
		writeErr("unknown command: \(command)\n\n\(help)")
		return 2
	}
	return 0
}

// Typed internal errors become stable machine-readable messages (spec §15.15); they never
// interpolate secrets.
func describe(_ error: Error) -> String {
	(error as? VaultError)?.description ?? (error as? StoreError)?.description ?? (error as? RelayError)?.description
		?? (error as? TotpError)?.description ?? "\(error)"
}

public enum VaultCommands {
	// The executable's entry point: real stdin/stdout/env, core dumps disabled.
	public static func main(_ argv: [String]) async -> Int32 {
		Platform.processSecurity.disableCoreDumps()
		// Decide the output mode before parsing so even argument errors honor --json.
		jsonOutput = argv.prefix { $0 != "--" }.contains("--json")
		do { return try await run(argv) } catch {
			// JSON mode emits {"ok":false,"error":...} on stdout so callers parse one stream.
			emitError(describe(error))
			return 1
		}
	}

	public struct Output: Sendable {
		public var exitCode: Int32
		public var stdout: String
		public var stderr: String
	}

	private final class Capture: @unchecked Sendable {
		private let lock = NSLock()
		private var buf = ""
		func add(_ s: String) { lock.withLock { buf += s } }
		var text: String { lock.withLock { buf } }
	}

	// Run a command IN-PROCESS: no subprocess, and no IPC for secrets. `secrets` are
	// consumed one per prompt, in the order the command asks for them (account
	// passphrase first, then `--field-stdin` values, then an item password), exactly
	// as with `--passphrase-stdin`. `environment` overlays the process environment
	// (e.g. relay credentials, which gate reachability, not confidentiality).
	public static func execute(_ argv: [String], secrets: [String] = [], environment: [String: String] = [:]) async -> Output {
		let out = Capture(), err = Capture()
		let env = ProcessInfo.processInfo.environment.merging(environment) { $1 }
		let ctx = CommandContext(environment: env, isProcess: false, secrets: secrets, out: { out.add($0) }, err: { err.add($0) })
		let code: Int32 = await CommandContext.$current.withValue(ctx) {
			ctx.json = argv.prefix { $0 != "--" }.contains("--json")
			do { return try await run(argv) } catch {
				emitError(describe(error))
				return 1
			}
		}
		return Output(exitCode: code, stdout: out.text, stderr: err.text)
	}
}
