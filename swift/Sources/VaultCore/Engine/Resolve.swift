import Foundation

// Resolve `.env` declarations against ambient env and the local replica.
// Reads only the local replica, so it is offline and instant.

extension VaultEngine {
	private func fieldValue(_ item: ItemView, _ field: String) throws -> String? {
		if field == "password" {
			if item.passwords.count == 1 { return item.passwords[0] }
			if item.passwords.isEmpty { return nil }
			throw VaultError.invalidArgument("item \"\(item.title ?? "")\" has \(item.passwords.count) unresolved password values; resolve the conflict first")
		}
		return item.fields[field]
	}

	// Precedence: ambient non-empty -> vault:// ref -> literal -> vault lookup by name.
	public func resolve(_ decl: EnvDecl, openVault: String? = nil, environment: [String: String] = ProcessInfo.processInfo.environment) throws -> String? {
		if let a = environment[decl.key], !a.isEmpty { return a }
		if let v = decl.value, v.hasPrefix("vault://") {
			guard let ref = DotEnv.parseRef(v) else { throw VaultError.invalidArgument("bad vault reference for \(decl.key): \(v)") }
			// A ref to a different vault must fail loudly, not pull a same-named item
			// out of the wrong replica.
			if let open = openVault, ref.vault != open {
				throw VaultError.invalidArgument("\(decl.key): reference targets vault \"\(ref.vault)\" but \"\(open)\" is open — open that vault with --vault \(ref.vault)")
			}
			guard let item = item(title: ref.item) else { return nil }
			return try fieldValue(item, ref.field ?? "password")
		}
		if let v = decl.value, !v.isEmpty { return v }
		guard let item = item(title: decl.key) else { return nil }
		if let named = item.fields[decl.key], !named.isEmpty { return named }
		return try fieldValue(item, "password") ?? item.fields[decl.key]
	}

	public func resolveEnv(envFile: String, openVault: String?) throws -> (env: [(String, String)], missing: [String]) {
		guard let data = FileManager.default.contents(atPath: envFile) else { throw VaultError.invalidArgument("cannot read \(envFile)") }
		var env: [(String, String)] = []
		var missing: [String] = []
		for d in try DotEnv.parse(String(decoding: data, as: UTF8.self)) {
			if let v = try resolve(d, openVault: openVault) { env.append((d.key, v)) } else { missing.append(d.key) }
		}
		return (env, missing)
	}
}
