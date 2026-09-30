import Foundation
import VaultCore

// OS config-dir resolution: VAULT_HOME, XDG_CONFIG_HOME, then
// platform defaults. Each vault is an independent replica at <config>/vaults/<name>.db.

let defaultVault = "personal"

func configDir() -> String { VaultPaths.configDir(environment: envVars()) }

// The config tree holds the encrypted replica and cleartext membership metadata:
// restrict it to the owner so another local user cannot copy it for offline attack.
private func ensureDir700(_ path: String) throws {
	try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
	try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: path)
}

private func vaultsDir() throws -> String {
	let cfg = configDir()
	try ensureDir700(cfg)
	let dir = (cfg as NSString).appendingPathComponent("vaults")
	try ensureDir700(dir)
	return dir
}

private func safeName(_ name: String) throws -> String {
	guard !name.isEmpty, name.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) || ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "." || $0 == "_" || $0 == "-" }) else {
		throw VaultError.invalidArgument("invalid vault name: \(name)")
	}
	return name
}

func dbPath(_ name: String = defaultVault) throws -> String {
	(try vaultsDir() as NSString).appendingPathComponent("\(try safeName(name)).db")
}

func listVaultNames() throws -> [String] {
	try FileManager.default.contentsOfDirectory(atPath: try vaultsDir()).filter { $0.hasSuffix(".db") }
		.map { String($0.dropLast(3)) }.sorted()
}
