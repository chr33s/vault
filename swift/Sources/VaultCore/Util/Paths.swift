import Foundation

public enum VaultPaths {
	// OS config-dir resolution: VAULT_HOME, XDG_CONFIG_HOME, then
	// platform defaults.
	public static func configDir(environment env: [String: String] = ProcessInfo.processInfo.environment) -> String {
		if let o = env["VAULT_HOME"], !o.isEmpty { return o }
		if let x = env["XDG_CONFIG_HOME"], !x.isEmpty { return (x as NSString).appendingPathComponent("vault") }
		let home = NSHomeDirectory()
		#if os(macOS)
			return home + "/Library/Application Support/vault"
		#elseif os(Windows)
			return ((env["APPDATA"] ?? home + "\\AppData\\Roaming") as NSString).appendingPathComponent("vault")
		#else
			return home + "/.config/vault"
		#endif
	}
}
