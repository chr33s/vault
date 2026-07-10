// Relay coordinates for sync + enrollment (spec §8). The CLI's sync path needs a
// relay URL: either saved at enrollment (Token B / Join Token carry it) or passed
// explicitly. The app stores them here so a vault created locally (no enrollment
// to carry them) can still sync, and so an authorizer can stamp them into the
// tokens it hands out.
//
// The URL and the Access client id are not secrets and live in UserDefaults. The
// app-layer token and the Cloudflare Access client SECRET are credentials, so
// they are kept in the login Keychain (ThisDeviceOnly, non-synchronizable) rather
// than UserDefaults — a plist flows into Time Machine / unencrypted backups and is
// readable by any same-user process, an exposure the "reachability, not
// confidentiality" rationale does not cover. They still cross to the CLI as
// environment variables (never argv), keeping them out of the process table.

import Combine
import Foundation
import Security

// Minimal generic-password Keychain wrapper for the two relay secrets.
private enum RelayKeychain {
	static let service = "dev.vault.relay"

	@discardableResult
	static func set(_ account: String, _ value: String) -> Bool {
		let base: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account,
		]
		guard !value.isEmpty else {
			let status = SecItemDelete(base as CFDictionary)
			return status == errSecSuccess || status == errSecItemNotFound
		}

		let attributes: [String: Any] = [
			kSecValueData as String: Data(value.utf8),
			// At rest only after first unlock, never synced to iCloud Keychain.
			kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
		]
		let updateStatus = SecItemUpdate(base as CFDictionary, attributes as CFDictionary)
		if updateStatus == errSecSuccess { return true }
		guard updateStatus == errSecItemNotFound else { return false }

		var add = base
		for (key, attribute) in attributes { add[key] = attribute }
		return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
	}

	static func get(_ account: String) -> String {
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account,
			kSecReturnData as String: true,
			kSecMatchLimit as String: kSecMatchLimitOne,
		]
		var out: AnyObject?
		guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
			let data = out as? Data,
			let value = String(data: data, encoding: .utf8)
		else { return "" }
		return value
	}
}

@MainActor
final class RelaySettings: ObservableObject {
	@Published var url: String { didSet { UserDefaults.standard.set(url, forKey: "relay.url") } }
	@Published var token: String { didSet { RelayKeychain.set("relay.token", token) } }
	@Published var accessId: String {
		didSet { UserDefaults.standard.set(accessId, forKey: "relay.accessId") }
	}
	@Published var accessSecret: String {
		didSet { RelayKeychain.set("relay.accessSecret", accessSecret) }
	}

	init() {
		let d = UserDefaults.standard
		url = d.string(forKey: "relay.url") ?? ""
		accessId = d.string(forKey: "relay.accessId") ?? ""
		token = Self.loadCredential("relay.token", defaults: d)
		accessSecret = Self.loadCredential("relay.accessSecret", defaults: d)
	}

	private static func loadCredential(_ account: String, defaults: UserDefaults) -> String {
		let stored = RelayKeychain.get(account)
		if !stored.isEmpty {
			// A successful earlier migration may have been interrupted before cleanup.
			defaults.removeObject(forKey: account)
			return stored
		}

		guard let legacy = defaults.string(forKey: account), !legacy.isEmpty else {
			defaults.removeObject(forKey: account)
			return ""
		}
		guard RelayKeychain.set(account, legacy) else {
			// Keep both the working in-memory value and the legacy fallback if Keychain
			// access is temporarily unavailable; retry migration on the next launch.
			return legacy
		}
		defaults.removeObject(forKey: account)
		return legacy
	}

	private var trimmedURL: String { url.trimmingCharacters(in: .whitespacesAndNewlines) }

	var isConfigured: Bool { !trimmedURL.isEmpty }

	// argv portion: just the (non-secret) URL.
	var urlArgs: [String] { isConfigured ? ["--relay", trimmedURL] : [] }

	// Credentials, passed via env so they never touch argv / the process table.
	var credentialEnv: [String: String] {
		var e: [String: String] = [:]
		if !token.isEmpty { e["VAULT_RELAY_TOKEN"] = token }
		if !accessId.isEmpty { e["CF_ACCESS_CLIENT_ID"] = accessId }
		if !accessSecret.isEmpty { e["CF_ACCESS_CLIENT_SECRET"] = accessSecret }
		return e
	}
}
