// Relay coordinates for sync + enrollment (spec §8). The CLI's sync path needs a
// relay URL: either saved at enrollment (Token B / Join Token carry it) or passed
// explicitly. The app stores them here so a vault created locally (no enrollment
// to carry them) can still sync, and so an authorizer can stamp them into the
// tokens it hands out.
//
// The URL is not secret and rides argv (--relay). The app-layer token and the
// Cloudflare Access service token ARE credentials, so they cross to the CLI as
// environment variables (the CLI reads VAULT_RELAY_TOKEN / CF_ACCESS_CLIENT_ID /
// CF_ACCESS_CLIENT_SECRET as fallbacks) rather than argv, keeping them out of the
// process table. They gate reachability/metadata, not confidentiality (§8.3), so
// UserDefaults at-rest is acceptable under this app's threat model.

import Combine
import Foundation

@MainActor
final class RelaySettings: ObservableObject {
	@Published var url: String { didSet { persist("relay.url", url) } }
	@Published var token: String { didSet { persist("relay.token", token) } }
	@Published var accessId: String { didSet { persist("relay.accessId", accessId) } }
	@Published var accessSecret: String { didSet { persist("relay.accessSecret", accessSecret) } }

	init() {
		let d = UserDefaults.standard
		url = d.string(forKey: "relay.url") ?? ""
		token = d.string(forKey: "relay.token") ?? ""
		accessId = d.string(forKey: "relay.accessId") ?? ""
		accessSecret = d.string(forKey: "relay.accessSecret") ?? ""
	}

	private func persist(_ key: String, _ value: String) { UserDefaults.standard.set(value, forKey: key) }

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
