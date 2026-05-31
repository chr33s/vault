// Vault creation + relay settings (locked-state setup). Vault creation runs the
// CLI's `init` (optionally with the OS keystore second factor); relay settings
// persist the §8 hub coordinates so a locally-created vault can still sync.

import SwiftUI

// Create a brand-new personal vault (a team-of-one, spec §1) under a local name.
struct CreateVaultView: View {
	@EnvironmentObject private var state: AppState
	@Environment(\.dismiss) private var dismiss

	@State private var name = "personal"
	@State private var passphrase = ""
	@State private var confirm = ""
	@State private var useKeychain = true

	private var canCreate: Bool {
		!name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !passphrase.isEmpty
			&& passphrase == confirm
	}

	var body: some View {
		VStack(alignment: .leading, spacing: 12) {
			Text("Create a vault").font(.headline)
			TextField("Local vault name", text: $name).textFieldStyle(.roundedBorder)
			SecureField("Passphrase", text: $passphrase)
				.textFieldStyle(.roundedBorder).secureKeyboardEntry()
			SecureField("Confirm passphrase", text: $confirm)
				.textFieldStyle(.roundedBorder).secureKeyboardEntry()
			if !confirm.isEmpty && passphrase != confirm {
				Text("Passphrases don't match").font(.caption).foregroundStyle(.red)
			}
			Toggle("Protect with Touch ID / keychain", isOn: $useKeychain)
			Text("Touch ID adds a hardware second factor so a stolen disk can't be brute-forced.")
				.font(.caption).foregroundStyle(.secondary)
			if let error = state.errorMessage {
				Text(error).foregroundStyle(.red).font(.caption)
			}
			HStack {
				Spacer()
				Button("Cancel") { dismiss() }
				Button("Create") {
					let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
					let p = passphrase
					let k = useKeychain
					Task {
						await state.createVault(name: n, passphrase: p, useKeychain: k)
						if state.phase == .unlocked { dismiss() }
					}
				}
				.keyboardShortcut(.defaultAction)
				.disabled(!canCreate)
			}
		}
		.padding(20)
		.frame(width: 380)
	}
}

// The §8 relay coordinates used for sync and stamped into enrollment tokens.
struct RelaySettingsView: View {
	@Environment(\.dismiss) private var dismiss
	@ObservedObject var settings: RelaySettings

	var body: some View {
		VStack(alignment: .leading, spacing: 12) {
			Text("Relay settings").font(.headline)
			Text("The always-on hub used to sync (spec §8). The URL is not secret; the tokens gate reachability.")
				.font(.caption).foregroundStyle(.secondary)
			TextField("Relay URL (https://…)", text: $settings.url).textFieldStyle(.roundedBorder)
			SecureField("App-layer relay token (optional)", text: $settings.token)
				.textFieldStyle(.roundedBorder)
			TextField("Cloudflare Access client ID (optional)", text: $settings.accessId)
				.textFieldStyle(.roundedBorder)
			SecureField("Cloudflare Access client secret (optional)", text: $settings.accessSecret)
				.textFieldStyle(.roundedBorder)
			HStack {
				Spacer()
				Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
			}
		}
		.padding(20)
		.frame(width: 420)
	}
}
