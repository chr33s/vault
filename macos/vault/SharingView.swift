// Sharing a vault with other people (spec §5; invite/share/join). Mirrors device
// enrollment but at the person level:
//
//   • Joiner  → run `invite` (emit an Invite Token), hand it to an admin, then
//     scan/paste the returned Join Token and run `join`. Reachable while locked
//     (the joiner has no vault yet).
//   • Admin   → scan/paste the joiner's Invite Token, run `share`, show the Join
//     Token QR + SAS. Reachable from the unlocked workspace.

import SwiftUI

struct SharingView: View {
	@Environment(\.dismiss) private var dismiss

	enum Role { case join, addPerson }
	let role: Role

	var body: some View {
		VStack(spacing: 16) {
			Text(role == .join ? "Join a shared vault" : "Add a person to this vault")
				.font(.headline)
			switch role {
			case .join: JoinerFlow()
			case .addPerson: AdminFlow()
			}
			Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
		}
		.padding(20)
		.frame(width: 460, height: 600)
	}
}

// Joiner: name a local slot + passphrase → invite token → scan join token → confirm.
private struct JoinerFlow: View {
	@EnvironmentObject private var state: AppState
	@Environment(\.dismiss) private var dismiss
	@State private var vaultName = ""
	@State private var passphrase = ""
	@State private var useKeychain = true
	@State private var inviteToken: String?
	@State private var scanningJoin = false
	@State private var sas: String?

	var body: some View {
		VStack(spacing: 12) {
			if let sas {
				Label("Joined — verify this code matches the admin:", systemImage: "checkmark.seal")
				Text(sas).font(.system(.title, design: .monospaced)).bold()
				Button("Open vault") {
					Task {
						await state.completeEnrollment()
						dismiss()
					}
				}
				.keyboardShortcut(.defaultAction)
			} else if scanningJoin {
				ScanOrPaste(prompt: "Scan or paste the Join Token from the admin") { value in
					Task {
						sas = await state.confirmJoin(joinToken: value, useKeychain: useKeychain)
						scanningJoin = false
					}
				}
			} else if let inviteToken {
				Text("Give this Invite Token to a vault admin")
				TokenQRView(token: inviteToken)
				Button("I've shared it — scan the Join Token") { scanningJoin = true }
					.keyboardShortcut(.defaultAction)
			} else {
				TextField("Local name for this vault", text: $vaultName)
					.textFieldStyle(.roundedBorder)
				SecureField("New passphrase for this device", text: $passphrase)
					.textFieldStyle(.roundedBorder)
					.secureKeyboardEntry()
				Toggle("Protect with Touch ID / keychain", isOn: $useKeychain)
				Button("Generate Invite Token") {
					let name = vaultName.trimmingCharacters(in: .whitespacesAndNewlines)
					let candidate = passphrase
					Task {
						inviteToken = await state.startInvite(
							vault: name.isEmpty ? nil : name, passphrase: candidate)
					}
				}
				.disabled(passphrase.isEmpty || vaultName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
			}
			if let error = state.errorMessage {
				Text(error).foregroundStyle(.red).font(.caption)
			}
		}
	}
}

// Admin: scan/paste an Invite Token → share → show Join Token QR + SAS.
private struct AdminFlow: View {
	@EnvironmentObject private var state: AppState
	@State private var result: (sas: String, joinToken: String)?

	var body: some View {
		VStack(spacing: 12) {
			if let result {
				Label("Verify this code matches the joiner:", systemImage: "checkmark.seal")
				Text(result.sas).font(.system(.title2, design: .monospaced)).bold()
				Text("Then give them the Join Token:")
				TokenQRView(token: result.joinToken)
			} else {
				ScanOrPaste(prompt: "Scan or paste the joiner's Invite Token") { value in
					Task { result = await state.shareVault(inviteToken: value) }
				}
				if !state.relay.isConfigured {
					Label(
						"No relay configured — the Join Token won't carry sync coordinates.",
						systemImage: "exclamationmark.triangle"
					)
					.font(.caption).foregroundStyle(.secondary)
				}
			}
			if let error = state.errorMessage {
				Text(error).foregroundStyle(.red).font(.caption)
			}
		}
	}
}
