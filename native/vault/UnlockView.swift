// Passphrase unlock + locked-state setup. Secure Keyboard Entry is on while this
// view is shown. For a Secure-Enclave-protected vault the CLI additionally raises
// a Touch ID prompt (via vault-helper) the moment we run the verifying `list` — so
// unlock is passphrase + biometric without this view knowing the difference.
//
// A fresh device has no vault to unlock, so the setup actions (create / enroll as
// a new device / join a shared vault / relay settings) must be reachable from
// here — not only from the unlocked workspace.

import SwiftUI

struct UnlockView: View {
	@EnvironmentObject private var state: AppState
	@State private var passphrase = ""

	private enum Sheet: String, Identifiable {
		case create, enroll, join, relay
		var id: String { rawValue }
	}
	@State private var sheet: Sheet?

	var body: some View {
		VStack(spacing: 16) {
			Image(systemName: "lock.shield")
				.font(.system(size: 48))
				.foregroundStyle(.tint)
			Text("Unlock your vault").font(.title2).bold()

			if !state.vaults.isEmpty {
				Picker("Vault", selection: vaultBinding) {
					ForEach(state.vaults, id: \.self) { Text($0).tag($0) }
				}
				.frame(maxWidth: 320)
			}

			SecureField("Passphrase", text: $passphrase)
				.textFieldStyle(.roundedBorder)
				.frame(maxWidth: 320)
				.onSubmit(unlock)
				.disabled(state.phase == .unlocking || state.vaults.isEmpty)

			if let error = state.errorMessage {
				Text(error).foregroundStyle(.red).font(.callout)
			}

			Button(action: unlock) {
				if state.phase == .unlocking {
					ProgressView().controlSize(.small)
				} else {
					Text("Unlock")
				}
			}
			.keyboardShortcut(.defaultAction)
			.disabled(passphrase.isEmpty || state.phase == .unlocking || state.vaults.isEmpty)

			if state.vaults.isEmpty {
				Text("No vaults on this device yet — create one or set it up as a new device.")
					.font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
			}

			Menu("Set up…") {
				Button("Create a new vault…") { sheet = .create }
				Button("Set up this device for an existing vault…") { sheet = .enroll }
				Button("Join a shared vault…") { sheet = .join }
				Divider()
				Button("Relay settings…") { sheet = .relay }
			}
			.frame(maxWidth: 220)
		}
		.padding(40)
		.secureKeyboardEntry()
		.sheet(item: $sheet) { which in
			switch which {
			case .create: CreateVaultView()
			case .enroll: EnrollmentView(initialRole: .newDevice, allowRoleSwitch: false)
			case .join: SharingView(role: .join)
			case .relay: RelaySettingsView(settings: state.relay)
			}
		}
	}

	private var vaultBinding: Binding<String> {
		Binding(
			get: { state.selectedVault ?? state.vaults.first ?? "" },
			set: { state.select(vault: $0) }
		)
	}

	private func unlock() {
		let candidate = passphrase
		Task { await state.unlock(passphrase: candidate) }
	}
}
