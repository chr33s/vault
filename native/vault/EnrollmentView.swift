// Device enrollment (plan §9). Two roles, both driven entirely through the CLI:
//
//   • This is a NEW device  → run `auth`, show Token A as a QR for an enrolled
//     device to scan; then scan/paste the returned Token B and run `device-confirm`.
//   • This authorizes a device → scan/paste the new device's Token A, run
//     `device-add`, show Token B as a QR (plus the SAS to verify aloud).
//
// QR rendering is CoreImage; scanning is the camera (AVFoundation) with a paste
// fallback (ScanOrPaste). The new-device role is reachable from the locked state
// (a fresh device has no vault to unlock); the authorize role from the unlocked
// workspace.

import SwiftUI

struct EnrollmentView: View {
	@Environment(\.dismiss) private var dismiss

	enum Role: String, CaseIterable, Identifiable {
		case newDevice = "This is a new device"
		case authorize = "Authorize a new device"
		var id: String { rawValue }
	}

	let initialRole: Role
	let allowRoleSwitch: Bool

	init(initialRole: Role = .newDevice, allowRoleSwitch: Bool = true) {
		self.initialRole = initialRole
		self.allowRoleSwitch = allowRoleSwitch
		_role = State(initialValue: initialRole)
	}

	@State private var role: Role

	var body: some View {
		VStack(spacing: 16) {
			if allowRoleSwitch {
				Picker("", selection: $role) {
					ForEach(Role.allCases) { Text($0.rawValue).tag($0) }
				}
				.pickerStyle(.segmented)
				.labelsHidden()
			} else {
				Text(role.rawValue).font(.headline)
			}

			switch role {
			case .newDevice: NewDeviceFlow()
			case .authorize: AuthorizeFlow()
			}

			Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
		}
		.padding(20)
		.frame(width: 460, height: 600)
	}
}

// New device: set passphrase → announce (Token A QR) → scan Token B → confirm.
private struct NewDeviceFlow: View {
	@EnvironmentObject private var state: AppState
	@Environment(\.dismiss) private var dismiss
	@State private var passphrase = ""
	@State private var vaultName = ""
	@State private var useKeychain = true
	@State private var tokenA: String?
	@State private var scanningTokenB = false
	@State private var sas: String?

	var body: some View {
		VStack(spacing: 12) {
			if let sas {
				Label(
					"Enrolled — verify this code matches the other device:", systemImage: "checkmark.seal")
				Text(sas).font(.system(.title, design: .monospaced)).bold()
				Button("Open vault") {
					Task {
						await state.completeEnrollment()
						dismiss()
					}
				}
				.keyboardShortcut(.defaultAction)
			} else if scanningTokenB {
				ScanOrPaste(prompt: "Scan or paste Token B from the authorizing device") { value in
					Task {
						sas = await state.confirmDevice(tokenB: value, useKeychain: useKeychain)
						scanningTokenB = false
					}
				}
			} else if let tokenA {
				Text("Show this to an enrolled device (Token A)")
				TokenQRView(token: tokenA)
				Button("I've shown it — scan Token B") { scanningTokenB = true }
					.keyboardShortcut(.defaultAction)
			} else {
				Text("Set up this new device").font(.headline)
				TextField("Local vault name (default: personal)", text: $vaultName)
					.textFieldStyle(.roundedBorder)
				SecureField("New passphrase for this device", text: $passphrase)
					.textFieldStyle(.roundedBorder)
					.secureKeyboardEntry()
				Toggle("Protect with Touch ID / keychain", isOn: $useKeychain)
				Button("Generate Token A") {
					let candidate = passphrase
					let name = vaultName.trimmingCharacters(in: .whitespacesAndNewlines)
					Task {
						tokenA = await state.startNewDeviceEnrollment(
							vault: name.isEmpty ? nil : name, passphrase: candidate)
					}
				}
				.disabled(passphrase.isEmpty)
			}
			if let error = state.errorMessage {
				Text(error).foregroundStyle(.red).font(.caption)
			}
		}
	}
}

// Authorizer: scan/paste Token A → device-add → show Token B QR + SAS.
private struct AuthorizeFlow: View {
	@EnvironmentObject private var state: AppState
	@State private var result: (sas: String, tokenB: String)?

	var body: some View {
		VStack(spacing: 12) {
			if let result {
				Label("Verify this code matches the new device:", systemImage: "checkmark.seal")
				Text(result.sas).font(.system(.title2, design: .monospaced)).bold()
				Text("Then have it scan Token B:")
				TokenQRView(token: result.tokenB)
			} else {
				ScanOrPaste(prompt: "Scan or paste the new device's Token A") { value in
					Task { result = await state.authorizeDevice(tokenA: value) }
				}
				if !state.relay.isConfigured {
					Label(
						"No relay configured — Token B won't carry sync coordinates.",
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
