// The unlocked workspace: a sidebar list of items, a detail/edit pane, a sync
// status line, and sheets for the enrollment handshake, people sharing, and relay
// settings. The current vault name is shown with a switch action (which re-locks,
// since each vault has its own passphrase).

import SwiftUI

struct VaultMainView: View {
	@EnvironmentObject private var state: AppState
	@State private var selection: String?
	@State private var showAdd = false

	private enum Sheet: String, Identifiable {
		case enroll, addPerson, relay
		var id: String { rawValue }
	}
	@State private var sheet: Sheet?
	@State private var keystoreNote: String?

	var body: some View {
		NavigationSplitView {
			List(state.items, selection: $selection) { item in
				Text(item.displayTitle).tag(item.displayTitle)
			}
			.navigationTitle(state.selectedVault ?? "Vault")
			.toolbar {
				ToolbarItemGroup {
					Button { showAdd = true } label: { Image(systemName: "plus") }
						.help("Add item")
					Menu {
						Button("Authorize a new device…") { sheet = .enroll }
						Button("Add a person to this vault…") { sheet = .addPerson }
						Divider()
						Button("Enable Touch ID / keychain") {
							Task {
								if let p = await state.enableKeystore() { keystoreNote = "keystore enabled → \(p)" }
							}
						}
						Button("Relay settings…") { sheet = .relay }
						Divider()
						Button("Switch vault / lock") { state.lock() }
					} label: {
						Image(systemName: "ellipsis.circle")
					}
					Button { state.lock() } label: { Image(systemName: "lock") }
						.help("Lock")
				}
			}
		} detail: {
			if let selection {
				ItemDetailView(title: selection)
					.id(selection)
			} else {
				ContentUnavailableView("Select an item", systemImage: "key")
			}
		}
		.safeAreaInset(edge: .bottom) { SyncStatusBar(keystoreNote: keystoreNote) }
		.sheet(isPresented: $showAdd) { AddItemView() }
		.sheet(item: $sheet) { which in
			switch which {
			case .enroll: EnrollmentView(initialRole: .authorize, allowRoleSwitch: false)
			case .addPerson: SharingView(role: .addPerson)
			case .relay: RelaySettingsView(settings: state.relay)
			}
		}
		.task { await state.refresh() }
	}
}

struct SyncStatusBar: View {
	@EnvironmentObject private var state: AppState
	let keystoreNote: String?

	var body: some View {
		HStack {
			Image(systemName: "arrow.triangle.2.circlepath")
			Text(keystoreNote ?? state.syncStatus).font(.callout).foregroundStyle(.secondary)
			Spacer()
			if let error = state.errorMessage {
				Text(error).font(.callout).foregroundStyle(.red).lineLimit(1)
			}
			Button("Sync") { Task { await state.sync() } }
		}
		.padding(.horizontal, 12)
		.padding(.vertical, 8)
		.background(.bar)
	}
}

struct ItemDetailView: View {
	@EnvironmentObject private var state: AppState
	let title: String

	@State private var detail: ItemDetail?
	@State private var revealPassword = false
	@State private var showEdit = false

	var body: some View {
		Group {
			if let detail {
				loaded(detail)
			} else {
				ProgressView()
			}
		}
		.task { detail = await state.detail(for: title) }
	}

	@ViewBuilder
	private func loaded(_ detail: ItemDetail) -> some View {
		Form {
			Section("Fields") {
				ForEach(detail.fields.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
					LabeledContent(k, value: v)
				}
			}
			if !detail.passwords.isEmpty {
				passwordSection(detail.passwords)
			}
		}
		.formStyle(.grouped)
		.navigationTitle(detail.title)
		.toolbar {
			Button { showEdit = true } label: { Image(systemName: "pencil") }
				.help("Edit fields")
			Button(role: .destructive) {
				Task { await state.remove(title: title) }
			} label: {
				Image(systemName: "trash")
			}
		}
		.sheet(isPresented: $showEdit) {
			EditItemView(title: detail.title, fields: detail.fields) {
				self.detail = await state.detail(for: title)
			}
		}
	}

	@ViewBuilder
	private func passwordSection(_ passwords: [String]) -> some View {
		Section(passwords.count > 1 ? "Password (conflicting!)" : "Password") {
			ForEach(Array(passwords.enumerated()), id: \.offset) { _, pw in
				HStack {
					// Fixed-width mask: never encode the true length (a screenshot /
					// shoulder-surf of the dots would otherwise narrow a brute-force).
					Text(revealPassword ? pw : "••••••••••")
						.font(.system(.body, design: .monospaced))
					Spacer()
					Button(revealPassword ? "Hide" : "Reveal") { revealPassword.toggle() }
				}
			}
		}
	}
}

// Edit an item's non-password fields. Password is a multi-value register handled
// at add time (and surfaced for conflict resolution), so it isn't edited here.
struct EditItemView: View {
	@EnvironmentObject private var state: AppState
	@Environment(\.dismiss) private var dismiss

	let title: String
	@State private var rows: [(key: String, value: String)]
	@State private var newKey = ""
	@State private var newValue = ""
	let onSaved: () async -> Void

	init(title: String, fields: [String: String], onSaved: @escaping () async -> Void) {
		self.title = title
		self.onSaved = onSaved
		_rows = State(initialValue: fields.sorted(by: { $0.key < $1.key }).map { ($0.key, $0.value) })
	}

	var body: some View {
		VStack(alignment: .leading, spacing: 12) {
			Text("Edit \(title)").font(.headline)
			ForEach(rows.indices, id: \.self) { i in
				HStack {
					Text(rows[i].key).frame(width: 110, alignment: .leading)
					TextField("value", text: Binding(get: { rows[i].value }, set: { rows[i].value = $0 }))
						.textFieldStyle(.roundedBorder)
				}
			}
			HStack {
				TextField("new field", text: $newKey).frame(width: 110)
				TextField("value", text: $newValue).textFieldStyle(.roundedBorder)
				Button("Add") {
					let k = newKey.trimmingCharacters(in: .whitespacesAndNewlines)
					guard !k.isEmpty else { return }
					rows.append((k, newValue))
					newKey = ""
					newValue = ""
				}
				.disabled(newKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
			}
			HStack {
				Spacer()
				Button("Cancel") { dismiss() }
				Button("Save") {
					let fields = Dictionary(rows.map { ($0.key, $0.value) }, uniquingKeysWith: { _, b in b })
					Task {
						await state.edit(title: title, fields: fields)
						await onSaved()
						dismiss()
					}
				}
				.keyboardShortcut(.defaultAction)
			}
		}
		.padding(20)
		.frame(width: 420)
	}
}

struct AddItemView: View {
	@EnvironmentObject private var state: AppState
	@Environment(\.dismiss) private var dismiss

	@State private var title = ""
	@State private var username = ""
	@State private var password = ""

	var body: some View {
		VStack(alignment: .leading, spacing: 12) {
			Text("New item").font(.headline)
			TextField("Title", text: $title).textFieldStyle(.roundedBorder)
			TextField("Username", text: $username).textFieldStyle(.roundedBorder)
			SecureField("Password", text: $password)
				.textFieldStyle(.roundedBorder)
				.secureKeyboardEntry()
			HStack {
				Spacer()
				Button("Cancel") { dismiss() }
				Button("Add") {
					let fields = username.isEmpty ? [:] : ["username": username]
					Task {
						await state.add(title: title, fields: fields, password: password)
						dismiss()
					}
				}
				.keyboardShortcut(.defaultAction)
				.disabled(title.isEmpty)
			}
		}
		.padding(20)
		.frame(width: 360)
	}
}
