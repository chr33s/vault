// Vault.app entry point (plan §12a Step 3). A thin SwiftUI shell over the CLI:
// create/unlock vaults → browse/edit items → sync, plus the §9 device-enrollment
// and §5 people-sharing token handshakes (QR rendering + camera scanning) and
// in-app relay settings. No crypto lives here.

import SwiftUI

@main
struct VaultApp: App {
	@StateObject private var state = AppState()

	var body: some Scene {
		MenuBarExtra("Vault", systemImage: "lock.shield") {
			RootView()
				.environmentObject(state)
				.fixedSize()
				.task { await state.loadVaults() }
		}
		.menuBarExtraStyle(.window)
	}
}

struct RootView: View {
	@EnvironmentObject private var state: AppState

	var body: some View {
		switch state.phase {
		case .locked, .unlocking:
			UnlockView()
		case .unlocked:
			VaultMainView()
		}
	}
}
