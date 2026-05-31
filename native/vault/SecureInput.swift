// Secure Keyboard Entry for the passphrase field (README §"Passphrase-entry
// hardening"). EnableSecureEventInput() asks the window server to stop userland
// event-tap keyloggers from observing keystrokes while it's active. It needs a
// window-server connection, which is why it lives in the app and not the CLI.
// It is bracketed tightly around passphrase entry: enabled while the field is on
// screen, disabled the moment it leaves. It does NOT defend against root / kernel
// / hardware keyloggers, and only covers the typing window.

import AppKit
import Carbon.HIToolbox
import SwiftUI

// Refcount enable/disable so nested/overlapping passphrase fields stay balanced
// (EnableSecureEventInput is itself refcounted by the OS, but we mirror it so a
// view that disappears without appearing can't underflow).
final class SecureInputGuard {
	static let shared = SecureInputGuard()
	private var count = 0

	func acquire() {
		if count == 0 { EnableSecureEventInput() }
		count += 1
	}

	func release() {
		guard count > 0 else { return }
		count -= 1
		if count == 0 { DisableSecureEventInput() }
	}
}

// Attach to any view containing a passphrase field: `.secureKeyboardEntry()`.
private struct SecureKeyboardEntry: ViewModifier {
	func body(content: Content) -> some View {
		content
			.onAppear { SecureInputGuard.shared.acquire() }
			.onDisappear { SecureInputGuard.shared.release() }
	}
}

extension View {
	func secureKeyboardEntry() -> some View { modifier(SecureKeyboardEntry()) }
}
