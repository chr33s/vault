// The app's single source of truth. It is deliberately thin: it shells every
// action out to the CLI and caches only what the UI shows. The account passphrase
// is held in memory for the session and re-supplied to each (stateless) CLI
// invocation — the documented wrapper tradeoff (a compromised-while-unlocked host
// is out of the threat model). For Secure-Enclave-protected vaults the CLI also
// triggers a Touch ID prompt per command via vault-helper.

import Combine
import Foundation
import SwiftUI

@MainActor
final class AppState: ObservableObject {
	enum Phase: Equatable {
		case locked
		case unlocking
		case unlocked
	}

	@Published var phase: Phase = .locked
	@Published var items: [ItemSummary] = []
	@Published var errorMessage: String?
	@Published var syncStatus: String = "not synced"
	@Published var vaults: [String] = []
	@Published var selectedVault: String?  // nil → the CLI default ("personal")

	let relay: RelaySettings
	private let cli: VaultCLI
	private var passphrase: String = ""  // session-only; cleared on lock

	init(cli: VaultCLI? = nil, relay: RelaySettings? = nil) {
		self.cli = cli ?? .bundled()
		self.relay = relay ?? RelaySettings()
	}

	// Each CLI run that needs the account key re-supplies the cached passphrase.
	private func passphrases(extra: [String] = []) -> [String] { [passphrase] + extra }

	// Point the (stateless) CLI at a specific local vault before the next call.
	func select(vault name: String?) {
		selectedVault = name
		cli.vaultName = name
	}

	func loadVaults() async {
		do {
			vaults = try await cli.run(["vaults"], as: VaultsResponse.self).vaults
			if selectedVault == nil, let first = vaults.first { select(vault: first) }
		} catch {
			vaults = []
			// `vault vaults` returns {vaults:[]} for an empty-but-healthy state, so a
			// thrown error here is not "no vaults yet" — it's a spawn/exec failure
			// (missing or non-executable CLI binary) or unparseable output. Surface it
			// instead of masquerading as an empty device, which would leave the user
			// staring at a disabled "create a vault" screen with no diagnostic.
			errorMessage =
				(error as? CLIError)?.message
				?? "could not run the vault CLI: \(error.localizedDescription)"
		}
	}

	// Verify the passphrase by listing items; cache it only on success.
	func unlock(passphrase candidate: String) async {
		phase = .unlocking
		errorMessage = nil
		do {
			let list = try await cli.run(["list"], passphrases: [candidate], as: ListResponse.self)
			passphrase = candidate
			items = list.items
			phase = .unlocked
		} catch {
			passphrase = ""
			phase = .locked
			errorMessage = (error as? CLIError)?.message ?? error.localizedDescription
		}
	}

	func lock() {
		passphrase = ""
		items = []
		phase = .locked
	}

	// Mark a freshly created vault as the unlocked session.
	private func enterUnlocked(passphrase pass: String) async {
		passphrase = pass
		phase = .unlocked
		await loadVaults()
		await refresh()
	}

	// Flip to the unlocked workspace after an enrollment/join whose SAS the user has
	// already verified. Called from the flow's "Open vault" action (not inside the
	// confirm call) so the SAS screen isn't torn down before it's read — the
	// passphrase was cached during the auth/invite step.
	func completeEnrollment() async {
		phase = .unlocked
		await loadVaults()
		await refresh()
	}

	// ---- vault lifecycle ----

	// Create a brand-new vault (a personal team-of-one) under a local name, with an
	// optional OS keystore second factor (Secure Enclave / keychain).
	func createVault(name: String, passphrase pass: String, useKeychain: Bool) async {
		phase = .unlocking
		errorMessage = nil
		let previous = selectedVault
		select(vault: name)
		do {
			_ = try await cli.run(
				["init"] + (useKeychain ? ["--keychain"] : []), passphrases: [pass], as: InitResponse.self)
			await enterUnlocked(passphrase: pass)
		} catch {
			// Roll back the optimistic selection: the vault was never created, so
			// leaving it selected would point every later unlock at a nonexistent
			// vault while the picker appears to show a real one.
			select(vault: previous)
			phase = .locked
			report(error)
		}
	}

	func refresh() async {
		do {
			items = try await cli.run(["list"], passphrases: passphrases(), as: ListResponse.self).items
		} catch {
			report(error)
		}
	}

	func detail(for title: String) async -> ItemDetail? {
		do {
			// `--` terminates option parsing so a title like "--json" or "--vault" is
			// treated as a positional, never spliced in as a flag.
			return try await cli.run(["get", "--", title], passphrases: passphrases(), as: ItemDetail.self)
		} catch {
			report(error)
			return nil
		}
	}

	func add(title: String, fields: [String: String], password: String?) async {
		// Field values may hold secrets (PINs, security answers) and titles are
		// attacker-influenced, so keep field VALUES off argv (over stdin via
		// --field-stdin) and put the title after `--` so it can't be read as a flag.
		var args = ["add"]
		var extra: [String] = []
		let fieldLines = fields.map { "\($0.key)=\($0.value)" }
		if !fieldLines.isEmpty {
			args += ["--field-stdin", String(fieldLines.count)]
			extra += fieldLines
		}
		if let password, !password.isEmpty {
			args.append("--password")
			extra.append(password)  // item password is a further stdin line
		}
		args += ["--", title]
		do {
			try await cli.run(args, passphrases: passphrases(extra: extra))
			await refresh()
		} catch {
			report(error)
		}
	}

	func edit(title: String, fields: [String: String]) async {
		var args = ["edit"]
		var extra: [String] = []
		let fieldLines = fields.map { "\($0.key)=\($0.value)" }
		if !fieldLines.isEmpty {
			args += ["--field-stdin", String(fieldLines.count)]
			extra += fieldLines
		}
		args += ["--", title]
		do {
			try await cli.run(args, passphrases: passphrases(extra: extra))
			await refresh()
		} catch {
			report(error)
		}
	}

	func remove(title: String) async {
		do {
			try await cli.run(["rm", "--", title], passphrases: passphrases())
			await refresh()
		} catch {
			report(error)
		}
	}

	func sync() async {
		guard relay.isConfigured else {
			syncStatus = "no relay configured"
			errorMessage = "Set a relay URL in Relay settings to sync."
			return
		}
		syncStatus = "syncing…"
		do {
			let r = try await cli.run(
				["sync"] + relay.urlArgs, passphrases: passphrases(), extraEnv: relay.credentialEnv,
				as: SyncResponse.self)
			var msg = "pulled \(r.pulled), pushed \(r.pushed)"
			if let epoch = r.catchUpEpoch { msg += " · catch-up rotation → epoch \(epoch)" }
			syncStatus = msg
			await refresh()
		} catch {
			syncStatus = "sync failed"
			report(error)
		}
	}

	// Turn on the OS keystore second factor for the currently unlocked vault.
	func enableKeystore() async -> String? {
		do {
			struct R: Decodable { let provider: String }
			let r = try await cli.run(["keystore", "enable"], passphrases: passphrases(), as: R.self)
			return r.provider
		} catch {
			report(error)
			return nil
		}
	}

	// ---- device enrollment (plan §9 token handshake) ----

	// This device announces itself into a (possibly new) local vault: returns Token
	// A (base64) to render as a QR. The passphrase is cached for the later confirm.
	func startNewDeviceEnrollment(vault name: String?, passphrase candidate: String) async -> String? {
		let previous = selectedVault
		select(vault: name)
		do {
			let r = try await cli.run(["auth"], passphrases: [candidate], as: AuthResponse.self)
			passphrase = candidate
			return r.tokenA
		} catch {
			select(vault: previous)  // undo the optimistic selection on failure
			report(error)
			return nil
		}
	}

	// An already-enrolled device authorizes a scanned Token A, yielding Token B + SAS.
	// Relay coordinates are stamped into Token B so the new device can sync.
	func authorizeDevice(tokenA: String) async -> (sas: String, tokenB: String)? {
		do {
			let r = try await cli.run(
				["device-add", "--token", tokenA] + relay.urlArgs, passphrases: passphrases(),
				extraEnv: relay.credentialEnv, as: AddDeviceResponse.self)
			return (r.sas, r.tokenB)
		} catch {
			report(error)
			return nil
		}
	}

	// The new device confirms a scanned Token B and builds its replica. Returns the
	// SAS to verify; the caller flips to the workspace via completeEnrollment() once
	// the user has compared it.
	func confirmDevice(tokenB: String, useKeychain: Bool) async -> String? {
		do {
			let r = try await cli.run(
				["device-confirm", "--token", tokenB] + (useKeychain ? ["--keychain"] : []),
				passphrases: passphrases(), as: ConfirmResponse.self)
			return r.sas
		} catch {
			report(error)
			return nil
		}
	}

	// ---- sharing with other people (spec §5; invite/share/join) ----

	// Joiner side, step 1: generate this person's identity into a local vault slot
	// and emit an Invite Token to hand to an admin. Caches the new passphrase.
	func startInvite(vault name: String?, passphrase candidate: String) async -> String? {
		let previous = selectedVault
		select(vault: name)
		do {
			let r = try await cli.run(["invite"], passphrases: [candidate], as: InviteResponse.self)
			passphrase = candidate
			return r.inviteToken
		} catch {
			select(vault: previous)  // undo the optimistic selection on failure
			report(error)
			return nil
		}
	}

	// Admin side: scan a joiner's Invite Token, add them, and emit a Join Token
	// (with relay coordinates) plus a SAS to verify aloud.
	func shareVault(inviteToken: String) async -> (sas: String, joinToken: String)? {
		do {
			let r = try await cli.run(
				["share", "--token", inviteToken] + relay.urlArgs, passphrases: passphrases(),
				extraEnv: relay.credentialEnv, as: ShareResponse.self)
			return (r.sas, r.joinToken)
		} catch {
			report(error)
			return nil
		}
	}

	// Joiner side, step 2: confirm a scanned Join Token and build the replica.
	// Returns the SAS; completeEnrollment() flips to the workspace afterward.
	func confirmJoin(joinToken: String, useKeychain: Bool) async -> String? {
		do {
			let r = try await cli.run(
				["join", "--token", joinToken] + (useKeychain ? ["--keychain"] : []),
				passphrases: passphrases(), as: JoinResponse.self)
			return r.sas
		} catch {
			report(error)
			return nil
		}
	}

	private func report(_ error: Error) {
		errorMessage = (error as? CLIError)?.message ?? error.localizedDescription
	}
}
