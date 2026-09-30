import Foundation
import VaultCore

#if !os(Windows)
	import VaultNet
#endif

#if canImport(VaultPlatformDarwin)
	import VaultPlatformDarwin
#elseif canImport(VaultPlatformLinux)
	import VaultPlatformLinux
#elseif canImport(VaultPlatformWindows)
	import VaultPlatformWindows
#endif

#if canImport(Darwin)
	import Darwin
#elseif canImport(Glibc)
	import Glibc
#elseif canImport(Musl)
	import Musl
#endif

// Secrets come only from `--<name>-file` or env, never argv (visible via `ps`).
func readSecretFlag(_ a: ParsedArgs, _ name: String, env: String?) throws -> String? {
	if let file = a.value("\(name)-file") {
		guard let d = FileManager.default.contents(atPath: file) else { throw VaultError.invalidArgument("cannot read \(file)") }
		return String(decoding: d, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
	}
	if let env, let v = envVars()[env], !v.isEmpty { return v }
	return nil
}

func relayAuth(_ a: ParsedArgs) throws -> RelayAuth {
	let env = envVars()
	return RelayAuth(
		token: try readSecretFlag(a, "relay-token", env: "VAULT_RELAY_TOKEN"),
		accessId: a.value("access-id") ?? env["CF_ACCESS_CLIENT_ID"],
		accessSecret: try readSecretFlag(a, "access-secret", env: "CF_ACCESS_CLIENT_SECRET"))
}

func relayInfo(_ a: ParsedArgs) throws -> RelayInfo? {
	guard let url = a.value("relay") else { return nil }
	let au = try relayAuth(a)
	return RelayInfo(url: url, token: au.token, accessId: au.accessId, accessSecret: au.accessSecret)
}

func readToken<T: WireToken>(_ a: ParsedArgs, as: T.Type) throws -> T {
	if let t = a.value("token") { return try T.decode(t) }
	if let f = a.value("token-file") {
		guard let d = FileManager.default.contents(atPath: f) else { throw VaultError.invalidArgument("cannot read \(f)") }
		return try T.decode(String(decoding: d, as: UTF8.self))
	}
	throw VaultError.invalidArgument("provide --token <base64> or --token-file <path>")
}

// `--with-key host|tpm2|auto` picks the systemd-creds binding for a NEW key. It is passed
// to the provider as a parameter, never via setenv: process-global state would leak
// across in-process commands and race with concurrent getenv calls.
func requestedKeyStore(_ a: ParsedArgs) async throws -> PlatformKeyStore? {
	guard a.flag("keychain") else { return nil }
	guard let ks = await Platform.keyStore(named: nil, mode: a.value("with-key")) else {
		throw VaultError.invalidArgument("no OS keystore available here; re-run without --keychain for a passphrase-only vault")
	}
	return ks
}

// Signal sources must outlive the wait (a released source silently stops firing).
nonisolated(unsafe) private var signalSources: [DispatchSourceSignal] = []

// systemd Type=notify: READY=1 once listening, then a WATCHDOG=1 heartbeat at half the
// interval so a hung (not crashed) relay is killed and restarted. No-ops without
// NOTIFY_SOCKET / WATCHDOG_USEC. Uses the `systemd-notify` helper that ships with systemd.
func startSystemdNotify(_ env: [String: String]) -> Task<Void, Never>? {
	guard env["NOTIFY_SOCKET"] != nil else { return nil }
	Task { _ = try? await ProcessRunner.run("systemd-notify", ["READY=1"]) }
	guard let usec = Double(env["WATCHDOG_USEC"] ?? ""), usec > 0 else { return nil }
	return Task {
		while !Task.isCancelled {
			_ = try? await ProcessRunner.run("systemd-notify", ["WATCHDOG=1"])
			try? await Task.sleep(nanoseconds: UInt64(usec * 1000 / 2))
		}
	}
}

func waitForTermination() async {
	#if os(Windows)
		try? await Task.sleep(nanoseconds: .max)
	#else
		signal(SIGINT, SIG_IGN)
		signal(SIGTERM, SIG_IGN)
		await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
			final class Once: @unchecked Sendable { var done = false; let lock = NSLock() }
			let once = Once()
			for sig in [SIGINT, SIGTERM] {
				let src = DispatchSource.makeSignalSource(signal: sig, queue: .global())
				src.setEventHandler {
					once.lock.lock()
					let first = !once.done
					once.done = true
					once.lock.unlock()
					if first { c.resume() }
				}
				src.resume()
				signalSources.append(src)
			}
		}
	#endif
}

// VaultNet (NIO + AsyncHTTPClient) isn't built on Windows; say so rather than "unknown command".
func netUnsupported(_ what: String) -> VaultError {
	VaultError.invalidArgument("vault \(what) is not supported on Windows yet (needs the networking layer)")
}

// Commands beyond the item basics. Returns nil when `command` is not one of them.
func runExtended(_ command: String, _ a: ParsedArgs, _ rest: [String]) async throws -> Int32? {
	switch command {
	case "sync":
		try await withEngine(a) { e in
			// Two transports for the one op log: the always-on hub (primary) and the
			// direct tailnet path (fallback). --tailnet adds peers alongside the hub;
			// --tailnet-only skips the hub (e.g. it is down).
			let env = envVars()
			let tailnetOnly = a.flag("tailnet-only")
			let useTailnet = tailnetOnly || a.flag("tailnet") || env["VAULT_TAILNET"] == "1"
			let saved = try await e.savedRelay()
			let relay = a.value("relay") ?? saved?.url
			if relay == nil && !useTailnet {
				throw VaultError.invalidArgument("usage: vault sync --relay <url> [--relay-token-file <path>] [--access-id <id> --access-secret-file <path>] [--tailnet]\n(no relay saved from enrollment; pass --relay or --tailnet)")
			}
			// Saved coordinates are non-secret defaults; explicit flags/env win.
			var au = try relayAuth(a)
			au.accessId = au.accessId ?? saved?.accessId
			var pulled = 0, pushed = 0
			var notes: [String] = []
			// A sync where EVERY attempted transport failed must exit non-zero, or a
			// cron'd sync could be broken indefinitely while reporting success.
			var attempted = 0, succeeded = 0

			if !tailnetOnly, let relay {
				attempted += 1
				do {
					let st = try await e.syncWithRelay(url: relay, auth: au)
					pulled += st.pulled
					pushed += st.pushed
					succeeded += 1
					notes.append("relay: pulled \(st.pulled), pushed \(st.pushed)")
				} catch {
					// A hub failure is fatal only if the tailnet fallback is not also running.
					if !useTailnet { throw error }
					notes.append("relay: failed (\(error))")
				}
			}

			if useTailnet {
				#if !os(Windows)
				attempted += 1
				let port = Int(a.value("port") ?? env["VAULT_PEER_PORT"] ?? "") ?? Tailnet.defaultPeerPort
				let peerToken = try readSecretFlag(a, "peer-token", env: "VAULT_PEER_TOKEN")
				let allow = a.all("peer") + (env["VAULT_PEER_ALLOW"]?.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } ?? []).filter { !$0.isEmpty }
				if peerToken != nil && allow.isEmpty {
					writeErr("warning: presenting the peer token to ALL online tailnet nodes; set --peer/VAULT_PEER_ALLOW to restrict\n")
				}
				do {
					let status = try await Tailnet.status()
					let r = await Tailnet.sync(e, peers: status.peers, port: port, auth: RelayAuth(token: peerToken), allow: allow)
					pulled += r.pulled
					pushed += r.pushed
					if !r.reached.isEmpty { succeeded += 1 }
					var note = "tailnet: reached \(r.reached.count) peer(s)"
					if !r.failed.isEmpty { note += ", \(r.failed.count) unreachable" }
					notes.append(note)
				} catch {
					if tailnetOnly { throw error }
					notes.append("tailnet: failed (\(error))")
				}
				#else
				throw netUnsupported("sync --tailnet")
				#endif
			}
			if attempted > 0 && succeeded == 0 {
				throw VaultError.invalidArgument("sync failed on all transports — \(notes.joined(separator: "; "))")
			}
			let epoch = try await e.maybeCatchUp()
			var text = "Synced: pulled \(pulled), pushed \(pushed)\n"
			for n in notes { text += "  \(n)\n" }
			if let epoch { text += "Issued security catch-up rotation -> epoch \(epoch)\n" }
			emit(text, [
				JSONMember("pulled", .int(Int64(pulled))), JSONMember("pushed", .int(Int64(pushed))),
				JSONMember("catchUpEpoch", epoch.map { .int(Int64($0)) } ?? .null), JSONMember("notes", .array(notes.map { .string($0) })),
			])
		}

	#if !os(Windows)
	case "relay":
		// The self-hosted relay (spec §15.14): a keyless store-and-forward hub. No vault or
		// passphrase is involved. Configured by env, like the Node relay it replaces.
		let env = envVars()
		let port = Int(a.value("port") ?? env["PORT"] ?? "") ?? RelayServer.defaultPort
		let host = a.value("host") ?? "127.0.0.1"  // reached through the tunnel; --host 0.0.0.0 to expose
		let dbPath = a.value("db") ?? env["RELAY_DB"] ?? "relay.db"
		var access = AccessConfig(
			serviceTokens: Set((env["VAULT_RELAY_TOKENS"] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }),
			teamDomain: env["CF_ACCESS_TEAM_DOMAIN"], audience: env["CF_ACCESS_AUD"],
			requireAccess: ["1", "true"].contains(env["REQUIRE_ACCESS"] ?? ""))
		if access.teamDomain?.isEmpty == true { access.teamDomain = nil }
		if access.audience?.isEmpty == true { access.audience = nil }
		let (server, store) = try await RelayServer.start(dbPath: dbPath, host: host, port: port, access: access)
		emit("relay listening on \(host):\(server.port)\n", [JSONMember("host", .string(host)), JSONMember("port", .int(Int64(server.port)))])
		if !(access.hasControlsPublic) && !access.requireAccess { writeErr("warning: no access controls configured; the relay is open (set VAULT_RELAY_TOKENS / CF_ACCESS_*, or REQUIRE_ACCESS=1)\n") }
		let watchdog = startSystemdNotify(env)
		await waitForTermination()
		watchdog?.cancel()
		await server.stop()
		store.close()

	case "serve":
		// Always-on direct-path replica: a dumb store-and-forward peer that holds no
		// keys and needs no passphrase (ops stay end-to-end encrypted).
		let store = try openStore(a)
		defer { store.close() }
		guard let vaultId = try store.meta("vaultId") else { throw VaultError.notInitialized }
		try store.setBusyTimeout(milliseconds: 5000)
		let env = envVars()
		let port = Int(a.value("port") ?? env["VAULT_PEER_PORT"] ?? "") ?? Tailnet.defaultPeerPort
		let token = try readSecretFlag(a, "peer-token", env: "VAULT_PEER_TOKEN")
		// Bind to this device's tailnet IP by default: reachable over the tailnet (the
		// access gate), not the LAN or a public interface.
		var host = a.value("host")
		if host == nil {
			guard let ip = try await Tailnet.status().selfIP else {
				throw VaultError.invalidArgument("could not determine this device's Tailscale IP (is Tailscale up? pass --host to override)")
			}
			host = ip
		}
		let server = try await PeerServer.start(store: store, vaultId: vaultId, host: host!, port: port, token: token)
		emit("vault peer server listening on \(host!):\(server.port) (vault \(vaultId))\n" + (token == nil ? "warning: no peer token set; open to the whole tailnet\n" : ""),
			[JSONMember("host", .string(host!)), JSONMember("port", .int(Int64(server.port))), JSONMember("vaultId", .string(vaultId)), JSONMember("gated", .bool(token != nil))])
		await waitForTermination()
		await server.stop()

	#else
	case "relay", "serve": throw netUnsupported(command)
	#endif

	case "auth":
		let store = try openStore(a)
		defer { store.close() }
		var pass = try readPassphrase("New passphrase for this device: ")
		defer { SecureBytes.wipe(&pass) }
		let t = try VaultEngine.authNewDevice(store: store, password: pass)
		emit("Token A (show as QR / paste into 'device-add --token'):\n\n\(t.encoded)\n", [JSONMember("tokenA", .string(t.encoded)), JSONMember("deviceId", .string(t.deviceId))])

	case "device-add":
		if a.value("role") != nil { throw VaultError.invalidArgument("device roles come from signed membership; --role is only valid for share") }
		let token = try readToken(a, as: TokenA.self)
		let relay = try relayInfo(a)
		try await withEngine(a) { e in
			let b = try await e.deviceAdd(token, relay: relay)
			let sas = await e.enrollmentSas(newDeviceSignPub: token.signPub)
			emit("Verify SAS matches the new device: \(sas)\n\nToken B (show as QR / paste into 'device-confirm --token'):\n\n\(b.encoded)\n",
				[JSONMember("sas", .string(sas)), JSONMember("tokenB", .string(b.encoded))])
		}

	case "device-confirm":
		let store = try openStore(a)
		defer { store.close() }
		let token = try readToken(a, as: TokenB.self)
		var pass = try readPassphrase()
		defer { SecureBytes.wipe(&pass) }
		let sas = try await VaultEngine.deviceConfirm(store: store, password: pass, token: token, keystore: try await requestedKeyStore(a))
		emit("Enrolled. Verify SAS matches the other device: \(sas)\nRun 'vault sync --relay <url>' to pull history.\n", [JSONMember("sas", .string(sas))])

	case "invite":
		let store = try openStore(a)
		defer { store.close() }
		var pass = try readPassphrase("New passphrase for this device: ")
		defer { SecureBytes.wipe(&pass) }
		let t = try VaultEngine.inviteInit(store: store, password: pass)
		emit("Invite Token (give to a vault admin to run 'share --token'):\n\n\(t.encoded)\n", [JSONMember("inviteToken", .string(t.encoded)), JSONMember("userId", .string(t.userId))])

	case "share":
		let invite = try readToken(a, as: InviteToken.self)
		let relay = try relayInfo(a)
		let role = a.value("role").map { Role(rawValue: $0) } ?? .member
		guard let role else { throw VaultError.invalidArgument("invalid role: \(a.value("role")!) (expected \"member\" or \"admin\")") }
		try await withEngine(a) { e in
			let j = try await e.shareVault(invite, role: role, relay: relay)
			let sas = await e.enrollmentSas(newDeviceSignPub: invite.deviceSignPub)
			emit("Verify SAS matches the joiner: \(sas)\n\nJoin Token (give back to the joiner for 'join --token'):\n\n\(j.encoded)\n",
				[JSONMember("sas", .string(sas)), JSONMember("joinToken", .string(j.encoded))])
		}

	case "join":
		let store = try openStore(a)
		defer { store.close() }
		let token = try readToken(a, as: JoinToken.self)
		var pass = try readPassphrase()
		defer { SecureBytes.wipe(&pass) }
		let r = try await VaultEngine.joinConfirm(store: store, password: pass, token: token, keystore: try await requestedKeyStore(a))
		emit("Joined vault as user \(r.userId). Verify SAS matches the admin: \(r.sas)\nRun 'vault sync --relay <url>' to publish your device and pull history.\n",
			[JSONMember("userId", .string(r.userId)), JSONMember("sas", .string(r.sas))])

	case "recovery-enable":
		try await withEngine(a) { e in
			let k = try await e.recoveryEnable()
			emit("Recovery escrow enabled for this vault.\n\nORG PRIVATE KEY (store offline; anyone holding it can recover members' keys):\n\n\(k)\n\nMembers' identity keys are sealed to the org key on their next sync/enrollment.\n",
				[JSONMember("orgPrivateKey", .string(k))])
		}

	case "recover":
		// The org key decrypts every member's identity keys: never accepted on argv.
		let orgKey = try readSecretFlag(a, "org-key", env: "VAULT_ORG_KEY")
		guard let user = a.value("user"), let orgKey else {
			throw VaultError.invalidArgument("usage: vault recover --user <id> (--org-key-file <path> | VAULT_ORG_KEY=…) [--token <A> | --token-file <path>] [--relay <url>]")
		}
		if a.value("token") != nil || a.value("token-file") != nil {
			// Re-enroll the member on a fresh device (their `vault auth` Token A).
			let token = try readToken(a, as: TokenA.self)
			let relay = try relayInfo(a)
			try await withEngine(a) { e in
				let b = try await e.recoverDevice(user, orgPrivate: orgKey, token: token, relay: relay)
				let sas = await e.enrollmentSas(newDeviceSignPub: token.signPub)
				writeErr("audit: recovery enrolled device \(token.deviceId) for user \(user) at \(ISO8601DateFormatter().string(from: Date()))\n")
				emit("Recovery: verify SAS matches the member's new device: \(sas)\n\nToken B (member runs 'device-confirm --token'):\n\n\(b.encoded)\n\nThen sync so the enrollment reaches the relay, and have the member remove their lost devices.\n",
					[JSONMember("userId", .string(user)), JSONMember("sas", .string(sas)), JSONMember("tokenB", .string(b.encoded))])
			}
			return 0
		}
		try await withEngine(a) { e in
			let r = try await e.recoverUser(user, orgPrivate: orgKey)
			emit("Recovered identity keys for user \(user):\n\n\(r)\n\nDeliver securely to the member so they can re-establish access.\n",
				[JSONMember("userId", .string(user)), JSONMember("recovered", (try? JSONValue.parse(r)) ?? .null)])
		}

	case "keystore":
		let sub = rest.first ?? "status"
		let store = try openStore(a)
		defer { store.close() }
		if sub == "status" {
			let st = try VaultEngine.keystoreStatus(store)
			let platform = await Platform.keyStore(named: nil, mode: a.value("with-key"))
			let vaultLabel = !st.isProtected ? "passphrase-only" : (st.keyMode.map { "\(st.provider!) (--with-key=\($0))" } ?? st.provider!)
			emit("this vault: \(vaultLabel)\nplatform keystore: \(platform?.name ?? "none available")\n", [
				JSONMember("protected", .bool(st.isProtected)), JSONMember("provider", st.provider.map { .string($0) } ?? .null),
				JSONMember("keyMode", st.keyMode.map { .string($0) } ?? .null),
				JSONMember("platformKeystore", platform.map { .string($0.name) } ?? .null),
			])
		} else if sub == "enable" || sub == "disable" {
			var pass = try readPassphrase()
			defer { SecureBytes.wipe(&pass) }
			// Disable needs the CURRENT provider (to read + remove its key).
			let current = try store.meta("keystoreProvider").flatMap { $0.isEmpty ? nil : $0 }
			let persisted = try store.meta("keystoreKeyMode").flatMap { $0.isEmpty ? nil : $0 }
			let ks: PlatformKeyStore?
			// Disable/re-key resolves the CURRENT provider in its persisted binding; enabling
			// on a passphrase-only vault mints a new key in the requested one.
			if let current { ks = await Platform.keyStore(named: current, mode: persisted) } else { ks = await Platform.keyStore(named: nil, mode: a.value("with-key")) }
			let name = try await VaultEngine.setKeystore(store: store, password: pass, enable: sub == "enable", keystore: ks)
			emit("keystore \(sub)d -> \(name)\n", [JSONMember("action", .string(sub)), JSONMember("provider", .string(name))])
		} else {
			throw VaultError.invalidArgument("usage: vault keystore (status | enable | disable)")
		}

	#if !os(Windows)
	case "proxy":
		let files = a.all("config")
		guard !files.isEmpty else {
			throw VaultError.invalidArgument("usage: vault proxy --config <file> [--config <file> ...] [--port <n>] [--connect] [-- <cmd> [args...]]")
		}
		var status: Int32 = 0
		try await withEngine(a) { e in
			status = try await runProxy(e, a, files, rest)
		}
		return status
	#else
	case "proxy": throw netUnsupported(command)
	#endif

	case "run":
		guard let cmd = rest.first else {
			throw VaultError.invalidArgument("usage: vault run [--env f] [--vault n] [--allow-missing] [--mask] -- <cmd> [args...]")
		}
		var status: Int32 = 0
		try await withEngine(a) { e in
			status = try await runChild(e, a, cmd, Array(rest.dropFirst()))
		}
		return status

	default:
		return nil
	}
	return 0
}
