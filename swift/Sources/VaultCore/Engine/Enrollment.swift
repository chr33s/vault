import Foundation

// Device enrollment, cross-user sharing, recovery escrow and keystore management
//. The token handshakes run before a session exists, so those
// entry points are static and work directly on the store.

extension VaultEngine {
	// MARK: - SAS

	// 6-digit short authentication string over (enroller signing key, new device
	// signing key). The receiving side derives the enroller's key from the signed
	// log entry that admitted it, so a match proves the entry was signed by the
	// device the user is looking at.
	static func sas(_ a: Data, _ b: Data) -> String {
		let h = VaultCrypto.sha256(a + b)
		let n = (UInt32(h[0]) << 24 | UInt32(h[1]) << 16 | UInt32(h[2]) << 8 | UInt32(h[3])) % 1_000_000
		let s = String(n)
		return String(repeating: "0", count: 6 - s.count) + s
	}

	public func enrollmentSas(newDeviceSignPub: String) -> String {
		Self.sas(pub.deviceSign, Data(base64: newDeviceSignPub))
	}

	static func persistRelay(_ store: Store, _ relay: RelayInfo?) throws {
		guard let relay else { return }
		// The meta table is plaintext: never persist bearer secrets.
		try store.setMeta("relayInfo", RelayInfo(url: relay.url, accessId: relay.accessId).json.stringify())
	}

	public static func savedRelay(_ store: Store) throws -> RelayInfo? {
		try store.meta("relayInfo").flatMap { try? JSONValue.parse($0) }.flatMap { RelayInfo(json: $0) }
	}

	private static func proveDevice(_ chain: [LogEntry], userId: String, deviceId: String, signPriv: SecureBytes) throws -> LogEntry {
		try signedEntry(chain, .proveDevice(userId: userId, deviceId: deviceId), signerId: deviceId, kind: .device, priv: signPriv)
	}

	private static func privJSON(_ pairs: [(String, Data)]) -> Data {
		JSONValue.object(pairs.map { JSONMember($0.0, .string($0.1.base64)) }).serialized()
	}

	// MARK: - device enrollment

	// `auth` on the new device: create device keys sealed under the account key and
	// emit Token A. The user identity keys arrive later in Token B.
	public static func authNewDevice(store: Store, password: Data, kdf: KdfParams? = nil) throws -> TokenA {
		guard try !isInitialized(store) else { throw VaultError.invalidArgument("vault already initialized on this device") }
		let params = kdf ?? .defaultParams()
		let derived = try PasswordKDF.deriveKeys(password: password, params: params)
		let sign = VaultCrypto.generateEd25519()
		let enc = VaultCrypto.generateX25519()
		let deviceId = AuthLog.deviceId(ofSignPub: sign.publicKey.base64)
		let blob = try derived.accountKey.withData {
			try VaultCrypto.aeadEncrypt(key: $0, plaintext: privJSON([("deviceSign", sign.privateKey), ("deviceEnc", enc.privateKey)]))
		}
		try store.transaction {
			try store.setMeta("pending", "1")
			try store.setMeta("deviceId", deviceId)
			try store.setMeta("kdfParams", params.json.stringify())
			try store.setMeta("deviceSignPub", sign.publicKey.base64)
			try store.setMeta("deviceEncPub", enc.publicKey.base64)
			try store.setMeta("pendingPriv", VaultCrypto.encodeBox(blob).json.stringify())
		}
		return TokenA(deviceId: deviceId, signPub: sign.publicKey.base64, encPub: enc.publicKey.base64)
	}

	// `device-add` on an authorized device: sign add-device, seal every vault key and
	// the user identity keys to the new device, build Token B.
	public func deviceAdd(_ a: TokenA, relay: RelayInfo? = nil) throws -> TokenB {
		let newEncPub = Data(base64: a.encPub)
		let m = try AuthLog.replay(try store.authLog(), expectedVaultId: vaultId)
		guard let me = AuthLog.activeDeviceMember(m, deviceId), me.userId == userId else {
			throw VaultError.notAuthorized("this device is not authorized to enroll another")
		}
		let chain = try store.authLog()
		try store.appendAuthEntry(
			try Self.signedEntry(
				chain, .addDevice(userId: userId, deviceId: a.deviceId, deviceSignPub: a.signPub, deviceEncPub: a.encPub),
				signerId: deviceId, kind: .device, priv: priv.deviceSign))

		var grants = OrderedMap<String, SealedGrant>()
		for (commit, key) in keys.sorted(by: { jsLess($0.key, $1.key) }) {
			grants[commit] = SealedGrant(try key.withData { try SealedBoxes.seal($0, to: newEncPub) })
		}
		var userPrivJSON = Self.privJSONData([("userSign", priv.userSign), ("userEnc", priv.userEnc)])
		defer { SecureBytes.wipe(&userPrivJSON) }
		let userPriv = SealedGrant(try SealedBoxes.seal(userPrivJSON, to: newEncPub))
		return TokenB(
			vaultId: vaultId, userId: userId, authLog: try store.authLog(), rotations: try loadRotations(),
			epochGrants: grants, userPriv: userPriv, relay: relay)
	}

	static func privJSONData(_ p: [(String, SecureBytes)]) -> Data {
		JSONValue.object(p.map { JSONMember($0.0, .string($0.1.data.base64)) }).serialized()
	}

	// `device-confirm` on the new device. Returns the SAS for mutual verification.
	public static func deviceConfirm(store: Store, password: Data, token: TokenB, keystore: PlatformKeyStore? = nil) async throws -> String {
		guard try store.meta("pending") == "1" else { throw VaultError.invalidArgument("run `vault auth` first on this device") }
		guard let kj = try? JSONValue.parse(try requireMeta(store, "kdfParams")) else { throw VaultError.corrupt("kdfParams") }
		let derived = try PasswordKDF.deriveKeys(password: password, params: try KdfParams(json: kj))
		let deviceId = try requireMeta(store, "deviceId")
		let deviceEncPub = Data(base64: try requireMeta(store, "deviceEncPub"))
		let deviceSignPubB64 = try requireMeta(store, "deviceSignPub")

		var deviceSign = Data(), deviceEnc = Data()
		do {
			guard let bj = try? JSONValue.parse(try requireMeta(store, "pendingPriv")), let box = EncodedBox(json: bj) else { throw VaultError.corrupt("pendingPriv") }
			var pt = try derived.accountKey.withData { try VaultCrypto.aeadDecrypt(key: $0, box: VaultCrypto.decodeBox(box)) }
			defer { SecureBytes.wipe(&pt) }
			let o = try JSONValue.parse(pt)
			deviceSign = Data(base64: o["deviceSign"]?.string ?? "")
			deviceEnc = Data(base64: o["deviceEnc"]?.string ?? "")
		} catch { throw VaultError.incorrectPassphrase }
		defer {
			SecureBytes.wipe(&deviceSign)
			SecureBytes.wipe(&deviceEnc)
		}

		let m = try AuthLog.replay(token.authLog, expectedVaultId: token.vaultId)
		guard m.vaultId == token.vaultId else { throw VaultError.corrupt("auth log vault does not match the enrollment token") }
		guard let owner = m.members[token.userId], owner.active, let enrolled = owner.pendingDevices[deviceId], enrolled.signPub == deviceSignPubB64 else {
			throw VaultError.notAuthorized("auth log does not authorize this device")
		}
		// Derive the SAS ourselves; echoing a token-supplied string would let a forged
		// Token B pick it and defeat the comparison.
		guard let enroller = enrolled.enrolledByDeviceId, let enrollerKey = m.deviceKeys[enroller] else {
			throw VaultError.notAuthorized("auth log does not name the enrolling device")
		}
		let sas = Self.sas(enrollerKey, Data(base64: deviceSignPubB64))

		let up = try JSONValue.parse(try SealedBoxes.unseal(token.userPriv.sealedBox, priv: deviceEnc, pub: deviceEncPub))
		let userSign = Data(base64: up["userSign"]?.string ?? ""), userEnc = Data(base64: up["userEnc"]?.string ?? "")

		let proof = try proveDevice(token.authLog, userId: token.userId, deviceId: deviceId, signPriv: SecureBytes(deviceSign))
		guard AuthLog.activeDeviceMember(try AuthLog.replay(token.authLog + [proof], expectedVaultId: token.vaultId), deviceId) != nil else {
			throw VaultError.notAuthorized("auth log does not authorize this device")
		}

		let (wrap, wm) = try await createWrapKey(derived.accountKey, keystore: keystore)
		let enc = try wrap.withData {
			try sealPriv([("userSign", userSign), ("userEnc", userEnc), ("deviceSign", deviceSign), ("deviceEnc", deviceEnc)], under: $0)
		}
		try store.transaction {
			try store.setMeta("vaultId", token.vaultId)
			try store.setMeta("userId", token.userId)
			try store.setMeta("userSignPub", owner.signPub)
			try store.setMeta("userEncPub", owner.encPub)
			try persistWrapMeta(store, wm)
			try store.setMeta("encPrivKeys", enc)
			for e in token.authLog { try store.appendAuthEntry(e) }
			try store.appendAuthEntry(proof)
			for r in token.rotations { try store.putRotation(epoch: r.epoch, deviceId: r.deviceId, record: r.serialized) }
			try store.setMeta("selfEpochGrants", JSONValue.object(token.epochGrants.map { JSONMember($0.key, $0.value.json) }).stringify())
			try persistRelay(store, token.relay)
			// The pre-enrollment private keys were sealed under the bare account key. Left
			// behind, a brute-forced passphrase would yield them and bypass the keystore
			// second factor that now wraps `encPrivKeys`.
			try store.deleteMeta("pendingPriv")
			try store.setMeta("pending", "0")
		}
		return sas
	}

	static func persistWrapMeta(_ store: Store, _ w: WrapMeta) throws {
		try store.setMeta("keystoreProvider", w.provider)
		try store.setMeta("keystoreId", w.id)
		try store.setMeta("keystoreKeyMode", w.keyMode)
	}

	// MARK: - cross-user sharing

	// `invite` on the joining person's device: fresh user identity + first device.
	public static func inviteInit(store: Store, password: Data, kdf: KdfParams? = nil) throws -> InviteToken {
		guard try !isInitialized(store) else { throw VaultError.invalidArgument("vault already initialized on this device") }
		let params = kdf ?? .defaultParams()
		let derived = try PasswordKDF.deriveKeys(password: password, params: params)
		let us = VaultCrypto.generateEd25519(), ue = VaultCrypto.generateX25519()
		let ds = VaultCrypto.generateEd25519(), de = VaultCrypto.generateX25519()
		let userId = AuthLog.deviceId(ofSignPub: us.publicKey.base64)
		let deviceId = AuthLog.deviceId(ofSignPub: ds.publicKey.base64)
		let sealed = try derived.accountKey.withData {
			try sealPriv([("userSign", us.privateKey), ("userEnc", ue.privateKey), ("deviceSign", ds.privateKey), ("deviceEnc", de.privateKey)], under: $0)
		}
		try store.transaction {
			try store.setMeta("pending", "invite")
			try store.setMeta("kdfParams", params.json.stringify())
			try store.setMeta("userId", userId)
			try store.setMeta("deviceId", deviceId)
			try store.setMeta("userSignPub", us.publicKey.base64)
			try store.setMeta("userEncPub", ue.publicKey.base64)
			try store.setMeta("deviceSignPub", ds.publicKey.base64)
			try store.setMeta("deviceEncPub", de.publicKey.base64)
			try store.setMeta("pendingInvitePriv", sealed)
		}
		return InviteToken(
			userId: userId, userSignPub: us.publicKey.base64, userEncPub: ue.publicKey.base64, deviceId: deviceId,
			deviceSignPub: ds.publicKey.base64, deviceEncPub: de.publicKey.base64)
	}

	// `share` on an admin device: append a signed add-user, seal every epoch key to
	// the joiner's device, build the Join Token.
	public func shareVault(_ invite: InviteToken, role: Role = .member, relay: RelayInfo? = nil) throws -> JoinToken {
		let m = try AuthLog.replay(try store.authLog(), expectedVaultId: vaultId)
		guard Self.isAdminDevice(m, deviceId) else { throw VaultError.notAuthorized("only admins may share a vault") }
		guard role == .member || role == .admin else {
			throw VaultError.invalidArgument("invalid role: \(role.rawValue) (expected \"member\" or \"admin\")")
		}
		let chain = try store.authLog()
		try store.appendAuthEntry(
			try Self.signedEntry(
				chain, .addUser(userId: invite.userId, userSignPub: invite.userSignPub, userEncPub: invite.userEncPub, role: role),
				signerId: deviceId, kind: .device, priv: priv.deviceSign))
		let joinerPub = Data(base64: invite.deviceEncPub)
		var grants = OrderedMap<String, SealedGrant>()
		for (commit, key) in keys.sorted(by: { jsLess($0.key, $1.key) }) {
			grants[commit] = SealedGrant(try key.withData { try SealedBoxes.seal($0, to: joinerPub) })
		}
		return JoinToken(vaultId: vaultId, userId: invite.userId, authLog: try store.authLog(), rotations: try loadRotations(), epochGrants: grants, relay: relay)
	}

	// `join` on the joiner's device: validate, append the joiner's own add-device +
	// proof, persist identity. Returns (userId, SAS).
	public static func joinConfirm(store: Store, password: Data, token: JoinToken, keystore: PlatformKeyStore? = nil) async throws -> (userId: String, sas: String) {
		guard try store.meta("pending") == "invite" else { throw VaultError.invalidArgument("run `vault invite` first on this device") }
		guard let kj = try? JSONValue.parse(try requireMeta(store, "kdfParams")) else { throw VaultError.corrupt("kdfParams") }
		let derived = try PasswordKDF.deriveKeys(password: password, params: try KdfParams(json: kj))
		let userId = try requireMeta(store, "userId")
		let deviceId = try requireMeta(store, "deviceId")
		let deviceSignPub = try requireMeta(store, "deviceSignPub")
		let deviceEncPub = try requireMeta(store, "deviceEncPub")

		let priv: PrivKeys
		do {
			priv = try derived.accountKey.withData { try openPriv(try requireMeta(store, "pendingInvitePriv"), key: $0) }
		} catch { throw VaultError.incorrectPassphrase }

		let m = try AuthLog.replay(token.authLog, expectedVaultId: token.vaultId)
		guard m.vaultId == token.vaultId else { throw VaultError.corrupt("auth log vault does not match the join token") }
		guard let me = m.members[userId], me.active, me.signPub == (try requireMeta(store, "userSignPub")) else {
			throw VaultError.notAuthorized("join token does not grant this user membership")
		}
		guard let adder = me.addedByDeviceId, let adderKey = m.deviceKeys[adder] else {
			throw VaultError.notAuthorized("auth log does not name the admin device that added you")
		}
		let sas = Self.sas(adderKey, Data(base64: deviceSignPub))

		let addDevice = try signedEntry(
			token.authLog, .addDevice(userId: userId, deviceId: deviceId, deviceSignPub: deviceSignPub, deviceEncPub: deviceEncPub),
			signerId: userId, kind: .user, priv: priv.userSign)
		let proof = try proveDevice(token.authLog + [addDevice], userId: userId, deviceId: deviceId, signPriv: priv.deviceSign)
		// replay skips rather than throws on a rejected entry: check the outcome.
		let extended = try AuthLog.replay(token.authLog + [addDevice, proof], expectedVaultId: token.vaultId)
		guard extended.members[userId]?.active == true, extended.members[userId]?.devices[deviceId]?.signPub == deviceSignPub else {
			throw VaultError.notAuthorized("join token does not let this device join (was it already used?)")
		}

		let (wrap, wm) = try await createWrapKey(derived.accountKey, keystore: keystore)
		let enc = try wrap.withData {
			try sealPriv(
				[("userSign", priv.userSign.data), ("userEnc", priv.userEnc.data), ("deviceSign", priv.deviceSign.data), ("deviceEnc", priv.deviceEnc.data)],
				under: $0)
		}
		try store.transaction {
			for e in token.authLog { try store.appendAuthEntry(e) }
			try store.appendAuthEntry(addDevice)
			try store.appendAuthEntry(proof)
			for r in token.rotations { try store.putRotation(epoch: r.epoch, deviceId: r.deviceId, record: r.serialized) }
			try store.setMeta("vaultId", token.vaultId)
			try persistWrapMeta(store, wm)
			try store.setMeta("encPrivKeys", enc)
			try store.setMeta("selfEpochGrants", JSONValue.object(token.epochGrants.map { JSONMember($0.key, $0.value.json) }).stringify())
			try persistRelay(store, token.relay)
			try store.deleteMeta("pendingInvitePriv")  // see deviceConfirm
			try store.setMeta("pending", "0")
		}
		return (userId, sas)
	}

	// MARK: - recovery escrow

	static let orgPrincipal = "orgPublicKey"
	static func recoveryPrincipal(_ userId: String) -> String { "recovery:\(userId)" }

	private func signedGrant(_ principal: String, _ wrapped: String) throws -> GrantRow {
		let sig = try priv.deviceSign.withData {
			try VaultCrypto.sign(WireProtocol.grantBytes(teamId: vaultId, principal: principal, keyVersion: 0, wrapped: wrapped, signerId: deviceId), $0)
		}
		return GrantRow(principal: principal, keyVersion: 0, wrapped: wrapped, signerId: deviceId, sig: sig.base64)
	}

	// Read-back: a grant published by a since-removed device is still valid.
	private func verifiedLocalGrant(_ principal: String, _ m: Membership) throws -> GrantRow? {
		guard let g = try store.getGrant(teamId: vaultId, principal: principal, keyVersion: 0) else { return nil }
		return WireProtocol.grantVerifiable(teamId: vaultId, g, m) ? g : nil
	}

	// Mint the org keypair, announce its public half, contribute our own grant.
	// Returns the org PRIVATE key (base64) for offline custody; never persisted.
	public func recoveryEnable() throws -> String {
		let m = try membership()
		guard AuthLog.activeDeviceMember(m, deviceId)?.role == .owner else { throw VaultError.notAuthorized("only the owner may enable recovery escrow") }
		guard try verifiedLocalGrant(Self.orgPrincipal, m) == nil else { throw VaultError.invalidArgument("recovery escrow already enabled") }
		let org = VaultCrypto.generateX25519()
		try store.putGrant(teamId: vaultId, try signedGrant(Self.orgPrincipal, org.publicKey.base64))
		try contributeRecovery()
		return org.privateKey.base64
	}

	// Idempotent: seal our identity to the org key once escrow is enabled.
	public func contributeRecovery(membership known: Membership? = nil) throws {
		let m = try known ?? membership()
		guard let me = AuthLog.activeDeviceMember(m, deviceId), me.userId == userId else { return }
		guard let org = try verifiedLocalGrant(Self.orgPrincipal, m) else { return }
		if try verifiedLocalGrant(Self.recoveryPrincipal(userId), m) != nil { return }
		var material = Self.privJSONData([("userSign", priv.userSign), ("userEnc", priv.userEnc)])
		defer { SecureBytes.wipe(&material) }
		let sealed = SealedGrant(try SealedBoxes.seal(material, to: Data(base64: org.wrapped)))
		try store.putGrant(teamId: vaultId, try signedGrant(Self.recoveryPrincipal(userId), sealed.json.stringify()))
	}

	// Reconstruct a member's identity keys with the org private key.
	public func recoverUser(_ target: String, orgPrivate: String) throws -> String {
		let m = try membership()
		guard AuthLog.activeDeviceMember(m, deviceId)?.role == .owner else { throw VaultError.notAuthorized("only the owner may run recovery") }
		guard let org = try verifiedLocalGrant(Self.orgPrincipal, m) else { throw VaultError.invalidArgument("recovery escrow is not enabled") }
		guard let g = try verifiedLocalGrant(Self.recoveryPrincipal(target), m) else {
			throw VaultError.notFound("no recovery grant for \(target) (have they synced since escrow was enabled?)")
		}
		guard let sj = try? JSONValue.parse(g.wrapped), let sg = SealedGrant(json: sj),
			let pt = try? SealedBoxes.unseal(sg.sealedBox, priv: Data(base64: orgPrivate), pub: Data(base64: org.wrapped))
		else { throw VaultError.notAuthorized("recovery failed: org key does not match, or the grant is corrupt") }
		return String(decoding: pt, as: UTF8.self)
	}

	// Owner-assisted recovery: enroll a fresh device (the member's Token A) for a
	// locked-out member. This owner device signs the add-device (the auth log admits
	// an owner device enrolling for another member), seals every epoch key it holds
	// and the member's escrowed identity keys to the new device, and returns a
	// Token B for `device-confirm`. The recovered keys never leave this process.
	public func recoverDevice(_ target: String, orgPrivate: String, token a: TokenA, relay: RelayInfo? = nil) throws -> TokenB {
		let m = try membership()
		guard AuthLog.activeDeviceMember(m, deviceId)?.role == .owner else { throw VaultError.notAuthorized("only the owner may run recovery") }
		guard let member = m.members[target], member.active else { throw VaultError.notFound("\(target) is not an active member") }
		var material = Data(try recoverUser(target, orgPrivate: orgPrivate).utf8)
		defer { SecureBytes.wipe(&material) }
		guard let o = try? JSONValue.parse(material),
			let signPub = try? VaultCrypto.ed25519PublicKey(fromSeed: Data(base64: o["userSign"]?.string ?? "")),
			let encPub = try? VaultCrypto.x25519PublicKey(fromSeed: Data(base64: o["userEnc"]?.string ?? "")),
			signPub.base64 == member.signPub, encPub.base64 == member.encPub
		else { throw VaultError.corrupt("recovered identity keys do not match \(target)'s public keys in the auth log") }

		let newEncPub = Data(base64: a.encPub)
		try store.appendAuthEntry(
			try Self.signedEntry(
				try store.authLog(), .addDevice(userId: target, deviceId: a.deviceId, deviceSignPub: a.signPub, deviceEncPub: a.encPub),
				signerId: deviceId, kind: .device, priv: priv.deviceSign))
		var grants = OrderedMap<String, SealedGrant>()
		for (commit, key) in keys.sorted(by: { jsLess($0.key, $1.key) }) {
			grants[commit] = SealedGrant(try key.withData { try SealedBoxes.seal($0, to: newEncPub) })
		}
		return TokenB(
			vaultId: vaultId, userId: target, authLog: try store.authLog(), rotations: try loadRotations(),
			epochGrants: grants, userPriv: SealedGrant(try SealedBoxes.seal(material, to: newEncPub)), relay: relay)
	}

	// MARK: - keystore second factor

	public struct KeystoreStatus: Sendable, Equatable {
		public var provider: String?
		public var isProtected: Bool
		public var keyMode: String?
	}

	public static func keystoreStatus(_ store: Store) throws -> KeystoreStatus {
		let p = try store.meta("keystoreProvider").flatMap { $0.isEmpty ? nil : $0 }
		return KeystoreStatus(provider: p, isProtected: p != nil, keyMode: try store.meta("keystoreKeyMode").flatMap { $0.isEmpty ? nil : $0 })
	}

	// Re-wrap the at-rest private keys with (enable) or without (disable) the OS
	// keystore. Old DUK is deleted only after the new state commits.
	public static func setKeystore(store: Store, password: Data, enable: Bool, keystore: PlatformKeyStore?) async throws -> String {
		guard try isInitialized(store) else { throw VaultError.notInitialized }
		if enable, keystore == nil { throw VaultError.invalidArgument("no OS keystore is available on this platform") }
		if enable, let k = keystore, !(await k.available()) { throw VaultError.keystoreUnavailable(k.name) }
		guard let kj = try? JSONValue.parse(try requireMeta(store, "kdfParams")) else { throw VaultError.corrupt("kdfParams") }
		let derived = try PasswordKDF.deriveKeys(password: password, params: try KdfParams(json: kj))
		let current = try await openWrapKey(store, derived.accountKey, keystore: keystore)
		let priv: PrivKeys
		do { priv = try current.withData { try openPriv(try requireMeta(store, "encPrivKeys"), key: $0) } } catch { throw VaultError.incorrectPassphrase }
		let oldProvider = try store.meta("keystoreProvider"), oldId = try store.meta("keystoreId")
		let (wrap, meta) = enable ? try await createWrapKey(derived.accountKey, keystore: keystore) : (derived.accountKey, WrapMeta())
		let resealed = try wrap.withData {
			try sealPriv([("userSign", priv.userSign.data), ("userEnc", priv.userEnc.data), ("deviceSign", priv.deviceSign.data), ("deviceEnc", priv.deviceEnc.data)], under: $0)
		}
		try store.transaction {
			try persistWrapMeta(store, meta)
			try store.setMeta("encPrivKeys", resealed)
		}
		if let op = oldProvider, !op.isEmpty, let oid = oldId, let ks = keystore, ks.name == op, oid != meta.id { try await ks.delete(id: oid) }
		let now = try store.meta("keystoreProvider") ?? ""
		return now.isEmpty ? "none" : now
	}
}
