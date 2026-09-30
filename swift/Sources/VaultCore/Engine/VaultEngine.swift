import Foundation

// The vault engine (spec §15.3): ties crypto, CRDT, auth log, rotation and the
// store into the operations the CLI and macOS app invoke. All plaintext handling
// happens here, on-device. An actor serializes session state (spec §15.15).
//
// Enrollment, sharing, recovery escrow and relay sync extend this actor in Enrollment.swift
// and RelaySync.swift.

public struct PrivKeys: Sendable {
	public let userSign: SecureBytes
	public let userEnc: SecureBytes
	public let deviceSign: SecureBytes
	public let deviceEnc: SecureBytes
}

public struct PubKeys: Sendable {
	public let userSign: Data
	public let userEnc: Data
	public let deviceSign: Data
	public let deviceEnc: Data
}

public struct InitResult: Sendable, Equatable {
	public let vaultId: String
	public let userId: String
	public let deviceId: String
}

public typealias ItemFields = [(String, String?)]

let keystoreInfo = "credvault/keystore/v1"

struct WrapMeta {
	var provider = ""
	var id = ""
	var keyMode = ""
}

public actor VaultEngine {
	public let vaultId: String
	public let userId: String
	public let deviceId: String
	public private(set) var role: Role
	public private(set) var currentEpoch: Int
	public private(set) var currentKeyCommit: String

	let store: Store
	let priv: PrivKeys
	let pub: PubKeys
	// Vault keys by commitment, so concurrent same-epoch rotations coexist and
	// every op stays decryptable. New writes use `currentKeyCommit`.
	var keys: [String: SecureBytes]
	var clock: Clock
	var state = VaultState()

	private init(
		store: Store, vaultId: String, userId: String, deviceId: String, role: Role, priv: PrivKeys,
		pub: PubKeys, keys: [String: SecureBytes], epoch: Int, keyCommit: String, clock: Clock
	) {
		self.store = store
		self.vaultId = vaultId
		self.userId = userId
		self.deviceId = deviceId
		self.role = role
		self.priv = priv
		self.pub = pub
		self.keys = keys
		self.currentEpoch = epoch
		self.currentKeyCommit = keyCommit
		self.clock = clock
	}

	// MARK: - meta

	static func requireMeta(_ store: Store, _ k: String) throws -> String {
		guard let v = try store.meta(k) else { throw VaultError.corrupt("missing \(k)") }
		return v
	}

	public static func isInitialized(_ store: Store) throws -> Bool {
		try store.meta("vaultId") != nil && store.meta("encPrivKeys") != nil
	}

	// MARK: - at-rest private-key sealing

	static func sealPriv(_ p: [(String, Data)], under key: Data) throws -> String {
		let json = JSONValue.object(p.map { JSONMember($0.0, .string($0.1.base64)) }).serialized()
		return VaultCrypto.encodeBox(try VaultCrypto.aeadEncrypt(key: key, plaintext: json)).json.stringify()
	}

	static func openPriv(_ blob: String, key: Data) throws -> PrivKeys {
		guard let j = try? JSONValue.parse(blob), let box = EncodedBox(json: j) else {
			throw VaultError.corrupt("encPrivKeys")
		}
		var pt = try VaultCrypto.aeadDecrypt(key: key, box: VaultCrypto.decodeBox(box))
		defer { SecureBytes.wipe(&pt) }
		guard let o = try? JSONValue.parse(pt), let us = o["userSign"]?.string, let ue = o["userEnc"]?.string,
			let ds = o["deviceSign"]?.string, let de = o["deviceEnc"]?.string
		else { throw VaultError.corrupt("encPrivKeys") }
		return PrivKeys(
			userSign: SecureBytes(Data(base64: us)), userEnc: SecureBytes(Data(base64: ue)),
			deviceSign: SecureBytes(Data(base64: ds)), deviceEnc: SecureBytes(Data(base64: de)))
	}

	// MARK: - keystore second factor

	static func createWrapKey(_ accountKey: SecureBytes, keystore: PlatformKeyStore?) async throws -> (SecureBytes, WrapMeta) {
		guard let keystore else { return (accountKey, WrapMeta()) }
		// Requested but unusable: fail loudly rather than silently downgrade.
		guard await keystore.available() else { throw VaultError.keystoreUnavailable(keystore.name) }
		let id = "vault-\(VaultCrypto.randomBytes(8).hex)"
		var duk = VaultCrypto.randomBytes(32)
		defer { SecureBytes.wipe(&duk) }
		try await keystore.put(id: id, secret: duk)
		let wrap = accountKey.withData { VaultCrypto.hkdf(ikm: $0, salt: duk, info: keystoreInfo, length: 32) }
		return (SecureBytes(wrap), WrapMeta(provider: keystore.name, id: id, keyMode: keystore.bindingMode))
	}

	static func openWrapKey(_ store: Store, _ accountKey: SecureBytes, keystore: PlatformKeyStore?) async throws -> SecureBytes {
		guard let provider = try store.meta("keystoreProvider"), !provider.isEmpty else { return accountKey }
		guard let keystore, keystore.name == provider else { throw VaultError.keystoreUnavailable(provider) }
		guard let id = try store.meta("keystoreId"), !id.isEmpty else { throw VaultError.corrupt("keystore metadata") }
		guard var duk = try await keystore.get(id: id) else { throw VaultError.keystoreDenied(provider: provider, id: id) }
		defer { SecureBytes.wipe(&duk) }
		return SecureBytes(accountKey.withData { VaultCrypto.hkdf(ikm: $0, salt: duk, info: keystoreInfo, length: 32) })
	}

	// MARK: - op payloads

	private static func encryptOp(_ op: FieldOp, keyCommit: String, key: SecureBytes) throws -> Data {
		let box = try key.withData { try VaultCrypto.aeadEncrypt(key: $0, plaintext: op.json.serialized()) }
		let e = VaultCrypto.encodeBox(box)
		return JSONValue.obj([
			"keyCommit": .string(keyCommit), "iv": .string(e.iv), "ct": .string(e.ct), "tag": .string(e.tag),
		]).serialized()
	}

	private static func decryptOp(_ payloadB64: String, keys: [String: SecureBytes]) throws -> FieldOp? {
		let p = try JSONValue.parse(Data(base64: payloadB64))
		guard let commit = p["keyCommit"]?.string, let box = EncodedBox(json: p) else {
			throw VaultError.corrupt("op payload")
		}
		guard let key = keys[commit] else { return nil }  // encrypted under a key we don't hold
		let pt = try key.withData { try VaultCrypto.aeadDecrypt(key: $0, box: VaultCrypto.decodeBox(box)) }
		guard let op = FieldOp(json: try JSONValue.parse(pt)) else { throw VaultError.corrupt("op") }
		return op
	}

	// MARK: - auth-log / rotation helpers

	static func signedEntry(
		_ chain: [LogEntry], _ body: EntryBody, signerId: String, kind: SignerKind, priv: SecureBytes
	) throws -> LogEntry {
		try priv.withData {
			try AuthLog.makeEntry(parents: AuthLog.heads(chain), body: body, signerId: signerId, signerKind: kind, signerPriv: $0)
		}
	}

	func loadRotations() throws -> [RotationRecord] {
		try store.rotations().compactMap { RotationRecord.parse($0) }
	}

	func signatureVerifiedRotations(_ m: Membership) throws -> [RotationRecord] {
		try loadRotations().filter { Rotation.verifiable($0, m) }
	}

	func activeAdminRotations(_ m: Membership) throws -> [RotationRecord] {
		try loadRotations().filter { Rotation.authentic($0, m) }
	}

	static func isAdminDevice(_ m: Membership, _ deviceId: String) -> Bool {
		guard let s = AuthLog.activeDeviceMember(m, deviceId) else { return false }
		return s.role == .owner || s.role == .admin
	}

	static func recoverEpochKeys(_ rotations: [RotationRecord], pub: Data, priv: SecureBytes) -> [String: SecureBytes] {
		var keys: [String: SecureBytes] = [:]
		let pubB64 = pub.base64
		for r in rotations {
			guard let g = r.grants[pubB64] else { continue }
			guard let key = try? priv.withData({ try SealedBoxes.unseal(g.sealedBox, priv: $0, pub: pub) }) else { continue }
			if Rotation.keyCommit(key) == r.keyCommit { keys[r.keyCommit] = SecureBytes(key) }
		}
		return keys
	}

	// Vault keys captured at enrollment, sealed to this device (`selfEpochGrants`).
	static func recoverSelfGrants(_ store: Store, pub: Data, priv: SecureBytes, into keys: inout [String: SecureBytes]) throws {
		guard let raw = try store.meta("selfEpochGrants"), let j = try? JSONValue.parse(raw), let ms = j.members else { return }
		for m in ms where keys[m.key] == nil {
			guard let g = SealedGrant(json: m.value),
				let key = try? priv.withData({ try SealedBoxes.unseal(g.sealedBox, priv: $0, pub: pub) }),
				Rotation.keyCommit(key) == m.key
			else { continue }
			keys[m.key] = SecureBytes(key)
		}
	}

	// MARK: - init

	public static func initialize(
		store: Store, password: Data, keystore: PlatformKeyStore? = nil, kdf: KdfParams? = nil,
		now: @escaping @Sendable () -> Int64 = { HLCCodec.nowMillis() }
	) async throws -> InitResult {
		guard try !isInitialized(store) else { throw VaultError.alreadyInitialized }
		let kdfParams = kdf ?? .defaultParams()
		let derived = try PasswordKDF.deriveKeys(password: password, params: kdfParams)

		let userSign = VaultCrypto.generateEd25519()
		let userEnc = VaultCrypto.generateX25519()
		let deviceSign = VaultCrypto.generateEd25519()
		let deviceEnc = VaultCrypto.generateX25519()
		let userSignS = SecureBytes(userSign.privateKey)
		let deviceSignS = SecureBytes(deviceSign.privateKey)

		let userId = AuthLog.deviceId(ofSignPub: userSign.publicKey.base64)
		let deviceId = AuthLog.deviceId(ofSignPub: deviceSign.publicKey.base64)
		let vaultId = VaultCrypto.randomBytes(16).hex

		var chain: [LogEntry] = []
		chain.append(
			try signedEntry(
				chain,
				.genesis(vaultId: vaultId, userId: userId, userSignPub: userSign.publicKey.base64, userEncPub: userEnc.publicKey.base64),
				signerId: userId, kind: .user, priv: userSignS))
		chain.append(
			try signedEntry(
				chain,
				.addDevice(userId: userId, deviceId: deviceId, deviceSignPub: deviceSign.publicKey.base64, deviceEncPub: deviceEnc.publicKey.base64),
				signerId: userId, kind: .user, priv: userSignS))
		chain.append(
			try signedEntry(chain, .proveDevice(userId: userId, deviceId: deviceId), signerId: deviceId, kind: .device, priv: deviceSignS))

		// Epoch 1 key, sealed to this device (the bootstrap self-grant).
		var k1 = VaultCrypto.randomBytes(32)
		defer { SecureBytes.wipe(&k1) }
		var clock = Clock(deviceId: deviceId, now: now)
		var grants = OrderedMap<String, SealedGrant>()
		grants[deviceEnc.publicKey.base64] = SealedGrant(try SealedBoxes.seal(k1, to: deviceEnc.publicKey))
		let rec = try Rotation.sign(
			RotationRecord(
				epoch: 1, baseEpoch: 0, hlc: try HLCCodec.encode(clock.tick()), deviceId: deviceId,
				keyCommit: Rotation.keyCommit(k1), grants: grants, observed: chain.map(\.hash), signerId: deviceId),
			deviceSignPriv: deviceSign.privateKey)

		// Mint the wrap key + its meta BEFORE the transaction (it may create a DUK in
		// the OS keystore); persist atomically with encPrivKeys so meta can never
		// point at a DUK the private keys aren't sealed under.
		let (wrap, wrapMeta) = try await createWrapKey(derived.accountKey, keystore: keystore)
		let encPriv = try wrap.withData {
			try sealPriv(
				[
					("userSign", userSign.privateKey), ("userEnc", userEnc.privateKey),
					("deviceSign", deviceSign.privateKey), ("deviceEnc", deviceEnc.privateKey),
				], under: $0)
		}

		try store.transaction {
			try store.setMeta("vaultId", vaultId)
			try store.setMeta("userId", userId)
			try store.setMeta("deviceId", deviceId)
			try store.setMeta("kdfParams", kdfParams.json.stringify())
			try store.setMeta("userSignPub", userSign.publicKey.base64)
			try store.setMeta("userEncPub", userEnc.publicKey.base64)
			try store.setMeta("deviceSignPub", deviceSign.publicKey.base64)
			try store.setMeta("deviceEncPub", deviceEnc.publicKey.base64)
			try store.setMeta("keystoreProvider", wrapMeta.provider)
			try store.setMeta("keystoreId", wrapMeta.id)
			try store.setMeta("keystoreKeyMode", wrapMeta.keyMode)
			try store.setMeta("encPrivKeys", encPriv)
			for e in chain { try store.appendAuthEntry(e) }
			try store.putRotation(epoch: rec.epoch, deviceId: rec.deviceId, record: rec.serialized)
		}
		return InitResult(vaultId: vaultId, userId: userId, deviceId: deviceId)
	}

	// MARK: - unlock

	public static func unlock(
		store: Store, password: Data, keystore: PlatformKeyStore? = nil,
		now: @escaping @Sendable () -> Int64 = { HLCCodec.nowMillis() }
	) async throws -> VaultEngine {
		guard try isInitialized(store) else { throw VaultError.notInitialized }
		guard let kj = try? JSONValue.parse(try requireMeta(store, "kdfParams")) else { throw VaultError.corrupt("kdfParams") }
		let derived = try PasswordKDF.deriveKeys(password: password, params: try KdfParams(json: kj))

		// A missing keystore/DUK raises a distinct error before the passphrase check.
		let wrap = try await openWrapKey(store, derived.accountKey, keystore: keystore)
		let priv: PrivKeys
		do {
			priv = try wrap.withData { try openPriv(try requireMeta(store, "encPrivKeys"), key: $0) }
		} catch {
			throw VaultError.incorrectPassphrase
		}

		let pub = PubKeys(
			userSign: Data(base64: try requireMeta(store, "userSignPub")), userEnc: Data(base64: try requireMeta(store, "userEncPub")),
			deviceSign: Data(base64: try requireMeta(store, "deviceSignPub")), deviceEnc: Data(base64: try requireMeta(store, "deviceEncPub")))
		let vaultId = try requireMeta(store, "vaultId")
		let userId = try requireMeta(store, "userId")
		let deviceId = try requireMeta(store, "deviceId")

		let membership = try AuthLog.replay(try store.authLog(), expectedVaultId: vaultId)
		let role = AuthLog.activeDeviceMember(membership, deviceId)?.role ?? .member

		let stored = try store.rotations().compactMap { RotationRecord.parse($0) }
		var keys = recoverEpochKeys(stored.filter { Rotation.verifiable($0, membership) }, pub: pub.deviceEnc, priv: priv.deviceEnc)
		try recoverSelfGrants(store, pub: pub.deviceEnc, priv: priv.deviceEnc, into: &keys)
		let win = Rotation.winner(stored.filter { Rotation.authentic($0, membership) })

		let engine = VaultEngine(
			store: store, vaultId: vaultId, userId: userId, deviceId: deviceId, role: role, priv: priv, pub: pub,
			keys: keys, epoch: win?.epoch ?? 1, keyCommit: win?.keyCommit ?? "", clock: Clock(deviceId: deviceId, now: now))
		try await engine.rebuildState(membership)
		// If escrow is enabled, make sure this user has contributed a grant.
		try await engine.contributeRecovery()
		return engine
	}

	// Re-validate the auth log and rebuild the replica (e.g. after a sync round).
	public func rebuildSession(membership known: Membership? = nil) throws {
		let membership = try known ?? AuthLog.replay(try store.authLog(), expectedVaultId: vaultId)
		// Recompute the key set from scratch so a key whose rotation is no longer
		// valid is dropped.
		var fresh = Self.recoverEpochKeys(try signatureVerifiedRotations(membership), pub: pub.deviceEnc, priv: priv.deviceEnc)
		try Self.recoverSelfGrants(store, pub: pub.deviceEnc, priv: priv.deviceEnc, into: &fresh)
		keys = fresh
		if let win = Rotation.winner(try activeAdminRotations(membership)) {
			currentEpoch = win.epoch
			currentKeyCommit = win.keyCommit
		} else {
			currentEpoch = 1
			currentKeyCommit = ""
		}
		role = AuthLog.activeDeviceMember(membership, deviceId)?.role ?? .member
		try rebuildState(membership)
	}

	// Verify every op's signature against the auth log, decrypt, and merge. A
	// validly-signed but malformed op is skipped rather than fatal: throwing would
	// lock every replica out, including the admin who must remove the writer.
	func rebuildState(_ membership: Membership) throws {
		var fresh = VaultState()
		var maxHlc = ""
		for op in try store.allOps() {
			guard let signPub = AuthLog.deviceSignKey(membership, op.deviceId),
				WireProtocol.verifyEnvelope(op, signPub: signPub)
			else { continue }
			guard let field = try? Self.decryptOp(op.payload, keys: keys) else { continue }
			// Reject implausibly future-dated writes before they enter the CRDT.
			if op.deviceId != deviceId, !HLCCodec.isWithinForwardDrift(HLCCodec.decode(field.hlc)) { continue }
			fresh.apply(field)
			if jsLess(maxHlc, field.hlc) { maxHlc = field.hlc }
		}
		state = fresh
		if !maxHlc.isEmpty { clock.observe(HLCCodec.decode(maxHlc)) }
	}

	// MARK: - emit

	func emitOps(_ ops: [FieldOp]) throws {
		guard let key = keys[currentKeyCommit] else { throw VaultError.noCurrentKey }
		// Read the next seq and write under ONE write lock: another process (the CLI and
		// the app share a database) could otherwise claim the same (device, seq), and the
		// losing INSERT OR IGNORE would silently vanish while the command reported success.
		try store.transaction(immediate: true) {
			var seq = try store.maxSeq(for: deviceId)
			for op in ops {
				seq += 1
				let payload = try Self.encryptOp(op, keyCommit: currentKeyCommit, key: key)
				let env = try priv.deviceSign.withData {
					try WireProtocol.makeEnvelope(deviceId: deviceId, seq: seq, payload: payload, signPriv: $0)
				}
				guard try store.putOp(env) else { throw VaultError.corrupt("concurrent write conflict; retry") }
			}
		}
		for op in ops { state.apply(op) }
	}

	// Re-encrypt FieldOps verbatim: their HLCs and `replaces` sets are CRDT
	// causality, and fresh timestamps would let a stale offline value win.
	func reencryptableOps(_ membership: Membership) throws -> [FieldOp] {
		var seen = Set<String>()
		var out: [FieldOp] = []
		for env in try store.allOps() {
			guard let signPub = AuthLog.deviceSignKey(membership, env.deviceId),
				WireProtocol.verifyEnvelope(env, signPub: signPub),
				let field = try? Self.decryptOp(env.payload, keys: keys)
			else { continue }
			if env.deviceId != deviceId, !HLCCodec.isWithinForwardDrift(HLCCodec.decode(field.hlc)) { continue }
			if seen.insert(field.json.stringify()).inserted { out.append(field) }
		}
		return out
	}

	func nextHlc() throws -> String { try HLCCodec.encode(clock.tick()) }

	// MARK: - items

	func findByTitle(_ title: String) -> ItemView? { state.list().first { $0.fields["title"] == title } }

	// `{ title, ...fields, __type__ }` with JS object semantics: later duplicates
	// overwrite the value but keep the first key's position.
	private static func ordered(_ entries: ItemFields) -> ItemFields {
		var out: ItemFields = []
		for (k, v) in entries {
			if let i = out.firstIndex(where: { $0.0 == k }) { out[i].1 = v } else { out.append((k, v)) }
		}
		return out
	}

	@discardableResult
	public func addItem(title: String, fields: ItemFields = [], itemType: ItemType = .default) throws -> String {
		let itemId = VaultCrypto.randomBytes(16).hex
		let all = Self.ordered([("title", title)] + fields + [(CRDTFields.itemType, itemType.rawValue)])
		try emitOps(try ItemOps.build(itemId: itemId, fields: all, nextHlc: nextHlc))
		return itemId
	}

	public func editItem(title: String, fields: ItemFields, itemType: ItemType? = nil) throws {
		guard let item = findByTitle(title) else { throw VaultError.noSuchItem(title) }
		let merged = Self.ordered(itemType.map { fields + [(CRDTFields.itemType, $0.rawValue)] } ?? fields)
		try emitOps(
			try ItemOps.build(itemId: item.itemId, fields: merged, nextHlc: nextHlc, livePasswordHlcs: state.livePasswordHlcs(item.itemId)))
	}

	public func removeItem(title: String) throws {
		guard let item = findByTitle(title) else { throw VaultError.noSuchItem(title) }
		try emitOps([ItemOps.delete(itemId: item.itemId, hlc: try nextHlc())])
	}

	public func item(title: String) -> ItemView? { findByTitle(title) }
	public func listItems() -> [ItemView] { state.list() }

	// MARK: - rotation / revocation

	// Issue a new epoch, sealing a fresh key to every active (and pending) device of
	// the remaining members, then re-encrypt known ops under it.
	@discardableResult
	public func rotate(membership: Membership? = nil, carry: [FieldOp]? = nil) throws -> Int {
		let m = try membership ?? AuthLog.replay(try store.authLog(), expectedVaultId: vaultId)
		guard Self.isAdminDevice(m, deviceId) else { throw VaultError.notAuthorized("only an active admin device may rotate keys") }
		let baseEpoch = Rotation.winner(try activeAdminRotations(m))?.epoch ?? 0
		let epoch = baseEpoch + 1
		var newKey = VaultCrypto.randomBytes(32)
		defer { SecureBytes.wipe(&newKey) }

		var grants = OrderedMap<String, SealedGrant>()
		for (_, mem) in m.members where mem.active {
			// Pending devices too: one whose proof hasn't synced yet would otherwise
			// miss this epoch's key for good.
			for d in mem.devices.values + mem.pendingDevices.values {
				// A device may register an unusable encryption key (the auth log only checks
				// its signing key). Sealing to it must not be able to block every rotation and
				// revocation: skip it, it simply receives no key.
				guard let sealed = try? SealedBoxes.seal(newKey, to: Data(base64: d.encPub)) else { continue }
				grants[d.encPub] = SealedGrant(sealed)
			}
		}
		let rec = try priv.deviceSign.withData {
			try Rotation.sign(
				RotationRecord(
					epoch: epoch, baseEpoch: baseEpoch, hlc: try nextHlc(), deviceId: deviceId,
					keyCommit: Rotation.keyCommit(newKey), grants: grants, observed: try store.authHashes(), signerId: deviceId),
				deviceSignPriv: $0)
		}
		try store.putRotation(epoch: rec.epoch, deviceId: rec.deviceId, record: rec.serialized)
		keys[rec.keyCommit] = SecureBytes(newKey)
		currentEpoch = epoch
		currentKeyCommit = rec.keyCommit
		// Snapshot before writing so an op is copied at most once per rotation.
		try emitOps(try carry ?? reencryptableOps(m))
		return epoch
	}

	// Remove a person (revokes their whole device set) and rotate.
	@discardableResult
	public func removeUser(_ target: String) throws -> Int {
		let chain = try store.authLog()
		let m = try AuthLog.replay(chain, expectedVaultId: vaultId)
		guard Self.isAdminDevice(m, deviceId) else { throw VaultError.notAuthorized("only admins may remove users") }
		guard m.members.has(target) else { throw VaultError.notFound("no such member \(target)") }
		try store.appendAuthEntry(try Self.signedEntry(chain, .removeUser(userId: target), signerId: deviceId, kind: .device, priv: priv.deviceSign))
		return try rotateOrDeferToAdmin(before: m)
	}

	// Remove a single device subkey, leaving the owning user and their other
	// devices intact. Signed by the owning device or an admin device.
	@discardableResult
	public func removeDevice(_ target: String) throws -> Int {
		let chain = try store.authLog()
		let m = try AuthLog.replay(chain, expectedVaultId: vaultId)
		var ownerId: String?
		for (_, mem) in m.members where mem.active && (mem.devices.has(target) || mem.pendingDevices.has(target)) {
			ownerId = mem.userId
		}
		guard let ownerId else { throw VaultError.notFound("no such active device \(target)") }
		guard let signer = AuthLog.activeDeviceMember(m, deviceId), signer.userId == ownerId || signer.role == .owner || signer.role == .admin
		else { throw VaultError.notAuthorized("only the owning user or an admin may remove a device") }
		try store.appendAuthEntry(
			try Self.signedEntry(chain, .removeDevice(userId: ownerId, deviceId: target), signerId: deviceId, kind: .device, priv: priv.deviceSign))
		return try rotateOrDeferToAdmin(before: m)
	}

	// Rotate immediately if this device is still an active admin after the
	// revocation; otherwise leave the removal recorded for the next admin's catch-up.
	// Re-encrypting against the *pre*-removal membership keeps items the removed
	// device authored.
	private func rotateOrDeferToAdmin(before: Membership) throws -> Int {
		let after = try AuthLog.replay(try store.authLog(), expectedVaultId: vaultId)
		guard Self.isAdminDevice(after, deviceId) else { return currentEpoch }
		return try rotate(membership: after, carry: try reencryptableOps(before))
	}

	// After sync: issue a security catch-up rotation if the winning rotation did
	// not observe a removal that has since landed. Returns the new epoch, if any.
	public func maybeCatchUp() throws -> Int? {
		let chain = try store.authLog()
		let m = try AuthLog.replay(chain, expectedVaultId: vaultId)
		guard Self.isAdminDevice(m, deviceId) else { return nil }
		let win = Rotation.winner(try activeAdminRotations(m))
		// Only removals replay actually applied: an unauthorized remove-* entry must
		// not force a full re-encryption on every admin.
		let removals = chain.filter { $0.body.type == "remove-user" || $0.body.type == "remove-device" }
			.map(AuthLog.entryHash).filter { m.appliedHashes.contains($0) }
		return Rotation.needsCatchUp(win, removalHashes: removals) ? try rotate(membership: m) : nil
	}

	// Merge auth-log entries and rotation records pulled during sync. Never accepts
	// a second genesis (a hostile relay could otherwise hijack the root), and only
	// stores rotations whose signature verifies against the extended log.
	public func importAuthAndRotations(_ auth: [LogEntry], _ rotations: [String]) throws -> (auth: Int, rotations: Int) {
		let r = try importAuth(auth, rotations, prior: nil)
		return (r.auth, r.rotations)
	}

	// `prior` is the membership computed before the import; when nothing new is admitted the
	// log is unchanged and it is reused instead of replaying the DAG again.
	func importAuth(_ auth: [LogEntry], _ rotations: [String], prior: Membership?) throws -> (auth: Int, rotations: Int, membership: Membership) {
		var have = Set(try store.authHashes())
		var candidates: [LogEntry] = []
		for var e in auth {
			let h = AuthLog.entryHash(e)
			// Exactly one genesis roots the DAG; we already hold ours.
			if have.contains(h) || e.body.type == "genesis" { continue }
			e.hash = h
			have.insert(h)
			candidates.append(e)
		}
		// Persist only what replay accepts (see AuthLog.admissible): the relay is untrusted.
		var authImported = 0
		for e in AuthLog.admissible(candidates, existing: try store.authLog(), expectedVaultId: vaultId) {
			try store.appendAuthEntry(e)
			authImported += 1
		}
		let m: Membership
		if authImported == 0, let prior { m = prior } else { m = try AuthLog.replay(try store.authLog(), expectedVaultId: vaultId) }
		var haveRot = Set(try signatureVerifiedRotations(m).map { Rotation.id(epoch: $0.epoch, deviceId: $0.deviceId) })
		var rotImported = 0
		for raw in rotations {
			guard let r = RotationRecord.parse(raw), Rotation.verifiable(r, m) else { continue }
			let id = Rotation.id(epoch: r.epoch, deviceId: r.deviceId)
			if haveRot.contains(id) { continue }
			try store.putRotation(epoch: r.epoch, deviceId: r.deviceId, record: r.serialized)
			haveRot.insert(id)
			rotImported += 1
		}
		return (authImported, rotImported, m)
	}

	// MARK: - introspection

	public func membership() throws -> Membership {
		try AuthLog.replay(try store.authLog(), expectedVaultId: vaultId)
	}
	public var publicKeys: PubKeys { pub }
}
