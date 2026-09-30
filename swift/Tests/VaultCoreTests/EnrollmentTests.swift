import Foundation
import Testing

@testable import VaultCore

private let kdf = KdfParams.scrypt(salt: Data(repeating: 9, count: 16), n: 1024, r: 8, p: 1, length: 32)
private let pass = Data("pw".utf8)

private func mem() throws -> Store { try Store(path: ":memory:") }

// Move a replica's logical state to another store the way a relay round would.
private func copyAll(_ from: Store, _ to: Store) throws {
	for e in try from.authLog() where e.body.type != "genesis" { try to.appendAuthEntry(e) }
	for r in try from.rotations() { if let p = RotationRecord.parse(r) { try to.putRotation(epoch: p.epoch, deviceId: p.deviceId, record: r) } }
	try to.putOps(try from.allOps())
}

@Suite struct EnrollmentTests {
	@Test func tokensRoundTripAndRejectGarbage() throws {
		let t = TokenA(deviceId: "d", signPub: "s", encPub: "e")
		#expect(try TokenA.decode(t.encoded) == t)
		#expect(t.json.stringify() == #"{"deviceId":"d","signPub":"s","encPub":"e"}"#)
		#expect(throws: VaultError.self) { try TokenA.decode("bm90IGpzb24=") }
		let r = RelayInfo(url: "https://r", token: "t", accessId: "i", accessSecret: "s")
		#expect(RelayInfo(json: r.json) == r)
	}

	@Test func deviceEnrollmentEndToEnd() async throws {
		let s1 = try mem(), s2 = try mem()
		_ = try await VaultEngine.initialize(store: s1, password: pass, kdf: kdf)
		let owner = try await VaultEngine.unlock(store: s1, password: pass)
		try await owner.addItem(title: "gh", fields: [("password", "pw1")])

		let a = try VaultEngine.authNewDevice(store: s2, password: pass, kdf: kdf)
		let b = try await owner.deviceAdd(a, relay: RelayInfo(url: "http://r", token: "SECRET", accessId: "id", accessSecret: "SECRET2"))
		let sas = try await VaultEngine.deviceConfirm(store: s2, password: pass, token: b)
		let ownerSas = await owner.enrollmentSas(newDeviceSignPub: a.signPub)
		#expect(sas == ownerSas)
		#expect(sas.count == 6)

		// Bearer secrets from the token must never reach the plaintext meta table.
		let saved = try #require(try VaultEngine.savedRelay(s2))
		#expect(saved.url == "http://r" && saved.accessId == "id" && saved.token == nil && saved.accessSecret == nil)
		#expect(try s2.meta("relayInfo")?.contains("SECRET") == false)

		// New device's proof reaches the owner; the owner's ops reach the new device.
		try copyAll(s2, s1)
		try copyAll(s1, s2)
		_ = try await owner.importAuthAndRotations(try s2.authLog(), [])
		try await owner.rebuildSession()
		let dev = try await VaultEngine.unlock(store: s2, password: pass)
		#expect(await dev.item(title: "gh")?.passwords == ["pw1"])
		#expect(await dev.role == .owner)

		// Wrong-token cases.
		await #expect(throws: VaultError.self) { try await VaultEngine.deviceConfirm(store: s2, password: pass, token: b) }  // no longer pending
		let s3 = try mem()
		_ = try VaultEngine.authNewDevice(store: s3, password: pass, kdf: kdf)
		await #expect(throws: VaultError.self) { try await VaultEngine.deviceConfirm(store: s3, password: pass, token: b) }  // not addressed to this device
		await #expect(throws: VaultError.incorrectPassphrase) { try await VaultEngine.deviceConfirm(store: s3, password: Data("bad".utf8), token: b) }
	}

	@Test func sharingRotationAndRevocation() async throws {
		let so = try mem(), sj = try mem()
		_ = try await VaultEngine.initialize(store: so, password: pass, kdf: kdf)
		let owner = try await VaultEngine.unlock(store: so, password: pass)
		try await owner.addItem(title: "shared", fields: [("k", "v")])

		let invite = try VaultEngine.inviteInit(store: sj, password: pass, kdf: kdf)
		await #expect(throws: VaultError.self) { try await owner.shareVault(invite, role: .owner) }
		let join = try await owner.shareVault(invite, role: .member)
		let (uid, sas) = try await VaultEngine.joinConfirm(store: sj, password: pass, token: join)
		let ownerSas = await owner.enrollmentSas(newDeviceSignPub: invite.deviceSignPub)
		#expect(uid == invite.userId && sas == ownerSas)
		// A used token cannot enrol the device twice.
		await #expect(throws: VaultError.self) { try await VaultEngine.joinConfirm(store: sj, password: pass, token: join) }

		try copyAll(sj, so)
		try copyAll(so, sj)
		try await owner.rebuildSession()
		let joiner = try await VaultEngine.unlock(store: sj, password: pass)
		#expect(await joiner.role == .member)
		#expect(await joiner.item(title: "shared")?.fields["k"] == "v")
		// Members cannot rotate, share or remove.
		await #expect(throws: VaultError.self) { try await joiner.rotate() }
		await #expect(throws: VaultError.self) { try await joiner.removeUser(await owner.userId) }

		// Revoking the joiner rotates; new data is sealed only to remaining devices.
		#expect(try await owner.removeUser(uid) == 2)
		try await owner.addItem(title: "secret-after", fields: [])
		try copyAll(so, sj)
		try await joiner.rebuildSession()
		#expect(await joiner.item(title: "secret-after") == nil)
		#expect(await owner.item(title: "shared") != nil)
	}

	@Test func recoveryEscrowRoundTrip() async throws {
		let so = try mem(), sj = try mem()
		_ = try await VaultEngine.initialize(store: so, password: pass, kdf: kdf)
		let owner = try await VaultEngine.unlock(store: so, password: pass)
		let invite = try VaultEngine.inviteInit(store: sj, password: pass, kdf: kdf)
		_ = try await VaultEngine.joinConfirm(store: sj, password: pass, token: try await owner.shareVault(invite))
		try copyAll(sj, so)
		try copyAll(so, sj)
		try await owner.rebuildSession()

		let orgKey = try await owner.recoveryEnable()
		await #expect(throws: VaultError.self) { try await owner.recoveryEnable() }  // already enabled
		await #expect(throws: VaultError.self) { try await owner.recoverUser(invite.userId, orgPrivate: orgKey) }  // no grant yet

		// Joiner picks up the org key and contributes its grant on next unlock/sync.
		for g in try so.allGrants(teamId: await owner.vaultId) { try sj.putGrant(teamId: await owner.vaultId, g) }
		let joiner = try await VaultEngine.unlock(store: sj, password: pass)
		for g in try sj.allGrants(teamId: await owner.vaultId) { try so.putGrant(teamId: await owner.vaultId, g) }

		let json = try JSONValue.parse(try await owner.recoverUser(invite.userId, orgPrivate: orgKey))
		#expect(json["userSign"]?.string?.isEmpty == false)
		await #expect(throws: VaultError.self) { try await owner.recoverUser(invite.userId, orgPrivate: Data(count: 32).base64) }
		await #expect(throws: VaultError.self) { try await joiner.recoverUser(invite.userId, orgPrivate: orgKey) }  // owner only

		// The joiner loses their device: the owner re-enrolls a fresh one from escrow.
		try await owner.addItem(title: "after", fields: [("k", "v2")])
		let sn = try mem()
		let a = try VaultEngine.authNewDevice(store: sn, password: Data("new".utf8), kdf: kdf)
		await #expect(throws: VaultError.self) { try await joiner.recoverDevice(invite.userId, orgPrivate: orgKey, token: a) }  // owner only
		await #expect(throws: VaultError.self) { try await owner.recoverDevice(invite.userId, orgPrivate: Data(count: 32).base64, token: a) }
		let b = try await owner.recoverDevice(invite.userId, orgPrivate: orgKey, token: a)
		#expect(b.userId == invite.userId)
		let sas = try await VaultEngine.deviceConfirm(store: sn, password: Data("new".utf8), token: b)
		let ownerSas = await owner.enrollmentSas(newDeviceSignPub: a.signPub)
		#expect(sas == ownerSas)
		try copyAll(sn, so)
		try copyAll(so, sn)
		let recovered = try await VaultEngine.unlock(store: sn, password: Data("new".utf8))
		#expect(await recovered.userId == invite.userId)
		#expect(await recovered.role == .member)
		#expect(await recovered.item(title: "after")?.fields["k"] == "v2")

		// The owner-signed enrollment is admitted by the auth log; a member device
		// signing one for another user is not.
		let m = try AuthLog.replay(try so.authLog(), expectedVaultId: await owner.vaultId)
		#expect(AuthLog.activeDeviceMember(m, a.deviceId)?.userId == invite.userId)
	}

	@Test func memberDeviceCannotEnrollForAnotherUser() async throws {
		let so = try mem(), sj = try mem()
		_ = try await VaultEngine.initialize(store: so, password: pass, kdf: kdf)
		let owner = try await VaultEngine.unlock(store: so, password: pass)
		let invite = try VaultEngine.inviteInit(store: sj, password: pass, kdf: kdf)
		_ = try await VaultEngine.joinConfirm(store: sj, password: pass, token: try await owner.shareVault(invite))
		try copyAll(sj, so)
		try copyAll(so, sj)
		let joiner = try await VaultEngine.unlock(store: sj, password: pass)
		let ownerUser = await owner.userId
		let dev = VaultCrypto.generateEd25519(), enc = VaultCrypto.generateX25519()
		let entry = try VaultEngine.signedEntry(
			try so.authLog(),
			.addDevice(userId: ownerUser, deviceId: AuthLog.deviceId(ofSignPub: dev.publicKey.base64), deviceSignPub: dev.publicKey.base64, deviceEncPub: enc.publicKey.base64),
			signerId: invite.deviceId, kind: .device, priv: await joiner.priv.deviceSign)
		let m = try AuthLog.replay(try so.authLog() + [entry], expectedVaultId: await owner.vaultId)
		#expect(!m.appliedHashes.contains(AuthLog.entryHash(entry)))
	}

	@Test func keystoreCanBeEnabledAndDisabledOnExistingVault() async throws {
		final class KS: PlatformKeyStore, @unchecked Sendable {
			let name = "mem", bindingMode = ""
			var items: [String: Data] = [:]
			func available() async -> Bool { true }
			func put(id: String, secret: Data) async throws { items[id] = secret }
			func get(id: String) async throws -> Data? { items[id] }
			func delete(id: String) async throws { items[id] = nil }
		}
		let store = try mem(), ks = KS()
		_ = try await VaultEngine.initialize(store: store, password: pass, kdf: kdf)
		#expect(try VaultEngine.keystoreStatus(store).isProtected == false)
		#expect(try await VaultEngine.setKeystore(store: store, password: pass, enable: true, keystore: ks) == "mem")
		#expect(try VaultEngine.keystoreStatus(store) == .init(provider: "mem", isProtected: true, keyMode: nil))
		await #expect(throws: VaultError.self) { try await VaultEngine.unlock(store: store, password: pass) }
		let oldId = try #require(ks.items.keys.first)
		_ = try await VaultEngine.unlock(store: store, password: pass, keystore: ks)
		#expect(try await VaultEngine.setKeystore(store: store, password: pass, enable: false, keystore: ks) == "none")
		#expect(ks.items[oldId] == nil)  // old DUK removed after commit
		_ = try await VaultEngine.unlock(store: store, password: pass)
		await #expect(throws: VaultError.incorrectPassphrase) { try await VaultEngine.setKeystore(store: store, password: Data("x".utf8), enable: true, keystore: ks) }
	}
}
