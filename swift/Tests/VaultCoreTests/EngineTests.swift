import Foundation
import Testing

@testable import VaultCore

private let fastKdf = KdfParams.scrypt(salt: Data(repeating: 7, count: 16), n: 1024, r: 8, p: 1, length: 32)
private let pass = Data("hunter2 é".utf8)

private final class MemoryKeyStore: PlatformKeyStore, @unchecked Sendable {
	let name = "memory"
	let bindingMode = ""
	var items: [String: Data] = [:]
	var usable = true
	func available() async -> Bool { usable }
	func put(id: String, secret: Data) async throws { items[id] = secret }
	func get(id: String) async throws -> Data? { items[id] }
	func delete(id: String) async throws { items[id] = nil }
}

private func tempPath() -> String {
	FileManager.default.temporaryDirectory.appendingPathComponent("vault-eng-\(UUID().uuidString).db").path
}

@Suite struct EngineTests {
	@Test func initUnlockAndItemLifecycle() async throws {
		let path = tempPath()
		defer { try? FileManager.default.removeItem(atPath: path) }
		let store = try Store(path: path)
		let r = try await VaultEngine.initialize(store: store, password: pass, kdf: fastKdf)
		#expect(r.userId.count == 16 && r.deviceId.count == 16 && r.vaultId.count == 32)
		await #expect(throws: VaultError.alreadyInitialized) {
			try await VaultEngine.initialize(store: store, password: pass, kdf: fastKdf)
		}

		let e = try await VaultEngine.unlock(store: store, password: pass)
		let (role, epoch1) = await (e.role, e.currentEpoch)
		#expect(role == .owner && epoch1 == 1)
		let id = try await e.addItem(title: "github", fields: [("username", "octo"), ("password", "s3cret"), ("totp", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")], itemType: .login)
		try await e.addItem(title: "wifi", fields: [("notes", "n")], itemType: .note)
		let item = await e.item(title: "github")!
		#expect(item.itemId == id && item.fields["username"] == "octo" && item.passwords == ["s3cret"] && item.itemType == .login)
		#expect(await e.listItems().count == 2)

		try await e.editItem(title: "github", fields: [("username", "octocat"), ("password", "n3w")])
		let edited = await e.item(title: "github")!
		#expect(edited.fields["username"] == "octocat" && edited.passwords == ["n3w"])
		try await e.editItem(title: "wifi", fields: [], itemType: .card)
		#expect(await e.item(title: "wifi")?.itemType == .card)

		// A fresh unlock rebuilds identical state from the encrypted op log.
		let again = try await VaultEngine.unlock(store: store, password: pass)
		#expect(await again.item(title: "github") == edited)

		try await e.removeItem(title: "wifi")
		#expect(await e.item(title: "wifi") == nil)
		#expect(await e.listItems().count == 1)
		await #expect(throws: VaultError.noSuchItem("nope")) { try await e.removeItem(title: "nope") }
		await #expect(throws: VaultError.noSuchItem("nope")) { try await e.editItem(title: "nope", fields: [("a", "b")]) }
	}

	@Test func wrongPassphraseIsRejected() async throws {
		let store = try Store(path: ":memory:")
		await #expect(throws: VaultError.notInitialized) { try await VaultEngine.unlock(store: store, password: pass) }
		_ = try await VaultEngine.initialize(store: store, password: pass, kdf: fastKdf)
		await #expect(throws: VaultError.incorrectPassphrase) {
			try await VaultEngine.unlock(store: store, password: Data("wrong".utf8))
		}
	}

	@Test func storeHoldsOnlyCiphertext() async throws {
		let store = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: store, password: pass, kdf: fastKdf)
		let e = try await VaultEngine.unlock(store: store, password: pass)
		try await e.addItem(title: "very-secret-title", fields: [("password", "PLAINTEXT-PW-123")])
		for op in try store.allOps() {
			let raw = String(decoding: Data(base64: op.payload), as: UTF8.self)
			#expect(!raw.contains("PLAINTEXT-PW-123") && !raw.contains("very-secret-title"))
		}
		let blob = try #require(try store.meta("encPrivKeys"))
		#expect(blob.contains("\"iv\"") && !blob.contains("userSign"))
	}

	@Test func rotationKeepsDataReadableAndAdvancesEpoch() async throws {
		let store = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: store, password: pass, kdf: fastKdf)
		let e = try await VaultEngine.unlock(store: store, password: pass)
		try await e.addItem(title: "a", fields: [("password", "pw")])
		let first = await e.currentKeyCommit
		#expect(try await e.rotate() == 2)
		let (epoch2, commit2) = await (e.currentEpoch, e.currentKeyCommit)
		#expect(epoch2 == 2 && commit2 != first)
		try await e.addItem(title: "b", fields: [])
		let again = try await VaultEngine.unlock(store: store, password: pass)
		#expect(await again.currentEpoch == 2)
		#expect(await again.item(title: "a")?.passwords == ["pw"])
		#expect(await again.item(title: "b") != nil)
		// The re-encrypted copies carry the original causality: no duplicated passwords.
		#expect(await again.item(title: "a")?.passwords.count == 1)
		#expect(try await e.maybeCatchUp() == nil)
	}

	@Test func keystoreSecondFactorIsRequiredToUnlock() async throws {
		let store = try Store(path: ":memory:")
		let ks = MemoryKeyStore()
		_ = try await VaultEngine.initialize(store: store, password: pass, keystore: ks, kdf: fastKdf)
		#expect(try store.meta("keystoreProvider") == "memory")
		await #expect(throws: VaultError.self) { try await VaultEngine.unlock(store: store, password: pass) }
		_ = try await VaultEngine.unlock(store: store, password: pass, keystore: ks)
		ks.items.removeAll()  // lost DUK
		await #expect(throws: VaultError.self) { try await VaultEngine.unlock(store: store, password: pass, keystore: ks) }

		// Requested-but-unavailable must fail loudly rather than silently downgrade.
		let broken = MemoryKeyStore()
		broken.usable = false
		let s2 = try Store(path: ":memory:")
		await #expect(throws: VaultError.keystoreUnavailable("memory")) {
			try await VaultEngine.initialize(store: s2, password: pass, keystore: broken, kdf: fastKdf)
		}
		#expect(try VaultEngine.isInitialized(s2) == false)
	}

	@Test func syncImportRejectsSecondGenesisAndUnverifiableRotations() async throws {
		let store = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: store, password: pass, kdf: fastKdf)
		let e = try await VaultEngine.unlock(store: store, password: pass)
		let rival = try AuthLog.makeEntry(
			parents: [], body: .genesis(vaultId: "x", userId: "u", userSignPub: "", userEncPub: ""), signerId: "u",
			signerKind: .user, signerPriv: VaultCrypto.generateEd25519().privateKey)
		let junk = "{\"epoch\":9}"
		let r = try await e.importAuthAndRotations([rival], [junk])
		#expect(r.auth == 0 && r.rotations == 0)
		#expect(try store.authLog().count == 3)
		// Re-importing our own entries is a no-op.
		#expect(try await e.importAuthAndRotations(try store.authLog(), try store.rotations()) == (0, 0))
	}

	@Test func malformedOrForeignOpsDoNotBreakUnlock() async throws {
		let store = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: store, password: pass, kdf: fastKdf)
		let e = try await VaultEngine.unlock(store: store, password: pass)
		try await e.addItem(title: "ok", fields: [])
		// A validly signed op from an unknown device, and garbage from a known one.
		let rogue = VaultCrypto.generateEd25519()
		try store.putOp(try WireProtocol.makeEnvelope(deviceId: "ffff", seq: 1, payload: Data("junk".utf8), signPriv: rogue.privateKey))
		try store.putOp(OpEnvelope(deviceId: try await e.deviceId, seq: 99, hash: "zz", sig: "zz", payload: "!!"))
		let again = try await VaultEngine.unlock(store: store, password: pass)
		#expect(await again.listItems().count == 1)
	}
}
