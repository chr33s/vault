import Foundation
import Testing

@testable import VaultCommands
@testable import VaultCore

#if canImport(VaultPlatformDarwin)
	import CryptoKit
	import VaultPlatformDarwin

	@Suite struct SecureEnclaveSealTests {
		@Test func blobLayoutMatchesTheHelperFormatAndOpensOnlyWithTheKey() throws {
			// A software P-256 key stands in for the enclave key: the format is identical.
			let k = P256.KeyAgreement.PrivateKey()
			let blob = try SecureEnclaveSeal.seal(Data("duk-bytes".utf8), to: k.publicKey)
			// ephemeralPub(64) || AES-GCM combined (12 nonce + ct + 16 tag)
			#expect(blob.count == 64 + 12 + 9 + 16)
			#expect(try SecureEnclaveSeal.open(blob) { try k.sharedSecretFromKeyAgreement(with: $0) } == Data("duk-bytes".utf8))
			let other = P256.KeyAgreement.PrivateKey()
			#expect(throws: Error.self) { try SecureEnclaveSeal.open(blob) { try other.sharedSecretFromKeyAgreement(with: $0) } }
			var bad = blob
			bad[bad.count - 1] ^= 1
			#expect(throws: Error.self) { try SecureEnclaveSeal.open(bad) { try k.sharedSecretFromKeyAgreement(with: $0) } }
			#expect(throws: Error.self) { try SecureEnclaveSeal.open(Data(count: 10)) { try k.sharedSecretFromKeyAgreement(with: $0) } }
			// Each seal uses a fresh ephemeral key.
			#expect(try SecureEnclaveSeal.seal(Data("x".utf8), to: k.publicKey) != SecureEnclaveSeal.seal(Data("x".utf8), to: k.publicKey))
		}

		@Test func rejectsUnsafeIds() async {
			let ks = SecureEnclaveKeyStore(directory: NSTemporaryDirectory() + "vault-se-\(UUID().uuidString)")
			await #expect(throws: VaultError.self) { try await ks.put(id: "../evil", secret: Data([1])) }
			#expect((try? await ks.get(id: "../evil")) == nil)
			#expect(!FileManager.default.fileExists(atPath: NSTemporaryDirectory() + "evil.se"))
		}
	}
#endif

@Suite struct InProcessTests {
	private func home() -> String { NSTemporaryDirectory() + "vault-inproc-\(UUID().uuidString)" }

	@Test func runsCommandsWithoutASubprocessOrPipes() async throws {
		let h = home()
		defer { try? FileManager.default.removeItem(atPath: h) }
		let env = ["VAULT_HOME": h]
		func run(_ a: [String], _ secrets: [String]) async -> (Int32, JSONValue?) {
			let r = await VaultCommands.execute(["--json", "--passphrase-stdin"] + a, secrets: secrets, environment: env)
			return (r.exitCode, try? JSONValue.parse(r.stdout.split(separator: "\n").first.map(String.init) ?? ""))
		}
		let (c0, init0) = await run(["init"], ["pw"])
		#expect(c0 == 0 && init0?["ok"] == .bool(true) && init0?["vaultId"]?.string?.count == 32)
		// Secrets are consumed in prompt order: passphrase, --field-stdin lines, item password.
		let (c1, add) = await run(["add", "--field-stdin", "1", "--password", "--", "gh"], ["pw", "username=octo", "item-pw"])
		#expect(c1 == 0 && add?["title"]?.string == "gh")
		let (_, get) = await run(["get", "--", "gh"], ["pw"])
		#expect(get?["fields"]?["username"]?.string == "octo" && get?["passwords"]?.array?.first?.string == "item-pw")
		let (_, list) = await run(["list"], ["pw"])
		#expect(list?["items"]?.array?.count == 1)
		// Errors are the same stable machine-readable envelope.
		let (c2, bad) = await run(["list"], ["wrong"])
		#expect(c2 == 1 && bad?["ok"] == .bool(false) && bad?["error"]?.string == "incorrect passphrase")
		let (c3, missing) = await run(["list"], [])
		#expect(c3 == 1 && missing?["error"]?.string?.contains("expected a passphrase") == true)
		let (_, vaults) = await run(["vaults"], [])
		#expect(vaults?["vaults"]?.array?.first?.string == "personal")
	}

	@Test func concurrentCommandsDoNotShareContext() async throws {
		let h = home()
		defer { try? FileManager.default.removeItem(atPath: h) }
		let env = ["VAULT_HOME": h]
		_ = await VaultCommands.execute(["--json", "--passphrase-stdin", "init"], secrets: ["pw"], environment: env)
		await withTaskGroup(of: (Int32, String).self) { g in
			for i in 0..<6 {
				g.addTask {
					let secrets = i % 2 == 0 ? ["pw"] : ["wrong"]
					let r = await VaultCommands.execute(["--json", "--passphrase-stdin", "list"], secrets: secrets, environment: env)
					return (r.exitCode, r.stdout)
				}
			}
			var ok = 0, denied = 0
			for await (code, out) in g {
				if code == 0 && out.contains("\"items\"") { ok += 1 }
				if code == 1 && out.contains("incorrect passphrase") { denied += 1 }
			}
			#expect(ok == 3 && denied == 3)
		}
	}

	@Test func textModeAndUnknownCommandsStayOffTheRealStdout() async {
		let r = await VaultCommands.execute(["version"])
		#expect(r.exitCode == 0 && r.stdout.contains("swift"))
		let u = await VaultCommands.execute(["definitely-not-a-command"])
		#expect(u.exitCode == 2 && u.stderr.contains("unknown command"))
	}
}
