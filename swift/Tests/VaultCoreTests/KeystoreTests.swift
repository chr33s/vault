import Foundation
import Testing

@testable import VaultCore

private func tempDir() -> String {
	let d = FileManager.default.temporaryDirectory.appendingPathComponent("vault-ks-\(UUID().uuidString)").path
	try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
	return d
}

// Deterministic stand-in for a Hello-gated key: sig = sha256("oracle" || challenge).
private struct OracleSigner: HelloSigner {
	var deterministic = true
	var created: Box = Box()
	final class Box: @unchecked Sendable { var creates = 0 }
	func available() async -> Bool { true }
	func sign(_ challenge: Data, create: Bool) async throws -> Data {
		if create { created.creates += 1 }
		return deterministic ? VaultCrypto.sha256(Data("oracle".utf8) + challenge) : VaultCrypto.randomBytes(32)
	}
}

@Suite struct HelloTests {
	@Test func opensTypeScriptWrittenBlob() async throws {
		let h = try Vectors.load("crypto.json").at("hello")
		let cipher = HelloCipher(signer: OracleSigner())
		let duk = try await cipher.unprotect(b64(h.str("blob")), name: h.str("name"))
		#expect(duk.base64 == h.str("duk"))
		// The keystore id is bound as AEAD data: a renamed blob must not open.
		await #expect(throws: Error.self) { try await cipher.unprotect(b64(h.str("blob")), name: "other") }
	}

	@Test func roundTripAndFormat() async throws {
		let signer = OracleSigner()
		let cipher = HelloCipher(signer: signer)
		let blob = try await cipher.protect(Data("duk".utf8), name: "n")
		#expect(blob.prefix(4) == Data("VHW1".utf8) && blob.count == 4 + 32 + 12 + 16 + 3)
		#expect(try await cipher.unprotect(blob, name: "n") == Data("duk".utf8))
		#expect(signer.created.creates == 1)  // only enrollment may mint the credential
		await #expect(throws: Error.self) { try await cipher.unprotect(Data(blob.dropLast()), name: "n") }
		await #expect(throws: Error.self) { try await cipher.unprotect(Data("nope".utf8), name: "n") }
	}

	@Test func refusesNonDeterministicSigner() async {
		let cipher = HelloCipher(signer: OracleSigner(deterministic: false))
		await #expect(throws: VaultError.self) { try await cipher.protect(Data("duk".utf8), name: "n") }
	}
}

// The stubs below are /bin/sh scripts and the checks use POSIX permissions and tools.
#if os(Windows)
	let onWindows = true
#else
	let onWindows = false
#endif

@Suite(.disabled(if: onWindows, "POSIX shell stubs")) struct BlobKeystoreTests {
	// A tiny systemd-creds double: name-bound, base64 wrapped.
	private func stub(_ dir: String) throws -> String {
		let path = dir + "/systemd-creds-stub"
		let script = """
			#!/bin/sh
			cmd=$1; name=${2#--name=}
			if [ "$cmd" = encrypt ]; then printf 'CRED:%s:%s:' "$name" "${3#--with-key=}"; base64
			else
			  data=$(cat); prefix="CRED:$name:"
			  case "$data" in "$prefix"*) rest=${data#$prefix}; printf '%s' "${rest#*:}" | base64 -d;; *) echo bad >&2; exit 1;; esac
			fi
			"""
		try script.write(toFile: path, atomically: true, encoding: .utf8)
		try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
		return path
	}

	@Test func systemdCredsStoreLifecycle() async throws {
		let dir = tempDir()
		defer { try? FileManager.default.removeItem(atPath: dir) }
		let cipher = SystemdCredsCipher(keyMode: "tpm2", binary: try stub(dir), requireLinux: false)
		#expect(cipher.bindingMode == "tpm2")
		let ks = BlobKeyStore(name: "systemd-creds", subdir: "systemd-creds", ext: "cred", cipher: cipher, root: dir)
		#expect(await ks.available())
		let secret = VaultCrypto.randomBytes(32)
		try await ks.put(id: "vault-1", secret: secret)
		#expect(try await ks.get(id: "vault-1") == secret)
		let file = dir + "/systemd-creds/vault-1.cred"
		#expect((try FileManager.default.attributesOfItem(atPath: file)[.posixPermissions] as? Int) == 0o600)
		// A blob copied to another id no longer opens (--name binding).
		try FileManager.default.copyItem(atPath: file, toPath: dir + "/systemd-creds/vault-2.cred")
		#expect(try await ks.get(id: "vault-2") == nil)
		#expect(try await ks.get(id: "missing") == nil)
		await #expect(throws: VaultError.self) { try await ks.put(id: "../evil", secret: secret) }
		try await ks.delete(id: "vault-1")
		#expect(try await ks.get(id: "vault-1") == nil)
	}

	@Test func systemdCredsUnavailableWhenBinaryMissingOrOffLinux() async {
		#expect(await SystemdCredsCipher(binary: "/nonexistent/systemd-creds", requireLinux: false).available() == false)
		#if !os(Linux)
			#expect(await SystemdCredsCipher().available() == false)
		#endif
		#if !os(Windows)
			#expect(await DpapiCipher().available() == false)
		#endif
	}

	@Test func engineUsesBlobKeystoreEndToEnd() async throws {
		let dir = tempDir()
		defer { try? FileManager.default.removeItem(atPath: dir) }
		let ks = BlobKeyStore(name: "systemd-creds", subdir: "systemd-creds", ext: "cred", cipher: SystemdCredsCipher(keyMode: "host", binary: try stub(dir), requireLinux: false), root: dir)
		let store = try Store(path: ":memory:")
		let kdf = KdfParams.scrypt(salt: Data(repeating: 3, count: 16), n: 1024, r: 8, p: 1, length: 32)
		_ = try await VaultEngine.initialize(store: store, password: Data("p".utf8), keystore: ks, kdf: kdf)
		#expect(try store.meta("keystoreProvider") == "systemd-creds" && store.meta("keystoreKeyMode") == "host")
		_ = try await VaultEngine.unlock(store: store, password: Data("p".utf8), keystore: ks)
		// Disk theft without the blob: cannot unlock at any passphrase strength.
		try FileManager.default.removeItem(atPath: dir + "/systemd-creds")
		await #expect(throws: VaultError.self) { try await VaultEngine.unlock(store: store, password: Data("p".utf8), keystore: ks) }
	}
}

@Suite(.disabled(if: onWindows, "uses cat and sh")) struct ProcessRunnerTests {
	@Test func passesStdinAndReportsExitCodes() async throws {
		let r = try await ProcessRunner.run("cat", [], input: Data("hello".utf8))
		#expect(r.code == 0 && String(decoding: r.stdout, as: UTF8.self) == "hello")
		let f = try await ProcessRunner.run("sh", ["-c", "echo boom >&2; exit 3"])
		#expect(f.code == 3 && String(decoding: f.stderr, as: UTF8.self).contains("boom"))
		let k = try await ProcessRunner.run("sh", ["-c", "kill -9 $$"])
		#expect(k.code != 0)  // signal death is failure
		await #expect(throws: VaultError.self) { try await ProcessRunner.run("definitely-not-a-command", []) }
		// Large payloads must not deadlock the pipes.
		let big = Data(repeating: 65, count: 2_000_000)
		#expect(try await ProcessRunner.run("cat", [], input: big).stdout.count == big.count)
	}
}
