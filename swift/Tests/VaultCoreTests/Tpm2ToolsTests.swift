import Foundation
import Testing

@testable import VaultCore

// A POSIX-sh double for the tpm2-tools binaries: objects live in files, the PIN is an
// auth value checked on unseal, and every invocation's argv is logged so tests can prove
// secrets never appear on a command line.
private struct FakeTpm {
	let dir: String
	var log: String { dir + "/argv.log" }

	init() throws {
		dir = NSTemporaryDirectory() + "vault-faketpm-\(UUID().uuidString)"
		try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
		func tool(_ name: String, _ body: String) throws {
			let p = dir + "/" + name
			try ("#!/bin/sh\necho \"\(name) $*\" >> \"\(dir)/argv.log\"\n" + body).write(toFile: p, atomically: true, encoding: .utf8)
			try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: p)
		}
		let opt = #"""
			opt() { key=$1; shift; while [ $# -gt 0 ]; do [ "$1" = "$key" ] && { echo "$2"; return; }; shift; done; }
			pinof() { p=$(opt -p "$@"); [ -n "$p" ] && cat "${p#file:}" || true; }
			"""#
		try tool("tpm2_getrandom", "printf x\n")
		try tool("tpm2_flushcontext", "")
		try tool("tpm2_createprimary", opt + "\nprintf PRIMARY > \"$(opt -c \"$@\")\"\n")
		try tool("tpm2_create", opt + #"""

			pin=$(pinof "$@"); data=$(base64)
			printf 'PUB' > "$(opt -u "$@")"
			printf '%s|%s' "$data" "$pin" > "$(opt -r "$@")"
			"""#)
		try tool("tpm2_load", opt + #"""

			[ -f "$(opt -C "$@")" ] && [ -f "$(opt -u "$@")" ] || exit 1
			cp "$(opt -r "$@")" "$(opt -c "$@")"
			"""#)
		try tool("tpm2_unseal", opt + #"""

			pin=$(pinof "$@"); blob=$(cat "$(opt -c "$@")")
			[ "${blob#*|}" = "$pin" ] || { echo denied >&2; exit 1; }
			printf '%s' "${blob%%|*}" | base64 -d
			"""#)
	}

	func argv() -> String { (try? String(contentsOfFile: log, encoding: .utf8)) ?? "" }
	func cleanup() { try? FileManager.default.removeItem(atPath: dir) }
}


@Suite(.disabled(if: onWindows, "POSIX shell stubs")) struct Tpm2ToolsCipherTests {
	@Test func sealsAndUnsealsWithoutPin() async throws {
		let t = try FakeTpm()
		defer { t.cleanup() }
		let c = Tpm2ToolsCipher(pin: nil, binDir: t.dir)
		#expect(await c.available())
		let secret = VaultCrypto.randomBytes(32)
		let blob = try await c.protect(secret, name: "vault-1")
		#expect(blob.prefix(4) == Data("VTP1".utf8))
		#expect(try await c.unprotect(blob, name: "vault-1") == secret)
		#expect(c.bindingMode == "")
		// The private work dirs (contexts, sealed files, PIN file) are always removed.
		let workdirs = Set(t.argv().split(separator: " ").filter { $0.contains("/vault-tpm2-") }.map { ($0.description as NSString).deletingLastPathComponent })
		#expect(!workdirs.isEmpty && workdirs.allSatisfy { !FileManager.default.fileExists(atPath: $0) })
		// Sealing uses a data object that cannot leave the TPM and keeps lockout protection on.
		let log = t.argv()
		#expect(log.contains("fixedtpm|fixedparent|userwithauth") && !log.contains("noda"))
		// Transient objects are flushed after each step, or a raw TPM runs out of slots.
		#expect(log.components(separatedBy: "tpm2_flushcontext -t").count - 1 == 5)
	}

	@Test func aBlobCopiedToAnotherIdIsRefused() async throws {
		let t = try FakeTpm()
		defer { t.cleanup() }
		let c = Tpm2ToolsCipher(pin: nil, binDir: t.dir)
		let blob = try await c.protect(Data("duk".utf8), name: "vault-a")
		await #expect(throws: VaultError.self) { try await c.unprotect(blob, name: "vault-b") }
	}

	@Test func pinGatesUnsealAndNeverAppearsOnArgv() async throws {
		let t = try FakeTpm()
		defer { t.cleanup() }
		let pin = "correct-pin-8842"
		let c = Tpm2ToolsCipher(pin: pin, binDir: t.dir)
		#expect(c.bindingMode == "pin")
		let blob = try await c.protect(Data("duk".utf8), name: "v")
		#expect(try await c.unprotect(blob, name: "v") == Data("duk".utf8))
		#expect(!t.argv().contains(pin) && t.argv().contains("file:"))  // PIN goes through a 0600 file, not argv
		// Wrong PIN and missing PIN are both refused by the TPM.
		await #expect(throws: VaultError.self) { try await Tpm2ToolsCipher(pin: "wrong", binDir: t.dir).unprotect(blob, name: "v") }
		await #expect(throws: VaultError.self) { try await Tpm2ToolsCipher(pin: nil, binDir: t.dir).unprotect(blob, name: "v") }
	}

	@Test func aMissingPinIsRejectedBeforeTouchingTheTpm() async throws {
		let t = try FakeTpm()
		defer { t.cleanup() }
		let blob = try await Tpm2ToolsCipher(pin: "1234", binDir: t.dir).protect(Data("duk".utf8), name: "v")
		let before = t.argv()
		// A vault sealed with a PIN: unlocking without one must not burn a lockout attempt.
		await #expect(throws: VaultError.self) { try await Tpm2ToolsCipher(pin: nil, requirePin: true, binDir: t.dir).unprotect(blob, name: "v") }
		#expect(t.argv() == before)
	}

	@Test func malformedBlobsAndMissingToolsAreClearFailures() async throws {
		let t = try FakeTpm()
		defer { t.cleanup() }
		let c = Tpm2ToolsCipher(pin: nil, binDir: t.dir)
		await #expect(throws: VaultError.self) { try await c.unprotect(Data("nope".utf8), name: "v") }
		await #expect(throws: VaultError.self) { try await c.unprotect(Data("VTP1".utf8) + Data([0xFF, 0xFF, 0xFF, 0xFF, 1, 2]), name: "v") }
		#expect(await Tpm2ToolsCipher(pin: nil, binDir: "/nonexistent").available() == false)
		await #expect(throws: VaultError.self) { try await Tpm2ToolsCipher(pin: nil, binDir: "/nonexistent").protect(Data([1]), name: "v") }
	}

	@Test func engineSealsItsUnlockKeyToTheTpmEndToEnd() async throws {
		let t = try FakeTpm()
		let root = NSTemporaryDirectory() + "vault-tpmroot-\(UUID().uuidString)"
		defer {
			t.cleanup()
			try? FileManager.default.removeItem(atPath: root)
		}
		func ks(pin: String?, requirePin: Bool = false) -> BlobKeyStore {
			BlobKeyStore(name: "tpm2", subdir: "tpm2", ext: "tpm2", cipher: Tpm2ToolsCipher(pin: pin, requirePin: requirePin, binDir: t.dir), root: root)
		}
		let store = try Store(path: ":memory:")
		let kdf = KdfParams.scrypt(salt: Data(repeating: 2, count: 16), n: 1024, r: 8, p: 1, length: 32)
		_ = try await VaultEngine.initialize(store: store, password: Data("p".utf8), keystore: ks(pin: "9999"), kdf: kdf)
		#expect(try store.meta("keystoreProvider") == "tpm2" && store.meta("keystoreKeyMode") == "pin")
		_ = try await VaultEngine.unlock(store: store, password: Data("p".utf8), keystore: ks(pin: "9999", requirePin: true))
		// Disk theft: the passphrase alone (even if brute-forced) cannot unlock without the TPM's PIN gate.
		await #expect(throws: VaultError.self) { try await VaultEngine.unlock(store: store, password: Data("p".utf8), keystore: ks(pin: "0000", requirePin: true)) }
		await #expect(throws: VaultError.self) { try await VaultEngine.unlock(store: store, password: Data("p".utf8), keystore: ks(pin: nil, requirePin: true)) }
	}

	// Runs only where a real (or swtpm) TPM and tpm2-tools exist: CI's swtpm job sets this.
	@Test(.enabled(if: ProcessInfo.processInfo.environment["VAULT_TPM2_REAL"] == "1"))
	func realTpm() async throws {
		let c = Tpm2ToolsCipher(pin: "real-pin-1")
		#expect(await c.available())
		let secret = VaultCrypto.randomBytes(32)
		let blob = try await c.protect(secret, name: "vault-real")
		#expect(try await c.unprotect(blob, name: "vault-real") == secret)
		await #expect(throws: Error.self) { try await Tpm2ToolsCipher(pin: "bad-pin").unprotect(blob, name: "vault-real") }
		await #expect(throws: Error.self) { try await c.unprotect(blob, name: "other-id") }
	}
}
