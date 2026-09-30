import Foundation
import Testing

@testable import VaultCore

@Suite struct DotEnvTests {
	@Test func parsesManifest() throws {
		let d = try DotEnv.parse("""
			# comment
			BARE
			EMPTY=
			export LIT=value # trailing
			QUOTED="p@ss # w0rd"
			SINGLE='a b'
			REF=vault://personal/db/url
			x-api-key=abc
			""")
		#expect(d.map(\.key) == ["BARE", "EMPTY", "LIT", "QUOTED", "SINGLE", "REF", "x-api-key"])
		#expect(d.map(\.value) == [nil, "", "value", "p@ss # w0rd", "a b", "vault://personal/db/url", "abc"])
		#expect(throws: VaultError.self) { try DotEnv.parse("2FA_TOKEN=") }
		#expect(DotEnv.parseRef("vault://v/i/f") == VaultRef(vault: "v", item: "i", field: "f"))
		#expect(DotEnv.parseRef("vault://v") == nil && DotEnv.parseRef("x") == nil)
	}
}

@Suite struct ScrubberTests {
	@Test func redactsValueAndCommonEncodings() {
		let s = Scrubber()
		s.register("s3cr3t value!")
		s.register("short")  // below the minimum length: ignored
		#expect(s.scrub("a s3cr3t value! b") == "a [REDACTED] b")
		#expect(s.scrub("q=s3cr3t%20value!") == "q=[REDACTED]")
		#expect(s.scrub("q=s3cr3t+value%21") == "q=[REDACTED]")
		#expect(s.scrub("auth \(Data("s3cr3t value!".utf8).base64)") == "auth [REDACTED]")
		#expect(s.scrub("short stays") == "short stays")
	}

	@Test func streamingRedactsAcrossChunkBoundaries() {
		let s = Scrubber()
		s.register("hunter2hunter2")
		let st = s.stream()
		var out = Data()
		for chunk in ["prefix hunt", "er2hunt", "er2 suffix and hunt"] { out += st.feed(Data(chunk.utf8)) }
		out += st.flush()
		#expect(String(decoding: out, as: UTF8.self) == "prefix [REDACTED] suffix and hunt")
	}

	@Test func passthroughWithoutSecrets() {
		let st = Scrubber().stream()
		#expect(st.feed(Data("abc".utf8)) == Data("abc".utf8))
	}
}

@Suite struct ResolveTests {
	@Test func precedenceAndReferences() async throws {
		let store = try Store(path: ":memory:")
		let kdf = KdfParams.scrypt(salt: Data(repeating: 1, count: 16), n: 1024, r: 8, p: 1, length: 32)
		_ = try await VaultEngine.initialize(store: store, password: Data("p".utf8), kdf: kdf)
		let e = try await VaultEngine.unlock(store: store, password: Data("p".utf8))
		try await e.addItem(title: "DB_URL", fields: [("password", "pg://secret")])
		try await e.addItem(title: "api", fields: [("token", "tok"), ("password", "pw")])
		let env: [String: String] = ["AMBIENT": "from-env", "EMPTY_ENV": ""]
		func r(_ k: String, _ v: String?, open: String? = "personal") async throws -> String? {
			try await e.resolve(EnvDecl(key: k, value: v), openVault: open, environment: env)
		}
		#expect(try await r("AMBIENT", "vault://personal/api/token") == "from-env")  // ambient wins
		#expect(try await r("EMPTY_ENV", "lit") == "lit")  // empty ambient does not
		#expect(try await r("DB_URL", nil) == "pg://secret")  // bare -> item by name
		#expect(try await r("X", "vault://personal/api/token") == "tok")
		#expect(try await r("X", "vault://personal/api") == "pw")
		#expect(try await r("X", "literal") == "literal")
		#expect(try await r("MISSING", nil) == nil)
		await #expect(throws: VaultError.self) { try await r("X", "vault://prod/api/token") }  // wrong vault open
		await #expect(throws: VaultError.self) { try await r("X", "vault://bad") }
	}
}
