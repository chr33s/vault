#if !os(Windows)  // macOS + Linux only (see Package.swift)
import _CryptoExtras
import Crypto
import Foundation
import Testing

@testable import VaultCore
@testable import VaultNet

private let kdf = KdfParams.scrypt(salt: Data(repeating: 8, count: 16), n: 1024, r: 8, p: 1, length: 32)
private let pass = Data("pw".utf8)

private func b64url(_ d: Data) -> String { d.base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }

@Suite struct RelayServerTests {
	// Two devices of one user converge through the Swift relay; the relay never holds a key.
	@Test func replicasConvergeThroughTheSwiftRelay() async throws {
		let (server, rstore) = try await RelayServer.start(dbPath: ":memory:", host: "127.0.0.1", port: 0, access: AccessConfig(serviceTokens: ["dev-token"]))
		defer { Task { await server.stop() } }
		let url = "http://127.0.0.1:\(server.port)"
		let sa = try Store(path: ":memory:"), sb = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: sa, password: pass, kdf: kdf)
		let owner = try await VaultEngine.unlock(store: sa, password: pass)
		try await owner.addItem(title: "gh", fields: [("password", "pw1")])
		let t = try VaultEngine.authNewDevice(store: sb, password: pass, kdf: kdf)
		_ = try await VaultEngine.deviceConfirm(store: sb, password: pass, token: try await owner.deviceAdd(t))
		let dev = try await VaultEngine.unlock(store: sb, password: pass)

		await #expect(throws: Error.self) { try await owner.syncWithRelay(url: url) }  // no token: refused
		let auth = RelayAuth(token: "dev-token")
		try await owner.syncWithRelay(url: url, auth: auth)
		try await dev.syncWithRelay(url: url, auth: auth)
		#expect(await dev.item(title: "gh")?.passwords == ["pw1"])
		try await dev.editItem(title: "gh", fields: [("username", "d")])
		try await dev.syncWithRelay(url: url, auth: auth)
		try await owner.syncWithRelay(url: url, auth: auth)
		#expect(await owner.item(title: "gh")?.fields["username"] == "d")
		// Cleartext metadata only: the stored payloads hold no plaintext.
		let team = try await owner.vaultId
		#expect(try rstore.opsSince(team, [:]).allSatisfy { !String(decoding: Data(base64: $0.payload), as: UTF8.self).contains("pw1") })
	}

	@Test func refusesForgedOpsAndUnauthenticatedMetadata() async throws {
		let store = try RelayStore(path: ":memory:")
		let sa = try Store(path: ":memory:")
		_ = try await VaultEngine.initialize(store: sa, password: pass, kdf: kdf)
		let e = try await VaultEngine.unlock(store: sa, password: pass)
		let team = try await e.vaultId
		let deps = RelayServer.deps(store: store, access: AccessVerifier(AccessConfig()))
		func push(_ j: [JSONMember]) async -> RelayResponse {
			await RelayHandler.handle(RelayRequest(method: "POST", path: "/push", headers: [:], body: JSONValue.object([JSONMember("teamId", .string(team))] + j).serialized()), store: store, deps: deps)
		}
		// A forged op is refused before any membership exists...
		let forged = OpEnvelope(deviceId: "x", seq: 1, hash: "h", sig: "s", payload: "p")
		#expect(await push([JSONMember("ops", .array([forged.json]))]).body["accepted"]?.int == 0)
		// ...the real log establishes the team; junk entries are then not persisted.
		let log = try sa.authLog()
		_ = await push([JSONMember("ops", .array([])), JSONMember("authLog", .array(log.map(\.json)))])
		let held = try store.authExcept(team, []).count
		#expect(held == log.count)
		let junk = try (0..<50).map { i -> LogEntry in
			let k = VaultCrypto.generateEd25519()
			return try AuthLog.makeEntry(parents: [], body: .removeUser(userId: "v\(i)"), signerId: "nobody", signerKind: .device, signerPriv: k.privateKey)
		}
		_ = await push([JSONMember("ops", .array([])), JSONMember("authLog", .array(junk.map(\.json)))])
		#expect(try store.authExcept(team, []).count == held)
		// Real ops from the authorized device are accepted; a grant slot is first-write-wins.
		let ops = try sa.allOps()
		#expect(await push([JSONMember("ops", .array(ops.map(\.json)))]).body["accepted"]?.int == Int64(ops.count))
		let g1 = GrantRow(principal: "orgPublicKey", keyVersion: 0, wrapped: "one", signerId: "s", sig: "g")
		try store.putGrant(team, g1)
		try store.putGrant(team, GrantRow(principal: "orgPublicKey", keyVersion: 0, wrapped: "two", signerId: "s", sig: "g"))
		#expect(try store.allGrants(team).first?.wrapped == "one")
	}

	@Test func reopensItsOwnDatabase() throws {
		// The schema is created idempotently and survives a reopen.
		let path = NSTemporaryDirectory() + "relay-\(UUID().uuidString).db"
		defer { for s in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + s) } }
		let s = try RelayStore(path: path)
		s.close()
		let again = try RelayStore(path: path)
		#expect(try again.vector("t").isEmpty)
	}
}

@Suite struct AccessTests {
	private func jwt(_ key: _RSA.Signing.PrivateKey, kid: String = "k1", alg: String = "RS256", aud: String = "aud1", iss: String = "https://team.cloudflareaccess.com", exp: Double? = nil, nbf: Double? = nil) throws -> String {
		var payload: [JSONMember] = [JSONMember("aud", .string(aud)), JSONMember("iss", .string(iss)), JSONMember("sub", "user")]
		if let exp { payload.append(JSONMember("exp", .int(Int64(exp)))) }
		if let nbf { payload.append(JSONMember("nbf", .int(Int64(nbf)))) }
		let head = b64url(JSONValue.obj(["alg": .string(alg), "kid": .string(kid)]).serialized())
		let body = b64url(JSONValue.object(payload).serialized())
		let sig = try key.signature(for: Data("\(head).\(body)".utf8), padding: .insecurePKCS1v1_5)
		return "\(head).\(body).\(b64url(sig.rawRepresentation))"
	}

	private func jwks(_ key: _RSA.Signing.PrivateKey, kid: String = "k1") throws -> Data {
		let pub = key.publicKey
		let n = try pub.getKeyPrimitives()
		return JSONValue.obj(["keys": .array([.obj(["kty": "RSA", "kid": .string(kid), "n": .string(b64url(n.modulus)), "e": .string(b64url(n.publicExponent))])])]).serialized()
	}

	private func verifier(_ key: _RSA.Signing.PrivateKey, fetches: FetchCounter = FetchCounter()) -> AccessVerifier {
		var cfg = AccessConfig(teamDomain: "team.cloudflareaccess.com", audience: "aud1")
		let data = try! jwks(key)
		cfg.fetchJWKS = { _ in
			fetches.bump()
			return data
		}
		return AccessVerifier(cfg)
	}

	final class FetchCounter: @unchecked Sendable {
		private let l = NSLock()
		private var n = 0
		func bump() { l.lock(); n += 1; l.unlock() }
		var count: Int { l.lock(); defer { l.unlock() }; return n }
	}

	@Test func verifiesCloudflareAccessJwts() async throws {
		let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
		let now = Date().timeIntervalSince1970
		let counter = FetchCounter()
		let v = verifier(key, fetches: counter)
		func ok(_ t: String) async -> Bool { await v.authorize(["cf-access-jwt-assertion": t]) }
		#expect(await ok(try jwt(key, exp: now + 300)))
		#expect(counter.count == 1)
		_ = await ok(try jwt(key, exp: now + 300))
		#expect(counter.count == 1)  // JWKS cached across requests
		// Every claim is enforced, and exp/iss are REQUIRED rather than merely tolerated.
		#expect(!(await ok(try jwt(key, exp: now - 10))))
		#expect(!(await ok(try jwt(key))))  // no exp
		#expect(!(await ok(try jwt(key, aud: "other", exp: now + 300))))
		#expect(!(await ok(try jwt(key, iss: "https://evil.example", exp: now + 300))))
		#expect(!(await ok(try jwt(key, exp: now + 300, nbf: now + 3600))))
		#expect(!(await ok(try jwt(key, alg: "HS256", exp: now + 300))))
		#expect(!(await ok(try jwt(key, alg: "none", exp: now + 300))))
		// A token signed by a different key, or naming an unknown kid, is refused.
		let other = try _RSA.Signing.PrivateKey(keySize: .bits2048)
		#expect(!(await ok(try jwt(other, exp: now + 300))))
		#expect(!(await ok(try jwt(key, kid: "unknown", exp: now + 300))))
		let junk1 = await ok("not.a.jwt"), junk2 = await ok("a.b")
		#expect(!junk1 && !junk2)
	}

	@Test func serviceTokensAndFailClosedDefaults() async {
		let tokens = AccessVerifier(AccessConfig(serviceTokens: ["t1", "t2"]))
		let good = await tokens.authorize(["cf-access-token": "t2"])
		let bad = await tokens.authorize(["cf-access-token": "t"]), none = await tokens.authorize([:])
		let dev = await AccessVerifier(AccessConfig()).authorize([:])  // dev: open
		let closed = await AccessVerifier(AccessConfig(requireAccess: true)).authorize([:])  // public deploy: closed
		#expect(good && !bad && !none && dev && !closed)
	}

	@Test func jwksOutageDoesNotTrustARetiredKeyForever() async throws {
		let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
		final class Clock: @unchecked Sendable { var t = Date(); }
		let clock = Clock()
		final class Up: @unchecked Sendable { var up = true }
		let net = Up()
		var cfg = AccessConfig(teamDomain: "team.cloudflareaccess.com", audience: "aud1")
		let data = try jwks(key)
		cfg.fetchJWKS = { _ in
			if net.up { return data }
			throw RelayError(description: "down")
		}
		let v = AccessVerifier(cfg, now: { clock.t })
		let t = try jwt(key, exp: clock.t.timeIntervalSince1970 + 86400)
		#expect(await v.authorize(["cf-access-jwt-assertion": t]))
		net.up = false
		clock.t.addTimeInterval(11 * 60)  // past TTL: refresh fails, stale set still serves
		#expect(await v.authorize(["cf-access-jwt-assertion": t]))
		clock.t.addTimeInterval(2 * 3600)  // past the max-stale window: refuse
		#expect(!(await v.authorize(["cf-access-jwt-assertion": t])))
	}
}
#endif
