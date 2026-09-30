#if !os(Windows)  // VaultNet is empty on Windows (see Package.swift)
import _CryptoExtras
import Crypto
import Foundation
import VaultCore

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

// Access gate for the relay. Two independent, composable layers on
// top of the Tunnel/Access network gate; correctness never depends on either, since
// clients validate all crypto themselves:
//   1. static per-device service tokens on `cf-access-token` (constant-time compare);
//   2. a Cloudflare Access RS256 JWT on `cf-access-jwt-assertion`, verified against the
//      team's JWKS (audience, issuer, exp, nbf pinned; alg pinned to RS256).

public struct AccessConfig: Sendable {
	public var serviceTokens: Set<String> = []
	public var teamDomain: String?  // e.g. "myteam.cloudflareaccess.com"
	public var audience: String?
	// Fail closed on a public deployment: with no usable credential the request is DENIED
	// even if no controls are configured. Local/dev leaves this off.
	public var requireAccess = false
	public var fetchJWKS: @Sendable (URL) async throws -> Data = AccessVerifier.defaultFetch

	public init(serviceTokens: Set<String> = [], teamDomain: String? = nil, audience: String? = nil, requireAccess: Bool = false) {
		self.serviceTokens = serviceTokens
		self.teamDomain = teamDomain
		self.audience = audience
		self.requireAccess = requireAccess
	}

	public var hasControlsPublic: Bool { hasControls }
	var hasControls: Bool { !serviceTokens.isEmpty || (teamDomain != nil && audience != nil) }
}

public actor AccessVerifier {
	static let ttl: TimeInterval = 10 * 60
	static let retry: TimeInterval = 30
	static let maxStale: TimeInterval = 60 * 60

	private struct Cached {
		var keys: [String: (n: Data, e: Data)]
		var fetchedAt: Date
		var retryAt: Date
	}

	private let cfg: AccessConfig
	private var cache: Cached?
	private var failedUntil = Date.distantPast
	// One fetch in flight: the actor is re-entrant, so concurrent requests on a cold or expired
	// cache would otherwise each start their own HTTPS fetch and hammer the certs endpoint.
	private var inflight: Task<Data, Error>?
	private var now: @Sendable () -> Date

	public init(_ cfg: AccessConfig, now: @escaping @Sendable () -> Date = { Date() }) {
		self.cfg = cfg
		self.now = now
	}

	public static let defaultFetch: @Sendable (URL) async throws -> Data = { url in
		var req = URLRequest(url: url)
		req.timeoutInterval = 10  // a slow certs endpoint must not stall every request for URLSession's 60s default
		let (d, r) = try await URLSession.shared.data(for: req)
		guard (r as? HTTPURLResponse)?.statusCode == 200 else { throw RelayError(description: "JWKS fetch failed") }
		return d
	}

	// Gate a request given lowercased headers. Open only when no controls are configured
	// AND access is not required (pure local/dev).
	public func authorize(_ header: [String: String]) async -> Bool {
		guard cfg.hasControls else { return !cfg.requireAccess }
		if let svc = header["cf-access-token"], RelayHandler.tokenAllowed(cfg.serviceTokens, svc) { return true }
		if let jwt = header["cf-access-jwt-assertion"], await verify(jwt) { return true }
		return false
	}

	private static func b64url(_ s: String) -> Data { Data(base64: s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")) }

	func verify(_ token: String) async -> Bool {
		guard let team = cfg.teamDomain, let aud = cfg.audience else { return false }
		let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
		guard parts.count == 3, let header = try? JSONValue.parse(Self.b64url(parts[0])), let payload = try? JSONValue.parse(Self.b64url(parts[1])) else { return false }
		// Pin the algorithm so "none"/"HS256" can never reach the RSA verify.
		guard header["alg"]?.string == "RS256" else { return false }
		let auds: [String] = payload["aud"]?.array?.compactMap { $0.string } ?? payload["aud"]?.string.map { [$0] } ?? []
		guard auds.contains(aud), payload["iss"]?.string == "https://\(team)" else { return false }  // iss REQUIRED
		let t = now().timeIntervalSince1970
		guard let exp = payload["exp"].flatMap({ $0.int.map(Double.init) }), exp >= t else { return false }  // exp REQUIRED
		if let nbf = payload["nbf"]?.int, Double(nbf) > t + 60 { return false }
		guard let kid = header["kid"]?.string, let jwk = await key(kid, team: team) else { return false }
		guard let pub = try? _RSA.Signing.PublicKey(n: jwk.n, e: jwk.e) else { return false }
		return pub.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: Self.b64url(parts[2])), for: Data("\(parts[0]).\(parts[1])".utf8), padding: .insecurePKCS1v1_5)
	}

	// JWKS cache: reused for `ttl`; an unknown kid (key rotation) forces a refetch at most once
	// per `retry`; if a refresh fails the previous set keeps serving for at most `maxStale`
	// past its TTL, so an outage neither stalls every request nor trusts a retired key forever.
	private func key(_ kid: String, team: String) async -> (n: Data, e: Data)? {
		let t = now()
		if let c = cache {
			let usable = t.timeIntervalSince(c.fetchedAt) < Self.ttl + Self.maxStale
			if usable, t < c.retryAt { return c.keys[kid] }
			if t.timeIntervalSince(c.fetchedAt) < Self.ttl, let k = c.keys[kid] { return k }
		}
		let usable = cache.map { t.timeIntervalSince($0.fetchedAt) < Self.ttl + Self.maxStale } ?? false
		if !usable, t < failedUntil { return nil }
		guard let url = URL(string: "https://\(team)/cdn-cgi/access/certs"), let data = try? await fetchShared(url), let keys = Self.parseJWKS(data) else {
			if usable {
				cache?.retryAt = t.addingTimeInterval(Self.retry)
				return cache?.keys[kid]
			}
			failedUntil = t.addingTimeInterval(Self.retry)
			return nil
		}
		failedUntil = .distantPast
		cache = Cached(keys: keys, fetchedAt: t, retryAt: t.addingTimeInterval(Self.retry))
		return keys[kid]
	}

	private func fetchShared(_ url: URL) async throws -> Data {
		if let t = inflight { return try await t.value }
		let fetch = cfg.fetchJWKS
		let t = Task { try await fetch(url) }
		inflight = t
		defer { inflight = nil }
		return try await t.value
	}

	static func parseJWKS(_ data: Data) -> [String: (n: Data, e: Data)]? {
		guard let j = try? JSONValue.parse(data), let arr = j["keys"]?.array else { return nil }  // no keys array => failed fetch
		var out: [String: (n: Data, e: Data)] = [:]
		for k in arr where k["kty"]?.string == "RSA" {
			guard let kid = k["kid"]?.string, let n = k["n"]?.string, let e = k["e"]?.string else { continue }
			out[kid] = (b64url(n), b64url(e))
		}
		return out
	}
}
#endif
