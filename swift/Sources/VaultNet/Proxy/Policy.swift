#if !os(Windows)  // VaultNet is empty on Windows (see Package.swift)
import Foundation
import VaultCore

// Proxy policy manifests. One `.env`-format file per upstream: the
// reserved `UPSTREAM=` key names the destination (a literal URL, never resolved
// from the vault); a `?name` key is a query-param injection; every other key is a
// request header. Values resolve with `run`'s precedence (ambient -> literal -> vault).

public struct Injection: Sendable, Equatable {
	public enum Kind: Sendable { case header, query }
	public var kind: Kind
	public var name: String
	public var value: String
}

public struct Policy: Sendable {
	public var upstream: URL
	public var injections: [Injection]

	public var isHTTPS: Bool { upstream.scheme == "https" }
	public var hostname: String { (upstream.host ?? "").lowercased() }
	// `host[:port]`, omitting the scheme's default port (Node's URL.host).
	public var host: String { Policy.hostKey(host: hostname, port: upstream.port, https: isHTTPS) }

	static func hostKey(host: String, port: Int?, https: Bool) -> String {
		guard let port, port != (https ? 443 : 80) else { return host }
		return "\(host):\(port)"
	}
}

public struct LoadedPolicies: Sendable {
	public var byHost: [String: Policy]  // keyed `host[:port]`: absolute-URI allowlist
	public var byHostname: [String: Policy]  // bare hostname: CONNECT / Host-header match
	public var defaultPolicy: Policy  // first file: origin-form (base-URL mode) requests
}

public enum ProxyPolicies {
	public static let defaultPort = 8788
	static let reservedUpstream = "UPSTREAM"

	public static func parse(_ text: String, engine: VaultEngine, openVault: String?, scrubber: Scrubber) async throws -> Policy {
		var upstream: URL?
		var injections: [Injection] = []
		for decl in try DotEnv.parse(text) {
			if decl.key == reservedUpstream {
				guard let v = decl.value, !v.isEmpty else { throw VaultError.invalidArgument("UPSTREAM= must be a literal http(s) URL") }
				guard let c = URLComponents(string: v), let scheme = c.scheme?.lowercased(), c.host?.isEmpty == false else {
					throw VaultError.invalidArgument("bad UPSTREAM URL: \(v)")
				}
				guard scheme == "http" || scheme == "https" else { throw VaultError.invalidArgument("UPSTREAM must be http(s): \(v)") }
				// Request paths replace the base path, so a base path would be silently
				// dropped: reject it up front.
				guard c.path.isEmpty || c.path == "/", c.query == nil, c.fragment == nil else {
					throw VaultError.invalidArgument("UPSTREAM must be an origin with no path/query: \(v)")
				}
				upstream = c.url
				continue
			}
			let isQuery = decl.key.hasPrefix("?")
			let name = isQuery ? String(decl.key.dropFirst()) : decl.key
			guard !name.isEmpty else { throw VaultError.invalidArgument("bad policy key: \(decl.key)") }
			// Fail fast: a proxy that cannot resolve a declared secret must not start;
			// silently injecting nothing would be worse than an error.
			guard let value = try await engine.resolve(decl, openVault: openVault) else {
				throw VaultError.invalidArgument("cannot resolve policy entry \"\(decl.key)\" from the vault")
			}
			// Registered the moment it exists, so no later error/log path can print it.
			scrubber.register(value)
			injections.append(Injection(kind: isQuery ? .query : .header, name: isQuery ? name : name.lowercased(), value: value))
		}
		guard let upstream else { throw VaultError.invalidArgument("policy is missing a required UPSTREAM= line") }
		return Policy(upstream: upstream, injections: injections)
	}

	public static func load(files: [String], engine: VaultEngine, openVault: String?, scrubber: Scrubber) async throws -> LoadedPolicies {
		guard !files.isEmpty else { throw VaultError.invalidArgument("no --config policy file given") }
		var byHost: [String: Policy] = [:], byHostname: [String: Policy] = [:]
		var first: Policy?
		for f in files {
			guard let data = FileManager.default.contents(atPath: f) else { throw VaultError.invalidArgument("cannot read \(f)") }
			let p = try await parse(String(decoding: data, as: UTF8.self), engine: engine, openVault: openVault, scrubber: scrubber)
			byHost[p.host] = p
			byHostname[p.hostname] = p
			first = first ?? p
		}
		return LoadedPolicies(byHost: byHost, byHostname: byHostname, defaultPolicy: first!)
	}

	// SDK base-URL env vars to preset on a spawned child, by upstream host.
	static let baseURLEnv: [String: [String]] = [
		"api.anthropic.com": ["ANTHROPIC_BASE_URL"], "api.openai.com": ["OPENAI_BASE_URL", "OPENAI_API_BASE"],
	]

	// Always VAULT_PROXY_URL, plus the known base-URL var for each configured upstream.
	// The real secret is never added here: it lives only inside the proxy.
	public static func childEnv(_ p: LoadedPolicies, proxyURL: String) -> (env: [String: String], knownSDK: Bool) {
		var env = ["VAULT_PROXY_URL": proxyURL]
		var known = false
		for host in p.byHost.keys {
			for n in baseURLEnv[host] ?? [] {
				env[n] = proxyURL
				known = true
			}
		}
		return (env, known)
	}

	// CONNECT mode: route HTTPS through us and trust the ephemeral CA through every
	// common trust-store override. `caFile` holds only the public certificate.
	public static func connectEnv(proxyURL: String, caFile: String) -> [String: String] {
		[
			"HTTPS_PROXY": proxyURL, "https_proxy": proxyURL, "NODE_EXTRA_CA_CERTS": caFile, "SSL_CERT_FILE": caFile,
			"REQUESTS_CA_BUNDLE": caFile, "CURL_CA_BUNDLE": caFile,
		]
	}
}
#endif
