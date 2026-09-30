#if !os(Windows)  // VaultNet is empty on Windows (see Package.swift)
import Foundation
import VaultCore

// Direct tailnet fallback sync: the same op log over a second
// transport, so a down or eclipsing hub can never fully isolate two devices that
// can reach each other over the user's Tailscale tailnet. Tailscale is the user's
// own OS install; we shell out to its CLI for discovery. The tailnet is the access
// gate, never the confidentiality boundary.

public enum Tailnet {
	public static let defaultPeerPort = 8732

	public struct Peer: Sendable, Equatable {
		public var name: String
		public var ip: String
	}

	public struct Status: Sendable, Equatable {
		public var selfIP: String?
		public var peers: [Peer]
	}

	public struct SyncResult: Sendable {
		public var pulled = 0
		public var pushed = 0
		public var reached: [String] = []
		public var failed: [(peer: String, error: String)] = []
	}

	private static func ipv4(_ j: JSONValue?) -> String? { j?.array?.compactMap { $0.string }.first { $0.contains(".") } }

	// Only the fields of `tailscale status --json` we read; offline peers are skipped.
	public static func parseStatus(_ json: String) throws -> Status {
		let s = try JSONValue.parse(json)
		var peers: [Peer] = []
		for p in s["Peer"]?.members ?? [] {
			guard p.value["Online"] == .bool(true), let ip = ipv4(p.value["TailscaleIPs"]) else { continue }
			var name = p.value["DNSName"]?.string ?? p.value["HostName"]?.string ?? ip
			if name.hasSuffix(".") { name.removeLast() }
			peers.append(Peer(name: name, ip: ip))
		}
		return Status(selfIP: ipv4(s["Self"]?["TailscaleIPs"]), peers: peers)
	}

	// TAILSCALE_BIN, `tailscale` on PATH, then the macOS app bundle's CLI.
	static func candidates(environment env: [String: String] = ProcessInfo.processInfo.environment) -> [String] {
		[env["TAILSCALE_BIN"] ?? "tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"]
	}

	public static func status(binaries: [String]? = nil) async throws -> Status {
		for bin in binaries ?? candidates() {
			guard ProcessRunner.resolve(bin) != nil else { continue }
			let r = try await ProcessRunner.run(bin, ["status", "--json"])
			guard r.code == 0 else { throw VaultError.invalidArgument("tailscale status failed (exit \(r.code))") }
			return try parseStatus(String(decoding: r.stdout, as: UTF8.self))
		}
		throw VaultError.invalidArgument("tailscale CLI not found — install Tailscale or set TAILSCALE_BIN (the direct tailnet path needs it)")
	}

	// One anti-entropy round against every online peer at the agreed port (a peer is
	// just another relay endpoint). Per-peer failures are collected, never fatal.
	// When an allowlist is set, the peer token is presented ONLY to those nodes:
	// otherwise every online node would receive it on the first round.
	public static func sync(
		_ engine: VaultEngine, peers all: [Peer], port: Int = defaultPeerPort, auth: RelayAuth = RelayAuth(), timeout: TimeInterval = 8,
		allow: [String] = []
	) async -> SyncResult {
		let allowed = allow.map { $0.lowercased() }
		let peers = allowed.isEmpty ? all : all.filter { allowed.contains($0.name.lowercased()) || allowed.contains($0.ip) }
		var out = SyncResult()
		for p in peers {
			do {
				let st = try await engine.syncWithRelay(url: "http://\(p.ip):\(port)", auth: auth, timeout: timeout)
				out.pulled += st.pulled
				out.pushed += st.pushed
				out.reached.append(p.name)
			} catch {
				out.failed.append((p.name, "\(error)"))
			}
		}
		return out
	}
}
#endif
