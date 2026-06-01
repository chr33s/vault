// Direct tailnet fallback sync path (spec §8.6; plan §12a M8). Keeps Architecture
// B's direct path alive beside the Cloudflare hub: the SAME op-log over a second
// transport, so a down, throttled, or eclipsing hub can never fully isolate two
// devices that can reach each other over the user's Tailscale tailnet.
//
// Tailscale is the user's OWN OS install — not bundled, not an npm dep (preserves
// §0's zero-runtime-dependency rule). We shell out to its CLI for discovery, and
// let Tailscale handle NAT traversal + transport encryption (spec §7.3). The
// tailnet is the access gate, NEVER the confidentiality boundary: every op stays
// end-to-end encrypted and signed, and a peer only sees ciphertext plus the
// cleartext membership metadata it already gossips through the relay.

import { execFile } from "node:child_process";
import type { Session } from "./engine.ts";
import { syncWithRelay, type RelayAuth } from "./relayclient.ts";

// `tailscale` on PATH, overridable; the macOS GUI app ships the CLI in its bundle
// rather than on PATH, so fall back to that location.
const TS_BIN = process.env.TAILSCALE_BIN ?? "tailscale";
const TS_FALLBACKS = ["/Applications/Tailscale.app/Contents/MacOS/Tailscale"];

export const DEFAULT_PEER_PORT = 8732;

export type TailscalePeer = { name: string; ip: string };
export type TailscaleStatus = { selfIP?: string; peers: TailscalePeer[] };

// Try TS_BIN, then known fallback locations, skipping past "not found".
const runTailscale = (args: string[]): Promise<string> => {
	const bins = [TS_BIN, ...TS_FALLBACKS];
	const attempt = (i: number): Promise<string> =>
		new Promise<string>((resolve, reject) => {
			execFile(bins[i]!, args, { timeout: 5000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
				if (err) {
					const code = (err as NodeJS.ErrnoException).code;
					if (code === "ENOENT" && i + 1 < bins.length) {
						attempt(i + 1).then(resolve, reject);
						return;
					}
					reject(
						code === "ENOENT"
							? new Error(
									"tailscale CLI not found — install Tailscale or set TAILSCALE_BIN (the direct tailnet path needs it)",
								)
							: err,
					);
					return;
				}
				resolve(stdout);
			});
		});
	return attempt(0);
};

// Only the fields of `tailscale status --json` we read.
type StatusJson = {
	Self?: { TailscaleIPs?: string[] };
	Peer?: Record<
		string,
		{ TailscaleIPs?: string[]; DNSName?: string; HostName?: string; Online?: boolean }
	>;
};

const ipv4 = (ips: string[] | undefined): string | undefined => ips?.find((a) => a.includes("."));

export const parseStatus = (json: string): TailscaleStatus => {
	const s = JSON.parse(json) as StatusJson;
	const peers: TailscalePeer[] = [];
	for (const p of Object.values(s.Peer ?? {})) {
		if (!p.Online) continue; // unreachable right now — skip
		const ip = ipv4(p.TailscaleIPs);
		if (!ip) continue;
		peers.push({ name: (p.DNSName ?? p.HostName ?? ip).replace(/\.$/, ""), ip });
	}
	return { selfIP: ipv4(s.Self?.TailscaleIPs), peers };
};

export const tailscaleStatus = async (): Promise<TailscaleStatus> =>
	parseStatus(await runTailscale(["status", "--json"]));

export type TailnetSyncResult = {
	pulled: number;
	pushed: number;
	reached: string[];
	failed: { peer: string; error: string }[];
};

// Run one anti-entropy round against every currently-online tailnet peer at the
// agreed peer port. Reuses syncWithRelay (a peer is just another relay endpoint),
// which reconciles BOTH directions in a single call and dedups on each side.
// Per-peer failures (no server, wrong vault, timeout) are collected, never fatal —
// a sync that reaches some peers still succeeds.
export const syncTailnet = async (
	s: Session,
	opts: { port?: number; auth?: RelayAuth; timeoutMs?: number } = {},
): Promise<TailnetSyncResult> => {
	const port = opts.port ?? DEFAULT_PEER_PORT;
	const { peers } = await tailscaleStatus();
	let pulled = 0;
	let pushed = 0;
	const reached: string[] = [];
	const failed: { peer: string; error: string }[] = [];
	for (const peer of peers) {
		try {
			const st = await syncWithRelay(s, `http://${peer.ip}:${port}`, opts.auth ?? {}, {
				timeoutMs: opts.timeoutMs ?? 8000,
			});
			pulled += st.pulled;
			pushed += st.pushed;
			reached.push(peer.name);
		} catch (err) {
			failed.push({ peer: peer.name, error: err instanceof Error ? err.message : String(err) });
		}
	}
	return { pulled, pushed, reached, failed };
};
