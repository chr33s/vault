// HTTP peer server for the §8.6 direct tailnet path. Exposes this device's local
// replica through the SAME transport-agnostic relay handler (relay/handler.ts),
// backed by a PeerStore over the device's Store. It holds no keys and runs while
// the vault is locked — a device acting as "just another replica" (spec §8).
//
// The caller binds it to the Tailscale interface (the tailnet IP), so it is
// reachable over the tailnet — the access gate (spec §7.3, §8.6) — and not the
// LAN or any public interface. An optional shared token adds a second gate on top,
// reusing the relay's Cloudflare-Access model (the `cf-access-token` header); with
// no token it is open to the whole tailnet (documented). Confidentiality never
// rests on either gate: ops stay end-to-end encrypted and signed.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { verifyEnvelope } from "../core/protocol.ts";
import type { Store } from "../core/store.ts";
import { authorizeHeaders, type AccessConfig } from "../relay/access.ts";
import { handle } from "../relay/handler.ts";
import { PeerStore } from "./peerstore.ts";

const readBody = async (req: IncomingMessage): Promise<unknown> => {
	const chunks: Buffer[] = [];
	let size = 0;
	for await (const c of req) {
		size += (c as Buffer).length;
		if (size > 16 * 1024 * 1024) throw new Error("payload too large");
		chunks.push(c as Buffer);
	}
	return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
};

const send = (res: ServerResponse, status: number, body: unknown): void => {
	res.writeHead(status, { "content-type": "application/json" });
	res.end(JSON.stringify(body));
};

export type PeerServerOptions = { token?: string };

// Build (but don't listen on) a peer server over `store`, scoped to `vaultId`.
export const createPeerServer = (
	store: Store,
	vaultId: string,
	opts: PeerServerOptions = {},
): Server => {
	const peer = new PeerStore(store, vaultId);
	// A token makes the server fail-closed (require the token); none leaves it open
	// to the tailnet, mirroring the relay's dev-open / configured-closed behavior.
	const access: AccessConfig = opts.token
		? { serviceTokens: new Set([opts.token]), requireAccess: true }
		: {};

	return createServer((req, res) => {
		(async () => {
			const url = new URL(req.url ?? "/", "http://localhost");
			const { status, body } = await handle(
				{
					method: req.method ?? "GET",
					path: url.pathname,
					header: (name) => {
						const v = req.headers[name.toLowerCase()];
						return Array.isArray(v) ? v[0] : v;
					},
					body: () => readBody(req),
				},
				peer,
				{
					authorize: (header) => authorizeHeaders(header, access),
					// Cheap integrity check; the owner re-verifies signatures at replay.
					verifyOp: (op) => verifyEnvelope(op),
				},
			);
			send(res, status, body);
		})().catch((err) => {
			send(res, 500, { error: err instanceof Error ? err.message : "internal error" });
		});
	});
};
