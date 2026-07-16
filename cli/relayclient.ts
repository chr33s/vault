// Relay sync client (spec §7.4, §8). Runs one anti-entropy round against the
// always-on hub over outbound HTTPS: pull the op log, signed auth log, and
// rotation records past what we hold, then push whatever the relay lacks. The
// relay sees opaque OpEnvelopes plus cleartext membership/epoch metadata —
// never vault contents.

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { replay } from "../core/authlog.ts";
import {
	grantAuthentic,
	opsSince,
	rotationId,
	type OpEnvelope,
	type SyncResponse,
	type VersionVector,
} from "../core/protocol.ts";
import type { RotationRecord } from "../core/rotation.ts";
import type { Session } from "./engine.ts";
import { rebuildSession, importAuthAndRotations, contributeRecovery } from "./engine.ts";

// Credentials sent to the relay. Two independent, composable mechanisms:
//   - token: the app-layer per-device token, matched in-relay against
//     VAULT_RELAY_TOKENS (sent as the `cf-access-token` header).
//   - accessId/accessSecret: a Cloudflare Access SERVICE TOKEN. Sent as the
//     `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers that Cloudflare
//     authenticates at the EDGE; on success the edge injects the JWT the relay's
//     verifyAccessJwt checks. Required whenever an Access application fronts the
//     relay, otherwise the edge blocks the request before it reaches the relay.
export type RelayAuth = {
	token?: string;
	accessId?: string;
	accessSecret?: string;
};

const authHeaders = (auth: RelayAuth): Record<string, string> => {
	const h: Record<string, string> = {};
	if (auth.token) h["cf-access-token"] = auth.token;
	if (auth.accessId && auth.accessSecret) {
		h["CF-Access-Client-Id"] = auth.accessId;
		h["CF-Access-Client-Secret"] = auth.accessSecret;
	}
	return h;
};

// Cap on a single relay/peer response body. The relay is partially trusted
// (clients re-verify all crypto), but a compromised/buggy one must not OOM a
// syncing client with an unbounded stream. The peer server applies the same
// inbound cap. Override via PostOptions.maxBytes.
export const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;

export type PostOptions = { timeoutMs?: number; maxBytes?: number };

// Use node:http/https directly rather than fetch: fetch (undici) keeps a
// keep-alive connection pool that holds the event loop open after the request,
// so a CLI would either hang on exit or have to force-exit while those handles
// are still closing (the latter aborts on Windows). A plain request with the
// default agent closes its socket after the response, letting the process exit
// cleanly on its own.
const post = <T>(url: string, body: unknown, auth: RelayAuth, opts: PostOptions = {}): Promise<T> =>
	new Promise<T>((resolve, reject) => {
		const { timeoutMs, maxBytes = MAX_RESPONSE_BYTES } = opts;
		const u = new URL(url);
		const data = Buffer.from(JSON.stringify(body), "utf8");
		const requestFn = u.protocol === "https:" ? httpsRequest : httpRequest;
		const req = requestFn(
			u,
			{
				method: "POST",
				headers: {
					"content-type": "application/json",
					"content-length": data.byteLength,
					...authHeaders(auth),
				},
			},
			(res) => {
				const chunks: Buffer[] = [];
				let size = 0;
				res.on("data", (c: Buffer) => {
					size += c.length;
					if (size > maxBytes) {
						// Abort the transfer and fail; a later 'end'/resolve is a no-op once
						// the promise has rejected.
						req.destroy();
						reject(new Error(`relay response exceeded ${maxBytes} bytes`));
						return;
					}
					chunks.push(c);
				});
				res.on("end", () => {
					const text = Buffer.concat(chunks).toString("utf8");
					const status = res.statusCode ?? 0;
					if (status < 200 || status >= 300) {
						reject(new Error(`relay ${status}: ${text}`));
						return;
					}
					try {
						resolve(JSON.parse(text || "{}") as T);
					} catch (err) {
						reject(err instanceof Error ? err : new Error(String(err)));
					}
				});
			},
		);
		req.on("error", reject);
		// Bound the wait so an unreachable/half-open peer (the §8.6 direct path hits
		// many candidate addresses) can't stall the whole sync. The hub path leaves
		// this unset, preserving its prior behavior.
		if (timeoutMs)
			req.setTimeout(timeoutMs, () =>
				req.destroy(new Error(`request timed out after ${timeoutMs}ms`)),
			);
		req.end(data);
	});

export { authHeaders, post };

export type SyncStats = {
	pulled: number;
	pushed: number;
	authPulled: number;
	rotationsPulled: number;
};

const localRotationIds = (s: Session): string[] =>
	s.store
		.rotations()
		.map((r) => JSON.parse(r) as RotationRecord)
		.map((r) => rotationId(r.epoch, r.deviceId));

export const syncWithRelay = async (
	s: Session,
	relayUrl: string,
	auth: RelayAuth = {},
	opts: { timeoutMs?: number } = {},
): Promise<SyncStats> => {
	const base = relayUrl.replace(/\/$/, "");
	const localVector: VersionVector = s.store.versionVector();

	// Pull: ops past our vector, auth entries past our length, rotations we lack.
	const resp = await post<SyncResponse>(
		`${base}/sync`,
		{
			teamId: s.vaultId,
			vector: localVector,
			authHashes: s.store.authHashes(),
			rotationIds: localRotationIds(s),
		},
		auth,
		{ timeoutMs: opts.timeoutMs },
	);
	const pulled = s.store.putOps(resp.ops);
	const { authImported, rotationsImported } = importAuthAndRotations(
		s,
		resp.authLog,
		resp.rotations,
	);
	// The relay is only a transport.  Verify both the device signature and the
	// publisher's current role before an org key can influence recovery escrow.
	const membership = replay(s.store.authLog(), s.vaultId);
	for (const g of resp.grants ?? []) {
		if (grantAuthentic(s.vaultId, g, membership)) s.store.putGrant(s.vaultId, g);
	}

	// Push: everything the relay is missing (it dedups; volumes are tiny).
	const toPush: OpEnvelope[] = opsSince(s.store.allOps(), resp.vector);
	await post(
		`${base}/push`,
		{
			teamId: s.vaultId,
			ops: toPush,
			authLog: s.store.authLog(),
			rotations: s.store.rotations(),
			grants: s.store.allGrants(s.vaultId),
		},
		auth,
		{ timeoutMs: opts.timeoutMs },
	);

	// Rebuild the materialized replica; contribute a recovery grant if escrow is
	// now enabled and we don't yet have one for this user.
	rebuildSession(s);
	contributeRecovery(s);
	return {
		pulled,
		pushed: toPush.length,
		authPulled: authImported,
		rotationsPulled: rotationsImported,
	};
};
