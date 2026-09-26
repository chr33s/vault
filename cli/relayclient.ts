// Relay sync client (spec §7.4, §8). Runs one anti-entropy round against the
// always-on hub over outbound HTTPS: pull the op log, signed auth log, and
// rotation records past what we hold, then push whatever the relay lacks. The
// relay sees opaque OpEnvelopes plus cleartext membership/epoch metadata —
// never vault contents.

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { deviceSignKey, replay } from "../core/authlog.ts";
import {
	acceptContiguous,
	grantAuthentic,
	rotationId,
	verifyEnvelope,
	type GrantRow,
	type OpEnvelope,
	type SyncResponse,
	type VersionVector,
} from "../core/protocol.ts";
import { parseRotation, rotationAuthentic } from "../core/rotation.ts";
import type { Session } from "./engine.ts";
import {
	rebuildSession,
	importAuthAndRotations,
	contributeRecovery,
	verifiedRotationIds,
} from "./engine.ts";

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

// Relays keep the first grant per (principal, keyVersion) slot, so a filled slot
// is "held" whatever its contents; re-pushing ours would be ignored every round.
const grantKey = (g: GrantRow): string => JSON.stringify([g.principal, g.keyVersion]);

export const syncWithRelay = async (
	s: Session,
	relayUrl: string,
	auth: RelayAuth = {},
	opts: { timeoutMs?: number } = {},
): Promise<SyncStats> => {
	const base = relayUrl.replace(/\/$/, "");
	const before = replay(s.store.authLog(), s.vaultId);
	const localVector: VersionVector = s.store.versionVector();
	const authHashes = s.store.authHashes();
	const verifiedIds = verifiedRotationIds(s, before);

	// Pull: ops past our vector, auth entries and rotations we don't list.
	const resp = await post<SyncResponse>(
		`${base}/sync`,
		{
			teamId: s.vaultId,
			vector: localVector,
			authHashes,
			// Only records that verify: an unverifiable one stored by an older client
			// must not stop the relay sending us the genuine record for its slot.
			rotationIds: verifiedIds,
		},
		auth,
		{ timeoutMs: opts.timeoutMs },
	);
	// Membership first: a device's first ops arrive in the same round as the
	// add-device entry that authorizes them. The returned membership reflects the
	// imported entries and is reused for the rest of the round.
	const { authImported, rotationsImported, membership } = importAuthAndRotations(
		s,
		resp.authLog ?? [],
		resp.rotations ?? [],
		{ membership: before, verifiedIds },
	);
	// The relay/peer is only a transport. Store an op only if the key of the
	// device it names signed it: the ops table is UNIQUE(device_id, seq), so a
	// forged op would otherwise occupy the genuine op's slot for good. Historical
	// keys count: a removed device's old ops are kept (rebuild ignores them), so
	// our vector covers them and the relay doesn't resend them every round.
	const authentic = (resp.ops ?? []).filter((op) => {
		try {
			const key = membership.deviceKeys.get(op.deviceId);
			return !!key && verifyEnvelope(op, key);
		} catch {
			return false;
		}
	});
	// Gap-free ingest (see acceptContiguous): an op past a gap is dropped and
	// asked for again next round, so a withheld op is never skipped for good.
	const pulled = s.store.putOps(acceptContiguous(authentic, (id) => s.store.maxSeqFor(id)));
	// Verify both the device signature and the publisher's current role before an
	// org key can influence recovery escrow.
	for (const g of resp.grants ?? []) {
		if (grantAuthentic(s.vaultId, g, membership)) s.store.putGrant(s.vaultId, g);
	}

	// Push only what the relay lacks AND would accept. The relay admits ops,
	// rotations and grants only from currently active (admin) devices, so pushing
	// a removed device's records would just be refused again every round. An older
	// relay that doesn't report what it lacks gets everything else.
	const toPush: OpEnvelope[] = s.store
		.opsSince(resp.vector ?? {})
		.filter((op) => deviceSignKey(membership, op.deviceId) !== undefined);
	const lacksAuth = resp.lacksAuth && new Set(resp.lacksAuth);
	const lacksRot = resp.lacksRotations && new Set(resp.lacksRotations);
	const relayGrants = new Set((resp.grants ?? []).map(grantKey));
	await post(
		`${base}/push`,
		{
			teamId: s.vaultId,
			ops: toPush,
			authLog: lacksAuth
				? s.store.authLog().filter((e) => lacksAuth.has(e.hash)) // authLog() recomputes .hash
				: s.store.authLog(),
			rotations: s.store.rotations().filter((raw) => {
				const r = parseRotation(raw);
				if (!r || (lacksRot && !lacksRot.has(rotationId(r.epoch, r.deviceId)))) return false;
				return rotationAuthentic(r, membership);
			}),
			grants: s.store
				.allGrants(s.vaultId)
				.filter((g) => !relayGrants.has(grantKey(g)) && grantAuthentic(s.vaultId, g, membership)),
		},
		auth,
		{ timeoutMs: opts.timeoutMs },
	);

	// Rebuild the materialized replica; contribute a recovery grant if escrow is
	// now enabled and we don't yet have one for this user. Grants don't change
	// membership, so the round's membership is still current.
	rebuildSession(s, membership);
	contributeRecovery(s, membership);
	return {
		pulled,
		pushed: toPush.length,
		authPulled: authImported,
		rotationsPulled: rotationsImported,
	};
};
