// Transport-agnostic relay request handler (spec §8; plan §6). The same
// store-and-forward logic backs BOTH placements from spec §8.2:
//   - self-hosted Node behind Cloudflare Tunnel (relay/main.ts), and
//   - the serverless Worker + Durable Object (relay/worker/worker.ts).
//
// This module imports NO node:* built-ins and only `import type` from core, so
// it bundles unchanged into the Workers runtime. Each transport injects its
// storage, its authorization check, and its (optional) cheap op-hash verifier.

import type { LogEntry } from "../core/authlog.ts";
import type { OpEnvelope, VersionVector } from "../core/protocol.ts";
import type { GrantRow, SyncRequest, SyncResponse, PushRequest } from "../core/protocol.ts";
import type { RotationRecord } from "../core/rotation.ts";

// Storage the relay needs, team-partitioned. Implemented over node:sqlite (Node)
// or Durable Object SQL (Worker). All methods may be async (the DO API is).
export type RelayStorage = {
	putOp(teamId: string, op: OpEnvelope): Promise<boolean> | boolean; // false if dup
	allOps(teamId: string): Promise<OpEnvelope[]> | OpEnvelope[];
	vector(teamId: string): Promise<VersionVector> | VersionVector;
	putAuth(teamId: string, entry: LogEntry): Promise<void> | void;
	// Recompute and atomically pin the first root genesis hash seen for a team.
	// Returns false when another root is already pinned.
	pinGenesis(teamId: string, entry: LogEntry): Promise<boolean> | boolean;
	authExcept(teamId: string, have: Set<string>): Promise<LogEntry[]> | LogEntry[];
	putRotation(teamId: string, rec: RotationRecord): Promise<void> | void;
	rotationsExcept(teamId: string, have: Set<string>): Promise<string[]> | string[];
	putGrant(teamId: string, g: GrantRow): Promise<void> | void;
	allGrants(teamId: string): Promise<GrantRow[]> | GrantRow[];
};

export type RelayRequest = {
	method: string;
	path: string; // pathname only, e.g. "/sync"
	header: (name: string) => string | undefined; // lowercased lookup
	body: () => Promise<unknown>; // parsed JSON (or {} when empty)
};

export type RelayResponse = { status: number; body: unknown };

export type RelayDeps = {
	// Returns true if the request is allowed (network/Access gate). Open in dev.
	authorize: (header: (name: string) => string | undefined) => Promise<boolean>;
	// Accept an incoming op only if it is authentic: the transport verifies the
	// op's Ed25519 signature against the author device's key in the (already
	// relay-visible) auth log. This is NOT just a junk filter — it stops a
	// malicious writer from pre-claiming another device's (deviceId, seq) slot
	// under the UNIQUE constraint and thereby censoring that device's real op.
	// Default accepts everything (dev/no-auth-log transports).
	verifyOp?: (op: OpEnvelope, teamId: string) => boolean | Promise<boolean>;
	// Accept a rotation record only if it is well-formed and signed by a device
	// known to the auth log. Bounds a metadata-flood DoS where an authenticated
	// writer pushes unbounded synthetic rotations (unique epoch/deviceId) that
	// would otherwise persist to the store. Default accepts everything.
	verifyRotation?: (rec: RotationRecord, teamId: string) => boolean | Promise<boolean>;
	// Recovery-grant publishers are authenticated against the current membership:
	// only owners announce the org key and users publish their own grants.  Unlike
	// opaque ops, accepting an unauthenticated grant can make a client seal its
	// identity to an attacker's key, so the secure default is reject.
	verifyGrant?: (g: GrantRow, teamId: string) => boolean | Promise<boolean>;
};

// Pure helpers (inlined from core/protocol so this module pulls no crypto).
const opsSince = (have: OpEnvelope[], theirVector: VersionVector): OpEnvelope[] =>
	have.filter((op) => op.seq > (theirVector[op.deviceId] ?? 0));
const rotKey = (epoch: number, deviceId: string): string => `${epoch}:${deviceId}`;

export const handle = async (
	req: RelayRequest,
	store: RelayStorage,
	deps: RelayDeps,
): Promise<RelayResponse> => {
	if (req.method === "GET" && req.path === "/health") return { status: 200, body: { ok: true } };
	if (req.method !== "POST") return { status: 405, body: { error: "method not allowed" } };

	if (!(await deps.authorize(req.header))) return { status: 403, body: { error: "forbidden" } };

	if (req.path === "/sync") {
		const body = (await req.body()) as SyncRequest;
		if (!body.teamId) return { status: 400, body: { error: "teamId required" } };
		const have = await store.allOps(body.teamId);
		const resp: SyncResponse = {
			ops: opsSince(have, body.vector ?? {}),
			vector: await store.vector(body.teamId),
			authLog: await store.authExcept(body.teamId, new Set(body.authHashes ?? [])),
			rotations: await store.rotationsExcept(body.teamId, new Set(body.rotationIds ?? [])),
			grants: await store.allGrants(body.teamId),
		};
		return { status: 200, body: resp };
	}

	if (req.path === "/push") {
		const body = (await req.body()) as PushRequest;
		if (!body.teamId || !Array.isArray(body.ops))
			return { status: 400, body: { error: "teamId and ops required" } };
		// Ingest membership/rotations/grants BEFORE verifying ops: a device's first
		// ops travel in the same push as the add-device entry that authorizes them,
		// so op verification must see the just-added key.
		for (const entry of body.authLog ?? []) {
			if (entry.body.type === "genesis") {
				// A genesis is self-authorizing, so teamId alone cannot distinguish a
				// later rival root. Recompute its hash (the cached field is untrusted) and
				// let storage atomically pin the first well-scoped root before persisting.
				if (
					entry.body.vaultId !== body.teamId ||
					entry.parents.length !== 0 ||
					!(await store.pinGenesis(body.teamId, entry))
				)
					continue;
			}
			await store.putAuth(body.teamId, entry);
		}
		const verifyRotation = deps.verifyRotation ?? (() => true);
		for (const rec of body.rotations ?? []) {
			try {
				const parsed = JSON.parse(rec) as RotationRecord;
				if (!(await verifyRotation(parsed, body.teamId))) continue;
				await store.putRotation(body.teamId, parsed);
			} catch {
				/* skip malformed */
			}
		}
		const verifyGrant = deps.verifyGrant ?? (() => false);
		for (const g of body.grants ?? []) {
			if (await verifyGrant(g, body.teamId)) await store.putGrant(body.teamId, g);
		}

		const verifyOp = deps.verifyOp ?? (() => true);
		let accepted = 0;
		for (const op of body.ops) {
			if (!(await verifyOp(op, body.teamId))) continue;
			if (await store.putOp(body.teamId, op)) accepted++;
		}
		return { status: 200, body: { accepted } };
	}

	return { status: 404, body: { error: "not found" } };
};

export { rotKey };
