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
	// Cheap junk filter on incoming ops; correctness never depends on it (clients
	// re-verify signatures against the auth log). Default accepts everything.
	verifyOp?: (op: OpEnvelope) => boolean | Promise<boolean>;
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
		const verifyOp = deps.verifyOp ?? (() => true);
		let accepted = 0;
		for (const op of body.ops) {
			if (!(await verifyOp(op))) continue;
			if (await store.putOp(body.teamId, op)) accepted++;
		}
		for (const entry of body.authLog ?? []) await store.putAuth(body.teamId, entry);
		for (const rec of body.rotations ?? []) {
			try {
				await store.putRotation(body.teamId, JSON.parse(rec) as RotationRecord);
			} catch {
				/* skip malformed */
			}
		}
		for (const g of body.grants ?? []) await store.putGrant(body.teamId, g);
		return { status: 200, body: { accepted } };
	}

	return { status: 404, body: { error: "not found" } };
};

export { rotKey };
