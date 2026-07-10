// Serverless relay: Cloudflare Worker + Durable Object (spec §8.2 placement).
// One Durable Object per teamId (the "DO-per-vault stripped of authority") holds
// the opaque op log + auth log + rotations + grants in its built-in SQLite, and
// serves the same /sync /push /health protocol as the self-hosted Node relay.
//
// Shares the transport-agnostic relay/handler.ts AND reuses the same crypto/auth
// code as the Node relay (core/protocol, core/authlog, relay/access) via Wrangler's
// `nodejs_compat` node:crypto polyfill — so there is no duplicated WebCrypto path.
// Only storage differs (Durable Object SQLite vs node:sqlite). The wire protocol
// and SQL schema are identical to relay/main.ts by design.
//
// Build/deploy with Wrangler (see relay/worker/wrangler.toml and the deployment
// guide). This file is NEVER bundled into the SEA binary or run under Node.

import {
	entryHash,
	replay,
	deviceSignKey,
	validRootGenesis,
	type LogEntry,
	type Membership,
} from "../../core/authlog.ts";
import {
	verifyEnvelope,
	type OpEnvelope,
	type VersionVector,
	type GrantRow,
} from "../../core/protocol.ts";
import { verifyRotation, wellFormedRotation, type RotationRecord } from "../../core/rotation.ts";
import { authorizeHeaders, type AccessConfig } from "../access.ts";
import { handle, type RelayStorage } from "../handler.ts";

// Minimal Workers runtime typings (avoids a dependency on @cloudflare/workers-types).
type SqlStorage = {
	exec(query: string, ...bindings: unknown[]): { toArray(): Array<Record<string, unknown>> };
};
type DurableObjectStorage = { sql: SqlStorage };
type DurableObjectState = {
	storage: DurableObjectStorage;
	blockConcurrencyWhile(f: () => Promise<void>): void;
};
type DurableObjectNamespace = {
	idFromName(name: string): unknown;
	get(id: unknown): { fetch(req: Request): Promise<Response> };
};
type Env = {
	RELAY_DO: DurableObjectNamespace;
	VAULT_RELAY_TOKENS?: string;
	CF_ACCESS_TEAM_DOMAIN?: string;
	CF_ACCESS_AUD?: string;
	REQUIRE_ACCESS?: string; // "1"/"true" => fail closed (default for public deploys)
};

const accessFromEnv = (env: Env): AccessConfig => ({
	serviceTokens: env.VAULT_RELAY_TOKENS
		? new Set(
				env.VAULT_RELAY_TOKENS.split(",")
					.map((t) => t.trim())
					.filter(Boolean),
			)
		: undefined,
	teamDomain: env.CF_ACCESS_TEAM_DOMAIN,
	audience: env.CF_ACCESS_AUD,
	// wrangler.toml defaults this to "1": a button-deployed relay refuses traffic
	// until Access (tokens or CF_ACCESS_*) is configured, rather than running open.
	requireAccess: env.REQUIRE_ACCESS === "1" || env.REQUIRE_ACCESS === "true",
});

// ---- DO-backed storage (built-in SQLite) ----
//
// No explicit transaction is used here (unlike the Node client Store): the DO
// runtime already commits a handler's writes atomically at the request boundary
// (a crash before fetch() returns discards them), and the relay is idempotent
// store-and-forward — a partial /push is re-pushed on the next sync and deduped
// by hash. If atomic multi-write were ever needed, the DO API is
// ctx.storage.transactionSync(cb) — note sql.exec() cannot run BEGIN/COMMIT.

class DoRelayStorage implements RelayStorage {
	private sql: SqlStorage;
	constructor(sql: SqlStorage) {
		this.sql = sql;
		this.sql.exec(`CREATE TABLE IF NOT EXISTS relay_ops (
      team_id TEXT NOT NULL, device_id TEXT NOT NULL, seq INTEGER NOT NULL,
      hash TEXT NOT NULL, sig TEXT NOT NULL, payload TEXT NOT NULL,
      PRIMARY KEY (team_id, hash), UNIQUE (team_id, device_id, seq));`);
		this.sql.exec(`CREATE TABLE IF NOT EXISTS relay_authlog (
      team_id TEXT NOT NULL, hash TEXT NOT NULL, entry TEXT NOT NULL,
      PRIMARY KEY (team_id, hash));`);
		this.sql.exec(`CREATE TABLE IF NOT EXISTS relay_roots (
      team_id TEXT PRIMARY KEY, hash TEXT NOT NULL);`);
		this.sql.exec(`CREATE TABLE IF NOT EXISTS relay_rotations (
      team_id TEXT NOT NULL, epoch INTEGER NOT NULL, device_id TEXT NOT NULL, record TEXT NOT NULL,
      PRIMARY KEY (team_id, epoch, device_id));`);
		this.sql.exec(`CREATE TABLE IF NOT EXISTS relay_grants (
      team_id TEXT NOT NULL, principal TEXT NOT NULL, key_version INTEGER NOT NULL, wrapped TEXT NOT NULL,
      PRIMARY KEY (team_id, principal, key_version));`);
	}
	private rows(q: string, ...b: unknown[]): Array<Record<string, unknown>> {
		return this.sql.exec(q, ...b).toArray();
	}
	putOp(teamId: string, op: OpEnvelope): boolean {
		const before = this.rows(
			`SELECT COUNT(*) AS c FROM relay_ops WHERE team_id=? AND hash=?`,
			teamId,
			op.hash,
		)[0]!.c as number;
		if (before > 0) return false;
		this.sql.exec(
			`INSERT OR IGNORE INTO relay_ops (team_id,device_id,seq,hash,sig,payload) VALUES (?,?,?,?,?,?)`,
			teamId,
			op.deviceId,
			op.seq,
			op.hash,
			op.sig,
			op.payload,
		);
		return true;
	}
	allOps(teamId: string): OpEnvelope[] {
		return this.rows(
			`SELECT device_id,seq,hash,sig,payload FROM relay_ops WHERE team_id=? ORDER BY device_id,seq`,
			teamId,
		).map((r) => ({
			deviceId: r.device_id as string,
			seq: r.seq as number,
			hash: r.hash as string,
			sig: r.sig as string,
			payload: r.payload as string,
		}));
	}
	vector(teamId: string): VersionVector {
		const v: VersionVector = {};
		for (const r of this.rows(
			`SELECT device_id, MAX(seq) AS m FROM relay_ops WHERE team_id=? GROUP BY device_id`,
			teamId,
		))
			v[r.device_id as string] = r.m as number;
		return v;
	}
	putAuth(teamId: string, entry: LogEntry): void {
		// Key by the recomputed hash (don't trust the client's cached field) — same
		// as the Node relay, now that entryHash (node:crypto) runs under nodejs_compat.
		this.sql.exec(
			`INSERT OR IGNORE INTO relay_authlog (team_id,hash,entry) VALUES (?,?,?)`,
			teamId,
			entryHash(entry),
			JSON.stringify(entry),
		);
	}
	private rootHashFor(teamId: string, candidate?: string): string | undefined {
		let pinned = this.rows(`SELECT hash FROM relay_roots WHERE team_id=?`, teamId)[0] as
			| { hash: string }
			| undefined;
		if (!pinned) {
			// Preserve the first matching root already stored by a pre-pin Worker.
			const rows = this.rows(
				`SELECT entry FROM relay_authlog WHERE team_id=? ORDER BY rowid`,
				teamId,
			);
			let legacyHash: string | undefined;
			for (const row of rows) {
				try {
					const entry = JSON.parse(row.entry as string) as LogEntry;
					if (validRootGenesis(entry, teamId)) {
						legacyHash = entryHash(entry);
						break;
					}
				} catch {
					/* skip malformed legacy rows */
				}
			}
			const initial = legacyHash ?? candidate;
			if (!initial) return undefined;
			this.sql.exec(
				`INSERT OR IGNORE INTO relay_roots (team_id,hash) VALUES (?,?)`,
				teamId,
				initial,
			);
			pinned = this.rows(`SELECT hash FROM relay_roots WHERE team_id=?`, teamId)[0] as {
				hash: string;
			};
		}
		return pinned.hash;
	}
	pinGenesis(teamId: string, entry: LogEntry): boolean {
		if (!validRootGenesis(entry, teamId)) return false;
		const hash = entryHash(entry);
		return this.rootHashFor(teamId, hash) === hash;
	}
	authExcept(teamId: string, have: Set<string>): LogEntry[] {
		const pinned = this.rootHashFor(teamId);
		const seen = new Set(have);
		return this.rows(`SELECT entry FROM relay_authlog WHERE team_id=?`, teamId).flatMap((row) => {
			try {
				const entry = JSON.parse(row.entry as string) as LogEntry;
				const hash = entryHash(entry);
				if (entry.body.type === "genesis" && (hash !== pinned || !validRootGenesis(entry, teamId)))
					return [];
				if (seen.has(hash)) return [];
				seen.add(hash);
				return [entry];
			} catch {
				return [];
			}
		});
	}
	putRotation(teamId: string, rec: RotationRecord): void {
		this.sql.exec(
			`INSERT OR IGNORE INTO relay_rotations (team_id,epoch,device_id,record) VALUES (?,?,?,?)`,
			teamId,
			rec.epoch,
			rec.deviceId,
			JSON.stringify(rec),
		);
	}
	rotationsExcept(teamId: string, have: Set<string>): string[] {
		return this.rows(
			`SELECT epoch,device_id,record FROM relay_rotations WHERE team_id=? ORDER BY epoch`,
			teamId,
		)
			.filter((r) => !have.has(`${r.epoch as number}:${r.device_id as string}`))
			.map((r) => r.record as string);
	}
	putGrant(teamId: string, g: GrantRow): void {
		this.sql.exec(
			`INSERT OR IGNORE INTO relay_grants (team_id,principal,key_version,wrapped) VALUES (?,?,?,?)`,
			teamId,
			g.principal,
			g.keyVersion,
			g.wrapped,
		);
	}
	allGrants(teamId: string): GrantRow[] {
		return this.rows(
			`SELECT principal,key_version,wrapped FROM relay_grants WHERE team_id=? ORDER BY principal`,
			teamId,
		).map((r) => ({
			principal: r.principal as string,
			keyVersion: r.key_version as number,
			wrapped: r.wrapped as string,
		}));
	}

	// Membership for authenticating op/rotation signatures (see verifyOp note).
	// Memoized by auth-entry count since the log is append-only.
	private memberCache: { count: number; membership: Membership } | undefined;
	membershipFor(teamId: string): Membership | undefined {
		const count = (this.rows(`SELECT COUNT(*) AS c FROM relay_authlog WHERE team_id=?`, teamId)[0]!
			.c as number)!;
		if (!this.memberCache || this.memberCache.count !== count) {
			try {
				this.memberCache = {
					count,
					membership: replay(this.authExcept(teamId, new Set()), teamId),
				};
			} catch {
				return undefined;
			}
		}
		return this.memberCache.membership;
	}
}

// Build a RelayRequest from a Fetch API Request.
const toRelayRequest = (req: Request, access: AccessConfig) => ({
	method: req.method,
	path: new URL(req.url).pathname,
	header: (name: string) => req.headers.get(name) ?? undefined,
	body: async () => {
		const text = await req.text();
		return JSON.parse(text || "{}");
	},
	access,
});

// A JSON error response with a fixed, credential-free body. Errors are never
// echoed verbatim on Workers — the runtime would log the raw exception to
// Workers Logs / `wrangler tail`, persisted off-box (spec §8: zero-knowledge).
const jsonError = (status: number, error: string): Response =>
	new Response(JSON.stringify({ error }), {
		status,
		headers: { "content-type": "application/json" },
	});

const MAX_BODY_BYTES = 16 * 1024 * 1024;

// Return undefined as soon as the byte limit is crossed. Reading through the
// stream prevents chunked requests from being fully buffered by Request.text().
const readLimitedBody = async (req: Request): Promise<string | undefined> => {
	if (!req.body) return "";
	const reader = req.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > MAX_BODY_BYTES) {
				try {
					await reader.cancel();
				} catch {
					/* the response is still 413 if the producer's cancellation fails */
				}
				return undefined;
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}

	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return new TextDecoder().decode(bytes);
};

// The Durable Object: one instance per teamId, owning that team's SQLite.
export class RelayDO {
	private store: DoRelayStorage;
	private env: Env;
	constructor(state: DurableObjectState, env: Env) {
		this.store = new DoRelayStorage(state.storage.sql);
		this.env = env;
	}
	async fetch(req: Request): Promise<Response> {
		try {
			const access = accessFromEnv(this.env);
			const rr = toRelayRequest(req, access);
			const store = this.store;
			const { status, body } = await handle(rr, store, {
				authorize: (header) => authorizeHeaders(header, access),
				// Authenticate authorship against the auth log so a member can't
				// pre-claim/censor another device's (deviceId, seq) slot.
				verifyOp: (op, teamId) => {
					const m = store.membershipFor(teamId);
					const key = m && deviceSignKey(m, op.deviceId);
					return !!key && verifyEnvelope(op, key);
				},
				// Bound synthetic-rotation floods: only well-formed, device-signed
				// rotations are stored.
				verifyRotation: (rec, teamId) => {
					const key = store.membershipFor(teamId)?.deviceKeys.get(rec.signerId);
					return !!key && wellFormedRotation(rec) && verifyRotation(rec, key);
				},
			});
			return new Response(JSON.stringify(body), {
				status,
				headers: { "content-type": "application/json" },
			});
		} catch {
			// Never surface (or let the runtime log) the raw error: on Workers it
			// would land in Workers Logs / `wrangler tail` — persisted off-box — and
			// could carry the request's Access credential. Return a blank 500.
			return jsonError(500, "internal error");
		}
	}
}

// Worker entry: route each request to the DO for its teamId. /health is answered
// directly. The teamId is read from the JSON body (or `?team=` for health checks).
export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		try {
			const url = new URL(req.url);
			if (req.method === "GET" && url.pathname === "/health")
				return new Response(JSON.stringify({ ok: true }), {
					headers: { "content-type": "application/json" },
				});
			if (req.method !== "POST") return jsonError(405, "method not allowed");

			// Enforce the access gate at the EDGE, before reading the body or routing
			// to a Durable Object. Otherwise an unauthenticated flood of random
			// teamIds would each spin up a fresh DO (running its CREATE TABLE) and
			// buffer an uncapped body — a storage/billing amplification the token or
			// Access check exists to prevent. The DO re-checks auth defensively.
			const access = accessFromEnv(env);
			if (!(await authorizeHeaders((n) => req.headers.get(n) ?? undefined, access)))
				return jsonError(403, "forbidden");

			// Cap the body before buffering it (Content-Length fast path + hard cap on
			// the read) so a single request can't exhaust memory.
			if (Number(req.headers.get("content-length") ?? "0") > MAX_BODY_BYTES)
				return jsonError(413, "payload too large");
			const raw = await readLimitedBody(req);
			if (raw === undefined) return jsonError(413, "payload too large");
			let teamId = "";
			try {
				teamId = (JSON.parse(raw || "{}") as { teamId?: string }).teamId ?? "";
			} catch {
				/* fall through to 400 below */
			}
			if (!teamId) return jsonError(400, "teamId required");

			const id = env.RELAY_DO.idFromName(teamId);
			const stub = env.RELAY_DO.get(id);
			const forwarded = new Request(req.url, { method: "POST", headers: req.headers, body: raw });
			return stub.fetch(forwarded);
		} catch {
			return jsonError(500, "internal error");
		}
	},
};
