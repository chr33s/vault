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

import { entryHash, type LogEntry } from "../../core/authlog.ts";
import {
	verifyEnvelope,
	type OpEnvelope,
	type VersionVector,
	type GrantRow,
} from "../../core/protocol.ts";
import type { RotationRecord } from "../../core/rotation.ts";
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
	authExcept(teamId: string, have: Set<string>): LogEntry[] {
		return this.rows(`SELECT hash,entry FROM relay_authlog WHERE team_id=?`, teamId)
			.filter((r) => !have.has(r.hash as string))
			.map((r) => JSON.parse(r.entry as string) as LogEntry);
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

// The Durable Object: one instance per teamId, owning that team's SQLite.
export class RelayDO {
	private store: DoRelayStorage;
	private env: Env;
	constructor(state: DurableObjectState, env: Env) {
		this.store = new DoRelayStorage(state.storage.sql);
		this.env = env;
	}
	async fetch(req: Request): Promise<Response> {
		const access = accessFromEnv(this.env);
		const rr = toRelayRequest(req, access);
		const { status, body } = await handle(rr, this.store, {
			authorize: (header) => authorizeHeaders(header, access),
			// Cheap integrity check; clients re-verify signatures against the auth log.
			verifyOp: (op) => verifyEnvelope(op),
		});
		return new Response(JSON.stringify(body), {
			status,
			headers: { "content-type": "application/json" },
		});
	}
}

// Worker entry: route each request to the DO for its teamId. /health is answered
// directly. The teamId is read from the JSON body (or `?team=` for health checks).
export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		const url = new URL(req.url);
		if (req.method === "GET" && url.pathname === "/health")
			return new Response(JSON.stringify({ ok: true }), {
				headers: { "content-type": "application/json" },
			});
		if (req.method !== "POST")
			return new Response(JSON.stringify({ error: "method not allowed" }), { status: 405 });

		// Peek the teamId to pick the DO, then replay the body to the DO via a clone.
		const raw = await req.text();
		let teamId = "";
		try {
			teamId = (JSON.parse(raw || "{}") as { teamId?: string }).teamId ?? "";
		} catch {
			/* fall through to 400 below */
		}
		if (!teamId) return new Response(JSON.stringify({ error: "teamId required" }), { status: 400 });

		const id = env.RELAY_DO.idFromName(teamId);
		const stub = env.RELAY_DO.get(id);
		const forwarded = new Request(req.url, { method: "POST", headers: req.headers, body: raw });
		return stub.fetch(forwarded);
	},
};
