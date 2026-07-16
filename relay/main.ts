// The always-on relay hub (spec §8; plan §6). A dumb, zero-knowledge
// store-and-forward replica: it holds opaque OpEnvelopes per team, dedupes by
// hash, and answers "ops since your version vector". It never holds keys and
// enforces no content policy — payloads are opaque blobs it cannot read.

import { execFile } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { DatabaseSync } from "node:sqlite";
import {
	entryHash,
	replay,
	deviceSignKey,
	validRootGenesis,
	type LogEntry,
	type Membership,
} from "../core/authlog.ts";
import {
	grantAuthentic,
	verifyEnvelope,
	rotationId,
	type OpEnvelope,
	type VersionVector,
} from "../core/protocol.ts";
import type { GrantRow } from "../core/protocol.ts";
import { rotationAuthentic, type RotationRecord } from "../core/rotation.ts";
import { authorizeHeaders, type AccessConfig } from "./access.ts";
import { handle, type RelayStorage } from "./handler.ts";
import { GENERIC_500, installSafeFatalHandlers } from "./log.ts";

// ---- relay storage (team-partitioned opaque op log) ----

class RelayStore implements RelayStorage {
	private db: DatabaseSync;
	constructor(path: string) {
		this.db = new DatabaseSync(path);
		this.db.exec("PRAGMA journal_mode = WAL;");
		this.db.exec(`CREATE TABLE IF NOT EXISTS relay_ops (
      team_id   TEXT NOT NULL,
      device_id TEXT NOT NULL,
      seq       INTEGER NOT NULL,
      hash      TEXT NOT NULL,
      sig       TEXT NOT NULL,
      payload   TEXT NOT NULL,
      PRIMARY KEY (team_id, hash),
      UNIQUE (team_id, device_id, seq)
    );`);
		// Membership (auth log) and key-rotation records also gossip through the
		// relay. They are cleartext metadata — the relay can read but not forge
		// them (every entry is signed and clients re-validate the chain).
		this.db.exec(`CREATE TABLE IF NOT EXISTS relay_authlog (
      team_id TEXT NOT NULL,
      hash    TEXT NOT NULL,
      entry   TEXT NOT NULL,
      PRIMARY KEY (team_id, hash)
    );`);
		this.db.exec(`CREATE TABLE IF NOT EXISTS relay_roots (
      team_id TEXT PRIMARY KEY,
      hash    TEXT NOT NULL
    );`);
		this.db.exec(`CREATE TABLE IF NOT EXISTS relay_rotations (
      team_id   TEXT NOT NULL,
      epoch     INTEGER NOT NULL,
      device_id TEXT NOT NULL,
      record    TEXT NOT NULL,
      PRIMARY KEY (team_id, epoch, device_id)
    );`);
		// Recovery-escrow grants channel: org-key announcement + members' sealed
		// recovery material. Cleartext envelopes; the org private key never appears.
		this.db.exec(`CREATE TABLE IF NOT EXISTS relay_grants (
      team_id     TEXT NOT NULL,
      principal   TEXT NOT NULL,
      key_version INTEGER NOT NULL,
      wrapped     TEXT NOT NULL,
		  signer_id   TEXT NOT NULL DEFAULT '',
		  sig         TEXT NOT NULL DEFAULT '',
      PRIMARY KEY (team_id, principal, key_version)
    );`);
		try {
			this.db.exec("ALTER TABLE relay_grants ADD COLUMN signer_id TEXT NOT NULL DEFAULT '';");
		} catch {
			/* column already exists */
		}
		try {
			this.db.exec("ALTER TABLE relay_grants ADD COLUMN sig TEXT NOT NULL DEFAULT '';");
		} catch {
			/* column already exists */
		}
	}

	putGrant(teamId: string, g: GrantRow): void {
		// First-write-wins: a grant slot (team, principal, keyVersion) is immutable
		// once set, so a captured/stale authentic grant re-pushed later cannot
		// overwrite the current one (recovery material and the org key never change).
		this.db
			.prepare(
				`INSERT OR IGNORE INTO relay_grants
         (team_id, principal, key_version, wrapped, signer_id, sig) VALUES (?, ?, ?, ?, ?, ?)`,
			)
			.run(teamId, g.principal, g.keyVersion, g.wrapped, g.signerId, g.sig);
	}
	allGrants(teamId: string): GrantRow[] {
		const rows = this.db
			.prepare(
				`SELECT principal, key_version, wrapped, signer_id, sig
         FROM relay_grants WHERE team_id = ? ORDER BY principal`,
			)
			.all(teamId) as Array<Record<string, unknown>>;
		return rows.map((r) => ({
			principal: r.principal as string,
			keyVersion: r.key_version as number,
			wrapped: r.wrapped as string,
			signerId: r.signer_id as string,
			sig: r.sig as string,
		}));
	}

	putAuth(teamId: string, entry: LogEntry): void {
		// Key by the recomputed hash (don't trust the client's cached field).
		const hash = entryHash(entry);
		this.db
			.prepare(`INSERT OR IGNORE INTO relay_authlog (team_id, hash, entry) VALUES (?, ?, ?)`)
			.run(teamId, hash, JSON.stringify({ ...entry, hash }));
	}
	private rootHashFor(teamId: string, candidate?: string): string | undefined {
		let pinned = this.db.prepare(`SELECT hash FROM relay_roots WHERE team_id = ?`).get(teamId) as
			| { hash: string }
			| undefined;
		if (!pinned) {
			// Upgrade path: preserve the first matching genesis already stored by an
			// older relay instead of letting the next pusher choose a new root.
			const rows = this.db
				.prepare(`SELECT entry FROM relay_authlog WHERE team_id = ? ORDER BY rowid`)
				.all(teamId) as Array<{ entry: string }>;
			let legacyHash: string | undefined;
			for (const row of rows) {
				try {
					const entry = JSON.parse(row.entry) as LogEntry;
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
			this.db
				.prepare(`INSERT OR IGNORE INTO relay_roots (team_id, hash) VALUES (?, ?)`)
				.run(teamId, initial);
			pinned = this.db.prepare(`SELECT hash FROM relay_roots WHERE team_id = ?`).get(teamId) as {
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
	authExcept(teamId: string, haveHashes: Set<string>): LogEntry[] {
		const rows = this.db
			.prepare(`SELECT entry FROM relay_authlog WHERE team_id = ?`)
			.all(teamId) as Array<{ entry: string }>;
		const pinned = this.rootHashFor(teamId);
		const seen = new Set(haveHashes);
		return rows.flatMap((row) => {
			try {
				const entry = JSON.parse(row.entry) as LogEntry;
				const hash = entryHash(entry);
				if (entry.body.type === "genesis" && (hash !== pinned || !validRootGenesis(entry, teamId)))
					return [];
				if (seen.has(hash)) return [];
				seen.add(hash);
				return [{ ...entry, hash }];
			} catch {
				return [];
			}
		});
	}
	putRotation(teamId: string, rec: RotationRecord): void {
		this.db
			.prepare(
				`INSERT OR IGNORE INTO relay_rotations (team_id, epoch, device_id, record) VALUES (?, ?, ?, ?)`,
			)
			.run(teamId, rec.epoch, rec.deviceId, JSON.stringify(rec));
	}
	rotationsExcept(teamId: string, haveIds: Set<string>): string[] {
		const rows = this.db
			.prepare(
				`SELECT epoch, device_id, record FROM relay_rotations WHERE team_id = ? ORDER BY epoch`,
			)
			.all(teamId) as Array<Record<string, unknown>>;
		return rows
			.filter((r) => !haveIds.has(rotationId(r.epoch as number, r.device_id as string)))
			.map((r) => r.record as string);
	}
	close(): void {
		this.db.close();
	}
	putOp(teamId: string, op: OpEnvelope): boolean {
		const info = this.db
			.prepare(
				`INSERT OR IGNORE INTO relay_ops (team_id, device_id, seq, hash, sig, payload)
         VALUES (?, ?, ?, ?, ?, ?)`,
			)
			.run(teamId, op.deviceId, op.seq, op.hash, op.sig, op.payload);
		return info.changes > 0;
	}
	allOps(teamId: string): OpEnvelope[] {
		const rows = this.db
			.prepare(
				`SELECT device_id, seq, hash, sig, payload FROM relay_ops WHERE team_id = ? ORDER BY device_id, seq`,
			)
			.all(teamId) as Array<Record<string, unknown>>;
		return rows.map((r) => ({
			deviceId: r.device_id as string,
			seq: r.seq as number,
			hash: r.hash as string,
			sig: r.sig as string,
			payload: r.payload as string,
		}));
	}
	vector(teamId: string): VersionVector {
		const rows = this.db
			.prepare(
				`SELECT device_id, MAX(seq) AS m FROM relay_ops WHERE team_id = ? GROUP BY device_id`,
			)
			.all(teamId) as Array<Record<string, unknown>>;
		const v: VersionVector = {};
		for (const r of rows) v[r.device_id as string] = r.m as number;
		return v;
	}

	// Membership derived from the team's auth log, used to authenticate incoming
	// op and rotation signatures (see the verifyOp/verifyRotation notes). The auth
	// log only grows (INSERT OR IGNORE), so it is memoized by entry count and
	// recomputed only when a new entry lands — a burst of ops in one push doesn't
	// re-replay the DAG per op.
	private memberCache = new Map<string, { count: number; membership: Membership }>();
	membershipFor(teamId: string): Membership | undefined {
		const count = (
			this.db.prepare(`SELECT COUNT(*) AS c FROM relay_authlog WHERE team_id = ?`).get(teamId) as {
				c: number;
			}
		).c;
		let cached = this.memberCache.get(teamId);
		if (!cached || cached.count !== count) {
			try {
				// teamId === vaultId: pin the genesis so a gossiped rival root can't
				// change which keys authenticate ops.
				cached = { count, membership: replay(this.authExcept(teamId, new Set()), teamId) };
			} catch {
				return undefined; // no valid genesis yet — nothing is authorized
			}
			this.memberCache.set(teamId, cached);
		}
		return cached.membership;
	}
}

// An op is authentic iff signed by the author device's (currently-active) key.
const opAuthentic = (store: RelayStore, op: OpEnvelope, teamId: string): boolean => {
	const m = store.membershipFor(teamId);
	const key = m && deviceSignKey(m, op.deviceId);
	return !!key && verifyEnvelope(op, key);
};

// A rotation can advance the current epoch only when it is signed by an active
// owner/admin device (shared core rule; historical device keys are intentionally
// not enough, so a removed device cannot lock active members out with a later
// epoch even though its old records still decrypt old data).
const rotationAcceptable = (store: RelayStore, rec: RotationRecord, teamId: string): boolean => {
	const membership = store.membershipFor(teamId);
	return !!membership && rotationAuthentic(rec, membership);
};

const recoveryGrantAuthentic = (store: RelayStore, g: GrantRow, teamId: string): boolean => {
	const membership = store.membershipFor(teamId);
	return !!membership && grantAuthentic(teamId, g, membership);
};

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
	const json = JSON.stringify(body);
	res.writeHead(status, { "content-type": "application/json" });
	res.end(json);
};

export type RelayOptions = {
	dbPath?: string;
	access?: AccessConfig;
};

export const createRelay = (opts: RelayOptions = {}): { server: Server; store: RelayStore } => {
	const store = new RelayStore(opts.dbPath ?? ":memory:");
	const access = opts.access ?? {};

	const server = createServer((req, res) => {
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
				store,
				{
					authorize: (header) => authorizeHeaders(header, access),
					// Authenticate authorship: verify the op's signature against the
					// author device's key in the auth log, so a member can't pre-claim
					// (and thereby censor) another device's (deviceId, seq) slot.
					verifyOp: (op, teamId) => opAuthentic(store, op, teamId),
					verifyRotation: (rec, teamId) => rotationAcceptable(store, rec, teamId),
					verifyGrant: (g, teamId) => recoveryGrantAuthentic(store, g, teamId),
				},
			);
			send(res, status, body);
		})().catch(() => {
			// Never echo err.message: it could carry the request's Access credential.
			// Diagnostics stay server-side via the safe fatal handler / process logs.
			send(res, 500, GENERIC_500);
		});
	});

	return { server, store };
};

// ---- systemd integration (sd_notify watchdog) ----
//
// sd_notify needs an AF_UNIX *datagram* socket, which no node: built-in can open
// (node:dgram is UDP-only). Rather than add a native dependency, we shell out to
// `systemd-notify`, which ships with systemd. Everything here is gated on the
// NOTIFY_SOCKET env var that systemd sets, so off-systemd (dev, tests, the SEA
// CLI's bundled relay) it is a complete no-op and pulls in nothing.

// Fire a single sd_notify message (READY=1, WATCHDOG=1, …). Best-effort.
const sdNotify = (state: string): void => {
	if (!process.env.NOTIFY_SOCKET) return;
	execFile("systemd-notify", [state], () => {
		/* best-effort: a missing helper must never crash the relay */
	});
};

// If WatchdogSec is set on the unit, systemd exports WATCHDOG_USEC. Ping at half
// that interval from the event loop; a stalled loop stops pinging and systemd
// kills + restarts us — turning a silent hang into automatic recovery. Returns a
// stop() that clears the timer (used by tests / clean shutdown).
const startWatchdog = (): (() => void) => {
	const usec = Number(process.env.WATCHDOG_USEC ?? 0);
	if (!process.env.NOTIFY_SOCKET || !Number.isFinite(usec) || usec <= 0) return () => {};
	const intervalMs = Math.max(1000, Math.floor(usec / 1000 / 2));
	const timer = setInterval(() => sdNotify("WATCHDOG=1"), intervalMs);
	timer.unref(); // don't keep the process alive solely for the heartbeat
	return () => clearInterval(timer);
};

export { sdNotify, startWatchdog };

// ---- entrypoint ----

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
	// Replace Node's default crash dumper before we hold any Access credentials.
	installSafeFatalHandlers();
	const port = Number(process.env.PORT ?? 8731);
	const tokens = process.env.VAULT_RELAY_TOKENS;
	const access: AccessConfig = {
		serviceTokens: tokens
			? new Set(
					tokens
						.split(",")
						.map((t) => t.trim())
						.filter(Boolean),
				)
			: undefined,
		teamDomain: process.env.CF_ACCESS_TEAM_DOMAIN,
		audience: process.env.CF_ACCESS_AUD,
		requireAccess: process.env.REQUIRE_ACCESS === "1" || process.env.REQUIRE_ACCESS === "true",
	};
	const { server } = createRelay({ dbPath: process.env.RELAY_DB ?? "relay.db", access });
	// PORT=0 binds an ephemeral port; report the actual one we got.
	server.listen(port, () => {
		const addr = server.address();
		const actual = addr && typeof addr === "object" ? addr.port : port;
		process.stdout.write(`relay listening on :${actual}\n`);
		// Tell systemd we're up (Type=notify) and start the liveness heartbeat.
		sdNotify("READY=1");
		startWatchdog();
	});
}
