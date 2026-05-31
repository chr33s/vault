// The always-on relay hub (spec §8; plan §6). A dumb, zero-knowledge
// store-and-forward replica: it holds opaque OpEnvelopes per team, dedupes by
// hash, and answers "ops since your version vector". It never holds keys and
// enforces no content policy — payloads are opaque blobs it cannot read.

import { execFile } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { entryHash, type LogEntry } from "../core/authlog.ts";
import {
	verifyEnvelope,
	rotationId,
	type OpEnvelope,
	type VersionVector,
} from "../core/protocol.ts";
import type { GrantRow } from "../core/protocol.ts";
import type { RotationRecord } from "../core/rotation.ts";
import { authorizeHeaders, type AccessConfig } from "./access.ts";
import { handle, type RelayStorage } from "./handler.ts";

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
      PRIMARY KEY (team_id, principal, key_version)
    );`);
	}

	putGrant(teamId: string, g: GrantRow): void {
		this.db
			.prepare(
				`INSERT OR IGNORE INTO relay_grants (team_id, principal, key_version, wrapped) VALUES (?, ?, ?, ?)`,
			)
			.run(teamId, g.principal, g.keyVersion, g.wrapped);
	}
	allGrants(teamId: string): GrantRow[] {
		const rows = this.db
			.prepare(
				`SELECT principal, key_version, wrapped FROM relay_grants WHERE team_id = ? ORDER BY principal`,
			)
			.all(teamId) as Array<Record<string, unknown>>;
		return rows.map((r) => ({
			principal: r.principal as string,
			keyVersion: r.key_version as number,
			wrapped: r.wrapped as string,
		}));
	}

	putAuth(teamId: string, entry: LogEntry): void {
		// Key by the recomputed hash (don't trust the client's cached field).
		this.db
			.prepare(`INSERT OR IGNORE INTO relay_authlog (team_id, hash, entry) VALUES (?, ?, ?)`)
			.run(teamId, entryHash(entry), JSON.stringify(entry));
	}
	authExcept(teamId: string, haveHashes: Set<string>): LogEntry[] {
		const rows = this.db
			.prepare(`SELECT hash, entry FROM relay_authlog WHERE team_id = ?`)
			.all(teamId) as Array<Record<string, unknown>>;
		return rows
			.filter((r) => !haveHashes.has(r.hash as string))
			.map((r) => JSON.parse(r.entry as string) as LogEntry);
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
}

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
					// Cheap integrity check; clients re-verify signatures against the auth log.
					verifyOp: (op) => verifyEnvelope(op),
				},
			);
			send(res, status, body);
		})().catch((err) => {
			send(res, 500, { error: err instanceof Error ? err.message : "internal error" });
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
