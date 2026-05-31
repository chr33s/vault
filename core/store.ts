// node:sqlite storage (spec §9; plan §4, §6). Backs both the CLI replica
// (ciphertext + op log + materialized items + auth log + grants + meta) and the
// relay (the opaque `ops` table only). No decryption happens here — payloads are
// opaque blobs; the store is a persistence layer over the protocol types.

import { DatabaseSync } from "node:sqlite";
import type { LogEntry } from "./authlog.ts";
import type { OpEnvelope, VersionVector } from "./protocol.ts";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS ops (
  device_id TEXT NOT NULL,
  seq       INTEGER NOT NULL,
  hash      TEXT PRIMARY KEY,
  sig       TEXT NOT NULL,
  payload   TEXT NOT NULL,
  UNIQUE(device_id, seq)
);
CREATE TABLE IF NOT EXISTS items (
  item_id     TEXT PRIMARY KEY,
  team_id     TEXT,
  key_version INTEGER,
  ciphertext  BLOB,
  revision    INTEGER,
  deleted     INTEGER
);
CREATE TABLE IF NOT EXISTS authlog (   -- signed Merkle-DAG membership entries
  hash       TEXT PRIMARY KEY,
  entry      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
  team_id     TEXT,
  principal   TEXT,
  key_version INTEGER,
  wrapped     TEXT,
  PRIMARY KEY (team_id, principal, key_version)
);
CREATE TABLE IF NOT EXISTS rotations (
  epoch     INTEGER,
  device_id TEXT,
  record    TEXT NOT NULL,
  PRIMARY KEY (epoch, device_id)
);
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT
);
`;

export type StoreOptions = { relayOnly?: boolean };

export class Store {
	readonly db: DatabaseSync;

	constructor(path: string, _opts: StoreOptions = {}) {
		this.db = new DatabaseSync(path);
		this.db.exec("PRAGMA journal_mode = WAL;");
		this.db.exec(SCHEMA);
	}

	close(): void {
		this.db.close();
	}

	// Run fn inside a single SQLite transaction: all-or-nothing. Used to keep
	// multi-step mutations (enrollment, join) atomic so a crash can't leave the
	// replica half-initialized. Synchronous (node:sqlite is sync); nested calls
	// are not supported.
	transaction<T>(fn: () => T): T {
		this.db.prepare("BEGIN").run();
		try {
			const result = fn();
			this.db.prepare("COMMIT").run();
			return result;
		} catch (e) {
			this.db.prepare("ROLLBACK").run();
			throw e;
		}
	}

	// ---- ops (op log; source of truth) ----

	// Insert an envelope; returns false if already present (dedupe by hash).
	putOp(op: OpEnvelope): boolean {
		const stmt = this.db.prepare(
			`INSERT OR IGNORE INTO ops (device_id, seq, hash, sig, payload)
       VALUES (?, ?, ?, ?, ?)`,
		);
		const info = stmt.run(op.deviceId, op.seq, op.hash, op.sig, op.payload);
		return info.changes > 0;
	}

	putOps(ops: OpEnvelope[]): number {
		let n = 0;
		const tx = this.db.prepare("BEGIN");
		tx.run();
		try {
			for (const op of ops) if (this.putOp(op)) n++;
			this.db.prepare("COMMIT").run();
		} catch (e) {
			this.db.prepare("ROLLBACK").run();
			throw e;
		}
		return n;
	}

	allOps(): OpEnvelope[] {
		const rows = this.db
			.prepare(`SELECT device_id, seq, hash, sig, payload FROM ops ORDER BY device_id, seq`)
			.all() as Array<Record<string, unknown>>;
		return rows.map((r) => ({
			deviceId: r.device_id as string,
			seq: r.seq as number,
			hash: r.hash as string,
			sig: r.sig as string,
			payload: r.payload as string,
		}));
	}

	versionVector(): VersionVector {
		const rows = this.db
			.prepare(`SELECT device_id, MAX(seq) AS m FROM ops GROUP BY device_id`)
			.all() as Array<Record<string, unknown>>;
		const v: VersionVector = {};
		for (const r of rows) v[r.device_id as string] = r.m as number;
		return v;
	}

	// Highest seq this device has emitted (for minting the next seq).
	maxSeqFor(deviceId: string): number {
		const row = this.db
			.prepare(`SELECT MAX(seq) AS m FROM ops WHERE device_id = ?`)
			.get(deviceId) as Record<string, unknown> | undefined;
		return (row?.m as number | null) ?? 0;
	}

	// ---- auth log ----

	// Idempotent by content hash; entry order is derived at replay (DAG), not
	// stored. Insert-or-ignore so a re-seen entry never overwrites.
	appendAuthEntry(e: LogEntry): void {
		this.db
			.prepare(`INSERT OR IGNORE INTO authlog (hash, entry) VALUES (?, ?)`)
			.run(e.hash, JSON.stringify(e));
	}

	authLog(): LogEntry[] {
		const rows = this.db.prepare(`SELECT entry FROM authlog`).all() as Array<
			Record<string, unknown>
		>;
		return rows.map((r) => JSON.parse(r.entry as string) as LogEntry);
	}

	authHashes(): string[] {
		const rows = this.db.prepare(`SELECT hash FROM authlog`).all() as Array<
			Record<string, unknown>
		>;
		return rows.map((r) => r.hash as string);
	}

	// ---- rotations ----

	putRotation(epoch: number, deviceId: string, record: string): void {
		this.db
			.prepare(`INSERT OR REPLACE INTO rotations (epoch, device_id, record) VALUES (?, ?, ?)`)
			.run(epoch, deviceId, record);
	}

	rotations(): string[] {
		const rows = this.db.prepare(`SELECT record FROM rotations ORDER BY epoch`).all() as Array<
			Record<string, unknown>
		>;
		return rows.map((r) => r.record as string);
	}

	// ---- grants ----

	putGrant(teamId: string, principal: string, keyVersion: number, wrapped: string): void {
		this.db
			.prepare(
				`INSERT OR REPLACE INTO grants (team_id, principal, key_version, wrapped)
         VALUES (?, ?, ?, ?)`,
			)
			.run(teamId, principal, keyVersion, wrapped);
	}

	getGrant(teamId: string, principal: string, keyVersion: number): string | undefined {
		const row = this.db
			.prepare(`SELECT wrapped FROM grants WHERE team_id = ? AND principal = ? AND key_version = ?`)
			.get(teamId, principal, keyVersion) as Record<string, unknown> | undefined;
		return row?.wrapped as string | undefined;
	}

	allGrants(teamId: string): Array<{ principal: string; keyVersion: number; wrapped: string }> {
		const rows = this.db
			.prepare(
				`SELECT principal, key_version, wrapped FROM grants WHERE team_id = ? ORDER BY principal`,
			)
			.all(teamId) as Array<Record<string, unknown>>;
		return rows.map((r) => ({
			principal: r.principal as string,
			keyVersion: r.key_version as number,
			wrapped: r.wrapped as string,
		}));
	}

	// ---- meta (key/value) ----

	setMeta(k: string, v: string): void {
		this.db.prepare(`INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)`).run(k, v);
	}

	getMeta(k: string): string | undefined {
		const row = this.db.prepare(`SELECT v FROM meta WHERE k = ?`).get(k) as
			| Record<string, unknown>
			| undefined;
		return row?.v as string | undefined;
	}
}
