// node:sqlite storage (spec §9; plan §4, §6). Backs both the CLI replica
// (op log + auth log + rotations + grants + meta) and the
// relay (the opaque `ops` table only). No decryption happens here — payloads are
// opaque blobs; the store is a persistence layer over the protocol types.

import { chmodSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { entryHash, wellFormedEntry, type LogEntry } from "./authlog.ts";
import {
	opsSinceSql,
	rowToOp,
	vectorFromRows,
	vectorSql,
	type GrantRow,
	type OpEnvelope,
	type VersionVector,
} from "./protocol.ts";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS ops (
  device_id TEXT NOT NULL,
  seq       INTEGER NOT NULL,
  hash      TEXT PRIMARY KEY,
  sig       TEXT NOT NULL,
  payload   TEXT NOT NULL,
  UNIQUE(device_id, seq)
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
  signer_id   TEXT NOT NULL,
  sig         TEXT NOT NULL,
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

export class Store {
	readonly db: DatabaseSync;

	constructor(path: string) {
		this.db = new DatabaseSync(path);
		// The replica holds ciphertext plus cleartext membership/relay metadata;
		// default file perms are world-readable (0644 under umask 022). Tighten to
		// owner-only so another local user cannot copy it for offline attack. The
		// enclosing dir is already 0700 (see paths.ts), which also covers the derived
		// -wal/-shm files. Best-effort: skip in-memory and ignore Windows/no-op.
		if (path !== ":memory:") {
			try {
				chmodSync(path, 0o600);
			} catch {
				/* non-fatal: Windows / unsupported fs */
			}
		}
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
		return rows.map(rowToOp);
	}

	// Highest seq per device; contiguous because ingest is (protocol.vectorSql).
	versionVector(): VersionVector {
		return vectorFromRows(
			this.db.prepare(vectorSql("ops", false)).all() as Array<Record<string, unknown>>,
		);
	}

	opsSince(vector: VersionVector): OpEnvelope[] {
		const rows = this.db.prepare(opsSinceSql("ops", false)).all(JSON.stringify(vector));
		return (rows as Array<Record<string, unknown>>).map(rowToOp);
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
	// stored. Insert-or-ignore so a re-seen entry never overwrites. The key is the
	// *recomputed* hash, never the client-supplied `e.hash` field — a synced entry
	// that lies about its hash must not be able to occupy another entry's slot or
	// masquerade as already-held (the relay/worker path recomputes for the same
	// reason).
	appendAuthEntry(e: LogEntry): void {
		if (!wellFormedEntry(e)) return; // never persist a shape replay can't handle
		const hash = entryHash(e);
		this.db
			.prepare(`INSERT OR IGNORE INTO authlog (hash, entry) VALUES (?, ?)`)
			.run(hash, JSON.stringify({ ...e, hash }));
	}

	authLog(): LogEntry[] {
		const rows = this.db.prepare(`SELECT entry FROM authlog`).all() as Array<
			Record<string, unknown>
		>;
		// Skip rows a replay couldn't handle (corrupt) rather than throwing.
		return rows.flatMap((r) => {
			try {
				const entry: unknown = JSON.parse(r.entry as string);
				return wellFormedEntry(entry) ? [{ ...entry, hash: entryHash(entry) }] : [];
			} catch {
				return [];
			}
		});
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

	putGrant(teamId: string, g: GrantRow): void {
		this.db
			.prepare(
				`INSERT OR REPLACE INTO grants (team_id, principal, key_version, wrapped, signer_id, sig)
         VALUES (?, ?, ?, ?, ?, ?)`,
			)
			.run(teamId, g.principal, g.keyVersion, g.wrapped, g.signerId, g.sig);
	}

	getGrant(teamId: string, principal: string, keyVersion: number): GrantRow | undefined {
		const row = this.db
			.prepare(
				`SELECT principal, key_version, wrapped, signer_id, sig
         FROM grants WHERE team_id = ? AND principal = ? AND key_version = ?`,
			)
			.get(teamId, principal, keyVersion) as Record<string, unknown> | undefined;
		return row
			? {
					principal: row.principal as string,
					keyVersion: row.key_version as number,
					wrapped: row.wrapped as string,
					signerId: row.signer_id as string,
					sig: row.sig as string,
				}
			: undefined;
	}

	allGrants(teamId: string): GrantRow[] {
		const rows = this.db
			.prepare(
				`SELECT principal, key_version, wrapped, signer_id, sig
         FROM grants WHERE team_id = ? ORDER BY principal`,
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
