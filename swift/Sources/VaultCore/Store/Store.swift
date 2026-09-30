#if os(Windows)
	import CSQLiteBundled
#else
	import CSQLite
#endif
import Foundation

// SQLite persistence (spec §15.9). Payloads are opaque; no decryption happens here. The
// engine actor serializes access; a recursive lock additionally keeps the handle safe if it
// is shared, and holds a transaction's whole span.

public struct StoreError: Error, Sendable, CustomStringConvertible {
	public let description: String
}

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

private let schema = """
	CREATE TABLE IF NOT EXISTS ops (
	  device_id TEXT NOT NULL,
	  seq       INTEGER NOT NULL,
	  hash      TEXT PRIMARY KEY,
	  sig       TEXT NOT NULL,
	  payload   TEXT NOT NULL,
	  UNIQUE(device_id, seq)
	);
	CREATE TABLE IF NOT EXISTS authlog (
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
	"""

public final class Store: @unchecked Sendable {
	private var db: OpaquePointer?
	private let lock = NSRecursiveLock()

	public init(path: String) throws {
		var handle: OpaquePointer?
		guard sqlite3_open(path, &handle) == SQLITE_OK, let h = handle else {
			let msg = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "open failed"
			sqlite3_close(handle)
			throw StoreError(description: "cannot open database: \(msg)")
		}
		db = h
		// Several processes (CLI, app, peer server) may open one WAL database at once,
		// and even `journal_mode = WAL` below takes a lock: wait instead of failing busy.
		sqlite3_busy_timeout(h, 5000)
		// Ciphertext plus cleartext membership metadata: owner-only (spec §15.9).
		if path != ":memory:" {
			#if !os(Windows)
				chmod(path, 0o600)
			#endif
		}
		try exec("PRAGMA journal_mode = WAL;")
		try exec(schema)
	}

	deinit { close() }

	// A long-lived peer server and the CLI may open the same WAL db at once: wait
	// briefly for a concurrent writer instead of failing with SQLITE_BUSY.
	public func setBusyTimeout(milliseconds: Int) throws {
		try exec("PRAGMA busy_timeout = \(milliseconds);")
	}

	public func close() {
		lock.lock()
		defer { lock.unlock() }
		if let d = db {
			sqlite3_close_v2(d)
			db = nil
		}
	}

	// MARK: plumbing

	private var errmsg: String { db.map { String(cString: sqlite3_errmsg($0)) } ?? "closed" }

	private func exec(_ sql: String) throws {
		guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw StoreError(description: errmsg) }
	}

	enum Arg {
		case text(String)
		case int(Int)
	}

	// Runs `sql`; for each row calls `row` with the statement. Returns rows changed.
	@discardableResult
	private func run(_ sql: String, _ args: [Arg] = [], row: ((OpaquePointer) -> Void)? = nil) throws -> Int {
		lock.lock()
		defer { lock.unlock() }
		var st: OpaquePointer?
		guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK, let stmt = st else {
			throw StoreError(description: errmsg)
		}
		defer { sqlite3_finalize(stmt) }
		for (i, a) in args.enumerated() {
			switch a {
			case .text(let s): sqlite3_bind_text(stmt, Int32(i + 1), s, -1, SQLITE_TRANSIENT)
			case .int(let n): sqlite3_bind_int64(stmt, Int32(i + 1), Int64(n))
			}
		}
		while true {
			let rc = sqlite3_step(stmt)
			if rc == SQLITE_ROW {
				row?(stmt)
			} else if rc == SQLITE_DONE {
				break
			} else {
				throw StoreError(description: errmsg)
			}
		}
		return Int(sqlite3_changes(db))
	}

	private static func text(_ s: OpaquePointer, _ i: Int32) -> String {
		sqlite3_column_text(s, i).map { String(cString: $0) } ?? ""
	}

	// All-or-nothing; nested calls are not supported.
	// `immediate` takes the write lock up front, so a read-then-write inside cannot lose a race.
	public func transaction<T>(immediate: Bool = false, _ body: () throws -> T) throws -> T {
		lock.lock()
		defer { lock.unlock() }
		try exec(immediate ? "BEGIN IMMEDIATE" : "BEGIN")
		do {
			let r = try body()
			try exec("COMMIT")
			return r
		} catch {
			try? exec("ROLLBACK")
			throw error
		}
	}

	// MARK: ops

	// Returns false if already present (dedupe by hash).
	@discardableResult
	public func putOp(_ op: OpEnvelope) throws -> Bool {
		try run(
			"INSERT OR IGNORE INTO ops (device_id, seq, hash, sig, payload) VALUES (?, ?, ?, ?, ?)",
			[.text(op.deviceId), .int(op.seq), .text(op.hash), .text(op.sig), .text(op.payload)]) > 0
	}

	@discardableResult
	public func putOps(_ ops: [OpEnvelope]) throws -> Int {
		try transaction { try ops.reduce(0) { $0 + (try putOp($1) ? 1 : 0) } }
	}

	private static func op(_ s: OpaquePointer) -> OpEnvelope {
		OpEnvelope(
			deviceId: text(s, 0), seq: Int(sqlite3_column_int64(s, 1)), hash: text(s, 2), sig: text(s, 3),
			payload: text(s, 4))
	}

	public func allOps() throws -> [OpEnvelope] {
		var out: [OpEnvelope] = []
		try run("SELECT device_id, seq, hash, sig, payload FROM ops ORDER BY device_id, seq") {
			out.append(Store.op($0))
		}
		return out
	}

	// Highest seq per device; contiguous because ingest is (acceptContiguous).
	public func versionVector() throws -> VersionVector {
		var v: VersionVector = [:]
		try run("SELECT device_id, MAX(seq) AS m FROM ops GROUP BY device_id") {
			let m = Int(sqlite3_column_int64($0, 1))
			if m > 0 { v[Store.text($0, 0)] = m }
		}
		return v
	}

	public func opsSince(_ vector: VersionVector) throws -> [OpEnvelope] {
		var out: [OpEnvelope] = []
		try run(
			"""
			SELECT o.device_id, o.seq, o.hash, o.sig, o.payload FROM ops o
			LEFT JOIN json_each(?) v ON v.key = o.device_id
			WHERE o.seq > COALESCE(v.value, 0)
			ORDER BY o.device_id, o.seq
			""", [.text(vector.json.stringify())]
		) { out.append(Store.op($0)) }
		return out
	}

	public func maxSeq(for deviceId: String) throws -> Int {
		var m = 0
		try run("SELECT MAX(seq) FROM ops WHERE device_id = ?", [.text(deviceId)]) {
			m = Int(sqlite3_column_int64($0, 0))
		}
		return m
	}

	// MARK: auth log

	// Idempotent by the *recomputed* content hash, never a client-supplied one.
	public func appendAuthEntry(_ e: LogEntry) throws {
		var e = e
		e.hash = AuthLog.entryHash(e)
		try run(
			"INSERT OR IGNORE INTO authlog (hash, entry) VALUES (?, ?)",
			[.text(e.hash), .text(e.json.stringify())])
	}

	// Skips rows a replay could not handle (corrupt) rather than throwing.
	public func authLog() throws -> [LogEntry] {
		var out: [LogEntry] = []
		try run("SELECT entry FROM authlog") {
			if let j = try? JSONValue.parse(Store.text($0, 0)), let e = LogEntry(json: j) { out.append(e) }
		}
		return out
	}

	public func authCount() throws -> Int {
		var n = 0
		try run("SELECT COUNT(*) FROM authlog") { n = Int(sqlite3_column_int64($0, 0)) }
		return n
	}

	public func authHashes() throws -> [String] {
		var out: [String] = []
		try run("SELECT hash FROM authlog") { out.append(Store.text($0, 0)) }
		return out
	}

	// MARK: rotations

	public func putRotation(epoch: Int, deviceId: String, record: String) throws {
		try run(
			"INSERT OR REPLACE INTO rotations (epoch, device_id, record) VALUES (?, ?, ?)",
			[.int(epoch), .text(deviceId), .text(record)])
	}

	public func rotations() throws -> [String] {
		var out: [String] = []
		try run("SELECT record FROM rotations ORDER BY epoch") { out.append(Store.text($0, 0)) }
		return out
	}

	// MARK: grants

	public func putGrant(teamId: String, _ g: GrantRow) throws {
		try run(
			"""
			INSERT OR REPLACE INTO grants (team_id, principal, key_version, wrapped, signer_id, sig)
			VALUES (?, ?, ?, ?, ?, ?)
			""", [.text(teamId), .text(g.principal), .int(g.keyVersion), .text(g.wrapped), .text(g.signerId), .text(g.sig)])
	}

	private static func grant(_ s: OpaquePointer) -> GrantRow {
		GrantRow(
			principal: text(s, 0), keyVersion: Int(sqlite3_column_int64(s, 1)), wrapped: text(s, 2),
			signerId: text(s, 3), sig: text(s, 4))
	}

	public func getGrant(teamId: String, principal: String, keyVersion: Int) throws -> GrantRow? {
		var g: GrantRow?
		try run(
			"""
			SELECT principal, key_version, wrapped, signer_id, sig
			FROM grants WHERE team_id = ? AND principal = ? AND key_version = ?
			""", [.text(teamId), .text(principal), .int(keyVersion)]
		) { g = Store.grant($0) }
		return g
	}

	public func allGrants(teamId: String) throws -> [GrantRow] {
		var out: [GrantRow] = []
		try run(
			"""
			SELECT principal, key_version, wrapped, signer_id, sig
			FROM grants WHERE team_id = ? ORDER BY principal
			""", [.text(teamId)]
		) { out.append(Store.grant($0)) }
		return out
	}

	// MARK: meta

	public func setMeta(_ k: String, _ v: String) throws {
		try run("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", [.text(k), .text(v)])
	}

	public func deleteMeta(_ k: String) throws {
		try run("DELETE FROM meta WHERE k = ?", [.text(k)])
	}

	public func meta(_ k: String) throws -> String? {
		var v: String?
		try run("SELECT v FROM meta WHERE k = ?", [.text(k)]) { v = Store.text($0, 0) }
		return v
	}
}
