#if os(Windows)
	import CSQLiteBundled
#else
	import CSQLite
#endif
import Foundation

// Team-partitioned relay storage: the always-on hub's opaque op log plus the cleartext
// membership/rotation/grant metadata that gossips through it. It holds no keys and cannot
// read payloads. The relay is treated as untrusted by clients, but it still refuses to persist
// unauthenticated metadata so a hostile writer cannot grow it without bound.

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

private let relaySchema = """
	CREATE TABLE IF NOT EXISTS relay_ops (
	  team_id TEXT NOT NULL, device_id TEXT NOT NULL, seq INTEGER NOT NULL,
	  hash TEXT NOT NULL, sig TEXT NOT NULL, payload TEXT NOT NULL,
	  PRIMARY KEY (team_id, hash), UNIQUE (team_id, device_id, seq)
	);
	CREATE TABLE IF NOT EXISTS relay_authlog (
	  team_id TEXT NOT NULL, hash TEXT NOT NULL, entry TEXT NOT NULL, PRIMARY KEY (team_id, hash)
	);
	CREATE TABLE IF NOT EXISTS relay_roots (team_id TEXT PRIMARY KEY, hash TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS relay_rotations (
	  team_id TEXT NOT NULL, epoch INTEGER NOT NULL, device_id TEXT NOT NULL, record TEXT NOT NULL,
	  PRIMARY KEY (team_id, epoch, device_id)
	);
	CREATE TABLE IF NOT EXISTS relay_grants (
	  team_id TEXT NOT NULL, principal TEXT NOT NULL, key_version INTEGER NOT NULL, wrapped TEXT NOT NULL,
	  signer_id TEXT NOT NULL, sig TEXT NOT NULL, PRIMARY KEY (team_id, principal, key_version)
	);
	"""

public final class RelayStore: RelayStorage, @unchecked Sendable {
	private var db: OpaquePointer?
	private let lock = NSRecursiveLock()
	private var memberCache: [String: (count: Int, membership: Membership)] = [:]

	public init(path: String) throws {
		var handle: OpaquePointer?
		guard sqlite3_open(path, &handle) == SQLITE_OK, let h = handle else {
			sqlite3_close(handle)
			throw StoreError(description: "cannot open relay database")
		}
		db = h
		sqlite3_busy_timeout(h, 5000)
		#if !os(Windows)
			if path != ":memory:" { chmod(path, 0o600) }
		#endif
		try exec("PRAGMA journal_mode = WAL;")
		try exec(relaySchema)
	}

	deinit { close() }

	public func close() {
		lock.lock()
		defer { lock.unlock() }
		if let d = db {
			sqlite3_close_v2(d)
			db = nil
		}
	}

	// MARK: plumbing

	private func exec(_ sql: String) throws {
		guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw StoreError(description: db.map { String(cString: sqlite3_errmsg($0)) } ?? "closed") }
	}

	enum Arg {
		case text(String)
		case int(Int)
	}

	@discardableResult
	private func run(_ sql: String, _ args: [Arg] = [], row: ((OpaquePointer) -> Void)? = nil) throws -> Int {
		lock.lock()
		defer { lock.unlock() }
		var st: OpaquePointer?
		guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK, let stmt = st else {
			throw StoreError(description: db.map { String(cString: sqlite3_errmsg($0)) } ?? "closed")
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
			if rc == SQLITE_ROW { row?(stmt) } else if rc == SQLITE_DONE { break } else {
				throw StoreError(description: db.map { String(cString: sqlite3_errmsg($0)) } ?? "closed")
			}
		}
		return Int(sqlite3_changes(db))
	}

	private static func text(_ s: OpaquePointer, _ i: Int32) -> String { sqlite3_column_text(s, i).map { String(cString: $0) } ?? "" }

	// MARK: ops

	public func putOp(_ t: String, _ op: OpEnvelope) throws -> Bool {
		try run("INSERT OR IGNORE INTO relay_ops (team_id, device_id, seq, hash, sig, payload) VALUES (?, ?, ?, ?, ?, ?)",
			[.text(t), .text(op.deviceId), .int(op.seq), .text(op.hash), .text(op.sig), .text(op.payload)]) > 0
	}

	public func opsSince(_ t: String, _ vector: VersionVector) throws -> [OpEnvelope] {
		var out: [OpEnvelope] = []
		try run(
			"""
			SELECT o.device_id, o.seq, o.hash, o.sig, o.payload FROM relay_ops o
			LEFT JOIN json_each(?) v ON v.key = o.device_id
			WHERE o.team_id = ? AND o.seq > COALESCE(v.value, 0) ORDER BY o.device_id, o.seq
			""", [.text(vector.json.stringify()), .text(t)]
		) { out.append(OpEnvelope(deviceId: Self.text($0, 0), seq: Int(sqlite3_column_int64($0, 1)), hash: Self.text($0, 2), sig: Self.text($0, 3), payload: Self.text($0, 4))) }
		return out
	}

	public func maxSeq(_ t: String, _ d: String) throws -> Int {
		var m = 0
		try run("SELECT MAX(seq) FROM relay_ops WHERE team_id = ? AND device_id = ?", [.text(t), .text(d)]) { m = Int(sqlite3_column_int64($0, 0)) }
		return m
	}

	public func vector(_ t: String) throws -> VersionVector {
		var v: VersionVector = [:]
		try run("SELECT device_id, MAX(seq) FROM relay_ops WHERE team_id = ? GROUP BY device_id", [.text(t)]) {
			let m = Int(sqlite3_column_int64($0, 1))
			if m > 0 { v[Self.text($0, 0)] = m }
		}
		return v
	}

	// MARK: auth log

	private func storedAuth(_ t: String) throws -> [LogEntry] {
		var out: [LogEntry] = []
		try run("SELECT entry FROM relay_authlog WHERE team_id = ?", [.text(t)]) {
			if let j = try? JSONValue.parse(Self.text($0, 0)), let e = LogEntry(json: j) { out.append(e) }
		}
		return out
	}

	private func rootHash(_ t: String, candidate: String? = nil) throws -> String? {
		func pinned() throws -> String? {
			var h: String?
			try run("SELECT hash FROM relay_roots WHERE team_id = ?", [.text(t)]) { h = Self.text($0, 0) }
			return h
		}
		if let p = try pinned() { return p }
		guard let candidate else { return nil }
		try run("INSERT OR IGNORE INTO relay_roots (team_id, hash) VALUES (?, ?)", [.text(t), .text(candidate)])
		return try pinned()
	}

	public func pinGenesis(_ t: String, _ entry: LogEntry) throws -> Bool {
		guard AuthLog.validRootGenesis(entry, expectedVaultId: t) else { return false }
		let h = AuthLog.entryHash(entry)
		return try rootHash(t, candidate: h) == h
	}

	// Only entries that verify against the team's stored log are persisted.
	public func putAuthBatch(_ t: String, _ entries: [LogEntry]) throws {
		guard !entries.isEmpty else { return }
		let held = Set(try authHashes(t))
		var seen = held
		let fresh = entries.filter { seen.insert(AuthLog.entryHash($0)).inserted }
		for var e in AuthLog.admissible(fresh, existing: try authExcept(t, []), expectedVaultId: t) {
			let h = AuthLog.entryHash(e)  // keyed by the recomputed hash, never the client's field
			e.hash = h
			try run("INSERT OR IGNORE INTO relay_authlog (team_id, hash, entry) VALUES (?, ?, ?)", [.text(t), .text(h), .text(e.json.stringify())])
		}
	}

	private func authCount(_ t: String) throws -> Int {
		var n = 0
		try run("SELECT COUNT(*) FROM relay_authlog WHERE team_id = ?", [.text(t)]) { n = Int(sqlite3_column_int64($0, 0)) }
		return n
	}

	private func authHashes(_ t: String) throws -> [String] {
		var out: [String] = []
		try run("SELECT hash FROM relay_authlog WHERE team_id = ?", [.text(t)]) { out.append(Self.text($0, 0)) }
		return out
	}

	public func authExcept(_ t: String, _ have: Set<String>) throws -> [LogEntry] {
		let pinned = try rootHash(t)
		var seen = have
		return try storedAuth(t).filter { e in
			let h = AuthLog.entryHash(e)
			if e.body.type == "genesis", h != pinned || !AuthLog.validRootGenesis(e, expectedVaultId: t) { return false }
			return seen.insert(h).inserted
		}
	}

	public func authLacking(_ t: String, _ hashes: [String]) throws -> [String] {
		let held = Set(try authHashes(t))
		return hashes.filter { !held.contains($0) }
	}

	// Membership from the team's log, memoized by entry count (the log only grows).
	public func membershipFor(_ t: String) -> Membership? {
		lock.lock()
		defer { lock.unlock() }
		let count = (try? authCount(t)) ?? 0
		if let c = memberCache[t], c.count == count { return c.membership }
		// teamId == vaultId: pinning the genesis stops a gossiped rival root from changing
		// which keys authenticate ops.
		guard let entries = try? authExcept(t, []), let m = try? AuthLog.replay(entries, expectedVaultId: t) else { return nil }
		memberCache[t] = (count, m)
		return m
	}

	// MARK: rotations

	private func verifiedRotations(_ t: String) throws -> [(id: String, record: String)] {
		var rows: [String] = []
		try run("SELECT record FROM relay_rotations WHERE team_id = ? ORDER BY epoch", [.text(t)]) { rows.append(Self.text($0, 0)) }
		return Rotation.verifiableRecords(rows, membershipFor(t))
	}

	public func putRotation(_ t: String, _ rec: RotationRecord) throws {
		// Replace a slot's record unless the one there already verifies, so an
		// unverifiable record cannot shadow the genuine one.
		if try verifiedRotations(t).contains(where: { $0.id == Rotation.id(epoch: rec.epoch, deviceId: rec.deviceId) }) { return }
		try run("INSERT OR REPLACE INTO relay_rotations (team_id, epoch, device_id, record) VALUES (?, ?, ?, ?)",
			[.text(t), .int(rec.epoch), .text(rec.deviceId), .text(rec.serialized)])
	}

	public func rotationsExcept(_ t: String, _ have: Set<String>) throws -> [String] {
		try verifiedRotations(t).filter { !have.contains($0.id) }.map(\.record)
	}

	public func rotationsLacking(_ t: String, _ ids: [String]) throws -> [String] {
		let held = Set(try verifiedRotations(t).map(\.id))
		return ids.filter { !held.contains($0) }
	}

	// MARK: grants

	// First-write-wins: a (team, principal, keyVersion) slot is immutable once set, so a
	// captured, stale but authentic grant re-pushed later cannot overwrite the current one.
	public func putGrant(_ t: String, _ g: GrantRow) throws {
		try run("INSERT OR IGNORE INTO relay_grants (team_id, principal, key_version, wrapped, signer_id, sig) VALUES (?, ?, ?, ?, ?, ?)",
			[.text(t), .text(g.principal), .int(g.keyVersion), .text(g.wrapped), .text(g.signerId), .text(g.sig)])
	}

	public func allGrants(_ t: String) throws -> [GrantRow] {
		var out: [GrantRow] = []
		try run("SELECT principal, key_version, wrapped, signer_id, sig FROM relay_grants WHERE team_id = ? ORDER BY principal", [.text(t)]) {
			out.append(GrantRow(principal: Self.text($0, 0), keyVersion: Int(sqlite3_column_int64($0, 1)), wrapped: Self.text($0, 2), signerId: Self.text($0, 3), sig: Self.text($0, 4)))
		}
		return out
	}
}
