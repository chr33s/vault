import Foundation

// Relay-shaped storage over a device's OWN local replica, scoped to one vault
//. It lets a device act as a relay peer for the direct tailnet
// path: it serves and accepts the same opaque op log plus signed membership,
// rotation and grant metadata as the hub, holds no keys, and works while the
// vault is locked. Requests for any other teamId are refused.

public protocol RelayStorage: AnyObject {
	func putOp(_ teamId: String, _ op: OpEnvelope) throws -> Bool
	func opsSince(_ teamId: String, _ vector: VersionVector) throws -> [OpEnvelope]
	func maxSeq(_ teamId: String, _ deviceId: String) throws -> Int
	func vector(_ teamId: String) throws -> VersionVector
	// Persist only entries that verify against the stored log (see AuthLog.admissible).
	func putAuthBatch(_ teamId: String, _ entries: [LogEntry]) throws
	func pinGenesis(_ teamId: String, _ entry: LogEntry) throws -> Bool
	func authExcept(_ teamId: String, _ have: Set<String>) throws -> [LogEntry]
	func putRotation(_ teamId: String, _ rec: RotationRecord) throws
	func rotationsExcept(_ teamId: String, _ have: Set<String>) throws -> [String]
	func authLacking(_ teamId: String, _ hashes: [String]) throws -> [String]
	func rotationsLacking(_ teamId: String, _ ids: [String]) throws -> [String]
	func putGrant(_ teamId: String, _ g: GrantRow) throws
	func allGrants(_ teamId: String) throws -> [GrantRow]
}

public final class PeerStore: RelayStorage, @unchecked Sendable {
	private let store: Store
	public let vaultId: String
	private var pinnedGenesisHash: String?
	private var memberCache: (count: Int, membership: Membership?)?
	private let lock = NSRecursiveLock()

	public init(store: Store, vaultId: String) throws {
		self.store = store
		self.vaultId = vaultId
		pinnedGenesisHash = try store.authLog().first { AuthLog.validRootGenesis($0, expectedVaultId: vaultId) }.map(AuthLog.entryHash)
	}

	private func mine(_ t: String) -> Bool { t == vaultId }

	public func putOp(_ t: String, _ op: OpEnvelope) throws -> Bool { mine(t) ? try store.putOp(op) : false }
	public func opsSince(_ t: String, _ v: VersionVector) throws -> [OpEnvelope] { mine(t) ? try store.opsSince(v) : [] }
	public func maxSeq(_ t: String, _ d: String) throws -> Int { mine(t) ? try store.maxSeq(for: d) : 0 }
	public func vector(_ t: String) throws -> VersionVector { mine(t) ? try store.versionVector() : [:] }

	public func putAuthBatch(_ t: String, _ entries: [LogEntry]) throws {
		guard mine(t), !entries.isEmpty else { return }
		let have = Set(try store.authHashes())
		var seen = have
		let fresh = entries.filter { seen.insert(AuthLog.entryHash($0)).inserted }
		// Keyed by the recomputed hash (the store does this); never the pusher's field.
		for e in AuthLog.admissible(fresh, existing: try store.authLog(), expectedVaultId: vaultId) { try store.appendAuthEntry(e) }
	}

	public func pinGenesis(_ t: String, _ entry: LogEntry) throws -> Bool {
		lock.lock()
		defer { lock.unlock() }
		guard mine(t), AuthLog.validRootGenesis(entry, expectedVaultId: t) else { return false }
		let h = AuthLog.entryHash(entry)
		if pinnedGenesisHash == nil { pinnedGenesisHash = h }
		return pinnedGenesisHash == h
	}

	public func authExcept(_ t: String, _ have: Set<String>) throws -> [LogEntry] {
		guard mine(t) else { return [] }
		lock.lock()
		let pinned = pinnedGenesisHash
		lock.unlock()
		var seen = have
		return try store.authLog().filter { e in
			let h = AuthLog.entryHash(e)
			if e.body.type == "genesis", h != pinned || !AuthLog.validRootGenesis(e, expectedVaultId: t) { return false }
			return seen.insert(h).inserted
		}
	}

	public func putRotation(_ t: String, _ rec: RotationRecord) throws {
		if mine(t) { try store.putRotation(epoch: rec.epoch, deviceId: rec.deviceId, record: rec.serialized) }
	}

	// Membership from this device's own auth log, memoized by entry count (the log
	// only grows). nil until a valid genesis exists: nothing is authorized yet.
	public func membership() -> Membership? {
		lock.lock()
		defer { lock.unlock() }
		let count = (try? store.authCount()) ?? 0
		if memberCache?.count != count {
			let m = (try? store.authLog()).flatMap { try? AuthLog.replay($0, expectedVaultId: vaultId) }
			memberCache = (count, m)
		}
		return memberCache?.membership
	}

	// Only rotations that verify are served and counted as held, so a pusher's
	// genuine record for a slot holding a bogus one is requested and replaces it.
	private func rotationRows() throws -> [(id: String, record: String)] {
		Rotation.verifiableRecords(try store.rotations(), membership())
	}

	public func rotationsExcept(_ t: String, _ have: Set<String>) throws -> [String] {
		guard mine(t) else { return [] }
		return try rotationRows().filter { !have.contains($0.id) }.map(\.record)
	}

	public func authLacking(_ t: String, _ hashes: [String]) throws -> [String] {
		guard mine(t) else { return [] }
		let held = Set(try store.authHashes())
		return hashes.filter { !held.contains($0) }
	}

	public func rotationsLacking(_ t: String, _ ids: [String]) throws -> [String] {
		guard mine(t) else { return [] }
		let held = Set(try rotationRows().map(\.id))
		return ids.filter { !held.contains($0) }
	}

	public func putGrant(_ t: String, _ g: GrantRow) throws { if mine(t) { try store.putGrant(teamId: t, g) } }
	public func allGrants(_ t: String) throws -> [GrantRow] { mine(t) ? try store.allGrants(teamId: t) : [] }
}
