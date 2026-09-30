import Foundation

// Conflict-free key rotation (spec §10.2). Key material is a
// single-valued epoch chosen by a deterministic total order, so concurrent admin
// rotations converge with no coordinator.

public struct SealedGrant: Sendable, Equatable {
	public var ephPub: String
	public var iv: String
	public var ct: String
	public var tag: String

	public init(_ b: SealedBox) {
		ephPub = b.ephPub.base64
		iv = b.iv.base64
		ct = b.ct.base64
		tag = b.tag.base64
	}

	public var sealedBox: SealedBox {
		SealedBox(ephPub: Data(base64: ephPub), iv: Data(base64: iv), ct: Data(base64: ct), tag: Data(base64: tag))
	}

	public var json: JSONValue {
		.obj(["ephPub": .string(ephPub), "iv": .string(iv), "ct": .string(ct), "tag": .string(tag)])
	}

	public init?(json: JSONValue) {
		guard let e = json["ephPub"]?.string, let i = json["iv"]?.string, let c = json["ct"]?.string,
			let t = json["tag"]?.string
		else { return nil }
		ephPub = e
		iv = i
		ct = c
		tag = t
	}
}

public struct RotationRecord: Sendable, Equatable {
	public var epoch: Int
	public var baseEpoch: Int
	public var hlc: String
	public var deviceId: String
	public var keyCommit: String  // hex sha256(K_epoch)
	public var grants: OrderedMap<String, SealedGrant>  // recipient X25519 pub b64 -> sealed key
	public var observed: [String]
	public var signerId: String
	public var sig: String

	public init(
		epoch: Int, baseEpoch: Int, hlc: String, deviceId: String, keyCommit: String,
		grants: OrderedMap<String, SealedGrant>, observed: [String], signerId: String, sig: String = ""
	) {
		self.epoch = epoch
		self.baseEpoch = baseEpoch
		self.hlc = hlc
		self.deviceId = deviceId
		self.keyCommit = keyCommit
		self.grants = grants
		self.observed = observed
		self.signerId = signerId
		self.sig = sig
	}

	private var unsignedMembers: [JSONMember] {
		[
			JSONMember("epoch", .int(Int64(epoch))), JSONMember("baseEpoch", .int(Int64(baseEpoch))),
			JSONMember("hlc", .string(hlc)), JSONMember("deviceId", .string(deviceId)),
			JSONMember("keyCommit", .string(keyCommit)),
			JSONMember("grants", .object(grants.map { JSONMember($0.key, $0.value.json) })),
			JSONMember("observed", .array(observed.map { .string($0) })),
			JSONMember("signerId", .string(signerId)),
		]
	}

	public var signedBytes: Data { JSONValue.object(unsignedMembers).serialized() }
	public var json: JSONValue { .object(unsignedMembers + [JSONMember("sig", .string(sig))]) }
	public var serialized: String { json.stringify() }

	// Strict structural parse: nil if malformed.
	public init?(json: JSONValue) {
		guard case .object = json,
			let epoch = json["epoch"]?.int, let base = json["baseEpoch"]?.int,
			epoch >= 1, base == epoch - 1,
			let hlc = json["hlc"]?.string, let deviceId = json["deviceId"]?.string,
			let commit = json["keyCommit"]?.string, let signerId = json["signerId"]?.string,
			let sig = json["sig"]?.string, let gm = json["grants"]?.members,
			let obs = json["observed"]?.array
		else { return nil }
		var grants = OrderedMap<String, SealedGrant>()
		for m in gm {
			guard let g = SealedGrant(json: m.value) else { return nil }
			grants[m.key] = g
		}
		var observed: [String] = []
		for o in obs {
			guard let s = o.string else { return nil }
			observed.append(s)
		}
		self.init(
			epoch: Int(epoch), baseEpoch: Int(base), hlc: hlc, deviceId: deviceId, keyCommit: commit,
			grants: grants, observed: observed, signerId: signerId, sig: sig)
	}

	// Parse a stored/transported record, tolerating garbage.
	public static func parse(_ raw: String) -> RotationRecord? {
		(try? JSONValue.parse(raw)).flatMap { RotationRecord(json: $0) }
	}
}

public enum Rotation {
	public static func keyCommit(_ key: Data) -> String { VaultCrypto.sha256(key).hex }

	public static func sign(_ rec: RotationRecord, deviceSignPriv: Data) throws -> RotationRecord {
		var r = rec
		r.sig = try VaultCrypto.sign(rec.signedBytes, deviceSignPriv).base64
		return r
	}

	// Ed25519 results are memoized by (key, sig, digest of the signed bytes): every sync and every
	// relay push re-checks the same growing set of records several times, and hashing is far
	// cheaper than verifying. Bounded.
	private final class VerifyCache: @unchecked Sendable {
		private let lock = NSLock()
		private var hits: [String: Bool] = [:]
		func get(_ k: String) -> Bool? { lock.lock(); defer { lock.unlock() }; return hits[k] }
		func put(_ k: String, _ v: Bool) {
			lock.lock()
			if hits.count >= 8192 { hits.removeAll() }
			hits[k] = v
			lock.unlock()
		}
	}
	private static let verifyCache = VerifyCache()

	public static func verify(_ r: RotationRecord, signerPub: Data) -> Bool {
		let bytes = r.signedBytes
		let key = signerPub.base64 + "|" + r.sig + "|" + VaultCrypto.sha256(bytes).hex
		if let hit = verifyCache.get(key) { return hit }
		let ok = VaultCrypto.verify(bytes, pub: signerPub, sig: Data(base64: r.sig))
		verifyCache.put(key, ok)
		return ok
	}

	// Signed by the (possibly since-removed) device it names, against the retained
	// historical key. Enough to keep a record for key recovery.
	public static func verifiable(_ r: RotationRecord, _ m: Membership) -> Bool {
		guard r.signerId == r.deviceId, let pub = m.deviceKeys[r.signerId] else { return false }
		return verify(r, signerPub: pub)
	}

	// Whether a rotation may advance the *current* epoch: self-signed by an active
	// owner/admin device. Historical keys are deliberately insufficient.
	public static func authentic(_ r: RotationRecord, _ m: Membership) -> Bool {
		guard r.signerId == r.deviceId, let signer = AuthLog.activeDeviceMember(m, r.signerId),
			signer.role == .owner || signer.role == .admin,
			let d = signer.devices[r.signerId]
		else { return false }
		return verify(r, signerPub: Data(base64: d.signPub))
	}

	// Higher epoch wins; within an epoch, argmax over (hlc, deviceId).
	public static func winner(_ records: [RotationRecord]) -> RotationRecord? {
		var best: RotationRecord?
		for r in records {
			guard let b = best else {
				best = r
				continue
			}
			if r.epoch > b.epoch {
				best = r
			} else if r.epoch == b.epoch {
				let c = HLCCodec.compareEncoded(r.hlc, b.hlc)
				if c > 0 || (c == 0 && jsLess(b.deviceId, r.deviceId)) { best = r }
			}
		}
		return best
	}

	// The winning rotation did not observe a removal that has since landed.
	public static func needsCatchUp(_ win: RotationRecord?, removalHashes: [String]) -> Bool {
		guard let win else { return false }
		let observed = Set(win.observed)
		return removalHashes.contains { !observed.contains($0) }
	}

	public static func id(epoch: Int, deviceId: String) -> String { "\(epoch):\(deviceId)" }

	// Of serialized records, those that verify, with their ids.
	public static func verifiableRecords(_ records: [String], _ m: Membership?) -> [(id: String, record: String)] {
		guard let m else { return [] }
		return records.compactMap { raw in
			guard let r = RotationRecord.parse(raw), verifiable(r, m) else { return nil }
			return (id(epoch: r.epoch, deviceId: r.deviceId), raw)
		}
	}
}
