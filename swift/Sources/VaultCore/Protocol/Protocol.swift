import Foundation

// Wire protocol for anti-entropy sync (spec §8, §15.12).

public struct OpEnvelope: Sendable, Equatable {
	public var deviceId: String
	public var seq: Int
	public var hash: String  // hex sha256 over "deviceId|seq|payload"
	public var sig: String  // base64 Ed25519 over the hash bytes
	public var payload: String  // base64 opaque ciphertext

	public init(deviceId: String, seq: Int, hash: String, sig: String, payload: String) {
		self.deviceId = deviceId
		self.seq = seq
		self.hash = hash
		self.sig = sig
		self.payload = payload
	}

	public var json: JSONValue {
		.obj([
			"deviceId": .string(deviceId), "seq": .int(Int64(seq)), "hash": .string(hash),
			"sig": .string(sig), "payload": .string(payload),
		])
	}

	public init?(json: JSONValue) {
		guard let d = json["deviceId"]?.string, let s = json["seq"]?.int, let h = json["hash"]?.string,
			let sig = json["sig"]?.string, let p = json["payload"]?.string
		else { return nil }
		self.init(deviceId: d, seq: Int(s), hash: h, sig: sig, payload: p)
	}
}

// deviceId -> highest contiguous seq the holder has.
public typealias VersionVector = [String: Int]

extension Dictionary where Key == String, Value == Int {
	public var json: JSONValue {
		.object(Array(keys).jsSorted().map { JSONMember($0, .int(Int64(self[$0]!))) })
	}
	public init?(vectorJSON j: JSONValue) {
		guard let m = j.members else { return nil }
		self.init()
		for kv in m {
			guard let i = kv.value.int else { return nil }
			self[kv.key] = Int(i)
		}
	}
}

// A row of the grants channel: the org-key announcement and each member's
// recovery grant.
public struct GrantRow: Sendable, Equatable {
	public var principal: String  // "orgPublicKey" | "recovery:<userId>"
	public var keyVersion: Int
	public var wrapped: String
	public var signerId: String
	public var sig: String

	public init(principal: String, keyVersion: Int, wrapped: String, signerId: String, sig: String) {
		self.principal = principal
		self.keyVersion = keyVersion
		self.wrapped = wrapped
		self.signerId = signerId
		self.sig = sig
	}

	public var json: JSONValue {
		.obj([
			"principal": .string(principal), "keyVersion": .int(Int64(keyVersion)),
			"wrapped": .string(wrapped), "signerId": .string(signerId), "sig": .string(sig),
		])
	}

	public init?(json: JSONValue) {
		guard let p = json["principal"]?.string, let k = json["keyVersion"]?.int, k >= 0,
			let w = json["wrapped"]?.string, let s = json["signerId"]?.string, let sig = json["sig"]?.string
		else { return nil }
		self.init(principal: p, keyVersion: Int(k), wrapped: w, signerId: s, sig: sig)
	}
}

public struct SyncRequest: Sendable, Equatable {
	public var teamId: String
	public var vector: VersionVector
	public var authHashes: [String]
	public var rotationIds: [String]

	public init(teamId: String, vector: VersionVector, authHashes: [String], rotationIds: [String]) {
		self.teamId = teamId
		self.vector = vector
		self.authHashes = authHashes
		self.rotationIds = rotationIds
	}

	public var json: JSONValue {
		.obj([
			"teamId": .string(teamId), "vector": vector.json,
			"authHashes": .array(authHashes.map { .string($0) }),
			"rotationIds": .array(rotationIds.map { .string($0) }),
		])
	}
}

public struct SyncResponse: Sendable, Equatable {
	public var ops: [OpEnvelope]
	public var vector: VersionVector
	public var authLog: [LogEntry]
	public var rotations: [String]
	public var grants: [GrantRow]
	public var lacksAuth: [String]
	public var lacksRotations: [String]

	public init(
		ops: [OpEnvelope], vector: VersionVector, authLog: [LogEntry], rotations: [String], grants: [GrantRow],
		lacksAuth: [String], lacksRotations: [String]
	) {
		self.ops = ops
		self.vector = vector
		self.authLog = authLog
		self.rotations = rotations
		self.grants = grants
		self.lacksAuth = lacksAuth
		self.lacksRotations = lacksRotations
	}

	public var json: JSONValue {
		.obj([
			"ops": .array(ops.map(\.json)), "vector": vector.json, "authLog": .array(authLog.map(\.json)),
			"rotations": .array(rotations.map { .string($0) }), "grants": .array(grants.map(\.json)),
			"lacksAuth": .array(lacksAuth.map { .string($0) }), "lacksRotations": .array(lacksRotations.map { .string($0) }),
		])
	}

	public init?(json: JSONValue) {
		func strings(_ k: String) -> [String]? { json[k]?.array?.compactMap { $0.string } }
		// A relay may omit empty collections; only a non-object body is malformed.
		guard case .object = json else { return nil }
		let ops = json["ops"]?.array ?? []
		let auth = json["authLog"]?.array ?? []
		let rots = strings("rotations") ?? []
		self.ops = ops.compactMap { OpEnvelope(json: $0) }
		self.vector = json["vector"].flatMap { VersionVector(vectorJSON: $0) } ?? [:]
		// Malformed entries are dropped, never fatal (they'd break every replay).
		self.authLog = auth.compactMap { LogEntry(json: $0) }
		self.rotations = rots
		self.grants = (json["grants"]?.array ?? []).compactMap { GrantRow(json: $0) }
		self.lacksAuth = strings("lacksAuth") ?? []
		self.lacksRotations = strings("lacksRotations") ?? []
	}
}

public struct PushRequest: Sendable, Equatable {
	public var teamId: String
	public var ops: [OpEnvelope]
	public var authLog: [LogEntry]?
	public var rotations: [String]?
	public var grants: [GrantRow]?

	public init(
		teamId: String, ops: [OpEnvelope], authLog: [LogEntry]? = nil, rotations: [String]? = nil,
		grants: [GrantRow]? = nil
	) {
		self.teamId = teamId
		self.ops = ops
		self.authLog = authLog
		self.rotations = rotations
		self.grants = grants
	}

	public var json: JSONValue {
		var m: [JSONMember] = [
			JSONMember("teamId", .string(teamId)), JSONMember("ops", .array(ops.map(\.json))),
		]
		if let a = authLog { m.append(JSONMember("authLog", .array(a.map(\.json)))) }
		if let r = rotations { m.append(JSONMember("rotations", .array(r.map { .string($0) }))) }
		if let g = grants { m.append(JSONMember("grants", .array(g.map(\.json)))) }
		return .object(m)
	}
}

public enum WireProtocol {
	public static func envelopeBytes(deviceId: String, seq: Int, payload: String) -> Data {
		Data("\(deviceId)|\(seq)|\(payload)".utf8)
	}

	public static func makeEnvelope(deviceId: String, seq: Int, payload: Data, signPriv: Data) throws -> OpEnvelope {
		let b64 = payload.base64
		let hash = VaultCrypto.sha256(envelopeBytes(deviceId: deviceId, seq: seq, payload: b64))
		return OpEnvelope(
			deviceId: deviceId, seq: seq, hash: hash.hex,
			sig: try VaultCrypto.sign(hash, signPriv).base64, payload: b64)
	}

	public static func verifyEnvelope(_ env: OpEnvelope, signPub: Data) -> Bool {
		let expected = VaultCrypto.sha256(envelopeBytes(deviceId: env.deviceId, seq: env.seq, payload: env.payload))
		guard expected.hex == env.hash, let h = Data(hex: env.hash) else { return false }
		return VaultCrypto.verify(h, pub: signPub, sig: Data(base64: env.sig))
	}

	// ---- grants ----

	public static func grantBytes(teamId: String, principal: String, keyVersion: Int, wrapped: String, signerId: String)
		-> Data
	{
		JSONValue.obj([
			"teamId": .string(teamId), "principal": .string(principal),
			"keyVersion": .int(Int64(keyVersion)), "wrapped": .string(wrapped),
			"signerId": .string(signerId),
		]).serialized()
	}

	public static func verifyGrant(teamId: String, _ g: GrantRow, signerPub: Data) -> Bool {
		VaultCrypto.verify(
			grantBytes(teamId: teamId, principal: g.principal, keyVersion: g.keyVersion, wrapped: g.wrapped, signerId: g.signerId),
			pub: signerPub, sig: Data(base64: g.sig))
	}

	private static func principalOk(_ g: GrantRow, signerRole: Role, signerUserId: String) -> Bool {
		if g.principal == "orgPublicKey" { return g.keyVersion == 0 && signerRole == .owner }
		guard g.principal.hasPrefix("recovery:") else { return false }
		let userId = String(g.principal.dropFirst("recovery:".count))
		return g.keyVersion == 0 && !userId.isEmpty && signerUserId == userId
	}

	// Stored only if signed by a currently active device with the right authority.
	public static func grantAuthentic(teamId: String, _ g: GrantRow, _ m: Membership) -> Bool {
		guard g.keyVersion >= 0, let signer = AuthLog.activeDeviceMember(m, g.signerId),
			let d = signer.devices[g.signerId]
		else { return false }
		return verifyGrant(teamId: teamId, g, signerPub: Data(base64: d.signPub))
			&& principalOk(g, signerRole: signer.role, signerUserId: signer.userId)
	}

	// Reading back an accepted grant: the signer may since have been removed.
	public static func grantVerifiable(teamId: String, _ g: GrantRow, _ m: Membership) -> Bool {
		guard g.keyVersion >= 0, let pub = m.deviceKeys[g.signerId], let owner = m.deviceOwners[g.signerId],
			verifyGrant(teamId: teamId, g, signerPub: pub), let signer = m.members[owner]
		else { return false }
		return principalOk(g, signerRole: signer.role, signerUserId: owner)
	}

	// Keep an op log gap-free: of `ops`, those extending each device's run
	// contiguously from `maxSeq(deviceId)`, in order; anything past a gap is dropped.
	public static func acceptContiguous(_ ops: [OpEnvelope], maxSeq: (String) -> Int) -> [OpEnvelope] {
		var next: [String: Int] = [:]
		var out: [OpEnvelope] = []
		let sorted = ops.sorted {
			$0.deviceId == $1.deviceId ? $0.seq < $1.seq : jsLess($0.deviceId, $1.deviceId)
		}
		for op in sorted {
			guard op.seq >= 1 else { continue }
			let have = next[op.deviceId] ?? maxSeq(op.deviceId)
			if op.seq > have + 1 { continue }  // gap
			out.append(op)
			next[op.deviceId] = max(have, op.seq)
		}
		return out
	}
}
