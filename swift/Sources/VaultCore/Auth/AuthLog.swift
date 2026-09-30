import Foundation

// Signed membership log (spec §5, §15.10): a signed Merkle DAG.
// Entries reference the heads they observed and are signed over content+parents,
// so concurrent membership edits reconcile deterministically at replay.

public enum Role: String, Sendable { case owner, admin, member }

public enum SignerKind: String, Sendable { case user, device }

// An entry body kept as ordered JSON: the canonical bytes are
// `JSON.stringify(body)` of whatever the author produced, so member order (and
// unknown future types) must survive a parse/serialize round trip.
public struct EntryBody: Sendable, Equatable {
	public var raw: JSONValue
	public init(raw: JSONValue) { self.raw = raw }

	public var type: String? { raw["type"]?.string }
	public func str(_ k: String) -> String? { raw[k]?.string }

	public static func genesis(
		vaultId: String, userId: String, userSignPub: String, userEncPub: String
	) -> EntryBody {
		EntryBody(
			raw: .obj([
				"type": "genesis", "vaultId": .string(vaultId), "userId": .string(userId),
				"userSignPub": .string(userSignPub), "userEncPub": .string(userEncPub),
				"role": "owner",
			]))
	}
	public static func addUser(userId: String, userSignPub: String, userEncPub: String, role: Role)
		-> EntryBody
	{
		EntryBody(
			raw: .obj([
				"type": "add-user", "userId": .string(userId), "userSignPub": .string(userSignPub),
				"userEncPub": .string(userEncPub), "role": .string(role.rawValue),
			]))
	}
	public static func addDevice(
		userId: String, deviceId: String, deviceSignPub: String, deviceEncPub: String
	) -> EntryBody {
		EntryBody(
			raw: .obj([
				"type": "add-device", "userId": .string(userId), "deviceId": .string(deviceId),
				"deviceSignPub": .string(deviceSignPub), "deviceEncPub": .string(deviceEncPub),
			]))
	}
	public static func proveDevice(userId: String, deviceId: String) -> EntryBody {
		EntryBody(raw: .obj(["type": "prove-device", "userId": .string(userId), "deviceId": .string(deviceId)]))
	}
	public static func removeDevice(userId: String, deviceId: String) -> EntryBody {
		EntryBody(raw: .obj(["type": "remove-device", "userId": .string(userId), "deviceId": .string(deviceId)]))
	}
	public static func removeUser(userId: String) -> EntryBody {
		EntryBody(raw: .obj(["type": "remove-user", "userId": .string(userId)]))
	}

	// Structural check of an entry body.
	var wellFormed: Bool {
		guard case .object = raw, let t = type else { return false }
		func s(_ k: String) -> Bool { str(k) != nil }
		switch t {
		case "genesis":
			return s("vaultId") && s("userId") && s("userSignPub") && s("userEncPub") && str("role") == "owner"
		case "add-user": return s("userId") && s("userSignPub") && s("userEncPub") && s("role")
		case "add-device": return s("userId") && s("deviceId") && s("deviceSignPub") && s("deviceEncPub")
		case "prove-device", "remove-device": return s("userId") && s("deviceId")
		case "remove-user": return s("userId")
		default: return true  // newer entry type: relayed opaquely, skipped at replay
		}
	}
}

// A signed DAG node. `hash` is derived (cached for keying), not signed.
public struct LogEntry: Sendable, Equatable {
	public var parents: [String]
	public var body: EntryBody
	public var signerId: String
	public var signerKind: SignerKind
	public var sig: String  // base64 Ed25519 over canonicalBytes
	public var hash: String

	public init(
		parents: [String], body: EntryBody, signerId: String, signerKind: SignerKind, sig: String,
		hash: String
	) {
		self.parents = parents
		self.body = body
		self.signerId = signerId
		self.signerKind = signerKind
		self.sig = sig
		self.hash = hash
	}

	public var json: JSONValue {
		.obj([
			"parents": .array(parents.map { .string($0) }), "body": body.raw,
			"signerId": .string(signerId), "signerKind": .string(signerKind.rawValue),
			"sig": .string(sig), "hash": .string(hash),
		])
	}

	// Parses and structurally validates (`wellFormedEntry`); nil if malformed.
	public init?(json: JSONValue) {
		guard case .object = json, let parentsJ = json["parents"]?.array,
			let body = json["body"], let signerId = json["signerId"]?.string,
			let kind = json["signerKind"]?.string.flatMap(SignerKind.init(rawValue:)),
			let sig = json["sig"]?.string
		else { return nil }
		var parents: [String] = []
		for p in parentsJ {
			guard let s = p.string else { return nil }
			parents.append(s)
		}
		let b = EntryBody(raw: body)
		guard b.wellFormed else { return nil }
		self.init(parents: parents, body: b, signerId: signerId, signerKind: kind, sig: sig, hash: "")
		self.hash = AuthLog.entryHash(self)
	}
}

public struct Device: Sendable {
	public var deviceId: String
	public var signPub: String
	public var encPub: String
	public var enrolledByDeviceId: String?
	public var enrolledAtHash: String
}

public struct Member: Sendable {
	public var userId: String
	public var signPub: String
	public var encPub: String
	public var role: Role
	public var active: Bool
	public var devices = OrderedMap<String, Device>()
	public var pendingDevices = OrderedMap<String, Device>()
	public var hasEverHadDevice = false
	public var addedByDeviceId: String?
}

public struct Membership: Sendable {
	public var vaultId: String
	public var members = OrderedMap<String, Member>()
	public var deviceKeys: [String: Data] = [:]
	public var deviceOwners: [String: String] = [:]
	public var appliedHashes: Set<String> = []
}

struct AuthError: Error { let message: String }

public enum AuthLog {
	// The bytes that are signed and hashed; parents sorted for canonical form.
	public static func canonicalBytes(
		parents: [String], body: EntryBody, signerId: String, signerKind: SignerKind
	) -> Data {
		JSONValue.obj([
			"parents": .array(parents.jsSorted().map { .string($0) }), "body": body.raw,
			"signerId": .string(signerId), "signerKind": .string(signerKind.rawValue),
		]).serialized()
	}

	public static func entryHash(_ e: LogEntry) -> String {
		VaultCrypto.sha256(
			canonicalBytes(parents: e.parents, body: e.body, signerId: e.signerId, signerKind: e.signerKind)
		).hex
	}

	public static func makeEntry(
		parents: [String], body: EntryBody, signerId: String, signerKind: SignerKind, signerPriv: Data
	) throws -> LogEntry {
		let p = parents.jsSorted()
		let bytes = canonicalBytes(parents: p, body: body, signerId: signerId, signerKind: signerKind)
		return LogEntry(
			parents: p, body: body, signerId: signerId, signerKind: signerKind,
			sig: try VaultCrypto.sign(bytes, signerPriv).base64, hash: VaultCrypto.sha256(bytes).hex)
	}

	// Entries not referenced as a parent by any other entry.
	public static func heads(_ all: [LogEntry]) -> [String] {
		var referenced = Set<String>()
		for e in all { for p in e.parents { referenced.insert(p) } }
		return all.map(entryHash).filter { !referenced.contains($0) }.jsSorted()
	}

	// Deterministic topological sort: smallest hash among ready entries first.
	public static func linearize(_ entries: [LogEntry]) -> [LogEntry] {
		var byHash: [String: LogEntry] = [:]
		for e in entries { byHash[entryHash(e)] = e }
		var placed = Set<String>()
		var order: [LogEntry] = []
		while true {
			var pick: (hash: String, entry: LogEntry)?
			for (h, e) in byHash where !placed.contains(h) {
				guard e.parents.allSatisfy({ placed.contains($0) }) else { continue }
				if pick == nil || jsLess(h, pick!.hash) { pick = (h, e) }
			}
			guard let p = pick else { break }
			placed.insert(p.hash)
			order.append(p.entry)
		}
		return order
	}

	public static func deviceId(ofSignPub b64: String) -> String {
		String(VaultCrypto.sha256(Data(base64: b64)).hex.prefix(16))
	}

	static func isAdmin(_ m: Member?) -> Bool {
		guard let m else { return false }
		return m.active && (m.role == .owner || m.role == .admin)
	}

	// Resolve an *active* device to its owning member.
	public static func activeDeviceMember(_ state: Membership, _ deviceId: String) -> Member? {
		for (_, m) in state.members where m.active && m.devices.has(deviceId) { return m }
		return nil
	}

	private static func resolveSigner(_ state: Membership, _ e: LogEntry) throws -> String {
		let b = e.body
		func need(_ k: String) throws -> String {
			guard let v = b.str(k) else { throw AuthError(message: "malformed") }
			return v
		}
		switch b.type ?? "" {
		case "genesis":
			guard e.signerKind == .user, e.signerId == (try need("userId")) else {
				throw AuthError(message: "genesis must be self-signed by creator")
			}
			return try need("userSignPub")
		case "add-user":
			let signer = e.signerKind == .device ? activeDeviceMember(state, e.signerId) : nil
			guard let signer, isAdmin(signer) else {
				throw AuthError(message: "add-user requires an active admin device")
			}
			let pub = signer.devices[e.signerId]!.signPub
			if state.members[try need("userId")]?.active == true {
				throw AuthError(message: "add-user cannot overwrite an existing member")
			}
			if b.str("role") == "owner" { throw AuthError(message: "add-user cannot grant the owner role") }
			return pub
		case "remove-user":
			let signer = e.signerKind == .device ? activeDeviceMember(state, e.signerId) : nil
			guard let signer, isAdmin(signer) else {
				throw AuthError(message: "remove-user requires an active admin device")
			}
			let userId = try need("userId")
			if let t = state.members[userId], t.role == .owner, signer.userId != userId {
				throw AuthError(message: "the owner cannot be removed")
			}
			return signer.devices[e.signerId]!.signPub
		case "add-device":
			let userId = try need("userId")
			guard let target = state.members[userId], target.active else {
				throw AuthError(message: "add-device requires an active member")
			}
			guard try need("deviceId") == deviceId(ofSignPub: try need("deviceSignPub")) else {
				throw AuthError(message: "add-device deviceId must be derived from its signing key")
			}
			if e.signerKind == .user {
				if e.signerId != userId || target.hasEverHadDevice {
					throw AuthError(message: "add-device bootstrap must be the user's first device")
				}
				return target.signPub
			}
			// A member's own device enrolls its siblings; an active OWNER device may also
			// enroll a device for another member (owner-assisted recovery). The user
			// identity key is never enough past the first device: Token B copies it to
			// every device, so a removed device could otherwise re-enroll itself.
			guard let signer = activeDeviceMember(state, e.signerId), signer.userId == userId || signer.role == .owner else {
				throw AuthError(message: "add-device requires an active device of the owning user (or an owner device)")
			}
			return signer.devices[e.signerId]!.signPub
		case "prove-device":
			let deviceId = try need("deviceId")
			let userId = try need("userId")
			guard e.signerKind == .device, e.signerId == deviceId else {
				throw AuthError(message: "prove-device must be signed by the device itself")
			}
			guard let target = state.members[userId], target.active,
				let pending = target.pendingDevices[deviceId]
			else { throw AuthError(message: "prove-device requires a pending device of that user") }
			if let owner = state.deviceOwners[deviceId], owner != userId {
				throw AuthError(message: "prove-device cannot claim another user's device key")
			}
			return pending.signPub
		case "remove-device":
			guard e.signerKind == .device else { throw AuthError(message: "remove-device requires a device signer") }
			guard let signer = activeDeviceMember(state, e.signerId) else { throw AuthError(message: "unknown signer") }
			let userId = try need("userId")
			if signer.userId != userId && !isAdmin(signer) {
				throw AuthError(message: "remove-device requires owner-of-device or admin")
			}
			if let t = state.members[userId], t.role == .owner, signer.userId != userId {
				throw AuthError(message: "only the owner may remove the owner's device")
			}
			return signer.devices[e.signerId]!.signPub
		default:
			throw AuthError(message: "unknown entry type")
		}
	}

	private static func applyEntry(
		_ state: inout Membership, _ e: LogEntry, hash: String, ancestors: Set<String>
	) throws {
		let b = e.body
		func need(_ k: String) throws -> String {
			guard let v = b.str(k) else { throw AuthError(message: "malformed") }
			return v
		}
		switch b.type ?? "" {
		case "genesis":
			state.members[try need("userId")] = Member(
				userId: try need("userId"), signPub: try need("userSignPub"),
				encPub: try need("userEncPub"), role: .owner, active: true)
		case "add-user":
			state.members[try need("userId")] = Member(
				userId: try need("userId"), signPub: try need("userSignPub"),
				encPub: try need("userEncPub"), role: Role(rawValue: try need("role")) ?? .member,
				active: true, addedByDeviceId: e.signerKind == .device ? e.signerId : nil)
		case "remove-user":
			state.members.update(try need("userId")) {
				$0.active = false
				$0.devices.removeAll()
				$0.pendingDevices.removeAll()
			}
		case "add-device":
			let userId = try need("userId")
			guard state.members.has(userId) else { throw AuthError(message: "add-device for unknown user") }
			let d = Device(
				deviceId: try need("deviceId"), signPub: try need("deviceSignPub"),
				encPub: try need("deviceEncPub"),
				enrolledByDeviceId: e.signerKind == .device ? e.signerId : nil, enrolledAtHash: hash)
			state.members.update(userId) {
				$0.pendingDevices[d.deviceId] = d
				$0.hasEverHadDevice = true
			}
		case "prove-device":
			let userId = try need("userId")
			let deviceId = try need("deviceId")
			guard let d = state.members[userId]?.pendingDevices[deviceId] else {
				throw AuthError(message: "prove-device requires a pending device")
			}
			state.members.update(userId) {
				$0.pendingDevices[deviceId] = nil
				$0.devices[deviceId] = d
			}
			state.deviceKeys[deviceId] = Data(base64: d.signPub)
			state.deviceOwners[deviceId] = userId
		case "remove-device":
			let userId = try need("userId")
			guard state.members.has(userId) else { break }
			state.members.update(userId) { m in
				var revoked = [b.str("deviceId") ?? ""]
				var i = 0
				while i < revoked.count {
					let id = revoked[i]
					m.devices[id] = nil
					m.pendingDevices[id] = nil
					for d in m.devices.values + m.pendingDevices.values
					where d.enrolledByDeviceId == id && !ancestors.contains(d.enrolledAtHash) {
						revoked.append(d.deviceId)
					}
					i += 1
				}
			}
		default: break
		}
	}

	// Validate and fold the DAG into membership. Invalid/unauthorized entries are
	// skipped; only a missing genesis is fatal. `expectedVaultId` pins the root.
	public static func replay(_ entries: [LogEntry], expectedVaultId: String? = nil) throws -> Membership {
		let order = linearize(entries)
		let hashes = order.map(entryHash)
		var ancestors: [String: Set<String>] = [:]
		for (i, e) in order.enumerated() {
			var set = Set<String>()
			for p in e.parents {
				set.insert(p)
				if let a = ancestors[p] { set.formUnion(a) }
			}
			ancestors[hashes[i]] = set
		}
		func isRoot(_ e: LogEntry) -> Bool {
			e.body.type == "genesis" && e.parents.isEmpty
				&& (expectedVaultId == nil || e.body.str("vaultId") == expectedVaultId)
		}
		guard let gi = order.firstIndex(where: isRoot), let vaultId = order[gi].body.str("vaultId") else {
			throw AuthError(message: "auth log has no genesis")
		}
		var state = Membership(vaultId: vaultId)
		for (i, e) in order.enumerated() {
			if e.body.type == "genesis" && i != gi { continue }
			do {
				let signerPub = try resolveSigner(state, e)
				let ok = VaultCrypto.verify(
					canonicalBytes(parents: e.parents, body: e.body, signerId: e.signerId, signerKind: e.signerKind),
					pub: Data(base64: signerPub), sig: Data(base64: e.sig))
				if !ok { continue }
				try applyEntry(&state, e, hash: hashes[i], ancestors: ancestors[hashes[i]] ?? [])
				state.appliedHashes.insert(hashes[i])
			} catch {
				continue  // unauthorized / inapplicable — skip, keep folding
			}
		}
		return state
	}

	public static func validRootGenesis(_ entry: LogEntry, expectedVaultId: String) -> Bool {
		guard entry.body.type == "genesis", entry.body.str("vaultId") == expectedVaultId,
			entry.parents.isEmpty, let m = try? replay([entry], expectedVaultId: expectedVaultId),
			let c = m.members[entry.body.str("userId") ?? ""]
		else { return false }
		return c.active && c.role == .owner && c.signPub == entry.body.str("userSignPub")
			&& c.encPub == entry.body.str("userEncPub")
	}

	static let knownTypes: Set<String> = ["genesis", "add-user", "add-device", "prove-device", "remove-device", "remove-user"]

	// Which of `candidates` are worth persisting. Only entries replay actually applied
	// (validly signed AND authorized), plus entries of a type this version does not know
	// that a known key signed (kept opaquely so upgraded clients can exchange them through
	// older ones). Anything else is unauthenticated junk: persisting it would let any relay
	// or tailnet peer grow the append-only log without bound, and replay cost grows
	// superlinearly with its size. An entry whose ancestors have not arrived yet is not
	// admitted now; it is listed as lacking and requested again next round.
	public static func admissible(_ candidates: [LogEntry], existing: [LogEntry], expectedVaultId: String?) -> [LogEntry] {
		guard !candidates.isEmpty, let m = try? replay(existing + candidates, expectedVaultId: expectedVaultId) else { return [] }
		return candidates.filter { e in
			let h = entryHash(e)
			if m.appliedHashes.contains(h) { return true }
			guard let t = e.body.type, !knownTypes.contains(t) else { return false }
			let pub: String?
			switch e.signerKind {
			case .user: pub = m.members[e.signerId]?.signPub
			case .device: pub = m.deviceKeys[e.signerId].map { $0.base64 }
			}
			guard let pub else { return false }
			return VaultCrypto.verify(
				canonicalBytes(parents: e.parents, body: e.body, signerId: e.signerId, signerKind: e.signerKind),
				pub: Data(base64: pub), sig: Data(base64: e.sig))
		}
	}

	public static func deviceSignKey(_ state: Membership, _ deviceId: String) -> Data? {
		activeDeviceMember(state, deviceId)?.devices[deviceId].map { Data(base64: $0.signPub) }
	}
}
