import Foundation

// Enrollment / sharing tokens: base64(JSON) blobs carried
// out-of-band (paste or QR). Field order is part of the wire format, so tokens
// are interchangeable between clients.

// Relay coordinates handed to a new device. Only url + accessId are persisted;
// bearer secrets are never written to the plaintext meta table.
public struct RelayInfo: Sendable, Equatable {
	public var url: String
	public var token: String?
	public var accessId: String?
	public var accessSecret: String?

	public init(url: String, token: String? = nil, accessId: String? = nil, accessSecret: String? = nil) {
		self.url = url
		self.token = token
		self.accessId = accessId
		self.accessSecret = accessSecret
	}

	public var json: JSONValue {
		var m = [JSONMember("url", .string(url))]
		if let token { m.append(JSONMember("token", .string(token))) }
		if let accessId { m.append(JSONMember("accessId", .string(accessId))) }
		if let accessSecret { m.append(JSONMember("accessSecret", .string(accessSecret))) }
		return .object(m)
	}

	public init?(json: JSONValue) {
		guard let url = json["url"]?.string else { return nil }
		self.init(url: url, token: json["token"]?.string, accessId: json["accessId"]?.string, accessSecret: json["accessSecret"]?.string)
	}
}

public protocol WireToken: Sendable {
	var json: JSONValue { get }
	init?(json: JSONValue)
}

extension WireToken {
	// `base64(JSON.stringify(token))`
	public var encoded: String { json.serialized().base64 }

	public static func decode(_ s: String) throws -> Self {
		guard let j = try? JSONValue.parse(Data(base64: s.trimmingCharacters(in: .whitespacesAndNewlines))),
			let t = Self(json: j)
		else { throw VaultError.invalidArgument("malformed token") }
		return t
	}
}

private func grantsJSON(_ m: OrderedMap<String, SealedGrant>) -> JSONValue {
	.object(m.map { JSONMember($0.key, $0.value.json) })
}

private func grantsParse(_ j: JSONValue?) -> OrderedMap<String, SealedGrant>? {
	guard let ms = j?.members else { return nil }
	var out = OrderedMap<String, SealedGrant>()
	for m in ms {
		guard let g = SealedGrant(json: m.value) else { return nil }
		out[m.key] = g
	}
	return out
}

private func logParse(_ j: JSONValue?) -> [LogEntry]? {
	guard let a = j?.array else { return nil }
	var out: [LogEntry] = []
	for v in a {
		guard let e = LogEntry(json: v) else { return nil }
		out.append(e)
	}
	return out
}

private func rotationsParse(_ j: JSONValue?) -> [RotationRecord]? {
	guard let a = j?.array else { return nil }
	var out: [RotationRecord] = []
	for v in a {
		guard let r = RotationRecord(json: v) else { return nil }
		out.append(r)
	}
	return out
}

public struct TokenA: WireToken, Equatable {
	public var deviceId: String
	public var signPub: String
	public var encPub: String

	public var json: JSONValue { .obj(["deviceId": .string(deviceId), "signPub": .string(signPub), "encPub": .string(encPub)]) }
	public init(deviceId: String, signPub: String, encPub: String) {
		self.deviceId = deviceId
		self.signPub = signPub
		self.encPub = encPub
	}
	public init?(json: JSONValue) {
		guard let d = json["deviceId"]?.string, let s = json["signPub"]?.string, let e = json["encPub"]?.string else { return nil }
		self.init(deviceId: d, signPub: s, encPub: e)
	}
}

public struct TokenB: WireToken {
	public var vaultId: String
	public var userId: String
	public var authLog: [LogEntry]
	public var rotations: [RotationRecord]
	public var epochGrants: OrderedMap<String, SealedGrant>
	public var userPriv: SealedGrant
	public var relay: RelayInfo?

	public var json: JSONValue {
		var m: [JSONMember] = [
			JSONMember("vaultId", .string(vaultId)), JSONMember("userId", .string(userId)),
			JSONMember("authLog", .array(authLog.map(\.json))), JSONMember("rotations", .array(rotations.map(\.json))),
			JSONMember("epochGrants", grantsJSON(epochGrants)), JSONMember("userPriv", userPriv.json),
		]
		if let relay { m.append(JSONMember("relay", relay.json)) }
		return .object(m)
	}

	public init(vaultId: String, userId: String, authLog: [LogEntry], rotations: [RotationRecord], epochGrants: OrderedMap<String, SealedGrant>, userPriv: SealedGrant, relay: RelayInfo?) {
		self.vaultId = vaultId
		self.userId = userId
		self.authLog = authLog
		self.rotations = rotations
		self.epochGrants = epochGrants
		self.userPriv = userPriv
		self.relay = relay
	}

	public init?(json: JSONValue) {
		guard let v = json["vaultId"]?.string, let u = json["userId"]?.string, let a = logParse(json["authLog"]),
			let r = rotationsParse(json["rotations"]), let g = grantsParse(json["epochGrants"]),
			let up = json["userPriv"].flatMap({ SealedGrant(json: $0) })
		else { return nil }
		self.init(vaultId: v, userId: u, authLog: a, rotations: r, epochGrants: g, userPriv: up, relay: json["relay"].flatMap { RelayInfo(json: $0) })
	}
}

public struct InviteToken: WireToken, Equatable {
	public var userId: String
	public var userSignPub: String
	public var userEncPub: String
	public var deviceId: String
	public var deviceSignPub: String
	public var deviceEncPub: String

	public var json: JSONValue {
		.obj([
			"userId": .string(userId), "userSignPub": .string(userSignPub), "userEncPub": .string(userEncPub),
			"deviceId": .string(deviceId), "deviceSignPub": .string(deviceSignPub), "deviceEncPub": .string(deviceEncPub),
		])
	}

	public init(userId: String, userSignPub: String, userEncPub: String, deviceId: String, deviceSignPub: String, deviceEncPub: String) {
		self.userId = userId
		self.userSignPub = userSignPub
		self.userEncPub = userEncPub
		self.deviceId = deviceId
		self.deviceSignPub = deviceSignPub
		self.deviceEncPub = deviceEncPub
	}

	public init?(json: JSONValue) {
		guard let a = json["userId"]?.string, let b = json["userSignPub"]?.string, let c = json["userEncPub"]?.string,
			let d = json["deviceId"]?.string, let e = json["deviceSignPub"]?.string, let f = json["deviceEncPub"]?.string
		else { return nil }
		self.init(userId: a, userSignPub: b, userEncPub: c, deviceId: d, deviceSignPub: e, deviceEncPub: f)
	}
}

public struct JoinToken: WireToken {
	public var vaultId: String
	public var userId: String
	public var authLog: [LogEntry]
	public var rotations: [RotationRecord]
	public var epochGrants: OrderedMap<String, SealedGrant>
	public var relay: RelayInfo?

	public var json: JSONValue {
		var m: [JSONMember] = [
			JSONMember("vaultId", .string(vaultId)), JSONMember("userId", .string(userId)),
			JSONMember("authLog", .array(authLog.map(\.json))), JSONMember("rotations", .array(rotations.map(\.json))),
			JSONMember("epochGrants", grantsJSON(epochGrants)),
		]
		if let relay { m.append(JSONMember("relay", relay.json)) }
		return .object(m)
	}

	public init(vaultId: String, userId: String, authLog: [LogEntry], rotations: [RotationRecord], epochGrants: OrderedMap<String, SealedGrant>, relay: RelayInfo?) {
		self.vaultId = vaultId
		self.userId = userId
		self.authLog = authLog
		self.rotations = rotations
		self.epochGrants = epochGrants
		self.relay = relay
	}

	public init?(json: JSONValue) {
		guard let v = json["vaultId"]?.string, let u = json["userId"]?.string, let a = logParse(json["authLog"]),
			let r = rotationsParse(json["rotations"]), let g = grantsParse(json["epochGrants"])
		else { return nil }
		self.init(vaultId: v, userId: u, authLog: a, rotations: r, epochGrants: g, relay: json["relay"].flatMap { RelayInfo(json: $0) })
	}
}
