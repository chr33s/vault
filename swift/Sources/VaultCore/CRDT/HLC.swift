import Foundation

// Hybrid Logical Clock (spec §7.1). Encoded as a fixed-width string
// so lexicographic comparison equals logical order.

public struct HLC: Sendable, Equatable {
	public var millis: Int64
	public var counter: Int64
	public var deviceId: String
	public init(millis: Int64, counter: Int64, deviceId: String) {
		self.millis = millis
		self.counter = counter
		self.deviceId = deviceId
	}
}

public enum HLCError: Error, Sendable { case millisOverflow }

public enum HLCCodec {
	static let millisWidth = 15
	static let millisMax: Int64 = 999_999_999_999_999
	static let counterWidth = 6
	static let counterMax: Int64 = 999_999
	static let maxForwardDriftMs: Int64 = 24 * 60 * 60 * 1000

	public static func nowMillis() -> Int64 { Int64((Date().timeIntervalSince1970 * 1000).rounded(.down)) }

	public static func isWithinForwardDrift(_ remote: HLC, now: Int64 = nowMillis()) -> Bool {
		remote.millis <= now + maxForwardDriftMs
	}

	private static func pad(_ v: Int64, _ w: Int) -> String {
		let s = String(v)
		return String(repeating: "0", count: max(0, w - s.count)) + s
	}

	public static func encode(_ h: HLC) throws -> String {
		guard h.millis <= millisMax else { throw HLCError.millisOverflow }
		return "\(pad(h.millis, millisWidth)):\(pad(h.counter, counterWidth)):\(h.deviceId)"
	}

	public static func decode(_ s: String) -> HLC {
		let parts = s.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false)
		let m = parts.count > 0 ? Int64(parts[0]) ?? 0 : 0
		let c = parts.count > 1 ? Int64(parts[1]) ?? 0 : 0
		let d = parts.count > 2 ? String(parts[2]) : ""
		return HLC(millis: m, counter: c, deviceId: d)
	}

	// Total order: physical time, then counter, then deviceId.
	public static func compare(_ a: HLC, _ b: HLC) -> Int {
		if a.millis != b.millis { return a.millis < b.millis ? -1 : 1 }
		if a.counter != b.counter { return a.counter < b.counter ? -1 : 1 }
		if a.deviceId == b.deviceId { return 0 }
		return jsLess(a.deviceId, b.deviceId) ? -1 : 1
	}

	public static func compareEncoded(_ a: String, _ b: String) -> Int {
		compare(decode(a), decode(b))
	}
}

// Per-device clock; `now` is injectable for deterministic tests.
public struct Clock: Sendable {
	private var lastMillis: Int64 = 0
	private var counter: Int64 = 0
	private let deviceId: String
	private let now: @Sendable () -> Int64

	public init(deviceId: String, now: @escaping @Sendable () -> Int64 = { HLCCodec.nowMillis() }) {
		self.deviceId = deviceId
		self.now = now
	}

	public mutating func tick() -> HLC {
		let phys = now()
		if phys > lastMillis {
			lastMillis = phys
			counter = 0
		} else {
			counter += 1
		}
		carry()
		return HLC(millis: lastMillis, counter: counter, deviceId: deviceId)
	}

	private mutating func carry() {
		while counter > HLCCodec.counterMax {
			lastMillis += 1
			counter -= HLCCodec.counterMax + 1
		}
	}

	@discardableResult
	public mutating func observe(_ remote: HLC) -> HLC {
		let phys = now()
		let maxMillis = max(phys, lastMillis, remote.millis)
		if maxMillis == lastMillis && maxMillis == remote.millis {
			counter = max(counter, remote.counter) + 1
		} else if maxMillis == lastMillis {
			counter += 1
		} else if maxMillis == remote.millis {
			counter = remote.counter + 1
		} else {
			counter = 0
		}
		lastMillis = maxMillis
		carry()
		return HLC(millis: lastMillis, counter: counter, deviceId: deviceId)
	}
}
