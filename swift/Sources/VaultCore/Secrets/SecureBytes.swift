import Foundation

#if canImport(Glibc)
	import Glibc
#elseif canImport(Musl)
	import Musl
#elseif canImport(Darwin)
	import Darwin
#elseif canImport(WinSDK)
	import WinSDK
#endif

// Overwrite `count` bytes at `ptr` in a way the optimizer may not elide.
public func secureZero(_ ptr: UnsafeMutableRawPointer, count: Int) {
	guard count > 0 else { return }
	#if canImport(Darwin)
		_ = memset_s(ptr, count, 0, count)
	#elseif canImport(Glibc) || canImport(Musl)
		explicit_bzero(ptr, count)
	#elseif canImport(WinSDK)
		// `SecureZeroMemory` is a macro Swift can't import; this is the inline function behind it.
		_ = RtlSecureZeroMemory(ptr, SIZE_T(count))
	#else
		let p = ptr.assumingMemoryBound(to: UInt8.self)
		for i in 0..<count { p[i] = 0 }
	#endif
}

// Long-lived secret storage (spec §15.7): manually allocated, page-locked where the
// OS allows, zeroed before release, and never exposed through `String`.
//
// Honest limits: swift-crypto's API takes `Data`/`SymmetricKey`, so a transient
// copy exists whenever a key is used (`withData`). Those copies are short-lived
// and scrubbed via `wipe(_:)`, but Swift value semantics cannot rule out every
// copy — this shrinks the exposure window, it does not eliminate it.
public final class SecureBytes: @unchecked Sendable {
	private let storage: UnsafeMutableRawPointer?
	public let count: Int
	private var locked = false

	public init(count: Int) {
		self.count = count
		if count > 0 {
			let p = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: 16)
			p.initializeMemory(as: UInt8.self, repeating: 0, count: count)
			storage = p
			#if !os(Windows)
				locked = mlock(p, count) == 0  // best effort (RLIMIT_MEMLOCK)
			#endif
		} else {
			storage = nil
		}
	}

	public convenience init(_ data: Data) {
		self.init(count: data.count)
		if let s = storage {
			data.withUnsafeBytes { s.copyMemory(from: $0.baseAddress!, byteCount: data.count) }
		}
	}

	deinit {
		guard let s = storage else { return }
		secureZero(s, count: count)
		#if !os(Windows)
			if locked { munlock(s, count) }
		#endif
		s.deallocate()
	}

	// Run `body` with a transient `Data` copy, then scrub that copy.
	public func withData<T>(_ body: (Data) throws -> T) rethrows -> T {
		var d = data
		defer { Self.wipe(&d) }
		return try body(d)
	}

	// An unscrubbed copy; prefer `withData`.
	public var data: Data {
		guard let s = storage else { return Data() }
		return Data(bytes: s, count: count)
	}

	public static func wipe(_ d: inout Data) {
		d.withUnsafeMutableBytes { if let b = $0.baseAddress { secureZero(b, count: $0.count) } }
		d.removeAll()
	}

	// Constant-time comparison.
	public func constantTimeEquals(_ other: Data) -> Bool {
		guard other.count == count else { return false }
		var acc: UInt8 = 0
		withData { mine in
			for i in 0..<count { acc |= mine[mine.startIndex + i] ^ other[other.startIndex + i] }
		}
		return acc == 0
	}
}
