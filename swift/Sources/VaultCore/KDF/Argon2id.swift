import Foundation

// Argon2id (RFC 9106, v1.3) for reading existing vaults (spec §15.6).
// No secret/associated data. New vaults use scrypt.

enum Blake2b {
	private static let iv: [UInt64] = [
		0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b, 0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
		0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f, 0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
	]
	private static let sigma: [[Int]] = [
		[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
		[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
		[11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
		[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
		[9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
		[2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
		[12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
		[13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
		[6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
		[10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
	]

	@inline(__always) private static func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 {
		(x >> n) | (x << (64 - n))
	}

	private static func compress(_ h: inout [UInt64], _ block: ArraySlice<UInt8>, t: UInt64, last: Bool) {
		var m = [UInt64](repeating: 0, count: 16)
		let base = block.startIndex
		for i in 0..<16 {
			var w: UInt64 = 0
			for j in 0..<8 { w |= UInt64(block[base + i * 8 + j]) << UInt64(8 * j) }
			m[i] = w
		}
		var v = h + iv
		v[12] ^= t
		if last { v[14] = ~v[14] }
		func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
			v[a] = v[a] &+ v[b] &+ x
			v[d] = rotr(v[d] ^ v[a], 32)
			v[c] = v[c] &+ v[d]
			v[b] = rotr(v[b] ^ v[c], 24)
			v[a] = v[a] &+ v[b] &+ y
			v[d] = rotr(v[d] ^ v[a], 16)
			v[c] = v[c] &+ v[d]
			v[b] = rotr(v[b] ^ v[c], 63)
		}
		for r in 0..<12 {
			let s = sigma[r % 10]
			g(0, 4, 8, 12, m[s[0]], m[s[1]])
			g(1, 5, 9, 13, m[s[2]], m[s[3]])
			g(2, 6, 10, 14, m[s[4]], m[s[5]])
			g(3, 7, 11, 15, m[s[6]], m[s[7]])
			g(0, 5, 10, 15, m[s[8]], m[s[9]])
			g(1, 6, 11, 12, m[s[10]], m[s[11]])
			g(2, 7, 8, 13, m[s[12]], m[s[13]])
			g(3, 4, 9, 14, m[s[14]], m[s[15]])
		}
		for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
	}

	static func hash(_ input: [UInt8], outLen: Int) -> [UInt8] {
		precondition((1...64).contains(outLen))
		var h = iv
		h[0] ^= 0x0101_0000 ^ UInt64(outLen)
		var offset = 0
		while input.count - offset > 128 {
			compress(&h, input[offset..<offset + 128], t: UInt64(offset + 128), last: false)
			offset += 128
		}
		var tail = Array(input[offset...])
		let total = UInt64(input.count)
		tail.append(contentsOf: [UInt8](repeating: 0, count: 128 - tail.count))
		compress(&h, tail[0..<128], t: total, last: true)
		var out = [UInt8]()
		for w in h { for j in 0..<8 { out.append(UInt8((w >> UInt64(8 * j)) & 0xFF)) } }
		return Array(out[0..<outLen])
	}
}

enum Argon2id {
	private static let blockWords = 128
	private static func le32(_ v: Int) -> [UInt8] {
		let x = UInt32(truncatingIfNeeded: v)
		return [UInt8(x & 0xFF), UInt8((x >> 8) & 0xFF), UInt8((x >> 16) & 0xFF), UInt8((x >> 24) & 0xFF)]
	}

	// H' variable-length hash.
	private static func hPrime(_ x: [UInt8], _ t: Int) -> [UInt8] {
		let input = le32(t) + x
		if t <= 64 { return Blake2b.hash(input, outLen: t) }
		let r = (t + 31) / 32 - 2
		var v = Blake2b.hash(input, outLen: 64)
		var out = Array(v[0..<32])
		for _ in 1..<r {
			v = Blake2b.hash(v, outLen: 64)
			out += v[0..<32]
		}
		out += Blake2b.hash(v, outLen: t - 32 * r)
		return out
	}

	@inline(__always) private static func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 {
		(x >> n) | (x << (64 - n))
	}
	@inline(__always) private static func fBlaMka(_ x: UInt64, _ y: UInt64) -> UInt64 {
		x &+ y &+ 2 &* (x & 0xFFFF_FFFF) &* (y & 0xFFFF_FFFF)
	}

	@inline(__always) private static func gb(
		_ v: UnsafeMutablePointer<UInt64>, _ a: Int, _ b: Int, _ c: Int, _ d: Int
	) {
		v[a] = fBlaMka(v[a], v[b])
		v[d] = rotr(v[d] ^ v[a], 32)
		v[c] = fBlaMka(v[c], v[d])
		v[b] = rotr(v[b] ^ v[c], 24)
		v[a] = fBlaMka(v[a], v[b])
		v[d] = rotr(v[d] ^ v[a], 16)
		v[c] = fBlaMka(v[c], v[d])
		v[b] = rotr(v[b] ^ v[c], 63)
	}

	// BLAKE2 round over 16 words addressed as v[i0], v[i1], ... via a stride pattern:
	// word k lives at base + (k / 2) * s2 + (k % 2) — rows use (16, 1 pairs), columns (2-word pairs).
	@inline(__always) private static func round(
		_ v: UnsafeMutablePointer<UInt64>, _ i0: Int, _ i1: Int, _ i2: Int, _ i3: Int, _ i4: Int, _ i5: Int,
		_ i6: Int, _ i7: Int, _ i8: Int, _ i9: Int, _ i10: Int, _ i11: Int, _ i12: Int, _ i13: Int,
		_ i14: Int, _ i15: Int
	) {
		// Gather into locals so the G function works on registers.
		var t = (
			v[i0], v[i1], v[i2], v[i3], v[i4], v[i5], v[i6], v[i7], v[i8], v[i9], v[i10], v[i11], v[i12],
			v[i13], v[i14], v[i15]
		)
		withUnsafeMutableBytes(of: &t) { raw in
			let p = raw.baseAddress!.assumingMemoryBound(to: UInt64.self)
			gb(p, 0, 4, 8, 12)
			gb(p, 1, 5, 9, 13)
			gb(p, 2, 6, 10, 14)
			gb(p, 3, 7, 11, 15)
			gb(p, 0, 5, 10, 15)
			gb(p, 1, 6, 11, 12)
			gb(p, 2, 7, 8, 13)
			gb(p, 3, 4, 9, 14)
		}
		v[i0] = t.0; v[i1] = t.1; v[i2] = t.2; v[i3] = t.3; v[i4] = t.4; v[i5] = t.5; v[i6] = t.6
		v[i7] = t.7; v[i8] = t.8; v[i9] = t.9; v[i10] = t.10; v[i11] = t.11; v[i12] = t.12
		v[i13] = t.13; v[i14] = t.14; v[i15] = t.15
	}

	// next = P(prev ^ ref) ^ prev ^ ref [^ next when `xor`], all pointers to
	// 128-word blocks. `scratch` provides two 128-word work areas.
	private static func fillBlock(
		_ prev: UnsafePointer<UInt64>, _ ref: UnsafePointer<UInt64>, _ next: UnsafeMutablePointer<UInt64>,
		xor: Bool, scratch: UnsafeMutablePointer<UInt64>
	) {
		let r = scratch
		let t = scratch + blockWords
		for i in 0..<blockWords {
			let x = ref[i] ^ prev[i]
			r[i] = x
			t[i] = x
		}
		if xor { for i in 0..<blockWords { r[i] ^= next[i] } }
		for i in 0..<8 {
			let b = 16 * i
			round(t, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7, b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15)
		}
		for i in 0..<8 {
			let b = 2 * i
			round(t, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49, b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113)
		}
		for i in 0..<blockWords { next[i] = t[i] ^ r[i] }
	}

	static func derive(
		password: [UInt8], salt: [UInt8], memoryKiB: Int, passes: Int, parallelism: Int, tagLength: Int
	) throws -> [UInt8] {
		guard parallelism >= 1, passes >= 1, tagLength >= 4, memoryKiB >= 8 * parallelism else {
			throw VaultCryptoError.unsupportedKdf("invalid argon2id parameters")
		}
		let lanes = parallelism
		let mPrime = 4 * lanes * (memoryKiB / (4 * lanes))
		let laneLength = mPrime / lanes
		let segLength = laneLength / 4

		let h0 = Blake2b.hash(
			le32(lanes) + le32(tagLength) + le32(memoryKiB) + le32(passes) + le32(0x13) + le32(2)
				+ le32(password.count) + password + le32(salt.count) + salt + le32(0) + le32(0),
			outLen: 64)

		let mem = UnsafeMutablePointer<UInt64>.allocate(capacity: mPrime * blockWords)
		mem.initialize(repeating: 0, count: mPrime * blockWords)
		let scratch = UnsafeMutablePointer<UInt64>.allocate(capacity: 2 * blockWords)
		let zero = UnsafeMutablePointer<UInt64>.allocate(capacity: blockWords)
		let input = UnsafeMutablePointer<UInt64>.allocate(capacity: blockWords)
		let address = UnsafeMutablePointer<UInt64>.allocate(capacity: blockWords)
		zero.initialize(repeating: 0, count: blockWords)
		defer {
			// Argon2 memory holds password-derived state: scrub before release.
			secureZero(mem, count: mPrime * blockWords * 8)
			secureZero(scratch, count: 2 * blockWords * 8)
			mem.deallocate()
			scratch.deallocate()
			zero.deallocate()
			input.deallocate()
			address.deallocate()
		}

		func load(_ bytes: [UInt8], into block: Int) {
			for i in 0..<blockWords {
				var w: UInt64 = 0
				for j in 0..<8 { w |= UInt64(bytes[i * 8 + j]) << UInt64(8 * j) }
				mem[block * blockWords + i] = w
			}
		}
		for l in 0..<lanes {
			load(hPrime(h0 + le32(0) + le32(l), 1024), into: l * laneLength)
			load(hPrime(h0 + le32(1) + le32(l), 1024), into: l * laneLength + 1)
		}

		for pass in 0..<passes {
			for slice in 0..<4 {
				for lane in 0..<lanes {
					let independent = pass == 0 && slice < 2
					input.initialize(repeating: 0, count: blockWords)
					address.initialize(repeating: 0, count: blockWords)
					func nextAddresses() {
						input[6] &+= 1
						fillBlock(zero, input, address, xor: false, scratch: scratch)
						fillBlock(zero, address, address, xor: false, scratch: scratch)
					}
					if independent {
						input[0] = UInt64(pass)
						input[1] = UInt64(lane)
						input[2] = UInt64(slice)
						input[3] = UInt64(mPrime)
						input[4] = UInt64(passes)
						input[5] = 2
					}
					var start = 0
					if pass == 0 && slice == 0 {
						start = 2
						if independent { nextAddresses() }
					}
					var cur = lane * laneLength + slice * segLength + start
					var prev = cur % laneLength == 0 ? cur + laneLength - 1 : cur - 1
					for i in start..<segLength {
						if cur % laneLength == 1 { prev = cur - 1 }
						let pseudo: UInt64
						if independent {
							if i % blockWords == 0 { nextAddresses() }
							pseudo = address[i % blockWords]
						} else {
							pseudo = mem[prev * blockWords]
						}
						var refLane = Int((pseudo >> 32) % UInt64(lanes))
						if pass == 0 && slice == 0 { refLane = lane }
						let sameLane = refLane == lane
						let area: Int
						if pass == 0 {
							if slice == 0 {
								area = i - 1
							} else if sameLane {
								area = slice * segLength + i - 1
							} else {
								area = slice * segLength + (i == 0 ? -1 : 0)
							}
						} else if sameLane {
							area = laneLength - segLength + i - 1
						} else {
							area = laneLength - segLength + (i == 0 ? -1 : 0)
						}
						var rel = pseudo & 0xFFFF_FFFF
						rel = (rel &* rel) >> 32
						let relPos = UInt64(area) &- 1 &- ((UInt64(area) &* rel) >> 32)
						let startPos = pass != 0 ? (slice == 3 ? 0 : (slice + 1) * segLength) : 0
						let refIndex = (startPos + Int(relPos)) % laneLength
						fillBlock(
							mem + prev * blockWords, mem + (refLane * laneLength + refIndex) * blockWords,
							mem + cur * blockWords, xor: pass != 0, scratch: scratch)
						cur += 1
						prev += 1
					}
				}
			}
		}

		var final = [UInt64](repeating: 0, count: blockWords)
		for l in 0..<lanes {
			let b = mem + (l * laneLength + laneLength - 1) * blockWords
			for i in 0..<blockWords { final[i] ^= b[i] }
		}
		var bytes = [UInt8]()
		bytes.reserveCapacity(1024)
		for w in final { for j in 0..<8 { bytes.append(UInt8((w >> UInt64(8 * j)) & 0xFF)) } }
		return hPrime(bytes, tagLength)
	}
}
