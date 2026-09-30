import Crypto
import Foundation

// RFC 6238 TOTP over RFC 4226 HOTP. The stored value is a bare
// base32 secret or an `otpauth://totp/...` URI.

public enum TotpAlgorithm: String, Sendable { case sha1, sha256, sha512 }

public struct TotpParams: Sendable, Equatable {
	public var secret: String
	public var algorithm: TotpAlgorithm
	public var digits: Int
	public var period: Int
}

public struct TotpResult: Sendable, Equatable {
	public var code: String
	public var expiresInSec: Int
	public var period: Int
	public var digits: Int
	public var algorithm: TotpAlgorithm
}

public struct TotpError: Error, Sendable, CustomStringConvertible {
	public let description: String
}

public enum TOTP {
	private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

	static func base32Decode(_ input: String) throws -> Data {
		var clean = input.filter { !$0.isWhitespace }.uppercased()
		while clean.hasSuffix("=") { clean.removeLast() }
		var bits = 0
		var value: UInt32 = 0
		var out = Data()
		for ch in clean.utf8 {
			guard let idx = alphabet.firstIndex(of: ch) else {
				throw TotpError(description: "invalid base32 character in TOTP secret")
			}
			value = (value << 5) | UInt32(idx)
			bits += 5
			if bits >= 8 {
				bits -= 8
				out.append(UInt8((value >> UInt32(bits)) & 0xFF))
			}
		}
		return out
	}

	public static func parse(_ value: String) throws -> TotpParams {
		let v = value.trimmingCharacters(in: .whitespacesAndNewlines)
		guard v.lowercased().hasPrefix("otpauth://") else {
			return TotpParams(secret: v, algorithm: .sha1, digits: 6, period: 30)
		}
		guard let comps = URLComponents(string: v) else { throw TotpError(description: "bad otpauth URI") }
		guard comps.host?.lowercased() == "totp" else {
			throw TotpError(description: "unsupported otpauth type (expected totp)")
		}
		func q(_ n: String) -> String? { comps.queryItems?.first { $0.name == n }?.value }
		guard let secret = q("secret"), !secret.isEmpty else {
			throw TotpError(description: "otpauth URI is missing the secret parameter")
		}
		guard let alg = TotpAlgorithm(rawValue: (q("algorithm") ?? "SHA1").lowercased()) else {
			throw TotpError(description: "unsupported TOTP algorithm")
		}
		return TotpParams(
			secret: secret, algorithm: alg, digits: Int(q("digits") ?? "6") ?? -1,
			period: Int(q("period") ?? "30") ?? -1)
	}

	private static func hmac(_ alg: TotpAlgorithm, key: Data, msg: Data) -> [UInt8] {
		let k = SymmetricKey(data: key)
		switch alg {
		case .sha1: return Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: k))
		case .sha256: return Array(HMAC<SHA256>.authenticationCode(for: msg, using: k))
		case .sha512: return Array(HMAC<SHA512>.authenticationCode(for: msg, using: k))
		}
	}

	static func hotp(key: Data, counter: UInt64, algorithm: TotpAlgorithm, digits: Int) -> String {
		var c = counter.bigEndian
		let msg = Data(bytes: &c, count: 8)
		let mac = hmac(algorithm, key: key, msg: msg)
		let o = Int(mac[mac.count - 1] & 0x0F)
		let bin =
			(UInt64(mac[o] & 0x7F) << 24) | (UInt64(mac[o + 1]) << 16) | (UInt64(mac[o + 2]) << 8)
			| UInt64(mac[o + 3])
		var mod: UInt64 = 1
		for _ in 0..<digits { mod *= 10 }
		let s = String(bin % mod)
		return String(repeating: "0", count: max(0, digits - s.count)) + s
	}

	public static func generate(_ value: String, atMs: Int64 = HLCCodec.nowMillis()) throws -> TotpResult {
		let p = try parse(value)
		guard (6...10).contains(p.digits) else {
			throw TotpError(description: "unsupported TOTP digits (expected 6–10): \(p.digits)")
		}
		guard p.period > 0 else { throw TotpError(description: "invalid TOTP period: \(p.period)") }
		let key = try base32Decode(p.secret)
		guard !key.isEmpty else { throw TotpError(description: "empty TOTP secret") }
		let epoch = Int(atMs / 1000)
		return TotpResult(
			code: hotp(key: key, counter: UInt64(epoch / p.period), algorithm: p.algorithm, digits: p.digits),
			expiresInSec: p.period - (epoch % p.period), period: p.period, digits: p.digits,
			algorithm: p.algorithm)
	}
}
