import _CryptoExtras
import Foundation

// Password KDF and key split (spec §3.1, §15.6).
//
// New vaults use scrypt; existing Argon2id vaults stay readable through the
// compatibility implementation (Strategy A). Parameters live in vault meta
// (`kdfParams`) so they can be raised later.

public enum KdfParams: Sendable, Equatable {
	case argon2id(salt: Data, memoryKiB: Int, passes: Int, parallelism: Int)
	case scrypt(salt: Data, n: Int, r: Int, p: Int, length: Int)

	public static let defaultScryptN = 1 << 17
	public static let defaultScryptR = 8
	public static let defaultScryptP = 1
	public static let defaultLength = 32

	public static func defaultParams() -> KdfParams {
		.scrypt(
			salt: VaultCrypto.randomBytes(16), n: defaultScryptN, r: defaultScryptR,
			p: defaultScryptP, length: defaultLength)
	}

	public var salt: Data {
		switch self {
		case .argon2id(let s, _, _, _): return s
		case .scrypt(let s, _, _, _, _): return s
		}
	}

	public var json: JSONValue {
		switch self {
		case .argon2id(let salt, let m, let t, let p):
			return .obj([
				"algo": .string("argon2id"), "salt": .string(salt.base64),
				"memory": .int(Int64(m)), "passes": .int(Int64(t)), "parallelism": .int(Int64(p)),
			])
		case .scrypt(let salt, let n, let r, let p, let len):
			return .obj([
				"algo": .string("scrypt"), "salt": .string(salt.base64),
				"N": .int(Int64(n)), "r": .int(Int64(r)), "p": .int(Int64(p)),
				"length": .int(Int64(len)),
			])
		}
	}

	public init(json: JSONValue) throws {
		guard let algo = json["algo"]?.string, let salt = json["salt"]?.string else {
			throw VaultCryptoError.unsupportedKdf("missing algo/salt")
		}
		let s = Data(base64: salt)
		switch algo {
		case "argon2id":
			guard let m = json["memory"]?.int, let t = json["passes"]?.int,
				let p = json["parallelism"]?.int
			else { throw VaultCryptoError.unsupportedKdf("bad argon2id params") }
			self = .argon2id(salt: s, memoryKiB: Int(m), passes: Int(t), parallelism: Int(p))
		case "scrypt":
			guard let n = json["N"]?.int, let r = json["r"]?.int, let p = json["p"]?.int,
				let len = json["length"]?.int, s.count >= 16
			else { throw VaultCryptoError.unsupportedKdf("bad scrypt params") }
			self = .scrypt(salt: s, n: Int(n), r: Int(r), p: Int(p), length: Int(len))
		default:
			throw VaultCryptoError.unsupportedKdf(algo)
		}
	}
}

public struct DerivedKeys: Sendable {
	public let accountKey: SecureBytes  // wraps private keys; never leaves the device
	public let authVerifier: SecureBytes  // may authenticate to a server
}

public enum PasswordKDF {
	static let accountKeyInfo = "credvault/kdf/account-key/v1"
	static let authVerifierInfo = "credvault/kdf/auth-verifier/v1"

	static func masterKey(password: Data, params: KdfParams) throws -> Data {
		switch params {
		case .argon2id(let salt, let m, let t, let p):
			return Data(
				try Argon2id.derive(
					password: Array(password), salt: Array(salt), memoryKiB: m, passes: t,
					parallelism: p, tagLength: 32))
		case .scrypt(let salt, let n, let r, let p, let len):
			guard n > 1, n & (n - 1) == 0, r >= 1, p >= 1, len == 32 else {
				throw VaultCryptoError.unsupportedKdf("invalid scrypt parameters")
			}
			// ~128·N·r bytes of working memory (128 MiB at the defaults).
			let key = try KDF.Scrypt.deriveKey(
				from: password, salt: salt, outputByteCount: len, rounds: n, blockSize: r,
				parallelism: p, maxMemory: 128 * n * r * p + (16 << 20))
			return key.withUnsafeBytes { Data($0) }
		}
	}

	public static func deriveKeys(password: Data, params: KdfParams) throws -> DerivedKeys {
		var master = try masterKey(password: password, params: params)
		defer { SecureBytes.wipe(&master) }
		return DerivedKeys(
			accountKey: SecureBytes(
				VaultCrypto.hkdf(ikm: master, salt: params.salt, info: accountKeyInfo, length: 32)),
			authVerifier: SecureBytes(
				VaultCrypto.hkdf(ikm: master, salt: params.salt, info: authVerifierInfo, length: 32)))
	}

}
