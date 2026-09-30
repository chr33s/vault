import Crypto
import Foundation

// Cryptographic primitives (spec §3.2, §15.6) over swift-crypto. Public-key material
// crosses every boundary as raw 32-byte values.

public enum VaultCryptoError: Error, Sendable, Equatable {
	case invalidKey
	case authenticationFailed
	case unsupportedKdf(String)
}

public struct KeyPairRaw: Sendable {
	public let publicKey: Data  // raw 32 bytes
	public let privateKey: Data  // raw 32-byte seed
}

public struct AeadBox: Sendable, Equatable {
	public var iv: Data
	public var ct: Data
	public var tag: Data
	public init(iv: Data, ct: Data, tag: Data) {
		self.iv = iv
		self.ct = ct
		self.tag = tag
	}
}

// base64 `{iv, ct, tag}` transport/at-rest form.
public struct EncodedBox: Sendable, Equatable {
	public var iv: String
	public var ct: String
	public var tag: String
	public init(iv: String, ct: String, tag: String) {
		self.iv = iv
		self.ct = ct
		self.tag = tag
	}

	public var json: JSONValue {
		.obj(["iv": .string(iv), "ct": .string(ct), "tag": .string(tag)])
	}

	public init?(json: JSONValue) {
		guard let iv = json["iv"]?.string, let ct = json["ct"]?.string, let tag = json["tag"]?.string
		else { return nil }
		self.init(iv: iv, ct: ct, tag: tag)
	}
}

public enum VaultCrypto {
	public static func randomBytes(_ n: Int) -> Data {
		var g = SystemRandomNumberGenerator()
		return Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &g) })
	}

	public static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
	public static func sha256(_ s: String) -> Data { sha256(Data(s.utf8)) }

	public static func generateX25519() -> KeyPairRaw {
		let k = Curve25519.KeyAgreement.PrivateKey()
		return KeyPairRaw(publicKey: k.publicKey.rawRepresentation, privateKey: k.rawRepresentation)
	}

	public static func generateEd25519() -> KeyPairRaw {
		let k = Curve25519.Signing.PrivateKey()
		return KeyPairRaw(publicKey: k.publicKey.rawRepresentation, privateKey: k.rawRepresentation)
	}

	public static func ed25519PublicKey(fromSeed seed: Data) throws -> Data {
		guard let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else {
			throw VaultCryptoError.invalidKey
		}
		return k.publicKey.rawRepresentation
	}

	public static func x25519PublicKey(fromSeed seed: Data) throws -> Data {
		guard let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: seed) else {
			throw VaultCryptoError.invalidKey
		}
		return k.publicKey.rawRepresentation
	}

	public static func x25519(_ privSeed: Data, _ peerPub: Data) throws -> Data {
		do {
			let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privSeed)
			let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPub)
			let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
			return shared.withUnsafeBytes { Data($0) }
		} catch {
			throw VaultCryptoError.invalidKey
		}
	}

	public static func sign(_ msg: Data, _ privSeed: Data) throws -> Data {
		guard let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: privSeed) else {
			throw VaultCryptoError.invalidKey
		}
		return try k.signature(for: msg)
	}

	public static func verify(_ msg: Data, pub: Data, sig: Data) -> Bool {
		guard let k = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else { return false }
		return k.isValidSignature(sig, for: msg)
	}

	public static func hkdf(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
		let k = HKDF<SHA256>.deriveKey(
			inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: length)
		return k.withUnsafeBytes { Data($0) }
	}

	public static func hkdf(ikm: Data, salt: Data, info: String, length: Int) -> Data {
		hkdf(ikm: ikm, salt: salt, info: Data(info.utf8), length: length)
	}

	public static func aeadEncrypt(key: Data, plaintext: Data, aad: Data? = nil) throws -> AeadBox {
		let iv = randomBytes(12)
		guard key.count == 32 else { throw VaultCryptoError.invalidKey }
		let sealed = try AES.GCM.seal(
			plaintext, using: SymmetricKey(data: key), nonce: try AES.GCM.Nonce(data: iv),
			authenticating: aad ?? Data())
		return AeadBox(iv: iv, ct: sealed.ciphertext, tag: sealed.tag)
	}

	public static func aeadDecrypt(key: Data, box: AeadBox, aad: Data? = nil) throws -> Data {
		guard key.count == 32 else { throw VaultCryptoError.invalidKey }
		do {
			let sb = try AES.GCM.SealedBox(
				nonce: try AES.GCM.Nonce(data: box.iv), ciphertext: box.ct, tag: box.tag)
			return try AES.GCM.open(sb, using: SymmetricKey(data: key), authenticating: aad ?? Data())
		} catch {
			throw VaultCryptoError.authenticationFailed
		}
	}

	public static func encodeBox(_ b: AeadBox) -> EncodedBox {
		EncodedBox(iv: b.iv.base64, ct: b.ct.base64, tag: b.tag.base64)
	}

	public static func decodeBox(_ e: EncodedBox) -> AeadBox {
		AeadBox(iv: Data(base64: e.iv), ct: Data(base64: e.ct), tag: Data(base64: e.tag))
	}
}

// Sealed box: anonymous seal to an X25519 public key using
// an ephemeral keypair + ECDH + HKDF + AES-256-GCM.
public struct SealedBox: Sendable, Equatable {
	public var ephPub: Data
	public var iv: Data
	public var ct: Data
	public var tag: Data
}

public enum SealedBoxes {
	static let info = "credvault/seal/v1"

	public static func seal(_ plain: Data, to recipientPub: Data) throws -> SealedBox {
		let eph = VaultCrypto.generateX25519()
		var shared = try VaultCrypto.x25519(eph.privateKey, recipientPub)
		defer { SecureBytes.wipe(&shared) }
		let wrap = VaultCrypto.hkdf(
			ikm: shared, salt: eph.publicKey + recipientPub, info: info, length: 32)
		let box = try VaultCrypto.aeadEncrypt(key: wrap, plaintext: plain, aad: eph.publicKey)
		return SealedBox(ephPub: eph.publicKey, iv: box.iv, ct: box.ct, tag: box.tag)
	}

	public static func unseal(_ box: SealedBox, priv: Data, pub: Data) throws -> Data {
		var shared = try VaultCrypto.x25519(priv, box.ephPub)
		defer { SecureBytes.wipe(&shared) }
		let wrap = VaultCrypto.hkdf(ikm: shared, salt: box.ephPub + pub, info: info, length: 32)
		return try VaultCrypto.aeadDecrypt(
			key: wrap, box: AeadBox(iv: box.iv, ct: box.ct, tag: box.tag), aad: box.ephPub)
	}
}
