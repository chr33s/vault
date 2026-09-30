import Foundation
import Testing

@testable import VaultCore

@Suite struct CryptoVectorTests {
	let v = try! Vectors.load("crypto.json")

	@Test func sha256() {
		for c in v.at("sha256").items {
			#expect(VaultCrypto.sha256(c.str("input")).hex == c.str("sha256"))
		}
	}

	@Test func x25519() throws {
		let x = v.at("x25519")
		let ab = try VaultCrypto.x25519(b64(x.str("aPriv")), b64(x.str("bPub")))
		let ba = try VaultCrypto.x25519(b64(x.str("bPriv")), b64(x.str("aPub")))
		#expect(ab.base64 == x.str("shared"))
		#expect(ba == ab)
	}

	@Test func ed25519() throws {
		for c in v.at("ed25519").items {
			let msg = b64(c.str("msg"))
			// swift-crypto's Ed25519 signing is randomized, so signatures are not byte-equal
			// to the reference's; what must hold is cross-verification both ways.
			let mine = try VaultCrypto.sign(msg, b64(c.str("seed")))
			#expect(VaultCrypto.verify(msg, pub: b64(c.str("pub")), sig: mine))
			#expect(try VaultCrypto.ed25519PublicKey(fromSeed: b64(c.str("seed"))).base64 == c.str("pub"))
			#expect(VaultCrypto.verify(msg, pub: b64(c.str("pub")), sig: b64(c.str("sig"))))
			#expect(!VaultCrypto.verify(msg + Data([1]), pub: b64(c.str("pub")), sig: b64(c.str("sig"))))
		}
		#expect(!VaultCrypto.verify(Data(), pub: Data(repeating: 1, count: 5), sig: Data(count: 64)))
	}

	@Test func hkdf() {
		for c in v.at("hkdf").items {
			let info =
				c.str("infoEncoding") == "hex" ? Data(hex: c.str("info"))! : Data(c.str("info").utf8)
			let out = VaultCrypto.hkdf(
				ikm: Data(hex: c.str("ikm"))!, salt: Data(hex: c.str("salt"))!, info: info,
				length: Int(c.at("len").int!))
			#expect(out.hex == c.str("okm"))
		}
	}

	@Test func aeadDecryptsReferenceBoxes() throws {
		for c in v.at("aead").items {
			let aad = c["aad"]?.string.map { b64($0) }
			let box = AeadBox(iv: b64(c.str("iv")), ct: b64(c.str("ct")), tag: b64(c.str("tag")))
			let pt = try VaultCrypto.aeadDecrypt(key: b64(c.str("key")), box: box, aad: aad)
			#expect(pt.base64 == c.str("pt"))
			// Round trip and tamper detection.
			let mine = try VaultCrypto.aeadEncrypt(key: b64(c.str("key")), plaintext: pt, aad: aad)
			#expect(try VaultCrypto.aeadDecrypt(key: b64(c.str("key")), box: mine, aad: aad) == pt)
			var bad = box
			bad.tag[0] ^= 1
			#expect(throws: VaultCryptoError.self) {
				try VaultCrypto.aeadDecrypt(key: b64(c.str("key")), box: bad, aad: aad)
			}
		}
	}

	@Test func sealedBoxInterop() throws {
		for c in v.at("sealed").items {
			let b = c.at("box")
			let box = SealedBox(
				ephPub: b64(b.str("ephPub")), iv: b64(b.str("iv")), ct: b64(b.str("ct")), tag: b64(b.str("tag")))
			let pt = try SealedBoxes.unseal(box, priv: b64(c.str("recipientPriv")), pub: b64(c.str("recipientPub")))
			#expect(pt.base64 == c.str("plaintext"))
			// Swift-sealed boxes open in Swift, and only for the recipient.
			let mine = try SealedBoxes.seal(pt, to: b64(c.str("recipientPub")))
			#expect(try SealedBoxes.unseal(mine, priv: b64(c.str("recipientPriv")), pub: b64(c.str("recipientPub"))) == pt)
			let other = VaultCrypto.generateX25519()
			#expect(throws: Error.self) { try SealedBoxes.unseal(mine, priv: other.privateKey, pub: other.publicKey) }
		}
	}

	@Test func passwordKdf() throws {
		for c in v.at("kdf").items {
			let params = try KdfParams(json: c.at("params"))
			let d = try PasswordKDF.deriveKeys(password: Data(c.str("password").utf8), params: params)
			#expect(d.accountKey.data.base64 == c.str("accountKey"), "\(c.at("params").stringify())")
			#expect(d.authVerifier.data.base64 == c.str("authVerifier"))
			#expect(try KdfParams(json: params.json) == params)
		}
	}

	@Test func kdfRejectsUnknown() {
		#expect(throws: VaultCryptoError.self) {
			try KdfParams(json: .obj(["algo": "pbkdf2", "salt": "AAAA"]))
		}
	}

	@Test func scryptDefaultsAreProductionStrength() throws {
		guard case .scrypt(let salt, let n, let r, let p, let len) = KdfParams.defaultParams() else {
			Issue.record("default is not scrypt")
			return
		}
		#expect(salt.count == 16 && n == 1 << 17 && r == 8 && p == 1 && len == 32)
	}

	@Test func totp() throws {
		for c in v.at("totp").items {
			let r = try TOTP.generate(c.str("value"), atMs: c.at("atMs").int!)
			let e = c.at("result")
			#expect(r.code == e.str("code"), "\(c.str("value")) @\(c.at("atMs").int!)")
			#expect(Int64(r.expiresInSec) == e.at("expiresInSec").int!)
			#expect(Int64(r.period) == e.at("period").int!)
			#expect(r.algorithm.rawValue == e.str("algorithm"))
		}
		#expect(throws: TotpError.self) { try TOTP.generate("!!!") }
		#expect(throws: TotpError.self) { try TOTP.generate("otpauth://hotp/x?secret=AAAA") }
	}
}

@Suite struct SecureBytesTests {
	@Test func zeroesAndCompares() {
		let s = SecureBytes(Data([1, 2, 3, 4]))
		#expect(s.data == Data([1, 2, 3, 4]))
		#expect(s.constantTimeEquals(Data([1, 2, 3, 4])))
		#expect(!s.constantTimeEquals(Data([1, 2, 3, 5])))
		#expect(!s.constantTimeEquals(Data([1, 2, 3])))
		var d = Data([9, 9, 9])
		SecureBytes.wipe(&d)
		#expect(d.isEmpty)
		#expect(SecureBytes(count: 0).data.isEmpty)
	}
}

@Suite struct JSONTests {
	@Test func stringifyMatchesJavaScript() {
		#expect(JSONValue.string("a\"b\\c\n\t\u{08}\u{0C}\u{01}\u{7F}é😀\u{2028}").stringify() == "\"a\\\"b\\\\c\\n\\t\\b\\f\\u0001\u{7F}é😀\u{2028}\"")
		#expect(JSONValue.obj(["b": .int(1), "a": .array([.null, .bool(true), .double(2.0), .double(0.5)])]).stringify() == "{\"b\":1,\"a\":[null,true,2,0.5]}")
	}

	@Test func parsePreservesOrderAndDuplicates() throws {
		let j = try JSONValue.parse(#" {"z":1,"a":{"k":[1,2.5,"é😀"]},"z":3} "#)
		#expect(j.stringify() == "{\"z\":3,\"a\":{\"k\":[1,2.5,\"é😀\"]}}")
		#expect(throws: JSONError.self) { try JSONValue.parse("{\"a\":}") }
		#expect(throws: JSONError.self) { try JSONValue.parse("[1,]") }
		#expect(throws: JSONError.self) { try JSONValue.parse("1 2") }
	}

	@Test func lenientBase64MatchesNode() {
		#expect(Data(base64: "aGk").count == 2)  // missing padding
		#expect(Data(base64: "aG k=\n") == Data("hi".utf8))  // whitespace ignored
		#expect(Data(base64: "-_-_") == Data(base64: "+/+/"))  // url-safe alphabet
	}
}
