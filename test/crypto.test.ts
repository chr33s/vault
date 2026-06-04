import assert from "node:assert/strict";
import { test } from "node:test";
import * as crypto from "../core/crypto.ts";
import { deriveKeys, DEFAULT_KDF_PARAMS } from "../core/kdf.ts";
import { seal, unseal } from "../core/sealedbox.ts";

test("x25519 ECDH agrees both directions", async () => {
	const a = crypto.generateX25519();
	const b = crypto.generateX25519();
	assert.equal(a.publicKey.length, 32);
	assert.equal(a.privateKey.length, 32);
	assert.ok(
		crypto.x25519(a.privateKey, b.publicKey).equals(crypto.x25519(b.privateKey, a.publicKey)),
	);
});

test("ed25519 sign/verify round-trip and rejects tampering", async () => {
	const k = crypto.generateEd25519();
	const msg = Buffer.from("attest this");
	const sig = crypto.sign(msg, k.privateKey);
	assert.ok(crypto.verify(msg, k.publicKey, sig));
	assert.ok(!crypto.verify(Buffer.from("attest THIS"), k.publicKey, sig));
	assert.ok(!crypto.verify(msg, crypto.generateEd25519().publicKey, sig));
});

test("AEAD round-trip; wrong key/aad fails", async () => {
	const key = crypto.randomBytes(32);
	const box = crypto.aeadEncrypt(key, Buffer.from("top secret"), Buffer.from("ctx"));
	assert.equal(crypto.aeadDecrypt(key, box, Buffer.from("ctx")).toString(), "top secret");
	assert.throws(() => crypto.aeadDecrypt(crypto.randomBytes(32), box, Buffer.from("ctx")));
	assert.throws(() => crypto.aeadDecrypt(key, box, Buffer.from("wrong")));
});

test("encodeBox/decodeBox round-trips an AEAD box through its base64 form", () => {
	const key = crypto.randomBytes(32);
	const box = crypto.aeadEncrypt(key, Buffer.from("persist me"));
	const encoded = crypto.encodeBox(box);
	// Wire/at-rest shape is base64 strings (stable across persistence).
	assert.equal(typeof encoded.iv, "string");
	assert.equal(typeof encoded.ct, "string");
	assert.equal(typeof encoded.tag, "string");
	// JSON-trip it the way the engine persists meta, then decode + decrypt.
	const reloaded = crypto.decodeBox(JSON.parse(JSON.stringify(encoded)));
	assert.equal(crypto.aeadDecrypt(key, reloaded).toString(), "persist me");
});

test("sealed-box seal/unseal; wrong recipient fails", async () => {
	const recip = crypto.generateX25519();
	const other = crypto.generateX25519();
	const box = seal(Buffer.from("vault key bytes"), recip.publicKey);
	assert.equal(unseal(box, recip.privateKey, recip.publicKey).toString(), "vault key bytes");
	assert.throws(() => unseal(box, other.privateKey, other.publicKey));
});

test("KDF: account key and auth verifier are distinct and deterministic", async () => {
	const params = DEFAULT_KDF_PARAMS();
	const d1 = await deriveKeys("correct horse battery staple", params);
	const d2 = await deriveKeys("correct horse battery staple", params);
	assert.ok(d1.accountKey.equals(d2.accountKey));
	assert.ok(d1.authVerifier.equals(d2.authVerifier));
	assert.ok(!d1.accountKey.equals(d1.authVerifier));
	const d3 = await deriveKeys("wrong password", params);
	assert.ok(!d1.accountKey.equals(d3.accountKey));
});
