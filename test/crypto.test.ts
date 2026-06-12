import assert from "node:assert/strict";
import { test } from "node:test";
import * as crypto from "../core/crypto.ts";
import {
	deriveKeys,
	DEFAULT_KDF_PARAMS,
	type Argon2idParams,
	type ScryptParams,
} from "../core/kdf.ts";
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

test("KDF: new vaults default to Argon2id (spec §3.1's preferred primitive)", () => {
	const p = DEFAULT_KDF_PARAMS();
	assert.equal(p.algo, "argon2id");
});

// Known-answer tests pin the derivation so any future refactor that would change
// a vault's account key — locking out existing data — fails loudly. One KAT per
// algorithm: Argon2id (new vaults) and legacy scrypt (vaults sealed before the
// switch must keep unlocking, read via the `algo` discriminator — no migration).
const KAT_PW = "correct horse battery staple";
const KAT_SALT = Buffer.alloc(16, 0xab).toString("base64");

test("KDF KAT: Argon2id derivation is stable (backward-compat guard)", async () => {
	const params: Argon2idParams = {
		algo: "argon2id",
		salt: KAT_SALT,
		memory: 1 << 16,
		passes: 3,
		parallelism: 1,
	};
	const d = await deriveKeys(KAT_PW, params);
	assert.equal(
		d.accountKey.toString("hex"),
		"537dad7970336e46404563336f6b8c9b33153dac78058a58f08b6dda4a8f75b4",
	);
	assert.equal(
		d.authVerifier.toString("hex"),
		"c0c0a775b90e1906355dbf953c1f829fb0b13658c86d37d4f9ff51867f0bf46f",
	);
});

test("KDF KAT: legacy scrypt vaults still derive the same keys", async () => {
	const params: ScryptParams = { algo: "scrypt", salt: KAT_SALT, N: 1 << 15, r: 8, p: 1 };
	const d1 = await deriveKeys(KAT_PW, params);
	const d2 = await deriveKeys(KAT_PW, params);
	assert.ok(d1.accountKey.equals(d2.accountKey), "deterministic");
	assert.equal(
		d1.accountKey.toString("hex"),
		"c41a25b9d0deeb1db1d468a63b348f45ba9a2a25e8b2fc620b6f1d19846fe184",
	);
	assert.equal(
		d1.authVerifier.toString("hex"),
		"626fece6eb40feac6413238d67ac0e7d83710a6c42a5b0a1a06b32ca8ffe74b9",
	);
	// Same salt + password, different KDF → different key (the algos don't alias).
	const argon = await deriveKeys(KAT_PW, {
		algo: "argon2id",
		salt: KAT_SALT,
		memory: 1 << 16,
		passes: 3,
		parallelism: 1,
	});
	assert.ok(!d1.accountKey.equals(argon.accountKey));
});
