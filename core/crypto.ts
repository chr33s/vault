// Zero-dependency crypto primitives over node:crypto (spec §3.2, §8).
// All public-key material crosses module/wire boundaries as raw 32-byte buffers;
// helpers here convert between those raw bytes and node KeyObjects.
//
// These per-op primitives are intentionally synchronous: several have no promise
// form (diffieHellman, createCipheriv, createPublicKey), they are individually
// fast, and the storage layer (node:sqlite DatabaseSync) is sync-only — so async
// here would only add coloring without offloading work. The one deliberately
// heavy primitive, the password KDF, DOES use the promise form (see kdf.ts), and
// all filesystem I/O uses node:fs/promises.

import {
	generateKeyPairSync,
	diffieHellman,
	sign as nodeSign,
	verify as nodeVerify,
	createCipheriv,
	createDecipheriv,
	createPublicKey,
	createPrivateKey,
	hkdfSync,
	randomBytes as nodeRandomBytes,
	createHash,
	type KeyObject,
} from "node:crypto";

export type RawKey = Buffer;

export type KeyPairRaw = {
	publicKey: Buffer; // raw 32 bytes
	privateKey: Buffer; // raw 32 bytes (seed)
};

export type AeadBox = {
	iv: Buffer;
	ct: Buffer;
	tag: Buffer;
};

const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
// PKCS8 OKP prefixes (16 bytes) followed by the 32-byte seed.
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const ED25519_PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");

export const randomBytes = (n: number): Buffer => nodeRandomBytes(n);

export const sha256 = (data: Buffer | string): Buffer => createHash("sha256").update(data).digest();

// ---- key (de)serialization to raw 32-byte form ----

const rawFromPublicKey = (key: KeyObject): Buffer => {
	const der = key.export({ type: "spki", format: "der" }) as Buffer;
	return der.subarray(der.length - 32);
};

const rawSeedFromPrivateKey = (key: KeyObject): Buffer => {
	const der = key.export({ type: "pkcs8", format: "der" }) as Buffer;
	// The 32-byte seed is the final 32 bytes of the PKCS8 OKP encoding.
	return der.subarray(der.length - 32);
};

export const x25519PublicFromRaw = (raw: Buffer): KeyObject =>
	createPublicKey({
		key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
		format: "der",
		type: "spki",
	});

export const ed25519PublicFromRaw = (raw: Buffer): KeyObject =>
	createPublicKey({
		key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
		format: "der",
		type: "spki",
	});

export const x25519PrivateFromRaw = (seed: Buffer): KeyObject =>
	createPrivateKey({
		key: Buffer.concat([X25519_PKCS8_PREFIX, seed]),
		format: "der",
		type: "pkcs8",
	});

export const ed25519PrivateFromRaw = (seed: Buffer): KeyObject =>
	createPrivateKey({
		key: Buffer.concat([ED25519_PKCS8, seed]),
		format: "der",
		type: "pkcs8",
	});

// ---- keypair generation (raw form) ----

export const generateX25519 = (): KeyPairRaw => {
	const { publicKey, privateKey } = generateKeyPairSync("x25519");
	return {
		publicKey: rawFromPublicKey(publicKey),
		privateKey: rawSeedFromPrivateKey(privateKey),
	};
};

export const generateEd25519 = (): KeyPairRaw => {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return {
		publicKey: rawFromPublicKey(publicKey),
		privateKey: rawSeedFromPrivateKey(privateKey),
	};
};

// ---- ECDH ----

export const x25519 = (privSeed: Buffer, peerPub: Buffer): Buffer =>
	diffieHellman({
		privateKey: x25519PrivateFromRaw(privSeed),
		publicKey: x25519PublicFromRaw(peerPub),
	});

// ---- signing ----

export const sign = (msg: Buffer, privSeed: Buffer): Buffer =>
	nodeSign(null, msg, ed25519PrivateFromRaw(privSeed));

export const verify = (msg: Buffer, pub: Buffer, sig: Buffer): boolean => {
	try {
		return nodeVerify(null, msg, ed25519PublicFromRaw(pub), sig);
	} catch {
		return false;
	}
};

// ---- HKDF ----

export const hkdf = (ikm: Buffer, salt: Buffer, info: Buffer | string, len: number): Buffer =>
	Buffer.from(
		hkdfSync("sha256", ikm, salt, typeof info === "string" ? Buffer.from(info) : info, len),
	);

// ---- AEAD (AES-256-GCM) ----

export const aeadEncrypt = (key: Buffer, plaintext: Buffer, aad?: Buffer): AeadBox => {
	const iv = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", key, iv);
	if (aad) cipher.setAAD(aad);
	const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();
	return { iv, ct, tag };
};

export const aeadDecrypt = (key: Buffer, box: AeadBox, aad?: Buffer): Buffer => {
	const decipher = createDecipheriv("aes-256-gcm", key, box.iv);
	if (aad) decipher.setAAD(aad);
	decipher.setAuthTag(box.tag);
	return Buffer.concat([decipher.update(box.ct), decipher.final()]);
};
