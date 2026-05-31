// Sealed-box: a crypto_box_seal analog (spec §3.2, §8). Seals a payload to an
// X25519 public key using an ephemeral keypair + ECDH + HKDF + AES-256-GCM.
// Anonymous sealing — the recipient cannot identify the sender, only decrypt.

import { generateX25519, x25519, hkdf, aeadEncrypt, aeadDecrypt, type AeadBox } from "./crypto.ts";

const SEAL_INFO = "credvault/seal/v1";

export type SealedBox = {
	ephPub: Buffer; // raw 32-byte ephemeral X25519 public key
	iv: Buffer;
	ct: Buffer;
	tag: Buffer;
};

export const seal = (plain: Buffer, recipientPub: Buffer): SealedBox => {
	const eph = generateX25519();
	const shared = x25519(eph.privateKey, recipientPub);
	// Derive the wrap key from the shared secret, salted with the ephemeral and
	// recipient pubs so it's bound to this exact exchange (domain separation;
	// distinct ephemerals never collide). Confidentiality already rests on ECDH —
	// only the recipient's private key reproduces `shared`.
	const wrapKey = hkdf(shared, Buffer.concat([eph.publicKey, recipientPub]), SEAL_INFO, 32);
	const box: AeadBox = aeadEncrypt(wrapKey, plain, eph.publicKey);
	return { ephPub: eph.publicKey, iv: box.iv, ct: box.ct, tag: box.tag };
};

export const unseal = (box: SealedBox, myPriv: Buffer, myPub: Buffer): Buffer => {
	const shared = x25519(myPriv, box.ephPub);
	const wrapKey = hkdf(shared, Buffer.concat([box.ephPub, myPub]), SEAL_INFO, 32);
	return aeadDecrypt(wrapKey, { iv: box.iv, ct: box.ct, tag: box.tag }, box.ephPub);
};
