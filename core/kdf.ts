// Password KDF (spec §3.1, §3.3; plan §2). DECIDED: scrypt via node:crypto.
// The master password is stretched into a master key, then split into two
// branches via distinct HKDF info labels so neither can derive the other:
//   - accountKey  (encryption branch) — wraps the user's private keys, never leaves the device
//   - authVerifier (auth branch)      — may be sent to a server to authenticate login

import { scrypt as scryptCb } from "node:crypto";
import { promisify } from "node:util";
import { hkdf, randomBytes } from "./crypto.ts";

// Async scrypt (threadpool-offloaded) — the KDF is the one deliberately heavy,
// CPU-blocking primitive, so it uses the promise form to avoid stalling the
// event loop. The remaining per-op primitives stay synchronous (see crypto.ts).
const scrypt = promisify(scryptCb) as (
	password: Buffer,
	salt: Buffer,
	keylen: number,
	options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

// scrypt cost parameters. Stored in the vault meta so they can be raised over
// time without breaking existing vaults. maxmem must accommodate 128*N*r bytes.
export type KdfParams = {
	algo: "scrypt";
	salt: string; // base64
	N: number;
	r: number;
	p: number;
};

export const DEFAULT_KDF_PARAMS = (): KdfParams => ({
	algo: "scrypt",
	salt: randomBytes(16).toString("base64"),
	N: 1 << 15, // 32768
	r: 8,
	p: 1,
});

const ACCOUNT_KEY_INFO = "credvault/kdf/account-key/v1";
const AUTH_VERIFIER_INFO = "credvault/kdf/auth-verifier/v1";

const deriveMasterKey = (password: string, params: KdfParams): Promise<Buffer> => {
	const salt = Buffer.from(params.salt, "base64");
	// maxmem headroom: 128 * N * r bytes plus slack.
	const maxmem = 256 * params.N * params.r;
	return scrypt(Buffer.from(password, "utf8"), salt, 32, {
		N: params.N,
		r: params.r,
		p: params.p,
		maxmem,
	});
};

export type DerivedKeys = {
	accountKey: Buffer; // 32 bytes
	authVerifier: Buffer; // 32 bytes
};

export const deriveKeys = async (password: string, params: KdfParams): Promise<DerivedKeys> => {
	const master = await deriveMasterKey(password, params);
	const salt = Buffer.from(params.salt, "base64");
	return {
		accountKey: hkdf(master, salt, ACCOUNT_KEY_INFO, 32),
		authVerifier: hkdf(master, salt, AUTH_VERIFIER_INFO, 32),
	};
};
