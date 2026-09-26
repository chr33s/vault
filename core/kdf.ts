// Password KDF (spec §3.1, §3.3; plan §2). DECIDED: Argon2id via node:crypto —
// the spec's *preferred* primitive. Node 26 exposes crypto.argon2/argon2Sync, so
// Argon2id is reachable zero-dep with no WASM asset.
//
// The master password is stretched into a master key, then split into two
// branches via distinct HKDF info labels so neither can derive the other:
//   - accountKey  (encryption branch) — wraps the user's private keys, never leaves the device
//   - authVerifier (auth branch)      — may be sent to a server to authenticate login

import { argon2 as argon2Cb } from "node:crypto";
import { promisify } from "node:util";
import { hkdf, randomBytes } from "./crypto.ts";

// Async forms (threadpool-offloaded) — the KDF is the one deliberately heavy,
// CPU-blocking primitive, so it uses the promise form to avoid stalling the
// event loop. The remaining per-op primitives stay synchronous (see crypto.ts).
const argon2 = promisify(argon2Cb) as (
	algorithm: "argon2id",
	options: {
		message: Buffer;
		nonce: Buffer; // salt
		parallelism: number;
		tagLength: number;
		memory: number; // KiB
		passes: number;
	},
) => Promise<Buffer>;

// Cost parameters live in the vault meta (`kdfParams`) so they can be raised over
// time without breaking existing vaults; `algo` records the algorithm.
export type Argon2idParams = {
	algo: "argon2id";
	salt: string; // base64
	memory: number; // KiB (RFC 9106 'm')
	passes: number; // iterations / time cost ('t')
	parallelism: number; // lanes ('p')
};

export type KdfParams = Argon2idParams;

// New vaults: Argon2id at 64 MiB / 3 passes — comfortably above the OWASP
// minimums and memory-hard against GPU/ASIC cracking, ~tens of ms to unlock on a
// laptop. Raise over time; the chosen values are persisted per vault.
export const DEFAULT_KDF_PARAMS = (): KdfParams => ({
	algo: "argon2id",
	salt: randomBytes(16).toString("base64"),
	memory: 1 << 16, // 65536 KiB = 64 MiB
	passes: 3,
	parallelism: 1,
});

const ACCOUNT_KEY_INFO = "credvault/kdf/account-key/v1";
const AUTH_VERIFIER_INFO = "credvault/kdf/auth-verifier/v1";

const deriveMasterKey = (password: string, params: KdfParams): Promise<Buffer> => {
	if (params.algo !== "argon2id") throw new Error(`unsupported KDF: ${String(params.algo)}`);
	return argon2("argon2id", {
		message: Buffer.from(password, "utf8"),
		nonce: Buffer.from(params.salt, "base64"),
		parallelism: params.parallelism,
		tagLength: 32,
		memory: params.memory,
		passes: params.passes,
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
