// TOTP code generation (spec §4 `ItemPayload.totpSecret`; RFC 6238 over RFC 4226
// HOTP). Zero-dep: HMAC via node:crypto + a small base32 decoder. The stored
// value is either a bare base32 secret (SHA1 / 6 digits / 30s defaults) or a full
// `otpauth://totp/...` URI whose query overrides algorithm/digits/period.

import { createHmac } from "node:crypto";

const B32_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// RFC 4648 base32 decode: case-insensitive, ignores padding and whitespace.
const base32Decode = (input: string): Buffer => {
	const clean = input.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
	let bits = 0;
	let value = 0;
	const out: number[] = [];
	for (const ch of clean) {
		const idx = B32_ALPHA.indexOf(ch);
		if (idx === -1) throw new Error(`invalid base32 character in TOTP secret: ${ch}`);
		value = (value << 5) | idx;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			out.push((value >> bits) & 0xff);
		}
	}
	return Buffer.from(out);
};

export type TotpAlgorithm = "sha1" | "sha256" | "sha512";

export type TotpParams = {
	secret: string; // base32
	algorithm: TotpAlgorithm;
	digits: number;
	period: number; // seconds
};

export type TotpResult = {
	code: string;
	expiresInSec: number;
	period: number;
	digits: number;
	algorithm: TotpAlgorithm;
};

const asAlgorithm = (a: string): TotpAlgorithm => {
	const v = a.toLowerCase();
	if (v === "sha1" || v === "sha256" || v === "sha512") return v;
	throw new Error(`unsupported TOTP algorithm: ${a}`);
};

// Parse a stored value: a bare base32 secret, or an `otpauth://totp/...` URI.
export const parseTotp = (value: string): TotpParams => {
	const v = value.trim();
	if (v.toLowerCase().startsWith("otpauth://")) {
		const url = new URL(v);
		if (url.host.toLowerCase() !== "totp")
			throw new Error(`unsupported otpauth type (expected totp): ${url.host}`);
		const secret = url.searchParams.get("secret");
		if (!secret) throw new Error("otpauth URI is missing the secret parameter");
		return {
			secret,
			algorithm: asAlgorithm(url.searchParams.get("algorithm") ?? "SHA1"),
			digits: Number(url.searchParams.get("digits") ?? 6),
			period: Number(url.searchParams.get("period") ?? 30),
		};
	}
	return { secret: v, algorithm: "sha1", digits: 6, period: 30 };
};

// RFC 4226 HOTP: HMAC the 8-byte big-endian counter, dynamic-truncate, mod 10^d.
const hotp = (key: Buffer, counter: number, algorithm: TotpAlgorithm, digits: number): string => {
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(BigInt(counter));
	const mac = createHmac(algorithm, key).update(buf).digest();
	const offset = mac[mac.length - 1]! & 0x0f;
	const bin =
		((mac[offset]! & 0x7f) << 24) |
		((mac[offset + 1]! & 0xff) << 16) |
		((mac[offset + 2]! & 0xff) << 8) |
		(mac[offset + 3]! & 0xff);
	return (bin % 10 ** digits).toString().padStart(digits, "0");
};

export const generateTotp = (value: string, atMs: number = Date.now()): TotpResult => {
	const p = parseTotp(value);
	if (!Number.isInteger(p.digits) || p.digits < 6 || p.digits > 10)
		throw new Error(`unsupported TOTP digits (expected 6–10): ${p.digits}`);
	if (!Number.isInteger(p.period) || p.period <= 0)
		throw new Error(`invalid TOTP period: ${p.period}`);
	const key = base32Decode(p.secret);
	if (key.length === 0) throw new Error("empty TOTP secret");
	const epochSec = Math.floor(atMs / 1000);
	const counter = Math.floor(epochSec / p.period);
	return {
		code: hotp(key, counter, p.algorithm, p.digits),
		expiresInSec: p.period - (epochSec % p.period),
		period: p.period,
		digits: p.digits,
		algorithm: p.algorithm,
	};
};
