import assert from "node:assert/strict";
import { test } from "node:test";
import { generateTotp, parseTotp } from "../core/totp.ts";

// RFC 6238 Appendix B test vectors. The shared secrets are the ASCII strings
// "12345678901234567890" (repeated to 32/64 bytes for SHA256/SHA512), base32-encoded.
const SHA1_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SHA256_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const SHA512_B32 =
	"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

const uri = (secret: string, algo: string): string =>
	`otpauth://totp/ACME:alice?secret=${secret}&algorithm=${algo}&digits=8&period=30`;

// (time seconds, sha1, sha256, sha512) — the canonical RFC 6238 8-digit codes.
const VECTORS: [number, string, string, string][] = [
	[59, "94287082", "46119246", "90693936"],
	[1111111109, "07081804", "68084774", "25091201"],
	[1111111111, "14050471", "67062674", "99943326"],
	[1234567890, "89005924", "91819424", "93441116"],
	[2000000000, "69279037", "90698825", "38618901"],
	[20000000000, "65353130", "77737706", "47863826"], // counter > 2^32 — exercises the 8-byte counter
];

test("TOTP: RFC 6238 known-answer vectors (SHA1/SHA256/SHA512)", () => {
	for (const [t, s1, s256, s512] of VECTORS) {
		const ms = t * 1000;
		assert.equal(generateTotp(uri(SHA1_B32, "SHA1"), ms).code, s1, `sha1 @${t}`);
		assert.equal(generateTotp(uri(SHA256_B32, "SHA256"), ms).code, s256, `sha256 @${t}`);
		assert.equal(generateTotp(uri(SHA512_B32, "SHA512"), ms).code, s512, `sha512 @${t}`);
	}
});

test("TOTP: a bare base32 secret defaults to SHA1 / 6 digits / 30s", () => {
	const r = generateTotp(SHA1_B32, 59_000);
	assert.equal(r.digits, 6);
	assert.equal(r.period, 30);
	assert.equal(r.algorithm, "sha1");
	assert.equal(r.code, "287082"); // last 6 of the RFC 8-digit value 94287082
});

test("TOTP: expiresInSec counts down within the period window", () => {
	assert.equal(generateTotp(SHA1_B32, 0).expiresInSec, 30); // step boundary
	assert.equal(generateTotp(SHA1_B32, 1_000).expiresInSec, 29);
	assert.equal(generateTotp(SHA1_B32, 59_000).expiresInSec, 1);
});

test("TOTP: base32 decoding ignores case, padding, and whitespace", () => {
	const at = 59_000;
	const want = generateTotp(SHA1_B32, at).code;
	assert.equal(generateTotp(SHA1_B32.toLowerCase(), at).code, want);
	assert.equal(generateTotp(`${SHA1_B32}======`, at).code, want);
	assert.equal(generateTotp("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", at).code, want);
});

test("TOTP: otpauth URI parsing pulls secret + overrides", () => {
	const p = parseTotp(
		`otpauth://totp/Issuer:user?secret=${SHA1_B32}&algorithm=SHA256&digits=7&period=15`,
	);
	assert.equal(p.secret, SHA1_B32);
	assert.equal(p.algorithm, "sha256");
	assert.equal(p.digits, 7);
	assert.equal(p.period, 15);
});

test("TOTP: malformed inputs throw", () => {
	assert.throws(() => generateTotp("not!base32!"), /invalid base32/);
	assert.throws(() => generateTotp("otpauth://hotp/x?secret=AAAA"), /expected totp/);
	assert.throws(() => generateTotp(`otpauth://totp/x?algorithm=SHA1`), /missing the secret/);
	assert.throws(
		() => generateTotp(`otpauth://totp/x?secret=${SHA1_B32}&algorithm=md5`),
		/algorithm/,
	);
	assert.throws(() => generateTotp(`otpauth://totp/x?secret=${SHA1_B32}&digits=4`), /digits/);
});
