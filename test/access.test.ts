import assert from "node:assert/strict";
import { generateKeyPairSync, createSign } from "node:crypto";
import { test } from "node:test";
import { verifyAccessJwt, authorizeHeaders, type JwkSet } from "../relay/access.ts";

const b64url = (b: Buffer): string =>
	b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Mint an RS256 JWT and a matching JWKS, with a configurable payload.
const mintJwt = (payload: Record<string, unknown>) => {
	const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const jwk = publicKey.export({ format: "jwk" }) as { n: string; e: string };
	const header = { alg: "RS256", kid: "k1", typ: "JWT" };
	const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
		Buffer.from(JSON.stringify(payload)),
	)}`;
	const sig = createSign("RSA-SHA256").update(signingInput).sign(privateKey);
	const token = `${signingInput}.${b64url(sig)}`;
	const jwks: JwkSet = { keys: [{ kid: "k1", kty: "RSA", n: jwk.n, e: jwk.e }] };
	return { token, jwks };
};

// Mint a token with a custom header (to exercise alg pinning) but a valid RSA
// signature + matching JWKS, so only the header's `alg` claim is anomalous.
const mintWithHeader = (header: Record<string, unknown>, payload: Record<string, unknown>) => {
	const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const jwk = publicKey.export({ format: "jwk" }) as { n: string; e: string };
	const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(payload)))}`;
	const sig = createSign("RSA-SHA256").update(signingInput).sign(privateKey);
	return {
		token: `${signingInput}.${b64url(sig)}`,
		jwks: { keys: [{ kid: "k1", kty: "RSA", n: jwk.n, e: jwk.e }] },
	};
};

const TEAM = "myteam.cloudflareaccess.com";
const AUD = "app-audience-tag";
const validPayload = () => ({
	aud: AUD,
	iss: `https://${TEAM}`,
	exp: Math.floor(Date.now() / 1000) + 3600,
	sub: "device-42",
});

test("verifyAccessJwt accepts a well-formed token and returns the subject", async () => {
	const { token, jwks } = mintJwt(validPayload());
	const r = await verifyAccessJwt(token, {
		teamDomain: TEAM,
		audience: AUD,
		fetchJwks: async () => jwks,
	});
	assert.deepEqual(r, { sub: "device-42" });
});

test("verifyAccessJwt rejects wrong audience, expiry, issuer, and tampering", async () => {
	const cfg = (jwks: JwkSet) => ({ teamDomain: TEAM, audience: AUD, fetchJwks: async () => jwks });

	const wrongAud = mintJwt({ ...validPayload(), aud: "someone-else" });
	assert.equal(await verifyAccessJwt(wrongAud.token, cfg(wrongAud.jwks)), undefined);

	const expired = mintJwt({ ...validPayload(), exp: Math.floor(Date.now() / 1000) - 10 });
	assert.equal(await verifyAccessJwt(expired.token, cfg(expired.jwks)), undefined);

	const wrongIss = mintJwt({ ...validPayload(), iss: "https://evil.example.com" });
	assert.equal(await verifyAccessJwt(wrongIss.token, cfg(wrongIss.jwks)), undefined);

	// Tamper the payload after signing -> signature no longer matches.
	const ok = mintJwt(validPayload());
	const [h, , sg] = ok.token.split(".");
	const forgedPayload = b64url(Buffer.from(JSON.stringify({ ...validPayload(), sub: "attacker" })));
	const tampered = `${h}.${forgedPayload}.${sg}`;
	assert.equal(await verifyAccessJwt(tampered, cfg(ok.jwks)), undefined);
});

test("verifyAccessJwt returns undefined when Access is not configured", async () => {
	const { token } = mintJwt(validPayload());
	assert.equal(await verifyAccessJwt(token, {}), undefined);
});

test("verifyAccessJwt pins alg=RS256 (rejects none/HS256 headers)", async () => {
	const cfg = (jwks: JwkSet) => ({ teamDomain: TEAM, audience: AUD, fetchJwks: async () => jwks });
	for (const alg of ["none", "HS256", "RS384", ""]) {
		const { token, jwks } = mintWithHeader({ alg, kid: "k1", typ: "JWT" }, validPayload());
		assert.equal(await verifyAccessJwt(token, cfg(jwks)), undefined, `alg=${alg} must be rejected`);
	}
	// Sanity: the same minter with RS256 is accepted.
	const ok = mintWithHeader({ alg: "RS256", kid: "k1", typ: "JWT" }, validPayload());
	assert.deepEqual(await verifyAccessJwt(ok.token, cfg(ok.jwks)), { sub: "device-42" });
});

test("verifyAccessJwt requires iss and exp, and honors nbf", async () => {
	const cfg = (jwks: JwkSet) => ({ teamDomain: TEAM, audience: AUD, fetchJwks: async () => jwks });
	const now = Math.floor(Date.now() / 1000);

	// Missing iss -> rejected.
	const noIss = mintJwt({ aud: AUD, exp: now + 3600, sub: "d" });
	assert.equal(await verifyAccessJwt(noIss.token, cfg(noIss.jwks)), undefined);

	// Missing exp -> rejected.
	const noExp = mintJwt({ aud: AUD, iss: `https://${TEAM}`, sub: "d" });
	assert.equal(await verifyAccessJwt(noExp.token, cfg(noExp.jwks)), undefined);

	// nbf in the far future -> rejected.
	const future = mintJwt({
		aud: AUD,
		iss: `https://${TEAM}`,
		exp: now + 3600,
		nbf: now + 3600,
		sub: "d",
	});
	assert.equal(await verifyAccessJwt(future.token, cfg(future.jwks)), undefined);
});

// Lowercased header accessor over a plain record (what the transports provide).
const hdr =
	(headers: Record<string, string>) =>
	(name: string): string | undefined =>
		headers[name.toLowerCase()];

test("authorize: open only when no controls are configured", async () => {
	assert.equal(await authorizeHeaders(hdr({}), {}), true, "no controls -> open (dev)");
});

test("authorize: static service-token allowlist gate", async () => {
	const cfg = { serviceTokens: new Set(["tok-good"]) };
	assert.equal(await authorizeHeaders(hdr({ "cf-access-token": "tok-good" }), cfg), true);
	assert.equal(await authorizeHeaders(hdr({ "cf-access-token": "tok-bad" }), cfg), false);
	assert.equal(await authorizeHeaders(hdr({}), cfg), false);
});

test("authorize: constant-time token check accepts any allowlisted token, rejects near-misses", async () => {
	// Multi-token allowlist: each device's token works.
	const cfg = { serviceTokens: new Set(["alpha-token", "bravo-token", "charlie-token"]) };
	for (const t of ["alpha-token", "bravo-token", "charlie-token"]) {
		assert.equal(
			await authorizeHeaders(hdr({ "cf-access-token": t }), cfg),
			true,
			`${t} should pass`,
		);
	}
	// Near-misses the constant-time path must still reject:
	const reject = [
		"alpha-toke", // shorter (prefix of a real token — the side-channel case)
		"alpha-tokenX", // longer (real token is a prefix of the guess)
		"alpha-tokeX", // same length, last byte wrong
		"delta-token", // same length, not present
		"", // empty
	];
	for (const t of reject) {
		assert.equal(
			await authorizeHeaders(hdr({ "cf-access-token": t }), cfg),
			false,
			`${JSON.stringify(t)} should fail`,
		);
	}
});

test("authorize: empty serviceTokens set is treated as no control (not an allow-all)", async () => {
	// size===0 means "no token control"; with nothing else configured and not
	// fail-closed, it opens (dev) — but a presented token must never auto-pass.
	assert.equal(
		await authorizeHeaders(hdr({ "cf-access-token": "anything" }), { serviceTokens: new Set() }),
		true,
	);
	assert.equal(
		await authorizeHeaders(hdr({ "cf-access-token": "anything" }), {
			serviceTokens: new Set(),
			requireAccess: true,
		}),
		false,
		"fail-closed with an empty allowlist denies",
	);
});

test("authorize: accepts a valid Access JWT header (defense in depth)", async () => {
	const { token, jwks } = mintJwt(validPayload());
	const cfg = { teamDomain: TEAM, audience: AUD, fetchJwks: async () => jwks };
	assert.equal(await authorizeHeaders(hdr({ "cf-access-jwt-assertion": token }), cfg), true);
	assert.equal(await authorizeHeaders(hdr({ "cf-access-jwt-assertion": "garbage" }), cfg), false);
});

test("authorize: requireAccess fails closed when no controls are configured", async () => {
	// Public deploy (e.g. the Worker deploy button) with nothing configured yet:
	// must DENY rather than run open.
	assert.equal(await authorizeHeaders(hdr({}), { requireAccess: true }), false);
	// Once a control is configured, requireAccess behaves like normal gating.
	const cfg = { requireAccess: true, serviceTokens: new Set(["tok-good"]) };
	assert.equal(await authorizeHeaders(hdr({ "cf-access-token": "tok-good" }), cfg), true);
	assert.equal(await authorizeHeaders(hdr({ "cf-access-token": "tok-bad" }), cfg), false);
});
