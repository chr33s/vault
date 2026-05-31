// Cloudflare Access gate (spec §8.3; plan §6). Two layers, both defense in
// depth on top of the Tunnel/Access network gate:
//   1. Per-device service tokens — a shared static-token allowlist for the
//      self-hosted path (VAULT_RELAY_TOKENS), the analog of `tag:credvault`.
//      Compared in constant time (timingSafeEqual) to avoid a timing side channel.
//   2. Cf-Access-Jwt-Assertion verification against Cloudflare's JWKS via
//      node:crypto — verifies the edge actually authenticated.
// Both reuse node:crypto, available on Workers via nodejs_compat. Correctness
// never depends on this layer; clients validate all crypto themselves.

import { createPublicKey, verify as nodeVerify, timingSafeEqual } from "node:crypto";

// Constant-time membership test for the service-token allowlist. A plain
// Set.has / === leaks, via response timing, how many leading bytes of a guess
// match a real token — letting an attacker recover one byte-by-byte. We compare
// every candidate with timingSafeEqual and never short-circuit on a match, so
// the work (and timing) is independent of which token, if any, matched. Length
// is compared in constant time too (timingSafeEqual throws on length mismatch).
const tokenAllowed = (tokens: Set<string>, presented: string): boolean => {
	const want = Buffer.from(presented, "utf8");
	let ok = false;
	for (const t of tokens) {
		const candidate = Buffer.from(t, "utf8");
		const same = candidate.length === want.length && timingSafeEqual(candidate, want);
		ok = ok || same;
	}
	return ok;
};

export type AccessConfig = {
	// Static per-device tokens accepted on the `cf-access-token` header.
	serviceTokens?: Set<string>;
	// Cloudflare Access: team domain + application audience tag. When set, the
	// Cf-Access-Jwt-Assertion header is verified against the team's JWKS.
	teamDomain?: string; // e.g. "myteam.cloudflareaccess.com"
	audience?: string;
	// Injected JWKS fetcher (overridable for tests); defaults to fetch().
	fetchJwks?: (url: string) => Promise<JwkSet>;
	// Fail closed: when true, a request with no usable credential is DENIED even
	// if no controls are configured. Set on public deployments (e.g. the Worker
	// deploy button) so a misconfigured relay refuses traffic instead of running
	// open. Local/dev leaves this false, so an unconfigured relay stays open.
	requireAccess?: boolean;
};

export type Jwk = {
	kid: string;
	kty: string;
	n?: string;
	e?: string;
	alg?: string;
};
export type JwkSet = { keys: Jwk[] };

const b64urlToBuf = (s: string): Buffer =>
	Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

// Verify an RS256 Cloudflare Access JWT. Returns the subject on success.
export const verifyAccessJwt = async (
	token: string,
	cfg: AccessConfig,
): Promise<{ sub: string } | undefined> => {
	if (!cfg.teamDomain || !cfg.audience) return undefined;
	const parts = token.split(".");
	if (parts.length !== 3) return undefined;
	const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

	const header = JSON.parse(b64urlToBuf(headerB64).toString("utf8")) as {
		kid?: string;
		alg?: string;
	};
	// Pin the algorithm: reject anything but RS256 up front so a token claiming
	// "none"/"HS256" can never reach (or be confused with) the RSA verify below.
	if (header.alg !== "RS256") return undefined;

	const payload = JSON.parse(b64urlToBuf(payloadB64).toString("utf8")) as {
		aud?: string | string[];
		exp?: number;
		nbf?: number;
		sub?: string;
		iss?: string;
	};

	// Audience, issuer (required), expiry, and not-before checks.
	const auds = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
	if (!auds.includes(cfg.audience)) return undefined;
	const issuer = `https://${cfg.teamDomain}`;
	if (payload.iss !== issuer) return undefined; // require iss, don't merely tolerate it
	const nowSec = Date.now() / 1000;
	if (typeof payload.exp !== "number" || payload.exp < nowSec) return undefined; // require exp
	if (typeof payload.nbf === "number" && payload.nbf > nowSec + 60) return undefined; // 60s skew

	const fetcher = cfg.fetchJwks ?? defaultFetchJwks;
	const jwks = await fetcher(`${issuer}/cdn-cgi/access/certs`);
	const jwk = jwks.keys.find((k) => k.kid === header.kid);
	if (!jwk || jwk.kty !== "RSA" || !jwk.n || !jwk.e) return undefined;

	const key = createPublicKey({
		key: { kty: "RSA", n: jwk.n, e: jwk.e } as Record<string, string>,
		format: "jwk",
	});
	const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "utf8");
	const ok = nodeVerify("RSA-SHA256", signingInput, key, b64urlToBuf(sigB64));
	if (!ok) return undefined;
	return { sub: payload.sub ?? "unknown" };
};

const defaultFetchJwks = async (url: string): Promise<JwkSet> => {
	const res = await fetch(url);
	if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
	return (await res.json()) as JwkSet;
};

// Gate a request given a (lowercased) header accessor. Returns true if allowed.
// Open (true) only when no access controls are configured at all (pure local/
// dev). Transport-neutral so both the Node server and the Worker can use it.
export const authorizeHeaders = async (
	header: (name: string) => string | undefined,
	cfg: AccessConfig,
): Promise<boolean> => {
	const hasControls =
		(cfg.serviceTokens && cfg.serviceTokens.size > 0) || (cfg.teamDomain && cfg.audience);
	// No controls configured: deny when fail-closed (public deploy), else open (dev).
	if (!hasControls) return !cfg.requireAccess;

	const svc = header("cf-access-token");
	if (cfg.serviceTokens && typeof svc === "string" && tokenAllowed(cfg.serviceTokens, svc))
		return true;

	const jwt = header("cf-access-jwt-assertion");
	if (typeof jwt === "string") {
		const r = await verifyAccessJwt(jwt, cfg);
		if (r) return true;
	}
	return false;
};
