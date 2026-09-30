// Cloudflare Access gate (spec §8.3). Two layers, both defense in
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

	const jwk = await jwkFor(`${issuer}/cdn-cgi/access/certs`, header.kid, cfg.fetchJwks);
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

// JWKS cache, per fetcher and URL. Without it every JWT-gated request (twice per
// request on the Worker: edge + DO) makes an outbound HTTPS round trip, and a
// slow or rate-limited certs endpoint fails every request. Keys are reused for
// JWKS_TTL_MS; an unknown kid (key rotation) forces a refetch at most once per
// JWKS_RETRY_MS. If a refresh fails, the previous set keeps serving for at most
// JWKS_MAX_STALE_MS past its TTL, and the next attempt waits JWKS_RETRY_MS, so an
// outage neither stalls every request on a failing fetch nor trusts a retired
// key indefinitely.
const JWKS_TTL_MS = 10 * 60 * 1000;
const JWKS_RETRY_MS = 30 * 1000;
const JWKS_MAX_STALE_MS = 60 * 60 * 1000;
type CachedJwks = { jwks: JwkSet; fetchedAt: number; retryAt: number };
const jwksCache = new WeakMap<(url: string) => Promise<JwkSet>, Map<string, CachedJwks>>();
// One in-flight fetch per fetcher+URL, so a cold or expired cache under
// concurrent requests makes a single call to the certs endpoint.
const jwksInFlight = new WeakMap<(url: string) => Promise<JwkSet>, Map<string, Promise<JwkSet>>>();

// A response only counts as a key set if it has a `keys` array; anything else is
// treated as a failed fetch rather than cached (and then crashing every lookup).
const fetchJwkSet = (url: string, fetcher: (url: string) => Promise<JwkSet>): Promise<JwkSet> => {
	let byUrl = jwksInFlight.get(fetcher);
	if (!byUrl) jwksInFlight.set(fetcher, (byUrl = new Map()));
	const pending = byUrl.get(url);
	if (pending) return pending;
	const p = (async () => {
		const set = (await fetcher(url)) as unknown;
		const keys = (set as { keys?: unknown } | null)?.keys;
		if (!Array.isArray(keys)) throw new Error("JWKS response has no keys array");
		return { keys: keys.filter((k): k is Jwk => !!k && typeof k === "object") };
	})();
	byUrl.set(url, p);
	// Clear only after registering, and only our own entry: a fetcher that throws
	// synchronously settles `p` before this line, and clearing inside the IIFE
	// would then leave a rejected promise cached as "in flight" forever.
	const clear = (): void => {
		if (byUrl.get(url) === p) byUrl.delete(url);
	};
	p.then(clear, clear);
	return p;
};

// With nothing usable cached, a failed fetch is remembered until this time
// (per fetcher+URL), so requests fail fast instead of each waiting on the
// failing endpoint.
const jwksFailedUntil = new WeakMap<(url: string) => Promise<JwkSet>, Map<string, number>>();

const jwkFor = async (
	url: string,
	kid: string | undefined,
	fetcher: (url: string) => Promise<JwkSet> = defaultFetchJwks,
): Promise<Jwk | undefined> => {
	let byUrl = jwksCache.get(fetcher);
	if (!byUrl) jwksCache.set(fetcher, (byUrl = new Map()));
	const cached = byUrl.get(url);
	const now = Date.now();
	const find = (set: JwkSet): Jwk | undefined => set.keys.find((k) => k.kid === kid);
	const usable = cached && now - cached.fetchedAt < JWKS_TTL_MS + JWKS_MAX_STALE_MS;
	if (cached && usable && now < cached.retryAt) return find(cached.jwks);
	if (cached && now - cached.fetchedAt < JWKS_TTL_MS && find(cached.jwks)) return find(cached.jwks);
	let failed = jwksFailedUntil.get(fetcher);
	if (!failed) jwksFailedUntil.set(fetcher, (failed = new Map()));
	if (!usable && now < (failed.get(url) ?? 0))
		throw new Error("JWKS unavailable (recent fetch failed; retrying shortly)");
	let jwks: JwkSet;
	try {
		jwks = await fetchJwkSet(url, fetcher);
	} catch (err) {
		if (!cached || !usable) {
			failed.set(url, now + JWKS_RETRY_MS);
			throw err;
		}
		cached.retryAt = now + JWKS_RETRY_MS;
		return find(cached.jwks);
	}
	failed.delete(url);
	byUrl.set(url, { jwks, fetchedAt: now, retryAt: now + JWKS_RETRY_MS });
	return find(jwks);
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
