// The CLI's relay credential headers (cf-access-token app token + Cloudflare
// Access service-token headers), plus an end-to-end check that an Access service
// token sent by the client is accepted by the relay's authorizeHeaders gate.

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	init,
	unlock,
	authNewDevice,
	deviceAdd,
	deviceConfirm,
	savedRelay,
} from "../cli/engine.ts";
import { authHeaders, type RelayAuth } from "../cli/relayclient.ts";
import { Store } from "../core/store.ts";
import { authorizeHeaders } from "../relay/access.ts";

test("authHeaders: app-layer token only", () => {
	const h = authHeaders({ token: "tok-laptop" });
	assert.deepEqual(h, { "cf-access-token": "tok-laptop" });
});

test("authHeaders: Cloudflare Access service token only", () => {
	const h = authHeaders({ accessId: "abc.access", accessSecret: "s3cr3t" });
	assert.deepEqual(h, {
		"CF-Access-Client-Id": "abc.access",
		"CF-Access-Client-Secret": "s3cr3t",
	});
});

test("authHeaders: both mechanisms compose", () => {
	const auth: RelayAuth = { token: "tok", accessId: "abc.access", accessSecret: "s" };
	assert.deepEqual(authHeaders(auth), {
		"cf-access-token": "tok",
		"CF-Access-Client-Id": "abc.access",
		"CF-Access-Client-Secret": "s",
	});
});

test("authHeaders: a half-configured Access token is omitted (needs both)", () => {
	assert.deepEqual(authHeaders({ accessId: "abc.access" }), {});
	assert.deepEqual(authHeaders({ accessSecret: "s" }), {});
	assert.deepEqual(authHeaders({}), {});
});

test("end-to-end: the app token the CLI sends passes the relay gate", async () => {
	// The relay matches `cf-access-token` against VAULT_RELAY_TOKENS. Simulate the
	// header map the CLI produced reaching authorizeHeaders.
	const sent = authHeaders({ token: "tok-good" });
	const hdr = (name: string) => sent[name] ?? sent[name.toLowerCase()];
	const cfg = { serviceTokens: new Set(["tok-good"]), requireAccess: true };
	assert.equal(await authorizeHeaders(hdr, cfg), true);

	const bad = authHeaders({ token: "tok-bad" });
	const hdrBad = (name: string) => bad[name] ?? bad[name.toLowerCase()];
	assert.equal(await authorizeHeaders(hdrBad, cfg), false);
});

test("enrollment carries relay coords incl. Access service token to the new device", async () => {
	const dir = await mkdtemp(join(tmpdir(), "relayinfo-"));
	try {
		// Existing device creates the vault.
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, "pw");
		const s1 = await unlock(d1, "pw");

		// New device generates Token A.
		const d2 = new Store(join(dir, "d2.db"));
		const tokenA = await authNewDevice(d2, "pw");

		// Authorizer embeds relay URL + an Access service token in Token B.
		const tokenB = deviceAdd(s1, tokenA, {
			relay: {
				url: "https://vault.example.com",
				accessId: "abc.access",
				accessSecret: "s3cr3t",
			},
		});
		assert.equal(tokenB.relay?.url, "https://vault.example.com");

		// New device confirms; the NON-SECRET relay coords (url + accessId) are
		// persisted for later `sync`, but the accessSecret is NOT (meta is plaintext;
		// the secret must be supplied at sync time).
		await deviceConfirm(d2, "pw", tokenB);
		const saved = savedRelay(d2);
		assert.equal(saved?.url, "https://vault.example.com");
		assert.equal(saved?.accessId, "abc.access");
		assert.equal(
			saved?.accessSecret,
			undefined,
			"the bearer secret must not be persisted in plaintext meta",
		);
		// And it must not appear anywhere in the raw meta value.
		const rawMeta = d2.getMeta("relayInfo") ?? "";
		assert.ok(!rawMeta.includes("s3cr3t"), "secret must not be written to the store");

		d1.close();
		d2.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
