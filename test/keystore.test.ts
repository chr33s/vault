import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { init, unlock, addItem, getItem, setKeystore } from "../cli/engine.ts";
import type { KeyStore } from "../cli/keystore.ts";
import { Store } from "../core/store.ts";

const tmp = (): Promise<string> => mkdtemp(join(tmpdir(), "vault-ks-"));
const PASS = "ks-pass";

// In-memory stand-in for an OS keychain, with the backing map exposed for tests.
const memKeystore = (): KeyStore & { map: Map<string, Buffer> } => {
	const map = new Map<string, Buffer>();
	return {
		name: "memory",
		async available() {
			return true;
		},
		async put(id, secret) {
			map.set(id, Buffer.from(secret));
		},
		async get(id) {
			return map.get(id);
		},
		async del(id) {
			map.delete(id);
		},
		map,
	};
};

test("keystore-protected vault stores a DUK and round-trips with the keystore", async () => {
	const dir = await tmp();
	try {
		const ks = memKeystore();
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS, ks);
		assert.equal(store.getMeta("keystoreProvider"), "memory");
		assert.equal(ks.map.size, 1, "a device unlock key was placed in the keystore");

		const s = await unlock(store, PASS, ks);
		addItem(s, "github", { username: "alice", password: "pw" });
		const fresh = await unlock(store, PASS, ks);
		assert.equal(getItem(fresh, "github")!.fields.username, "alice");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("a stolen disk (no keystore secret) cannot unlock a protected vault", async () => {
	const dir = await tmp();
	try {
		const ks = memKeystore();
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS, ks);

		// Correct passphrase but the keystore is absent (different machine / cold disk).
		await assert.rejects(unlock(store, PASS, undefined), /protected by keystore "memory"/);

		// Keystore present but the DUK is gone -> still cannot unlock.
		ks.map.clear();
		await assert.rejects(unlock(store, PASS, ks), /keystore secret missing/);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("wrong passphrase still fails on a keystore-protected vault", async () => {
	const dir = await tmp();
	try {
		const ks = memKeystore();
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS, ks);
		await assert.rejects(unlock(store, "wrong", ks), /incorrect passphrase/);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("keystore enable/disable re-wraps an existing vault", async () => {
	const dir = await tmp();
	try {
		const ks = memKeystore();
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS); // passphrase-only
		await unlock(store, PASS, undefined); // opens fine, not protected

		// Enable: now the keystore is required.
		assert.equal(await setKeystore(store, PASS, true, ks), "memory");
		assert.equal(ks.map.size, 1);
		await assert.rejects(unlock(store, PASS, undefined), /protected by keystore/);
		await unlock(store, PASS, ks); // works with the keystore

		// Disable: back to passphrase-only and the DUK is cleaned up.
		assert.equal(await setKeystore(store, PASS, false, ks), "none");
		assert.equal(ks.map.size, 0, "the device unlock key was removed");
		await unlock(store, PASS, undefined); // works again without a keystore
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

// ---- platform-provider branch coverage (runs on this non-macOS/Windows host) ----

import { macKeychain, windowsDpapi, defaultKeyStore } from "../cli/keystore.ts";

test("macKeychain.available() is false off macOS", async () => {
	// On this Linux host: platform()!=="darwin" -> immediate false.
	assert.equal(await macKeychain.available(), false);
});

test("windowsDpapi.available() is false off Windows", async () => {
	assert.equal(await windowsDpapi.available(), false);
});

test("defaultKeyStore() is undefined when no platform keystore is available", async () => {
	assert.equal(await defaultKeyStore(), undefined);
});

test("macKeychain get/del swallow errors when `security` is unavailable", async () => {
	// /usr/bin/security doesn't exist here, so get returns undefined and del is a
	// no-op (both catch). put, by contrast, surfaces the spawn failure.
	assert.equal(await macKeychain.get("anything"), undefined);
	await macKeychain.del("anything"); // must not throw
	await assert.rejects(macKeychain.put("id", Buffer.from("x")));
});
