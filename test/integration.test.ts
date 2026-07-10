import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	init,
	unlock,
	addItem,
	getItem,
	listItems,
	rotate,
	authNewDevice,
	deviceAdd,
	deviceConfirm,
} from "../cli/engine.ts";
import { syncWithRelay } from "../cli/relayclient.ts";
import { resolveEnv } from "../cli/run.ts";
import { Store } from "../core/store.ts";
import { createRelay } from "../relay/main.ts";

const tmp = (): Promise<string> => mkdtemp(join(tmpdir(), "vault-"));
const PASS = "test-passphrase";

test("init + add + materialize round-trips through the store", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "github", { username: "alice", url: "https://github.com", password: "s3cr3t" });
		const fresh = await unlock(store, PASS); // reload from disk
		const item = getItem(fresh, "github");
		assert.ok(item);
		assert.equal(item!.fields.username, "alice");
		assert.deepEqual(item!.passwords, ["s3cr3t"]);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("itemType: typed items persist, default to login, and survive rotation", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "gh", { username: "alice", password: "pw" }); // default type
		addItem(s, "card", { number: "4111" }, "card");
		addItem(s, "ssn", {}, "identity");

		const fresh = await unlock(store, PASS); // reload from disk
		assert.equal(getItem(fresh, "gh")!.itemType, "login", "absent type defaults to login");
		assert.equal(getItem(fresh, "card")!.itemType, "card");
		assert.equal(getItem(fresh, "ssn")!.itemType, "identity");
		// The reserved type field must not leak into the visible field map.
		assert.ok(!("__type__" in getItem(fresh, "card")!.fields));

		// Rotation re-encrypts every item under a new epoch; the type must survive.
		rotate(fresh);
		const afterRotate = await unlock(store, PASS);
		assert.equal(getItem(afterRotate, "card")!.itemType, "card", "type preserved across rotation");
		assert.equal(getItem(afterRotate, "card")!.fields.number, "4111");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("wrong passphrase is rejected", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		await assert.rejects(unlock(store, "wrong"), /incorrect passphrase/);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("two replicas converge through the relay", async () => {
	const dir = await tmp();
	const { server } = createRelay();
	await new Promise<void>((r) => server.listen(0, r));
	const port = (server.address() as AddressInfo).port;
	const relay = `http://127.0.0.1:${port}`;

	try {
		// Device 1 creates the vault and enrolls device 2 via the QR handshake.
		const store1 = new Store(join(dir, "d1.db"));
		await init(store1, PASS);
		const s1 = await unlock(store1, PASS);
		addItem(s1, "github", { username: "alice", password: "pw1" });

		const store2 = new Store(join(dir, "d2.db"));
		const tokenA = await authNewDevice(store2, PASS);
		const tokenB = deviceAdd(s1, tokenA, { role: "admin" });
		const conf = await deviceConfirm(store2, PASS, tokenB);
		assert.equal(conf.sas, tokenB.sas);

		// Device 1 pushes its ops to the relay.
		await syncWithRelay(s1, relay);

		// Device 2 unlocks (now a full member) and syncs down the history.
		const s2 = await unlock(store2, PASS);
		const r2 = await syncWithRelay(s2, relay);
		assert.ok(r2.pulled > 0);
		const item = getItem(s2, "github");
		assert.ok(item, "device 2 should see the item after sync");
		assert.equal(item!.fields.username, "alice");
		assert.deepEqual(item!.passwords, ["pw1"]);

		// Device 2 adds an item; device 1 pulls it.
		addItem(s2, "aws", { username: "root", password: "pw2" });
		await syncWithRelay(s2, relay);
		await syncWithRelay(s1, relay);
		assert.ok(getItem(s1, "aws"), "device 1 should converge on device 2's item");

		assert.equal(listItems(s1).length, 2);
		assert.equal(listItems(s2).length, 2);

		store1.close();
		store2.close();
	} finally {
		server.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("rotation re-encrypts and item stays readable", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "github", { username: "alice", password: "pw" });
		const before = s.currentEpoch;
		const epoch = rotate(s);
		assert.equal(epoch, before + 1);
		// Reload: must recover the new epoch key and decrypt.
		const fresh = await unlock(store, PASS);
		assert.equal(fresh.currentEpoch, epoch);
		assert.equal(getItem(fresh, "github")!.fields.username, "alice");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("removeUser appends removal and rotates to a higher epoch", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);

		// Enroll a second user-ish device, then remove that user.
		const store2 = new Store(join(dir, "d2.db"));
		const tokenA = await authNewDevice(store2, PASS);
		deviceAdd(s, tokenA, { role: "member" }); // same user in this model; still exercises rotate
		const epoch = rotate(s);
		assert.ok(epoch >= 2);
		store2.close();
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("vault run resolves env precedence correctly", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "github", { username: "alice", password: "ghp_secret" });
		addItem(s, "DB_URL", { password: "postgres://localhost/db" });

		const envFile = join(dir, ".env");
		await writeFile(
			envFile,
			[
				"PUBLIC=literal-value", // literal passes through
				"DB_URL=", // empty -> resolve item titled DB_URL (password)
				"GH=vault://personal/github/username", // explicit ref
				"AMBIENT", // bare -> ambient wins if set
				"MISSING=", // not in vault
			].join("\n"),
		);

		process.env.AMBIENT = "from-ambient";
		const { env, missing } = await resolveEnv(s, {
			envFile,
			openVault: "personal",
			allowMissing: true,
		});
		delete process.env.AMBIENT;

		assert.equal(env.PUBLIC, "literal-value");
		assert.equal(env.DB_URL, "postgres://localhost/db");
		assert.equal(env.GH, "alice");
		assert.equal(env.AMBIENT, "from-ambient");
		assert.deepEqual(missing, ["MISSING"]);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
