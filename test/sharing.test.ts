import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	init,
	unlock,
	addItem,
	getItem,
	rotate,
	removeUser,
	removeDevice,
	inviteInit,
	shareVault,
	joinConfirm,
	recoveryEnable,
	recoverUser,
	authNewDevice,
	deviceAdd,
	deviceConfirm,
} from "../cli/engine.ts";
import { maybeCatchUp } from "../cli/engine.ts";
import { dbPath, listVaultNames } from "../cli/paths.ts";
import { syncWithRelay } from "../cli/relayclient.ts";
import * as cr from "../core/crypto.ts";
import { winner, type RotationRecord } from "../core/rotation.ts";
import { Store } from "../core/store.ts";
import { createRelay } from "../relay/main.ts";

const tmp = (): Promise<string> => mkdtemp(join(tmpdir(), "vault-share-"));
const PASS = "owner-pass";
const PASS_B = "joiner-pass";

const startRelay = async (): Promise<{ url: string; close: () => void }> => {
	const { server } = createRelay();
	await new Promise<void>((r) => server.listen(0, r));
	const port = (server.address() as AddressInfo).port;
	return { url: `http://127.0.0.1:${port}`, close: () => server.close() };
};

test("rotation propagates to a second device through the relay", async () => {
	const dir = await tmp();
	const relay = await startRelay();
	try {
		const s1Store = new Store(join(dir, "d1.db"));
		await init(s1Store, PASS);
		const s1 = await unlock(s1Store, PASS);
		addItem(s1, "github", { username: "alice", password: "pw1" });

		// Enroll device 2 (same user) and sync it up.
		const s2Store = new Store(join(dir, "d2.db"));
		const tokenA = await authNewDevice(s2Store, PASS);
		const tokenB = deviceAdd(s1, tokenA, { role: "admin" });
		await deviceConfirm(s2Store, PASS, tokenB);
		await syncWithRelay(s1, relay.url);
		const s2 = await unlock(s2Store, PASS);
		await syncWithRelay(s2, relay.url);
		assert.ok(getItem(s2, "github"));

		// Device 1 rotates; device 2 must learn the new epoch over sync and stay readable.
		const epoch = rotate(s1);
		await syncWithRelay(s1, relay.url);
		await syncWithRelay(s2, relay.url);
		assert.equal(s2.currentEpoch, epoch, "device 2 should adopt the new epoch via sync");
		assert.equal(getItem(s2, "github")!.fields.username, "alice");

		// A post-rotation write is readable on device 2 only because it got the key.
		addItem(s1, "aws", { username: "root", password: "pw2" });
		await syncWithRelay(s1, relay.url);
		await syncWithRelay(s2, relay.url);
		assert.equal(getItem(s2, "aws")!.fields.username, "root");

		s1Store.close();
		s2Store.close();
	} finally {
		relay.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("device-remove revokes a single device subkey and locks it out of new data (spec §9)", async () => {
	const dir = await tmp();
	const relay = await startRelay();
	try {
		// Owner on device 1; enroll device 2 (same user), share epoch 1 + an item.
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, PASS);
		const s1 = await unlock(d1, PASS);
		addItem(s1, "github", { username: "alice", password: "pw" });
		const d2 = new Store(join(dir, "d2.db"));
		await deviceConfirm(d2, PASS, deviceAdd(s1, await authNewDevice(d2, PASS), { role: "admin" }));
		await syncWithRelay(s1, relay.url);
		const s2 = await unlock(d2, PASS);
		await syncWithRelay(s2, relay.url);
		await syncWithRelay(s1, relay.url);
		assert.ok(getItem(s2, "github"), "device 2 reads the item before removal");

		// Revoke ONLY device 2 (not the whole user) and rotate.
		const epoch = removeDevice(s1, s2.deviceId);
		assert.ok(epoch >= 2);
		addItem(s1, "after-removal", { password: "secret" });
		await syncWithRelay(s1, relay.url);
		await syncWithRelay(s2, relay.url);

		// Device 1 keeps full access; device 2 is locked out of new data.
		assert.ok(getItem(s1, "after-removal"), "owner's surviving device reads new data");
		assert.equal(getItem(s2, "after-removal"), undefined, "removed device cannot read new data");

		d1.close();
		d2.close();
	} finally {
		relay.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("FORK over relay: concurrent device enrollments converge (both writers accepted)", async () => {
	const dir = await tmp();
	const relay = await startRelay();
	try {
		// Owner on device 1; enroll device 2 (same user, admin) and sync both.
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, PASS);
		const s1 = await unlock(d1, PASS);
		const d2 = new Store(join(dir, "d2.db"));
		const tA2 = await authNewDevice(d2, PASS);
		await deviceConfirm(d2, PASS, deviceAdd(s1, tA2, { role: "admin" }));
		await syncWithRelay(s1, relay.url);
		const s2 = await unlock(d2, PASS);
		await syncWithRelay(s2, relay.url);
		await syncWithRelay(s1, relay.url);

		// Concurrently (before syncing each other), device 1 enrolls device 3 and
		// device 2 enrolls device 4 — both add-device entries fork from the same
		// head of the membership DAG.
		const d3 = new Store(join(dir, "d3.db"));
		await deviceConfirm(d3, PASS, deviceAdd(s1, await authNewDevice(d3, PASS), { role: "admin" }));
		const d4 = new Store(join(dir, "d4.db"));
		await deviceConfirm(d4, PASS, deviceAdd(s2, await authNewDevice(d4, PASS), { role: "admin" }));

		// Devices 3 and 4 each write an item, then everyone syncs to converge.
		const s3 = await unlock(d3, PASS);
		const s4 = await unlock(d4, PASS);
		addItem(s3, "from-d3", { password: "p3" });
		addItem(s4, "from-d4", { password: "p4" });
		for (const s of [s1, s2, s3, s4]) await syncWithRelay(s, relay.url);
		for (const s of [s1, s2, s3, s4]) await syncWithRelay(s, relay.url);

		// The fork reconciled: every replica accepts BOTH new devices' signed ops.
		for (const s of [s1, s2, s3, s4]) {
			assert.ok(getItem(s, "from-d3"), "d3's write accepted everywhere");
			assert.ok(getItem(s, "from-d4"), "d4's write accepted everywhere");
		}

		for (const st of [d1, d2, d3, d4]) st.close();
	} finally {
		relay.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("two concurrent admin rotations converge on one winner (spec §10.2)", async () => {
	const dir = await tmp();
	const relay = await startRelay();
	try {
		// Owner + a second admin device sharing epoch 1 and an item.
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, PASS);
		const s1 = await unlock(d1, PASS);
		addItem(s1, "github", { username: "alice", password: "pw" });
		const d2 = new Store(join(dir, "d2.db"));
		await deviceConfirm(d2, PASS, deviceAdd(s1, await authNewDevice(d2, PASS), { role: "admin" }));
		await syncWithRelay(s1, relay.url);
		const s2 = await unlock(d2, PASS);
		await syncWithRelay(s2, relay.url);
		await syncWithRelay(s1, relay.url);
		assert.ok(getItem(s2, "github"));

		// Both admins rotate concurrently (offline from each other): two rotation
		// records at the same epoch, different keys.
		const e1 = rotate(s1);
		const e2 = rotate(s2);
		assert.equal(e1, e2, "both rotate to the same epoch number");

		// Converge through the relay (a couple of rounds to settle).
		for (let i = 0; i < 3; i++) {
			await syncWithRelay(s1, relay.url);
			await syncWithRelay(s2, relay.url);
		}

		// Both devices must elect the SAME winning key, so post-convergence writes
		// are mutually readable and old data survives.
		assert.equal(s1.currentEpoch, e1);
		assert.equal(s2.currentEpoch, e1);
		assert.equal(getItem(s1, "github")!.fields.username, "alice");
		assert.equal(getItem(s2, "github")!.fields.username, "alice");

		addItem(s1, "after1", { password: "a1" });
		addItem(s2, "after2", { password: "a2" });
		for (let i = 0; i < 2; i++) {
			await syncWithRelay(s1, relay.url);
			await syncWithRelay(s2, relay.url);
		}
		assert.ok(getItem(s2, "after1"), "device 2 reads device 1's post-rotation write");
		assert.ok(getItem(s1, "after2"), "device 1 reads device 2's post-rotation write");

		d1.close();
		d2.close();
	} finally {
		relay.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("cross-user sharing, convergence, and multi-user removal", async () => {
	const dir = await tmp();
	const relay = await startRelay();
	try {
		// Owner creates the vault and an item.
		const ownerStore = new Store(join(dir, "owner.db"));
		await init(ownerStore, PASS);
		const owner = await unlock(ownerStore, PASS);
		addItem(owner, "github", { username: "alice", password: "shared-pw" });

		// Bob (a different person) generates an invite; owner shares; Bob joins.
		const bobStore = new Store(join(dir, "bob.db"));
		const invite = await inviteInit(bobStore, PASS_B);
		const joinToken = shareVault(owner, invite, { role: "member" });
		const conf = await joinConfirm(bobStore, PASS_B, joinToken);
		assert.equal(conf.userId, invite.userId);

		// Publish everything through the relay.
		await syncWithRelay(owner, relay.url);
		const bob = await unlock(bobStore, PASS_B);
		await syncWithRelay(bob, relay.url); // pull membership + ops + grants; push Bob's add-device
		await syncWithRelay(owner, relay.url); // owner learns Bob's device

		// Bob can read the shared item.
		assert.ok(getItem(bob, "github"), "Bob should see the shared item");
		assert.equal(getItem(bob, "github")!.fields.username, "alice");

		// Bob writes; owner converges on it (owner must accept Bob's signed op).
		addItem(bob, "bobsecret", { password: "bob-only" });
		await syncWithRelay(bob, relay.url);
		await syncWithRelay(owner, relay.url);
		assert.ok(getItem(owner, "bobsecret"), "owner should converge on Bob's item");

		// Owner removes Bob and rotates; a post-removal write must NOT reach Bob.
		removeUser(owner, invite.userId);
		addItem(owner, "post-removal", { password: "after-bob-left" });
		await syncWithRelay(owner, relay.url);
		await syncWithRelay(bob, relay.url);

		assert.ok(getItem(owner, "post-removal"), "owner can read post-removal item");
		assert.equal(getItem(bob, "post-removal"), undefined, "Bob is locked out of new data");

		ownerStore.close();
		bobStore.close();
	} finally {
		relay.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("security catch-up: an unobserved removal forces a following rotation (spec §10.2)", async () => {
	const dir = await tmp();
	const relay = await startRelay();
	try {
		// Owner with two admin devices, plus member Bob.
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, PASS);
		const s1 = await unlock(d1, PASS);
		const d2 = new Store(join(dir, "d2.db"));
		await deviceConfirm(d2, PASS, deviceAdd(s1, await authNewDevice(d2, PASS), { role: "admin" }));
		await syncWithRelay(s1, relay.url);
		const s2 = await unlock(d2, PASS);
		await syncWithRelay(s2, relay.url);
		await syncWithRelay(s1, relay.url);

		const bobStore = new Store(join(dir, "bob.db"));
		const invite = await inviteInit(bobStore, PASS_B);
		await joinConfirm(bobStore, PASS_B, shareVault(s1, invite, { role: "member" }));
		await syncWithRelay(s1, relay.url);
		const bob = await unlock(bobStore, PASS_B);
		await syncWithRelay(bob, relay.url);
		await syncWithRelay(bob, relay.url);
		await syncWithRelay(s1, relay.url);
		await syncWithRelay(s2, relay.url);
		assert.ok(getItem(bob, "github") === undefined); // (no item yet) sanity: synced

		// RACE: device 1 removes Bob and rotates (its rotation observes the removal).
		// device 2, not having seen the removal, rotates concurrently (its rotation
		// does NOT observe the removal).
		removeUser(s1, invite.userId);
		rotate(s2);

		// Converge, then let every admin run catch-up to a fixpoint.
		const removalHash = s1.store
			.authLog()
			.find((e) => e.body.type === "remove-user" && e.body.userId === invite.userId)!.hash;

		for (let round = 0; round < 6; round++) {
			for (const s of [s1, s2]) {
				await syncWithRelay(s, relay.url);
				maybeCatchUp(s);
				await syncWithRelay(s, relay.url);
			}
		}
		await syncWithRelay(s1, relay.url);
		await syncWithRelay(s2, relay.url);

		// Invariant restored: the winning rotation now causally follows the removal
		// (it observed the removal entry), on every replica.
		const winnerOf = (st: typeof s1): RotationRecord =>
			winner(st.store.rotations().map((r) => JSON.parse(r) as RotationRecord))!;
		assert.ok(winnerOf(s1).observed.includes(removalHash), "winner observed the removal (d1)");
		assert.ok(winnerOf(s2).observed.includes(removalHash), "winner observed the removal (d2)");
		assert.equal(s1.currentKeyCommit, s2.currentKeyCommit, "admins agree on the current key");

		// And Bob is locked out of data written after the dust settles.
		addItem(s1, "post-catchup", { password: "secret" });
		await syncWithRelay(s1, relay.url);
		await syncWithRelay(bob, relay.url);
		assert.equal(getItem(bob, "post-catchup"), undefined, "removed member cannot read new data");

		d1.close();
		d2.close();
		bobStore.close();
	} finally {
		relay.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("recovery escrow reconstructs a member's identity keys", async () => {
	const dir = await tmp();
	const relay = await startRelay();
	try {
		const ownerStore = new Store(join(dir, "owner.db"));
		await init(ownerStore, PASS);
		const owner = await unlock(ownerStore, PASS);

		// Enable escrow; the owner safeguards the returned org private key offline.
		const orgPriv = recoveryEnable(owner);
		assert.ok(orgPriv.length > 0);

		// Bob joins; recovery escrow is enabled, so Bob contributes a RecoveryGrant.
		const bobStore = new Store(join(dir, "bob.db"));
		const invite = await inviteInit(bobStore, PASS_B);
		const joinToken = shareVault(owner, invite, { role: "member" });
		await joinConfirm(bobStore, PASS_B, joinToken);

		await syncWithRelay(owner, relay.url); // push org-key announcement + owner grant
		const bob = await unlock(bobStore, PASS_B);
		await syncWithRelay(bob, relay.url); // pull org key; contributeRecovery mints Bob's grant
		await syncWithRelay(bob, relay.url); // push Bob's grant
		await syncWithRelay(owner, relay.url); // owner pulls Bob's grant

		// Owner reconstructs Bob's identity keys using the org private key.
		const recoveredJson = recoverUser(owner, invite.userId, orgPriv);
		const recovered = JSON.parse(recoveredJson) as { userSign: string; userEnc: string };
		assert.ok(recovered.userSign && recovered.userEnc, "recovered both identity keys");

		// Prove the recovered signing key matches Bob's public identity key.
		const msg = Buffer.from("recovery proof");
		const sig = cr.sign(msg, Buffer.from(recovered.userSign, "base64"));
		assert.ok(
			cr.verify(msg, Buffer.from(invite.userSignPub, "base64"), sig),
			"recovered key signs as Bob",
		);

		// Wrong org key fails.
		const wrong = cr.generateX25519().privateKey.toString("base64");
		assert.throws(() => recoverUser(owner, invite.userId, wrong), /recovery failed/);

		ownerStore.close();
		bobStore.close();
	} finally {
		relay.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("named vaults are independent replicas", async () => {
	const home = await tmp();
	const prev = process.env.VAULT_HOME;
	process.env.VAULT_HOME = home;
	try {
		// dbPath reads VAULT_HOME at call time, so the real multi-vault layout is used.
		const a = new Store(await dbPath("work"));
		await init(a, PASS);
		const sa = await unlock(a, PASS);
		addItem(sa, "work-item", { password: "w" });
		a.close();

		const b = new Store(await dbPath("personal"));
		await init(b, PASS);
		const sb = await unlock(b, PASS);
		addItem(sb, "home-item", { password: "h" });

		// Isolation: the personal vault never sees the work item.
		assert.ok(getItem(sb, "home-item"));
		assert.equal(getItem(sb, "work-item"), undefined);
		b.close();

		assert.deepEqual((await listVaultNames()).sort(), ["personal", "work"]);
	} finally {
		if (prev === undefined) delete process.env.VAULT_HOME;
		else process.env.VAULT_HOME = prev;
		await rm(home, { recursive: true, force: true });
	}
});
