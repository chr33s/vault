import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	init,
	unlock,
	addItem,
	editItem,
	getItem,
	rotate,
	removeDevice,
	removeUser,
	recoverUser,
	maybeCatchUp,
	rebuildSession,
	authNewDevice,
	deviceAdd,
	deviceConfirm,
	inviteInit,
	shareVault,
	joinConfirm,
	recoveryEnable,
	contributeRecovery,
} from "../cli/engine.ts";
import { entryHash, heads, makeEntry, replay } from "../core/authlog.ts";
import * as cr from "../core/crypto.ts";
import { encodeHLC } from "../core/hlc.ts";
import { grantAuthentic, grantBytes, makeEnvelope, type GrantRow } from "../core/protocol.ts";
import { keyCommit, encodeGrant, rotationBytes, type RotationRecord } from "../core/rotation.ts";
import { seal } from "../core/sealedbox.ts";
import { Store } from "../core/store.ts";

const tmp = (): Promise<string> => mkdtemp(join(tmpdir(), "vault-sec-"));
const PASS = "sec-pass";

// Build a fully-formed RotationRecord signed by an arbitrary key (the "forger").
const forgeRotation = (
	epoch: number,
	signerId: string,
	signerPriv: Buffer,
	recipientEncPub: Buffer,
): { record: RotationRecord; attackerKey: Buffer } => {
	const attackerKey = cr.randomBytes(32);
	const unsigned: Omit<RotationRecord, "sig"> = {
		epoch,
		baseEpoch: epoch - 1,
		hlc: encodeHLC({ millis: 9_000_000_000, counter: 0, deviceId: signerId }),
		deviceId: signerId,
		keyCommit: keyCommit(attackerKey),
		// Seal the attacker-known key to the victim's device so that, if the forged
		// rotation were (wrongly) accepted, the victim would adopt it for new writes.
		grants: {
			[recipientEncPub.toString("base64")]: encodeGrant(seal(attackerKey, recipientEncPub)),
		},
		observed: [],
		signerId,
	};
	const sig = cr.sign(rotationBytes(unsigned), signerPriv).toString("base64");
	return { record: { ...unsigned, sig }, attackerKey };
};

test("forged rotation signed by a non-key-holder is rejected (spec §8.4)", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "github", { username: "alice", password: "pw" });
		const legitEpoch = s.currentEpoch;
		const legitCommit = s.currentKeyCommit;

		// Attacker (no authorized device key) forges a high-epoch rotation, naming
		// the victim's real deviceId as signer but signing with a key they invented.
		const attackerSignKey = cr.generateEd25519();
		const { record } = forgeRotation(99, s.deviceId, attackerSignKey.privateKey, s.pub.deviceEnc);
		store.putRotation(record.epoch, record.deviceId, JSON.stringify(record));

		// Rebuild: the forged rotation must be ignored (bad signature), so the
		// current epoch/key are unchanged and the item is still readable.
		rebuildSession(s);
		assert.equal(s.currentEpoch, legitEpoch, "forged epoch must not win");
		assert.equal(s.currentKeyCommit, legitCommit, "must not adopt the attacker key");
		assert.equal(getItem(s, "github")!.fields.username, "alice");

		// Same outcome on a fresh unlock from disk.
		const fresh = await unlock(store, PASS);
		assert.equal(fresh.currentEpoch, legitEpoch);
		assert.equal(fresh.currentKeyCommit, legitCommit);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("rotation naming an unknown device as signer is rejected", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "x", { password: "pw" });
		const legitCommit = s.currentKeyCommit;

		// signerId is a device that was never added to the auth log.
		const ghost = cr.generateEd25519();
		const { record } = forgeRotation(99, "ghostdevice0000", ghost.privateKey, s.pub.deviceEnc);
		store.putRotation(record.epoch, record.deviceId, JSON.stringify(record));

		rebuildSession(s);
		assert.equal(s.currentEpoch, 1);
		assert.equal(s.currentKeyCommit, legitCommit);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("future-dated remote field ops are rejected before CRDT application", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		const itemId = addItem(s, "clock", {});

		const remoteStore = new Store(join(dir, "remote.db"));
		const tokenA = await authNewDevice(remoteStore, PASS);
		const tokenB = deviceAdd(s, tokenA);
		await deviceConfirm(remoteStore, PASS, tokenB);
		const remote = await unlock(remoteStore, PASS);
		const key = remote.keys.get(remote.currentKeyCommit)!;
		const field = {
			itemId,
			field: "username",
			value: "future-wins",
			hlc: encodeHLC({
				millis: Date.now() + 2 * 24 * 60 * 60 * 1000,
				counter: 0,
				deviceId: remote.deviceId,
			}),
		};
		const box = cr.aeadEncrypt(key, Buffer.from(JSON.stringify(field), "utf8"));
		const payload = Buffer.from(
			JSON.stringify({ keyCommit: remote.currentKeyCommit, ...cr.encodeBox(box) }),
			"utf8",
		);
		store.putOp(
			makeEnvelope(
				remote.deviceId,
				store.maxSeqFor(remote.deviceId) + 1,
				payload,
				remote.priv.deviceSign,
			),
		);

		rebuildSession(s);
		assert.equal(getItem(s, "clock")!.fields.username, undefined);
		remoteStore.close();
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("rotation preserves CRDT timestamps and every live password conflict", async () => {
	const dir = await tmp();
	try {
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, PASS);
		const s1 = await unlock(d1, PASS);
		addItem(s1, "service", { username: "base", password: "base-password" });

		const d2 = new Store(join(dir, "d2.db"));
		await deviceConfirm(d2, PASS, deviceAdd(s1, await authNewDevice(d2, PASS)));
		const s2 = await unlock(d2, PASS);
		for (const op of d1.allOps()) d2.putOp(op);
		rebuildSession(s2);

		// Both devices edit "service" concurrently. The username is a single LWW
		// register whose winner is decided by the HLC tiebreak (deviceId), so we do
		// not assume which value wins — only that rotation preserves it. The two
		// password writes are conflicts that must both survive.
		editItem(s1, "service", { username: "d1", password: "one" });
		editItem(s2, "service", { username: "d2", password: "two" });
		for (const op of d2.allOps()) d1.putOp(op);
		rebuildSession(s1);
		const mergedUsername = getItem(s1, "service")!.fields.username;
		assert.deepEqual(new Set(getItem(s1, "service")!.passwords), new Set(["one", "two"]));

		rotate(s1);
		rebuildSession(s1);
		assert.equal(
			getItem(s1, "service")!.fields.username,
			mergedUsername,
			"re-encrypting a field must not mint a newer LWW timestamp that flips the winner",
		);
		assert.deepEqual(
			new Set(getItem(s1, "service")!.passwords),
			new Set(["one", "two"]),
			"re-encryption must retain both password conflict branches",
		);
		d1.close();
		d2.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("a removed device cannot use its retained user identity to re-enroll", async () => {
	const dir = await tmp();
	try {
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, PASS);
		const s1 = await unlock(d1, PASS);
		const d2 = new Store(join(dir, "d2.db"));
		await deviceConfirm(d2, PASS, deviceAdd(s1, await authNewDevice(d2, PASS)));
		const s2 = await unlock(d2, PASS);
		removeDevice(s1, s2.deviceId);

		const replacement = await authNewDevice(new Store(join(dir, "d3.db")), PASS);
		const staleChain = s2.store.authLog(); // the removed device has not learned its removal
		const reEnrollment = makeEntry(
			heads(staleChain),
			{
				type: "add-device",
				userId: s2.userId,
				deviceId: replacement.deviceId,
				deviceSignPub: replacement.signPub,
				deviceEncPub: replacement.encPub,
			},
			s2.userId,
			"user",
			s2.priv.userSign,
		);
		const membership = replay([...s1.store.authLog(), reEnrollment], s1.vaultId);
		assert.equal(
			membership.members.get(s1.userId)!.devices.has(replacement.deviceId),
			false,
			"a removed device's copied user key is not an enrollment authority",
		);
		const delegatedId = `${replacement.deviceId}-delegated`;
		const delegatedReplacement = makeEntry(
			heads(staleChain),
			{
				type: "add-device",
				userId: s2.userId,
				deviceId: delegatedId,
				deviceSignPub: replacement.signPub,
				deviceEncPub: replacement.encPub,
			},
			s2.deviceId,
			"device",
			s2.priv.deviceSign,
		);
		assert.equal(
			replay([...s1.store.authLog(), delegatedReplacement], s1.vaultId)
				.members.get(s1.userId)!
				.devices.has(delegatedId),
			false,
			"removal also revokes a stale device's concurrent enrollment delegation",
		);

		d1.close();
		d2.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("rotation rejects member and removed-device signers even with valid historical keys", async () => {
	const dir = await tmp();
	try {
		const ownerStore = new Store(join(dir, "owner.db"));
		await init(ownerStore, PASS);
		const owner = await unlock(ownerStore, PASS);

		const memberStore = new Store(join(dir, "member.db"));
		const invite = await inviteInit(memberStore, "member-pass");
		const joinToken = shareVault(owner, invite, { role: "member" });
		await joinConfirm(memberStore, "member-pass", { ...joinToken, role: "owner" });
		const member = await unlock(memberStore, "member-pass");
		assert.equal(member.role, "member", "join role is derived from signed membership, not Token B");
		const memberDeviceStore = new Store(join(dir, "member-device.db"));
		const memberToken = deviceAdd(member, await authNewDevice(memberDeviceStore, "member-pass"));
		await deviceConfirm(memberDeviceStore, "member-pass", { ...memberToken, role: "owner" });
		assert.equal(
			(await unlock(memberDeviceStore, "member-pass")).role,
			"member",
			"device-confirm also ignores an unauthenticated requested role",
		);
		memberDeviceStore.close();
		for (const entry of memberStore.authLog()) ownerStore.appendAuthEntry(entry);
		rebuildSession(owner);
		const epochBeforeMemberForgery = owner.currentEpoch;
		const { record: memberForgery } = forgeRotation(
			99,
			member.deviceId,
			member.priv.deviceSign,
			owner.pub.deviceEnc,
		);
		ownerStore.putRotation(
			memberForgery.epoch,
			memberForgery.deviceId,
			JSON.stringify(memberForgery),
		);
		rebuildSession(owner);
		assert.equal(owner.currentEpoch, epochBeforeMemberForgery, "members cannot advance an epoch");

		const removedStore = new Store(join(dir, "removed.db"));
		await deviceConfirm(
			removedStore,
			PASS,
			deviceAdd(owner, await authNewDevice(removedStore, PASS)),
		);
		const removed = await unlock(removedStore, PASS);
		removeDevice(owner, removed.deviceId);
		const epochAfterRemoval = owner.currentEpoch;
		const { record: removedForgery } = forgeRotation(
			99,
			removed.deviceId,
			removed.priv.deviceSign,
			owner.pub.deviceEnc,
		);
		ownerStore.putRotation(
			removedForgery.epoch,
			removedForgery.deviceId,
			JSON.stringify(removedForgery),
		);
		rebuildSession(owner);
		assert.equal(owner.currentEpoch, epochAfterRemoval, "removed keys remain decrypt-only");

		ownerStore.close();
		memberStore.close();
		removedStore.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("recovery grants require an authorized signed publisher", async () => {
	const dir = await tmp();
	try {
		const ownerStore = new Store(join(dir, "owner.db"));
		await init(ownerStore, PASS);
		const owner = await unlock(ownerStore, PASS);
		const memberStore = new Store(join(dir, "member.db"));
		const invite = await inviteInit(memberStore, "member-pass");
		await joinConfirm(memberStore, "member-pass", shareVault(owner, invite, { role: "member" }));
		const member = await unlock(memberStore, "member-pass");
		for (const entry of memberStore.authLog()) ownerStore.appendAuthEntry(entry);

		const unsigned = {
			principal: "orgPublicKey",
			keyVersion: 0,
			wrapped: cr.generateX25519().publicKey.toString("base64"),
			signerId: member.deviceId,
		};
		const forged: GrantRow = {
			...unsigned,
			sig: cr.sign(grantBytes(owner.vaultId, unsigned), member.priv.deviceSign).toString("base64"),
		};
		const membership = replay(ownerStore.authLog(), owner.vaultId);
		assert.equal(grantAuthentic(owner.vaultId, forged, membership), false);
		ownerStore.putGrant(owner.vaultId, forged);
		contributeRecovery(owner);
		assert.equal(ownerStore.getGrant(owner.vaultId, `recovery:${owner.userId}`, 0), undefined);

		const orgPriv = recoveryEnable(owner);
		assert.ok(orgPriv.length > 0);
		const published = ownerStore.getGrant(owner.vaultId, "orgPublicKey", 0)!;
		assert.equal(grantAuthentic(owner.vaultId, published, membership), true);

		ownerStore.close();
		memberStore.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("catch-up derives removal hashes instead of trusting cached transport fields", async () => {
	const dir = await tmp();
	try {
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, PASS);
		const s1 = await unlock(d1, PASS);
		const d2 = new Store(join(dir, "d2.db"));
		await deviceConfirm(d2, PASS, deviceAdd(s1, await authNewDevice(d2, PASS)));
		const s2 = await unlock(d2, PASS);
		const chain = d1.authLog();
		const removal = makeEntry(
			heads(chain),
			{ type: "remove-device", userId: s1.userId, deviceId: s2.deviceId },
			s1.deviceId,
			"device",
			s1.priv.deviceSign,
		);
		const initialRotation = JSON.parse(d1.rotations()[0]!) as RotationRecord;
		// Simulate an old/hostile import that stored a valid entry under its real
		// DB key while retaining an attacker-controlled cached `hash` in JSON.
		d1.db
			.prepare(`INSERT INTO authlog (hash, entry) VALUES (?, ?)`)
			.run(entryHash(removal), JSON.stringify({ ...removal, hash: initialRotation.observed[0]! }));
		assert.equal(
			d1.authLog().find((e) => e.body.type === "remove-device")!.hash,
			entryHash(removal),
			"auth-log reads normalize cached hashes",
		);

		const { maybeCatchUp } = await import("../cli/engine.ts");
		assert.ok(maybeCatchUp(s1), "the genuine removal hash requires a catch-up rotation");
		d1.close();
		d2.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("a member removing its own device defers the rotation instead of half-committing", async () => {
	const dir = await tmp();
	try {
		const ownerStore = new Store(join(dir, "owner.db"));
		await init(ownerStore, PASS);
		const owner = await unlock(ownerStore, PASS);

		const memberStore = new Store(join(dir, "member.db"));
		const invite = await inviteInit(memberStore, "member-pass");
		await joinConfirm(memberStore, "member-pass", shareVault(owner, invite, { role: "member" }));
		const member = await unlock(memberStore, "member-pass");
		assert.equal(member.role, "member");

		// The member enrolls a second device (a phone) from its first.
		const phoneStore = new Store(join(dir, "phone.db"));
		await deviceConfirm(
			phoneStore,
			"member-pass",
			deviceAdd(member, await authNewDevice(phoneStore, "member-pass")),
		);
		rebuildSession(member);
		const phone = await unlock(phoneStore, "member-pass");
		const epochBefore = member.currentEpoch;

		// The phone is lost. A member may not rotate, so removing it must record the
		// revocation and return the unchanged epoch — not throw after appending the
		// entry, which would leave the removal half-committed with no rotation.
		const epochAfter = removeDevice(member, phone.deviceId);
		assert.equal(epochAfter, epochBefore, "a member removal defers the rotation to an admin");
		assert.equal(
			replay(memberStore.authLog(), member.vaultId)
				.members.get(member.userId)!
				.devices.has(phone.deviceId),
			false,
			"the revocation is still recorded in the signed log",
		);

		// An admin that syncs the removal issues the catch-up rotation.
		for (const entry of memberStore.authLog()) ownerStore.appendAuthEntry(entry);
		rebuildSession(owner);
		assert.ok(maybeCatchUp(owner), "an active admin performs the deferred catch-up rotation");

		ownerStore.close();
		memberStore.close();
		phoneStore.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("removing a device preserves the devices it earlier (causally) enrolled", async () => {
	const dir = await tmp();
	try {
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, PASS);
		const s1 = await unlock(d1, PASS);

		// The owner enrolls a second device from the first (causally before any
		// removal), then confirms it and removes the original bootstrap device.
		const d2 = new Store(join(dir, "d2.db"));
		await deviceConfirm(d2, PASS, deviceAdd(s1, await authNewDevice(d2, PASS)));
		const s2 = await unlock(d2, PASS);
		removeDevice(s2, s1.deviceId);

		const owner = replay(s2.store.authLog(), s2.vaultId).members.get(s2.userId)!;
		assert.equal(
			owner.devices.has(s2.deviceId),
			true,
			"a device enrolled before the removal is legitimate prior delegation and survives",
		);
		assert.equal(owner.devices.has(s1.deviceId), false, "the removed bootstrap device is gone");

		d1.close();
		d2.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("removing a device keeps the items it authored before removal", async () => {
	const dir = await tmp();
	try {
		const d1 = new Store(join(dir, "d1.db"));
		await init(d1, PASS);
		const s1 = await unlock(d1, PASS);

		const d2 = new Store(join(dir, "d2.db"));
		await deviceConfirm(d2, PASS, deviceAdd(s1, await authNewDevice(d2, PASS)));
		const s2 = await unlock(d2, PASS);
		addItem(s2, "bank", { username: "me", password: "hunter2" });
		for (const op of d2.allOps()) d1.putOp(op);
		rebuildSession(s1);
		assert.ok(getItem(s1, "bank"), "the owner sees the item the second device authored");

		// The second device is lost and removed. Its data must not vanish with it.
		removeDevice(s1, s2.deviceId);
		rebuildSession(s1);
		const item = getItem(s1, "bank");
		assert.ok(item, "the removed device's item survives the revocation rotation");
		assert.equal(item!.fields.username, "me", "its fields are re-encrypted intact");
		assert.deepEqual(
			new Set(item!.passwords),
			new Set(["hunter2"]),
			"its password survives re-encryption",
		);

		d1.close();
		d2.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("recovery escrow survives removal of the grant's publishing device", async () => {
	const dir = await tmp();
	try {
		const ownerStore = new Store(join(dir, "owner.db"));
		await init(ownerStore, PASS);
		const owner = await unlock(ownerStore, PASS);
		const orgPriv = recoveryEnable(owner);

		const memberStore = new Store(join(dir, "member.db"));
		const invite = await inviteInit(memberStore, "member-pass");
		await joinConfirm(memberStore, "member-pass", shareVault(owner, invite, { role: "member" }));
		const member = await unlock(memberStore, "member-pass");

		// The member learns the org key and contributes its sealed recovery grant,
		// signed by its own device; the owner receives both the grant and the log.
		memberStore.putGrant(owner.vaultId, ownerStore.getGrant(owner.vaultId, "orgPublicKey", 0)!);
		contributeRecovery(member);
		ownerStore.putGrant(
			owner.vaultId,
			memberStore.getGrant(owner.vaultId, `recovery:${member.userId}`, 0)!,
		);
		for (const entry of memberStore.authLog()) ownerStore.appendAuthEntry(entry);
		rebuildSession(owner);

		// The member loses all access; the owner removes them. Recovery must still
		// work — the grant was signed by the now-removed device.
		removeUser(owner, member.userId);
		const recovered = recoverUser(owner, member.userId, orgPriv);
		assert.ok(recovered.length > 0, "the removed member's identity is recoverable from escrow");

		ownerStore.close();
		memberStore.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
