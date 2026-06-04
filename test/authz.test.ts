// Authorization boundaries enforced by the engine (spec §9, §10.2). The happy
// paths (an owner/admin removing users, sharing, enabling recovery) are covered
// in sharing.test.ts; these assert the NEGATIVE paths — that a plain member is
// refused — so a dropped role check is caught as a regression rather than a
// silent privilege escalation. (The auth-log replay independently rejects a
// forged signature; this is the local pre-flight guard a client relies on.)

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	init,
	unlock,
	inviteInit,
	shareVault,
	joinConfirm,
	removeUser,
	removeDevice,
	recoveryEnable,
	type Session,
} from "../cli/engine.ts";
import { Store } from "../core/store.ts";

const PASS_O = "owner-pass";
const PASS_M = "member-pass";

type Fixture = {
	owner: Session;
	member: Session;
	stores: Store[];
	dir: string;
};

// An owner vault with one extra person joined as a plain "member".
const setup = async (): Promise<Fixture> => {
	const dir = await mkdtemp(join(tmpdir(), "vault-authz-"));
	const ownerStore = new Store(join(dir, "owner.db"));
	await init(ownerStore, PASS_O);
	const owner = await unlock(ownerStore, PASS_O);

	const memberStore = new Store(join(dir, "member.db"));
	const invite = await inviteInit(memberStore, PASS_M);
	const joinToken = shareVault(owner, invite, { role: "member" });
	await joinConfirm(memberStore, PASS_M, joinToken);
	const member = await unlock(memberStore, PASS_M);
	assert.equal(member.role, "member");

	return { owner, member, stores: [ownerStore, memberStore], dir };
};

const teardown = async (f: Fixture): Promise<void> => {
	for (const s of f.stores) s.close();
	await rm(f.dir, { recursive: true, force: true });
};

test("a member cannot remove a user", async () => {
	const f = await setup();
	try {
		assert.throws(() => removeUser(f.member, f.owner.userId), /only admins may remove users/);
	} finally {
		await teardown(f);
	}
});

test("a member cannot remove another user's device", async () => {
	const f = await setup();
	try {
		assert.throws(
			() => removeDevice(f.member, f.owner.deviceId),
			/only the owning user or an admin may remove a device/,
		);
	} finally {
		await teardown(f);
	}
});

test("a member cannot share the vault", async () => {
	const f = await setup();
	try {
		// A throwaway invite from a third would-be joiner; the role check fires first.
		const thirdStore = new Store(join(f.dir, "third.db"));
		const invite = await inviteInit(thirdStore, "third-pass");
		thirdStore.close();
		assert.throws(() => shareVault(f.member, invite), /only admins may share a vault/);
	} finally {
		await teardown(f);
	}
});

test("a member cannot enable recovery escrow (owner-only)", async () => {
	const f = await setup();
	try {
		assert.throws(() => recoveryEnable(f.member), /only the owner may enable recovery escrow/);
	} finally {
		await teardown(f);
	}
});

test("control: the owner CAN remove the member", async () => {
	const f = await setup();
	try {
		const epoch = removeUser(f.owner, f.member.userId);
		assert.ok(epoch >= 2, "removing a user issues a fresh rotation epoch");
	} finally {
		await teardown(f);
	}
});
