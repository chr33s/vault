import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { init, unlock, addItem, getItem, rebuildSession } from "../cli/engine.ts";
import * as cr from "../core/crypto.ts";
import { encodeHLC } from "../core/hlc.ts";
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
