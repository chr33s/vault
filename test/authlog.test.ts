import assert from "node:assert/strict";
import { test } from "node:test";
import {
	replay,
	makeEntry,
	heads,
	entryHash,
	deviceSignKey,
	type LogEntry,
	type EntryBody,
	deviceIdOf,
} from "../core/authlog.ts";
import * as crypto from "../core/crypto.ts";

type Identity = { sign: crypto.KeyPairRaw; enc: crypto.KeyPairRaw };
const id = (): Identity => ({ sign: crypto.generateEd25519(), enc: crypto.generateX25519() });

// Append a signed entry that references the current heads of `chain`.
const add = (
	chain: LogEntry[],
	body: EntryBody,
	signerId: string,
	signerKind: "user" | "device",
	signerPriv: Buffer,
): LogEntry[] => [...chain, makeEntry(heads(chain), body, signerId, signerKind, signerPriv)];

// add-device + the device's own prove-device (device ids derive from the key).
const enroll = (
	chain: LogEntry[],
	userId: string,
	dev: Identity,
	signerId: string,
	signerKind: "user" | "device",
	signerPriv: Buffer,
): { chain: LogEntry[]; deviceId: string } => {
	const deviceId = deviceIdOf(dev.sign.publicKey.toString("base64"));
	chain = add(
		chain,
		{
			type: "add-device",
			userId,
			deviceId,
			deviceSignPub: dev.sign.publicKey.toString("base64"),
			deviceEncPub: dev.enc.publicKey.toString("base64"),
		},
		signerId,
		signerKind,
		signerPriv,
	);
	chain = add(
		chain,
		{ type: "prove-device", userId, deviceId },
		deviceId,
		"device",
		dev.sign.privateKey,
	);
	return { chain, deviceId };
};

const genesis = (owner: Identity, userId = "owner", vaultId = "v1"): EntryBody => ({
	type: "genesis",
	vaultId,
	userId,
	userSignPub: owner.sign.publicKey.toString("base64"),
	userEncPub: owner.enc.publicKey.toString("base64"),
	role: "owner",
});

const userBody = (uid: string, who: Identity, role: "admin" | "member" = "member"): EntryBody => ({
	type: "add-user",
	userId: uid,
	userSignPub: who.sign.publicKey.toString("base64"),
	userEncPub: who.enc.publicKey.toString("base64"),
	role,
});

test("genesis + add-device + add-user replays into membership", () => {
	const owner = id();
	const dev = id();
	const bob = id();
	let chain: LogEntry[] = [];
	chain = add(chain, genesis(owner), "owner", "user", owner.sign.privateKey);
	const e1 = enroll(chain, "owner", dev, "owner", "user", owner.sign.privateKey);
	chain = e1.chain;
	const dev1 = e1.deviceId;
	chain = add(chain, userBody("bob", bob), dev1, "device", dev.sign.privateKey);

	const m = replay(chain);
	assert.equal(m.vaultId, "v1");
	assert.equal(m.members.size, 2);
	assert.equal(m.members.get("owner")!.role, "owner");
	assert.equal(m.members.get("bob")!.role, "member");
	assert.ok(deviceSignKey(m, dev1)!.equals(dev.sign.publicKey));
});

test("forged signature is skipped, not fatal", () => {
	const owner = id();
	const attacker = crypto.generateEd25519();
	let chain: LogEntry[] = [];
	chain = add(chain, genesis(owner), "owner", "user", owner.sign.privateKey);
	// add-user signed by a non-owner key but claiming the owner as signer.
	const mallory = id();
	const bad = makeEntry(
		heads(chain),
		userBody("evil", mallory, "admin"),
		"owner",
		"user",
		attacker.privateKey,
	);
	chain = [...chain, bad];
	const m = replay(chain);
	assert.equal(m.members.size, 1, "forged entry must not take effect");
	assert.equal(m.members.has("evil"), false);
});

test("unauthorized signer (non-admin) is skipped", () => {
	const owner = id();
	const mallory = id();
	let chain: LogEntry[] = [];
	chain = add(chain, genesis(owner), "owner", "user", owner.sign.privateKey);
	// mallory isn't even a member; signing add-user must have no effect.
	chain = [
		...chain,
		makeEntry(heads(chain), userBody("evil", mallory), "mallory", "user", mallory.sign.privateKey),
	];
	assert.equal(replay(chain).members.has("evil"), false);
});

test("remove-user deactivates the member and clears devices", () => {
	const owner = id();
	const bob = id();
	const bobDev = id();
	let chain: LogEntry[] = [];
	chain = add(chain, genesis(owner), "owner", "user", owner.sign.privateKey);
	chain = add(chain, userBody("bob", bob), "owner", "user", owner.sign.privateKey);
	const e = enroll(chain, "bob", bobDev, "bob", "user", bob.sign.privateKey);
	chain = e.chain;
	const bdev = e.deviceId;
	assert.ok(deviceSignKey(replay(chain), bdev), "active before removal");
	chain = add(
		chain,
		{ type: "remove-user", userId: "bob" },
		"owner",
		"user",
		owner.sign.privateKey,
	);
	const m = replay(chain);
	assert.equal(m.members.get("bob")!.active, false);
	assert.equal(deviceSignKey(m, bdev), undefined);
	assert.equal(m.members.get("bob")!.devices.size, 0);
});

test("FORK: concurrent entries on the same parent reconcile deterministically", () => {
	const owner = id();
	const x = id();
	const y = id();
	let base: LogEntry[] = [];
	base = add(base, genesis(owner), "owner", "user", owner.sign.privateKey);

	// Two admins-of-one: owner makes two concurrent add-user entries that both
	// reference the same head (a fork).
	const parent = heads(base);
	const e1 = makeEntry(parent, userBody("x", x), "owner", "user", owner.sign.privateKey);
	const e2 = makeEntry(parent, userBody("y", y), "owner", "user", owner.sign.privateKey);
	assert.deepEqual(e1.parents, e2.parents, "both fork from the same parent");

	// Two replicas receive the fork in opposite orders; both must converge.
	const replicaA = replay([...base, e1, e2]);
	const replicaB = replay([...base, e2, e1]);
	const keys = (m: ReturnType<typeof replay>) => [...m.members.keys()].sort();
	assert.deepEqual(keys(replicaA), keys(replicaB));
	assert.deepEqual(keys(replicaA), ["owner", "x", "y"], "both concurrent adds take effect");
});

test("FORK: concurrent removals of different members both take effect", () => {
	const owner = id();
	const x = id();
	const y = id();
	let base: LogEntry[] = [];
	base = add(base, genesis(owner), "owner", "user", owner.sign.privateKey);
	base = add(base, userBody("x", x), "owner", "user", owner.sign.privateKey);
	base = add(base, userBody("y", y), "owner", "user", owner.sign.privateKey);

	const parent = heads(base);
	const rmX = makeEntry(
		parent,
		{ type: "remove-user", userId: "x" },
		"owner",
		"user",
		owner.sign.privateKey,
	);
	const rmY = makeEntry(
		parent,
		{ type: "remove-user", userId: "y" },
		"owner",
		"user",
		owner.sign.privateKey,
	);

	const m = replay([...base, rmX, rmY]);
	assert.equal(m.members.get("x")!.active, false);
	assert.equal(m.members.get("y")!.active, false);
	// Order-independent.
	const m2 = replay([...base, rmY, rmX]);
	assert.equal(m2.members.get("x")!.active, false);
	assert.equal(m2.members.get("y")!.active, false);
});

test("tamper-evidence: mutating an ancestor orphans its descendants", () => {
	const owner = id();
	const dev = id();
	let chain: LogEntry[] = [];
	chain = add(chain, genesis(owner), "owner", "user", owner.sign.privateKey);
	const e = enroll(chain, "owner", dev, "owner", "user", owner.sign.privateKey);
	chain = e.chain;
	assert.ok(deviceSignKey(replay(chain), e.deviceId), "active before tampering");
	// Tamper the genesis body without re-signing. Its hash changes, so the
	// add-device's parent reference dangles and its signature no longer matches.
	const tampered = structuredClone(chain);
	(tampered[0]!.body as { vaultId: string }).vaultId = "evil";
	assert.notEqual(entryHash(tampered[0]!), chain[0]!.hash);
	const m = replay(tampered);
	assert.equal(m.members.size, 0, "tampering destroys the derived membership");
	assert.equal(deviceSignKey(m, e.deviceId), undefined);
});

test("an admin cannot overwrite an existing member (owner-lockout guard)", () => {
	const owner = id();
	const admin = id();
	const attacker = id();
	let chain: LogEntry[] = [];
	chain = add(chain, genesis(owner, "owner"), "owner", "user", owner.sign.privateKey);
	chain = add(chain, userBody("admin", admin, "admin"), "owner", "user", owner.sign.privateKey);
	// The admin signs an add-user reusing the owner's userId with attacker keys —
	// an attempt to replace the owner's identity/role on every replica.
	chain = add(chain, userBody("owner", attacker, "admin"), "admin", "user", admin.sign.privateKey);

	const m = replay(chain);
	const ownerMember = m.members.get("owner")!;
	assert.equal(ownerMember.role, "owner", "owner role is preserved");
	assert.equal(
		ownerMember.signPub,
		owner.sign.publicKey.toString("base64"),
		"owner keys are not overwritten",
	);
});

test("an admin cannot mint another owner via add-user", () => {
	const owner = id();
	const admin = id();
	const mallory = id();
	let chain: LogEntry[] = [];
	chain = add(chain, genesis(owner), "owner", "user", owner.sign.privateKey);
	chain = add(chain, userBody("admin", admin, "admin"), "owner", "user", owner.sign.privateKey);
	chain = add(
		chain,
		{ ...userBody("mallory", mallory), role: "owner" } as EntryBody,
		"admin",
		"user",
		admin.sign.privateKey,
	);
	assert.equal(replay(chain).members.has("mallory"), false, "owner-role add-user is rejected");
});

test("an admin cannot remove the owner", () => {
	const owner = id();
	const admin = id();
	let chain: LogEntry[] = [];
	chain = add(chain, genesis(owner), "owner", "user", owner.sign.privateKey);
	chain = add(chain, userBody("admin", admin, "admin"), "owner", "user", owner.sign.privateKey);
	chain = add(
		chain,
		{ type: "remove-user", userId: "owner" },
		"admin",
		"user",
		admin.sign.privateKey,
	);
	assert.equal(replay(chain).members.get("owner")!.active, true, "owner stays active");
});

test("replay pins the genesis to the expected vaultId (forged-root rejected)", () => {
	const owner = id();
	const attacker = id();
	// The real vault.
	const real = add([], genesis(owner, "owner", "v-real"), "owner", "user", owner.sign.privateKey);
	// A forged, self-signed rival genesis for a different vault, gossiped in.
	const forged = makeEntry(
		[],
		genesis(attacker, "attacker", "v-evil"),
		"attacker",
		"user",
		attacker.sign.privateKey,
	);
	const mixed = [...real, forged];
	// Pinned to the real vaultId, the forged root can never be selected regardless
	// of hash order.
	const m = replay(mixed, "v-real");
	assert.equal(m.vaultId, "v-real");
	assert.equal(m.members.has("attacker"), false);
});

test("add-device alone does not activate a device: the key holder must prove it", () => {
	const owner = id();
	const ownerDev = id();
	const member = id();
	const memberDev = id();
	const laptop = id(); // the owner's second device, whose public key is visible
	let chain: LogEntry[] = [];
	chain = add(chain, genesis(owner), "owner", "user", owner.sign.privateKey);
	const o = enroll(chain, "owner", ownerDev, "owner", "user", owner.sign.privateKey);
	chain = add(o.chain, userBody("m", member), o.deviceId, "device", ownerDev.sign.privateKey);
	const mm = enroll(chain, "m", memberDev, "m", "user", member.sign.privateKey);
	chain = mm.chain;
	const laptopId = deviceIdOf(laptop.sign.publicKey.toString("base64"));
	const addBody = (userId: string): EntryBody => ({
		type: "add-device",
		userId,
		deviceId: laptopId,
		deviceSignPub: laptop.sign.publicKey.toString("base64"),
		deviceEncPub: member.enc.publicKey.toString("base64"),
	});
	// The member claims the laptop's key for themselves, and even signs a
	// "proof" with their own device key; neither activates it.
	chain = add(chain, addBody("m"), mm.deviceId, "device", memberDev.sign.privateKey);
	chain = add(
		chain,
		{ type: "prove-device", userId: "m", deviceId: laptopId },
		laptopId,
		"device",
		memberDev.sign.privateKey,
	);
	let m = replay(chain);
	assert.equal(deviceSignKey(m, laptopId), undefined);
	assert.equal(m.deviceOwners.get(laptopId), undefined);
	// The owner's genuine enrollment, proven by the laptop, wins regardless of order.
	const genuine = enroll(chain, "owner", laptop, o.deviceId, "device", ownerDev.sign.privateKey);
	m = replay(genuine.chain);
	assert.ok(deviceSignKey(m, laptopId)!.equals(laptop.sign.publicKey));
	assert.equal(m.deviceOwners.get(laptopId), "owner");
	assert.equal(m.members.get("m")!.devices.has(laptopId), false);
});
