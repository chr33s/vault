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
	chain = add(
		chain,
		{
			type: "add-device",
			userId: "owner",
			deviceId: "dev1",
			deviceSignPub: dev.sign.publicKey.toString("base64"),
			deviceEncPub: dev.enc.publicKey.toString("base64"),
		},
		"owner",
		"user",
		owner.sign.privateKey,
	);
	chain = add(chain, userBody("bob", bob), "owner", "user", owner.sign.privateKey);

	const m = replay(chain);
	assert.equal(m.vaultId, "v1");
	assert.equal(m.members.size, 2);
	assert.equal(m.members.get("owner")!.role, "owner");
	assert.equal(m.members.get("bob")!.role, "member");
	assert.ok(deviceSignKey(m, "dev1")!.equals(dev.sign.publicKey));
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
	chain = add(
		chain,
		{
			type: "add-device",
			userId: "bob",
			deviceId: "bdev",
			deviceSignPub: bobDev.sign.publicKey.toString("base64"),
			deviceEncPub: bobDev.enc.publicKey.toString("base64"),
		},
		"bob",
		"user",
		bob.sign.privateKey,
	);
	chain = add(
		chain,
		{ type: "remove-user", userId: "bob" },
		"owner",
		"user",
		owner.sign.privateKey,
	);
	const m = replay(chain);
	assert.equal(m.members.get("bob")!.active, false);
	assert.equal(deviceSignKey(m, "bdev"), undefined);
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
	chain = add(
		chain,
		{
			type: "add-device",
			userId: "owner",
			deviceId: "dev1",
			deviceSignPub: dev.sign.publicKey.toString("base64"),
			deviceEncPub: dev.enc.publicKey.toString("base64"),
		},
		"owner",
		"user",
		owner.sign.privateKey,
	);
	// Tamper the genesis body without re-signing. Its hash changes, so the
	// add-device's parent reference dangles and its signature no longer matches.
	const tampered = structuredClone(chain);
	(tampered[0]!.body as { vaultId: string }).vaultId = "evil";
	assert.notEqual(entryHash(tampered[0]!), chain[0]!.hash);
	const m = replay(tampered);
	assert.equal(m.members.size, 0, "tampering destroys the derived membership");
	assert.equal(deviceSignKey(m, "dev1"), undefined);
});
