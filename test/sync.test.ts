import assert from "node:assert/strict";
import { test } from "node:test";
import * as crypto from "../core/crypto.ts";
import { encodeHLC } from "../core/hlc.ts";
import {
	makeEnvelope,
	verifyEnvelope,
	opsSince,
	vectorFromOps,
	type OpEnvelope,
} from "../core/protocol.ts";
import {
	winner,
	winnerAtEpoch,
	needsCatchUp,
	keyCommit,
	wellFormedRotation,
	type RotationRecord,
} from "../core/rotation.ts";

const mkOp = (device: string, seq: number, signPriv: Buffer, body = "x"): OpEnvelope =>
	makeEnvelope(device, seq, Buffer.from(`${body}:${seq}`), signPriv);

test("envelope hash + signature verify; tamper detected", () => {
	const k = crypto.generateEd25519();
	const op = mkOp("devA", 1, k.privateKey);
	assert.ok(verifyEnvelope(op, k.publicKey));
	assert.ok(verifyEnvelope(op)); // hash-only (relay path)
	const tampered = { ...op, payload: Buffer.from("evil").toString("base64") };
	assert.ok(!verifyEnvelope(tampered));
});

test("envelope: a valid hash signed by the wrong key fails signature verification", () => {
	// The hash-only check passes (the bytes are internally consistent), but the
	// signature must be rejected when checked against a different device's key —
	// guards the relay-then-replica boundary where the op-author key is enforced.
	const author = crypto.generateEd25519();
	const impostor = crypto.generateEd25519();
	const op = mkOp("devA", 1, author.privateKey);
	assert.ok(verifyEnvelope(op)); // hash-only path accepts it
	assert.ok(verifyEnvelope(op, author.publicKey)); // correct key accepts it
	assert.ok(!verifyEnvelope(op, impostor.publicKey)); // wrong key rejects it
});

test("anti-entropy: two stores reconcile to identical op sets in one round", () => {
	const ka = crypto.generateEd25519();
	const kb = crypto.generateEd25519();
	// Device A has ops 1..3, Device B has ops 1..2 of its own + A's op 1.
	const aOps = [
		mkOp("A", 1, ka.privateKey),
		mkOp("A", 2, ka.privateKey),
		mkOp("A", 3, ka.privateKey),
	];
	const bOps = [mkOp("B", 1, kb.privateKey), mkOp("B", 2, kb.privateKey)];

	let storeA = [...aOps, bOps[0]!]; // A already saw B:1
	let storeB = [...bOps, aOps[0]!]; // B already saw A:1

	// A pulls from B: B sends ops past A's vector.
	const vecA = vectorFromOps(storeA);
	const fromB = opsSince(storeB, vecA);
	storeA = dedupe([...storeA, ...fromB]);

	// B pulls from A.
	const vecB = vectorFromOps(storeB);
	const fromA = opsSince(storeA, vecB);
	storeB = dedupe([...storeB, ...fromA]);

	assert.deepEqual(vectorFromOps(storeA), vectorFromOps(storeB));
	assert.equal(storeA.length, 5);
	assert.equal(storeB.length, 5);
});

test("partition then heal converges", () => {
	const ka = crypto.generateEd25519();
	const kb = crypto.generateEd25519();
	// During partition each side accumulates independently.
	let a = [mkOp("A", 1, ka.privateKey), mkOp("A", 2, ka.privateKey)];
	let b = [mkOp("B", 1, kb.privateKey)];
	// Heal: exchange in both directions.
	const fromB = opsSince(b, vectorFromOps(a));
	const fromA = opsSince(a, vectorFromOps(b));
	a = dedupe([...a, ...fromB]);
	b = dedupe([...b, ...fromA]);
	assert.deepEqual(vectorFromOps(a), vectorFromOps(b));
	assert.equal(a.length, 3);
});

const dedupe = (ops: OpEnvelope[]): OpEnvelope[] => {
	const seen = new Map<string, OpEnvelope>();
	for (const op of ops) seen.set(op.hash, op);
	return [...seen.values()];
};

test("rotation winner: higher epoch supersedes; (hlc,deviceId) breaks ties", () => {
	const rec = (epoch: number, millis: number, deviceId: string): RotationRecord => ({
		epoch,
		baseEpoch: epoch - 1,
		hlc: encodeHLC({ millis, counter: 0, deviceId }),
		deviceId,
		keyCommit: keyCommit(Buffer.from(`${epoch}-${deviceId}`)),
		grants: {},
		observed: [],
		signerId: deviceId,
		sig: "",
	});
	const r1 = rec(1, 100, "A");
	const r2 = rec(1, 100, "B"); // same epoch+hlc millis, higher deviceId wins
	const r3 = rec(2, 50, "A"); // higher epoch wins regardless of hlc
	assert.equal(winnerAtEpoch([r1, r2], 1)!.deviceId, "B");
	assert.equal(winner([r1, r2, r3])!.epoch, 2);
});

test("security catch-up needed when winner didn't observe a removal", () => {
	const win: RotationRecord = {
		epoch: 1,
		baseEpoch: 0,
		hlc: encodeHLC({ millis: 1, counter: 0, deviceId: "A" }),
		deviceId: "A",
		keyCommit: "x",
		grants: {},
		observed: ["h-add"],
		signerId: "A",
		sig: "",
	};
	// A removal whose hash the winner never observed -> catch-up required.
	assert.ok(needsCatchUp(win, ["h-removal"]));
	// Removal hash was observed by the winner -> no catch-up.
	assert.ok(!needsCatchUp({ ...win, observed: ["h-add", "h-removal"] }, ["h-removal"]));
	// No removals -> no catch-up.
	assert.ok(!needsCatchUp(win, []));
});

test("wellFormedRotation accepts a valid epoch chain and rejects nonsense", () => {
	const rec = (epoch: number, baseEpoch: number): RotationRecord => ({
		epoch,
		baseEpoch,
		hlc: encodeHLC({ millis: 1, counter: 0, deviceId: "A" }),
		deviceId: "A",
		keyCommit: "x",
		grants: {},
		observed: [],
		signerId: "A",
		sig: "",
	});
	assert.ok(wellFormedRotation(rec(1, 0))); // genesis epoch
	assert.ok(wellFormedRotation(rec(7, 6))); // baseEpoch === epoch - 1
	assert.ok(!wellFormedRotation(rec(0, -1))); // epoch must be >= 1
	assert.ok(!wellFormedRotation(rec(5, 1))); // baseEpoch must be epoch - 1
	assert.ok(!wellFormedRotation(rec(3, 3))); // base cannot equal epoch
	assert.ok(!wellFormedRotation(rec(2.5, 1.5))); // must be integers
});
