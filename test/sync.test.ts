import assert from "node:assert/strict";
import { test } from "node:test";
import * as crypto from "../core/crypto.ts";
import { encodeHLC } from "../core/hlc.ts";
import {
	acceptContiguous,
	makeEnvelope,
	verifyEnvelope,
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
import { Store } from "../core/store.ts";

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

// Two replicas exchange ops past each other's vector, as syncWithRelay does.
const exchange = (a: Store, b: Store): void => {
	a.putOps(acceptContiguous(b.opsSince(a.versionVector()), (id) => a.maxSeqFor(id)));
	b.putOps(acceptContiguous(a.opsSince(b.versionVector()), (id) => b.maxSeqFor(id)));
};

test("anti-entropy: two stores reconcile to identical op sets in one round", () => {
	const ka = crypto.generateEd25519();
	const kb = crypto.generateEd25519();
	const a = new Store(":memory:");
	const b = new Store(":memory:");
	// Device A has ops 1..3, Device B has ops 1..2 of its own; each saw the other's op 1.
	const aOps = [1, 2, 3].map((n) => mkOp("A", n, ka.privateKey));
	const bOps = [1, 2].map((n) => mkOp("B", n, kb.privateKey));
	a.putOps([...aOps, bOps[0]!]);
	b.putOps([...bOps, aOps[0]!]);
	exchange(a, b);
	assert.deepEqual(a.versionVector(), b.versionVector());
	assert.equal(a.allOps().length, 5);
	assert.equal(b.allOps().length, 5);
});

test("partition then heal converges", () => {
	const ka = crypto.generateEd25519();
	const kb = crypto.generateEd25519();
	const a = new Store(":memory:");
	const b = new Store(":memory:");
	a.putOps([mkOp("A", 1, ka.privateKey), mkOp("A", 2, ka.privateKey)]);
	b.putOps([mkOp("B", 1, kb.privateKey)]);
	exchange(a, b);
	assert.deepEqual(a.versionVector(), b.versionVector());
	assert.equal(a.allOps().length, 3);
});

test("ingest stays gap-free: an op past a gap waits for the missing one", () => {
	const k = crypto.generateEd25519();
	const ops = [1, 2, 3, 4].map((n) => mkOp("A", n, k.privateKey));
	const s = new Store(":memory:");
	// A transport withholds seq 2: 3 and 4 are not stored, so the vector keeps
	// asking for everything after 1.
	s.putOps(acceptContiguous([ops[0]!, ops[2]!, ops[3]!], (id) => s.maxSeqFor(id)));
	assert.deepEqual(s.versionVector(), { A: 1 });
	s.putOps(acceptContiguous(ops, (id) => s.maxSeqFor(id)));
	assert.deepEqual(s.versionVector(), { A: 4 });
	// A writer that skips seq 1 gets nothing stored at all.
	assert.deepEqual(
		acceptContiguous([mkOp("B", 2, k.privateKey)], () => 0),
		[],
	);
});

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
