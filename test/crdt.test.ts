import assert from "node:assert/strict";
import { test } from "node:test";
import { VaultState, buildItemOps, buildDeleteOp, type FieldOp } from "../core/crdt.ts";
import { Clock, encodeHLC } from "../core/hlc.ts";

const mkClock = (device: string, start = 1000) => {
	let t = start;
	return new Clock(device, () => t++);
};

test("CRDT converges regardless of apply order (property-style)", () => {
	// Build a pool of ops from two devices editing overlapping fields.
	const ca = mkClock("devA", 1000);
	const cb = mkClock("devB", 1005);
	const ops: FieldOp[] = [
		...buildItemOps("i1", { title: "a", url: "x" }, () => encodeHLC(ca.tick())),
		...buildItemOps("i1", { title: "b", notes: "n" }, () => encodeHLC(cb.tick())),
		...buildItemOps("i2", { title: "two" }, () => encodeHLC(ca.tick())),
	];

	const apply = (order: FieldOp[]) => {
		const s = new VaultState();
		s.applyAll(order);
		return JSON.stringify(s.list());
	};

	const base = apply(ops);
	// Try several shuffles — all must converge.
	for (let i = 0; i < 20; i++) {
		const shuffled = [...ops].sort(() => Math.random() - 0.5);
		assert.equal(apply(shuffled), base, "diverged on reorder");
	}
});

test("CRDT apply is idempotent", () => {
	const c = mkClock("dev", 2000);
	const ops = buildItemOps("i1", { title: "hello" }, () => encodeHLC(c.tick()));
	const once = new VaultState();
	once.applyAll(ops);
	const twice = new VaultState();
	twice.applyAll([...ops, ...ops, ...ops]);
	assert.deepEqual(once.list(), twice.list());
});

test("LWW: higher HLC wins for ordinary fields", () => {
	const s = new VaultState();
	s.apply({
		itemId: "i",
		field: "title",
		value: "old",
		hlc: encodeHLC({ millis: 1, counter: 0, deviceId: "a" }),
	});
	s.apply({
		itemId: "i",
		field: "title",
		value: "new",
		hlc: encodeHLC({ millis: 2, counter: 0, deviceId: "a" }),
	});
	assert.equal(s.materialize("i")!.fields.title, "new");
	// Lower HLC arriving later must not win.
	s.apply({
		itemId: "i",
		field: "title",
		value: "stale",
		hlc: encodeHLC({ millis: 1, counter: 5, deviceId: "a" }),
	});
	assert.equal(s.materialize("i")!.fields.title, "new");
});

test("password is a multi-value register: concurrent edits surface", () => {
	const s = new VaultState();
	// Two concurrent password writes (neither observed the other).
	s.apply({
		itemId: "i",
		field: "password",
		value: "fromA",
		hlc: encodeHLC({ millis: 10, counter: 0, deviceId: "A" }),
	});
	s.apply({
		itemId: "i",
		field: "password",
		value: "fromB",
		hlc: encodeHLC({ millis: 10, counter: 0, deviceId: "B" }),
	});
	const v = s.materialize("i")!;
	assert.deepEqual([...v.passwords].sort(), ["fromA", "fromB"]);

	// A resolving write that observes both collapses to a single value.
	const live = s.livePasswordHlcs("i");
	s.apply({
		itemId: "i",
		field: "password",
		value: "resolved",
		hlc: encodeHLC({ millis: 20, counter: 0, deviceId: "A" }),
		replaces: live,
	});
	assert.deepEqual(s.materialize("i")!.passwords, ["resolved"]);
});

test("delete tombstone hides item from list", () => {
	const c = mkClock("dev", 3000);
	const s = new VaultState();
	s.applyAll(buildItemOps("i1", { title: "secret" }, () => encodeHLC(c.tick())));
	assert.equal(s.list().length, 1);
	s.apply(buildDeleteOp("i1", encodeHLC(c.tick())));
	assert.equal(s.list().length, 0);
	assert.equal(s.materialize("i1")!.deleted, true);
});
