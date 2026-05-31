import assert from "node:assert/strict";
import { test } from "node:test";
import { Clock, encodeHLC, decodeHLC, compareHLC } from "../core/hlc.ts";

test("HLC tick is strictly monotonic within a device", () => {
	let t = 1000;
	const c = new Clock("devA", () => t);
	const a = c.tick();
	const b = c.tick(); // same physical time -> counter advances
	t = 1001;
	const d = c.tick();
	assert.ok(compareHLC(a, b) < 0);
	assert.ok(compareHLC(b, d) < 0);
});

test("HLC observe advances past a future-dated remote stamp (causality)", () => {
	// Local physical clock is BEHIND the remote one.
	let localPhys = 1000;
	const c = new Clock("devLocal", () => localPhys);

	// A remote edit carries a far-future timestamp.
	const remote = decodeHLC(encodeHLC({ millis: 9_000_000, counter: 3, deviceId: "devRemote" }));

	// After observing it, the next local tick must out-rank the remote stamp —
	// otherwise a fresh local edit would silently lose the LWW race.
	c.observe(remote);
	const next = c.tick();
	assert.ok(compareHLC(next, remote) > 0, "local edit after observe must beat the observed remote");
});

test("encodeHLC is fixed-width so lexicographic order == logical order", () => {
	const lo = encodeHLC({ millis: 999, counter: 5, deviceId: "z" });
	const hi = encodeHLC({ millis: 1000, counter: 0, deviceId: "a" });
	assert.ok(lo < hi, "string compare matches logical compare across the millis boundary");
});

test("HLC counter overflow carries into millis, preserving fixed-width order", () => {
	// Frozen physical clock so every tick lands in the same millisecond, forcing
	// the counter to climb past its 6-digit width (>999999).
	const c = new Clock("devA", () => 5000);
	let prev = c.tick();
	let prevEnc = encodeHLC(prev);
	const baseWidth = prevEnc.length;
	for (let i = 0; i < 1_000_010; i++) {
		const next = c.tick();
		const enc = encodeHLC(next);
		// Encoding width must stay constant (no widening that would break ordering).
		assert.equal(enc.length, baseWidth, "encoded HLC width must be stable across overflow");
		// Strictly increasing in both logical and lexicographic order.
		assert.ok(compareHLC(next, prev) > 0, "logical order strictly increases");
		assert.ok(enc > prevEnc, "lexicographic order matches logical order across the carry");
		prev = next;
		prevEnc = enc;
	}
	// The carry advanced millis beyond the frozen physical time.
	assert.ok(prev.millis > 5000, "counter overflow advanced the millis component");
});
