// Exercises the serverless relay's logic without Wrangler/Miniflare: the shared
// handler over a fake DO-SQL storage. With nodejs_compat, the Worker reuses the
// SAME crypto/auth code as the Node relay (core/protocol verifyEnvelope,
// relay/access authorizeHeaders), so this drives those exact paths and proves
// the serverless placement produces identical protocol results to the Node path.

import assert from "node:assert/strict";
import { test } from "node:test";
import * as cr from "../core/crypto.ts";
import { makeEnvelope } from "../core/protocol.ts";
import { verifyEnvelope } from "../core/protocol.ts";
import { authorizeHeaders } from "../relay/access.ts";
import { handle, type RelayStorage } from "../relay/handler.ts";

// A tiny in-memory RelayStorage standing in for the Durable Object SQLite.
const memStore = (): RelayStorage => {
	const ops = new Map<string, Map<string, import("../core/protocol.ts").OpEnvelope>>();
	const auth = new Map<string, Map<string, import("../core/authlog.ts").LogEntry>>();
	const rots = new Map<string, Map<string, import("../core/rotation.ts").RotationRecord>>();
	const grants = new Map<string, import("../core/protocol.ts").GrantRow[]>();
	const m = <V>(map: Map<string, Map<string, V>>, t: string) => {
		let x = map.get(t);
		if (!x) map.set(t, (x = new Map()));
		return x;
	};
	return {
		putOp(t, op) {
			const o = m(ops, t);
			if (o.has(op.hash)) return false;
			o.set(op.hash, op);
			return true;
		},
		allOps(t) {
			return [...m(ops, t).values()].sort((a, b) =>
				a.deviceId + a.seq < b.deviceId + b.seq ? -1 : 1,
			);
		},
		vector(t) {
			const v: Record<string, number> = {};
			for (const op of m(ops, t).values()) v[op.deviceId] = Math.max(v[op.deviceId] ?? 0, op.seq);
			return v;
		},
		putAuth(t, e) {
			m(auth, t).set(e.hash, e);
		},
		authExcept(t, have) {
			return [...m(auth, t).values()].filter((e) => !have.has(e.hash));
		},
		putRotation(t, r) {
			m(rots, t).set(`${r.epoch}:${r.deviceId}`, r);
		},
		rotationsExcept(t, have) {
			return [...m(rots, t).entries()]
				.filter(([k]) => !have.has(k))
				.map(([, r]) => JSON.stringify(r));
		},
		putGrant(t, g) {
			const arr = grants.get(t) ?? [];
			if (!arr.some((x) => x.principal === g.principal && x.keyVersion === g.keyVersion))
				arr.push(g);
			grants.set(t, arr);
		},
		allGrants(t) {
			return grants.get(t) ?? [];
		},
	};
};

const req = (
	method: string,
	path: string,
	body: unknown,
	headers: Record<string, string> = {},
) => ({
	method,
	path,
	header: (n: string) => headers[n.toLowerCase()],
	body: async () => body,
});

test("worker handler: push then sync round-trips ops", async () => {
	const store = memStore();
	const k = cr.generateEd25519();
	const ops = [
		makeEnvelope("devA", 1, Buffer.from("op1"), k.privateKey),
		makeEnvelope("devA", 2, Buffer.from("op2"), k.privateKey),
	];

	const pushed = await handle(req("POST", "/push", { teamId: "t1", ops }), store, {
		authorize: async () => true,
		verifyOp: (op) => verifyEnvelope(op),
	});
	assert.deepEqual(pushed, { status: 200, body: { accepted: 2 } });

	const synced = await handle(
		req("POST", "/sync", { teamId: "t1", vector: {}, authHashes: [], rotationIds: [] }),
		store,
		{
			authorize: async () => true,
		},
	);
	assert.equal(synced.status, 200);
	const b = synced.body as { ops: unknown[]; vector: Record<string, number> };
	assert.equal(b.ops.length, 2);
	assert.deepEqual(b.vector, { devA: 2 });
});

test("worker handler: a tampered op is rejected by the op-hash check", async () => {
	const store = memStore();
	const k = cr.generateEd25519();
	const good = makeEnvelope("devA", 1, Buffer.from("op1"), k.privateKey);
	const tampered = { ...good, payload: Buffer.from("evil").toString("base64") };

	const r = await handle(req("POST", "/push", { teamId: "t1", ops: [tampered] }), store, {
		authorize: async () => true,
		verifyOp: (op) => verifyEnvelope(op),
	});
	assert.deepEqual(r.body, { accepted: 0 }, "hash mismatch -> not accepted");
});

test("worker handler: health + auth gate (shared authorizeHeaders)", async () => {
	const store = memStore();
	assert.deepEqual(
		await handle(req("GET", "/health", {}), store, { authorize: async () => true }),
		{
			status: 200,
			body: { ok: true },
		},
	);
	const cfg = { serviceTokens: new Set(["good"]) };
	const denied = await handle(req("POST", "/sync", { teamId: "t1" }), store, {
		authorize: (h) => authorizeHeaders(h, cfg),
	});
	assert.equal(denied.status, 403);
	const ok = await handle(
		req(
			"POST",
			"/sync",
			{ teamId: "t1", vector: {}, authHashes: [], rotationIds: [] },
			{ "cf-access-token": "good" },
		),
		store,
		{ authorize: (h) => authorizeHeaders(h, cfg) },
	);
	assert.equal(ok.status, 200);
});
