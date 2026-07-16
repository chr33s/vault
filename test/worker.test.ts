// Exercises the serverless relay's logic without Wrangler/Miniflare: the shared
// handler over a fake DO-SQL storage. With nodejs_compat, the Worker reuses the
// SAME crypto/auth code as the Node relay (core/protocol verifyEnvelope,
// relay/access authorizeHeaders), so this drives those exact paths and proves
// the serverless placement produces identical protocol results to the Node path.

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import {
	makeEntry,
	heads,
	entryHash,
	validRootGenesis,
	replay,
	deviceSignKey,
	type EntryBody,
	type LogEntry,
} from "../core/authlog.ts";
import * as cr from "../core/crypto.ts";
import { grantAuthentic, grantBytes, makeEnvelope } from "../core/protocol.ts";
import { verifyEnvelope } from "../core/protocol.ts";
import { authorizeHeaders } from "../relay/access.ts";
import { handle, type RelayStorage } from "../relay/handler.ts";
import { createRelay } from "../relay/main.ts";
import worker from "../relay/worker/worker.ts";

// A tiny in-memory RelayStorage standing in for the Durable Object SQLite.
const memStore = (): RelayStorage => {
	const ops = new Map<string, Map<string, import("../core/protocol.ts").OpEnvelope>>();
	const auth = new Map<string, Map<string, import("../core/authlog.ts").LogEntry>>();
	const rots = new Map<string, Map<string, import("../core/rotation.ts").RotationRecord>>();
	const grants = new Map<string, import("../core/protocol.ts").GrantRow[]>();
	const roots = new Map<string, string>();
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
			m(auth, t).set(entryHash(e), e);
		},
		pinGenesis(t, entry) {
			if (!validRootGenesis(entry, t)) return false;
			const hash = entryHash(entry);
			const pinned = roots.get(t);
			if (pinned) return pinned === hash;
			roots.set(t, hash);
			return true;
		},
		authExcept(t, have) {
			const seen = new Set(have);
			return [...m(auth, t).values()].filter((entry) => {
				const hash = entryHash(entry);
				if (seen.has(hash)) return false;
				seen.add(hash);
				return true;
			});
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

test("relay authenticates op authorship: a forged (deviceId,seq) claim is rejected", async () => {
	// Build a minimal auth log: owner user 'u1' with device 'devA'.
	const owner = { sign: cr.generateEd25519(), enc: cr.generateX25519() };
	const devA = { sign: cr.generateEd25519(), enc: cr.generateX25519() };
	const gen: EntryBody = {
		type: "genesis",
		vaultId: "t1",
		userId: "u1",
		userSignPub: owner.sign.publicKey.toString("base64"),
		userEncPub: owner.enc.publicKey.toString("base64"),
		role: "owner",
	};
	let chain: LogEntry[] = [makeEntry([], gen, "u1", "user", owner.sign.privateKey)];
	chain = [
		...chain,
		makeEntry(
			heads(chain),
			{
				type: "add-device",
				userId: "u1",
				deviceId: "devA",
				deviceSignPub: devA.sign.publicKey.toString("base64"),
				deviceEncPub: devA.enc.publicKey.toString("base64"),
			},
			"u1",
			"user",
			owner.sign.privateKey,
		),
	];

	const store = memStore();
	// The transport's real authorship check: teamId===vaultId pins the genesis.
	const verifyOp = (op: import("../core/protocol.ts").OpEnvelope, teamId: string) => {
		const m = replay(store.authExcept(teamId, new Set()) as LogEntry[], teamId);
		const key = deviceSignKey(m, op.deviceId);
		return !!key && verifyEnvelope(op, key);
	};

	// An attacker (not devA) forges an op claiming devA's slot (devA, seq 1).
	const attacker = { sign: cr.generateEd25519(), enc: cr.generateX25519() };
	const forged = makeEnvelope("devA", 1, Buffer.from("garbage"), attacker.sign.privateKey);
	const genuine = makeEnvelope("devA", 1, Buffer.from("real"), devA.sign.privateKey);

	// An invalid first root must not claim an otherwise-empty team. Its body hash
	// differs from the real root, while its stale signature no longer authenticates it.
	const invalidRoot: LogEntry = {
		...chain[0]!,
		body: { ...gen, userId: "forged-owner" },
	};
	assert.equal(validRootGenesis(invalidRoot, "t1"), false);
	await handle(req("POST", "/push", { teamId: "t1", ops: [], authLog: [invalidRoot] }), store, {
		authorize: async () => true,
		verifyOp,
	});
	assert.deepEqual(
		store.authExcept("t1", new Set()),
		[],
		"an invalid genesis is not pinned or stored",
	);

	// Push carries the auth log so membership is known; the forged op is rejected.
	const r1 = await handle(
		req("POST", "/push", { teamId: "t1", ops: [forged], authLog: chain }),
		store,
		{ authorize: async () => true, verifyOp },
	);
	assert.deepEqual(r1.body, { accepted: 0 }, "forged authorship is rejected");

	// A later self-signed genesis for the same team can sort below the real root.
	// It must not enter storage or authorize the attacker's key for devA.
	let rivalRoot: LogEntry | undefined;
	let rivalUserId = "";
	for (let nonce = 0; !rivalRoot; nonce++) {
		rivalUserId = `attacker-${nonce}`;
		const candidate = makeEntry(
			[],
			{
				type: "genesis",
				vaultId: "t1",
				userId: rivalUserId,
				userSignPub: attacker.sign.publicKey.toString("base64"),
				userEncPub: attacker.enc.publicKey.toString("base64"),
				role: "owner",
			},
			rivalUserId,
			"user",
			attacker.sign.privateKey,
		);
		if (entryHash(candidate) < entryHash(chain[0]!)) rivalRoot = candidate;
	}
	const rivalChain = [
		rivalRoot,
		makeEntry(
			[rivalRoot.hash],
			{
				type: "add-device",
				userId: rivalUserId,
				deviceId: "devA",
				deviceSignPub: attacker.sign.publicKey.toString("base64"),
				deviceEncPub: attacker.enc.publicKey.toString("base64"),
			},
			rivalUserId,
			"user",
			attacker.sign.privateKey,
		),
	];
	const rival = await handle(
		req("POST", "/push", { teamId: "t1", ops: [forged], authLog: rivalChain }),
		store,
		{ authorize: async () => true, verifyOp },
	);
	assert.deepEqual(rival.body, { accepted: 0 }, "a rival root cannot authorize forged ops");
	const storedGenesis = (store.authExcept("t1", new Set()) as LogEntry[]).filter(
		(e) => e.body.type === "genesis",
	);
	assert.deepEqual(storedGenesis.map(entryHash), [entryHash(chain[0]!)]);

	// The genuine device's real op for the same seq is accepted (slot not stolen).
	const r2 = await handle(req("POST", "/push", { teamId: "t1", ops: [genuine] }), store, {
		authorize: async () => true,
		verifyOp,
	});
	assert.deepEqual(r2.body, { accepted: 1 }, "the real device's op is not censored");
});

test("relay accepts only signed, role-authorized recovery-grant publishers", async () => {
	const owner = { sign: cr.generateEd25519(), enc: cr.generateX25519() };
	const ownerDevice = { sign: cr.generateEd25519(), enc: cr.generateX25519() };
	const member = { sign: cr.generateEd25519(), enc: cr.generateX25519() };
	const memberDevice = { sign: cr.generateEd25519(), enc: cr.generateX25519() };
	const genesis: EntryBody = {
		type: "genesis",
		vaultId: "grant-team",
		userId: "owner",
		userSignPub: owner.sign.publicKey.toString("base64"),
		userEncPub: owner.enc.publicKey.toString("base64"),
		role: "owner",
	};
	let chain: LogEntry[] = [makeEntry([], genesis, "owner", "user", owner.sign.privateKey)];
	chain = [
		...chain,
		makeEntry(
			heads(chain),
			{
				type: "add-device",
				userId: "owner",
				deviceId: "owner-device",
				deviceSignPub: ownerDevice.sign.publicKey.toString("base64"),
				deviceEncPub: ownerDevice.enc.publicKey.toString("base64"),
			},
			"owner",
			"user",
			owner.sign.privateKey,
		),
	];
	chain = [
		...chain,
		makeEntry(
			heads(chain),
			{
				type: "add-user",
				userId: "member",
				userSignPub: member.sign.publicKey.toString("base64"),
				userEncPub: member.enc.publicKey.toString("base64"),
				role: "member",
			},
			"owner-device",
			"device",
			ownerDevice.sign.privateKey,
		),
	];
	chain = [
		...chain,
		makeEntry(
			heads(chain),
			{
				type: "add-device",
				userId: "member",
				deviceId: "member-device",
				deviceSignPub: memberDevice.sign.publicKey.toString("base64"),
				deviceEncPub: memberDevice.enc.publicKey.toString("base64"),
			},
			"member",
			"user",
			member.sign.privateKey,
		),
	];
	const makeGrant = (principal: string, signerId: string, priv: Buffer) => {
		const unsigned = { principal, keyVersion: 0, wrapped: "public-material", signerId };
		return {
			...unsigned,
			sig: cr.sign(grantBytes("grant-team", unsigned), priv).toString("base64"),
		};
	};
	const memberOrgKey = makeGrant("orgPublicKey", "member-device", memberDevice.sign.privateKey);
	const ownerOrgKey = makeGrant("orgPublicKey", "owner-device", ownerDevice.sign.privateKey);
	const store = memStore();
	const verifyGrant = (g: import("../core/protocol.ts").GrantRow, teamId: string) =>
		grantAuthentic(teamId, g, replay(store.authExcept(teamId, new Set()) as LogEntry[], teamId));

	await handle(
		req("POST", "/push", {
			teamId: "grant-team",
			ops: [],
			authLog: chain,
			grants: [memberOrgKey, ownerOrgKey],
		}),
		store,
		{ authorize: async () => true, verifyGrant },
	);
	const grants = await store.allGrants("grant-team");
	assert.equal(grants.length, 1);
	assert.equal(grants[0]!.signerId, "owner-device", "a member cannot preseed the org key");
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

test("worker edge stops reading a chunked body once the byte limit is exceeded", async () => {
	const chunk = new Uint8Array(1024 * 1024);
	let pulls = 0;
	let cancelled = false;
	const body = new ReadableStream<Uint8Array>(
		{
			pull(controller) {
				pulls++;
				if (pulls > 17) throw new Error("reader consumed past the oversized chunk");
				controller.enqueue(chunk);
			},
			cancel() {
				cancelled = true;
			},
		},
		{ highWaterMark: 0 },
	);
	const request = new Request("https://relay.test/push", {
		method: "POST",
		body,
		duplex: "half",
	} as RequestInit & { duplex: "half" });
	let routed = false;
	const env = {
		RELAY_DO: {
			idFromName() {
				routed = true;
				return "unused";
			},
			get() {
				return { fetch: async () => new Response(null, { status: 204 }) };
			},
		},
	};

	const response = await worker.fetch(request, env);
	assert.equal(response.status, 413);
	assert.equal(cancelled, true, "the unread remainder is cancelled");
	assert.equal(pulls, 17, "only enough chunks to detect overflow are read");
	assert.equal(routed, false, "oversized requests never create or reach a Durable Object");
});

test("Node relay migrates and deduplicates a legacy root by its recomputed hash", async () => {
	const dir = await mkdtemp(join(tmpdir(), "vault-relay-root-"));
	const dbPath = join(dir, "relay.db");
	const owner = { sign: cr.generateEd25519(), enc: cr.generateX25519() };
	const root = makeEntry(
		[],
		{
			type: "genesis",
			vaultId: "legacy-team",
			userId: "owner",
			userSignPub: owner.sign.publicKey.toString("base64"),
			userEncPub: owner.enc.publicKey.toString("base64"),
			role: "owner",
		},
		"owner",
		"user",
		owner.sign.privateKey,
	);
	const legacyEntry = { ...root, hash: "client-supplied-spoof" };
	const invalidDuplicate = { ...legacyEntry, sig: "invalid-signature" };
	const db = new DatabaseSync(dbPath);
	db.exec(`CREATE TABLE relay_authlog (
      team_id TEXT NOT NULL, hash TEXT NOT NULL, entry TEXT NOT NULL,
      PRIMARY KEY (team_id, hash));`);
	const insert = db.prepare(`INSERT INTO relay_authlog (team_id, hash, entry) VALUES (?, ?, ?)`);
	insert.run("legacy-team", "legacy-row-key-1", JSON.stringify(invalidDuplicate));
	insert.run("legacy-team", "legacy-row-key-2", JSON.stringify(legacyEntry));
	insert.run("legacy-team", "legacy-row-key-3", JSON.stringify(legacyEntry));
	db.close();

	const { store } = createRelay({ dbPath });
	const sync = (authHashes: string[]) => store.authExcept("legacy-team", new Set(authHashes));

	try {
		const initial = sync([]);
		assert.equal(initial.length, 1, "duplicate legacy rows collapse by canonical hash");
		assert.equal(entryHash(initial[0]!), entryHash(root));
		assert.equal(
			validRootGenesis(initial[0]!, "legacy-team"),
			true,
			"an invalid duplicate cannot shadow the root",
		);
		assert.equal(sync([entryHash(root)]).length, 0, "have uses the canonical hash");

		assert.equal(store.pinGenesis("legacy-team", root), true, "the genuine root matches the pin");
		store.putAuth("legacy-team", root);
		assert.equal(sync([]).length, 1, "a canonical reinsert remains deduplicated");
	} finally {
		store.close();
		await rm(dir, { recursive: true, force: true });
	}
});
