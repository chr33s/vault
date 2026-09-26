// Regression tests for the codebase review findings: malformed-op lockout,
// deviceId reuse, forged ops/rotations over sync, SAS recomputation, child env
// scrubbing, contiguous version vectors, `run` field precedence, JWKS caching.

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	init,
	unlock,
	addItem,
	getItem,
	rebuildSession,
	removeDevice,
	maybeCatchUp,
	authNewDevice,
	deviceAdd,
	deviceConfirm,
	enrollmentSas,
	inviteInit,
	shareVault,
	joinConfirm,
	importAuthAndRotations,
	type Session,
} from "../cli/engine.ts";
import { PeerStore } from "../cli/peerstore.ts";
import { syncWithRelay } from "../cli/relayclient.ts";
import { childBaseEnv, resolveOne } from "../cli/run.ts";
import {
	deviceIdOf,
	heads,
	makeEntry,
	replay,
	type EntryBody,
	type LogEntry,
} from "../core/authlog.ts";
import * as cr from "../core/crypto.ts";
import { encodeHLC } from "../core/hlc.ts";
import { makeEnvelope, type SyncResponse } from "../core/protocol.ts";
import { keyCommit, rotationBytes, type RotationRecord } from "../core/rotation.ts";
import { Store } from "../core/store.ts";
import { verifyAccessJwt, type JwkSet } from "../relay/access.ts";
import { handle, type RelayStorage } from "../relay/handler.ts";
import { createRelay } from "../relay/main.ts";

// Minimal in-memory relay storage for driving handle() directly.
const memRelay = (): RelayStorage => ({
	putOp: () => true,
	allOps: () => [],
	opsSince: () => [],
	maxSeq: () => 0,
	authLacking: () => [],
	rotationsLacking: () => [],
	vector: () => ({}),
	putAuth: () => undefined,
	pinGenesis: () => false,
	authExcept: () => [],
	putRotation: () => undefined,
	rotationsExcept: () => [],
	putGrant: () => undefined,
	allGrants: () => [],
});

const PASS = "review-pass";

const withClockAhead = async (ms: number, fn: () => Promise<unknown>): Promise<void> => {
	const real = Date.now;
	Date.now = () => real() + ms;
	try {
		await fn();
	} finally {
		Date.now = real;
	}
};
const tmp = (): Promise<string> => mkdtemp(join(tmpdir(), "vault-review-"));

const twoDevices = async (dir: string): Promise<{ s1: Session; s2: Session; stores: Store[] }> => {
	const st1 = new Store(join(dir, "d1.db"));
	await init(st1, PASS);
	const s1 = await unlock(st1, PASS);
	const st2 = new Store(join(dir, "d2.db"));
	await deviceConfirm(st2, PASS, deviceAdd(s1, await authNewDevice(st2, PASS)));
	const s2 = await unlock(st2, PASS);
	// s2's proof of possession reaches s1 as it would on the first sync.
	for (const e of st2.authLog()) st1.appendAuthEntry(e);
	rebuildSession(s1);
	return { s1, s2, stores: [st1, st2] };
};

test("a validly-signed malformed op does not make unlock throw", async () => {
	const dir = await tmp();
	try {
		const { s1, s2, stores } = await twoDevices(dir);
		addItem(s1, "github", { username: "alice" });
		// Names a real keyCommit but carries a corrupt tag.
		const payload = Buffer.from(
			JSON.stringify({ keyCommit: s2.currentKeyCommit, iv: "AAAA", ct: "AAAA", tag: "AAAA" }),
			"utf8",
		);
		s1.store.putOp(makeEnvelope(s2.deviceId, 1, payload, s2.priv.deviceSign));
		// And one whose payload isn't JSON at all.
		s1.store.putOp(makeEnvelope(s2.deviceId, 2, Buffer.from("{"), s2.priv.deviceSign));
		const again = await unlock(s1.store, PASS);
		assert.equal(getItem(again, "github")!.fields.username, "alice");
		for (const st of stores) st.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("add-device cannot rebind an existing deviceId to another key", async () => {
	const dir = await tmp();
	try {
		const ownerStore = new Store(join(dir, "o.db"));
		await init(ownerStore, PASS);
		const owner = await unlock(ownerStore, PASS);
		const memberStore = new Store(join(dir, "m.db"));
		const invite = await inviteInit(memberStore, "m");
		await joinConfirm(memberStore, "m", shareVault(owner, invite));
		const member = await unlock(memberStore, "m");

		const log = memberStore.authLog();
		const evil = makeEntry(
			heads(log),
			{
				type: "add-device",
				userId: member.userId,
				deviceId: owner.deviceId,
				deviceSignPub: member.pub.deviceSign.toString("base64"),
				deviceEncPub: member.pub.deviceEnc.toString("base64"),
			},
			member.deviceId,
			"device",
			member.priv.deviceSign,
		);
		// Same id, the owner's real key, but claimed for the member's user: add-device
		// proves no possession, so this must not flip the device's owner.
		const claim = makeEntry(
			heads(log),
			{
				type: "add-device",
				userId: member.userId,
				deviceId: owner.deviceId,
				deviceSignPub: owner.pub.deviceSign.toString("base64"),
				deviceEncPub: member.pub.deviceEnc.toString("base64"),
			},
			member.deviceId,
			"device",
			member.priv.deviceSign,
		);
		const m = replay([...log, evil, claim], owner.vaultId);
		assert.deepEqual(m.deviceKeys.get(owner.deviceId), owner.pub.deviceSign);
		assert.equal(m.deviceOwners.get(owner.deviceId), owner.userId);
		assert.equal(m.members.get(member.userId)!.devices.has(owner.deviceId), false);
		ownerStore.close();
		memberStore.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

const stubRelay = (
	respond: () => SyncResponse,
): Promise<{ url: string; server: Server; pushes: unknown[]; syncs: unknown[] }> =>
	new Promise((resolve) => {
		const pushes: unknown[] = [];
		const syncs: unknown[] = [];
		const server = createServer((req, res) => {
			const chunks: Buffer[] = [];
			req.on("data", (c: Buffer) => chunks.push(c));
			req.on("end", () => {
				const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
				(req.url === "/push" ? pushes : syncs).push(parsed);
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify(req.url === "/sync" ? respond() : { accepted: 0 }));
			});
		});
		server.listen(0, () =>
			resolve({
				url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
				server,
				pushes,
				syncs,
			}),
		);
	});

test("sync drops forged ops so they cannot occupy the genuine (device, seq) slot", async () => {
	const dir = await tmp();
	try {
		const { s1, s2, stores } = await twoDevices(dir);
		addItem(s2, "real", { username: "genuine" });
		const genuine = s2.store.allOps().filter((o) => o.deviceId === s2.deviceId);
		const forged = makeEnvelope(
			s2.deviceId,
			genuine[0]!.seq,
			Buffer.from("junk"),
			cr.generateEd25519().privateKey,
		);
		let serve = [forged];
		const { url, server } = await stubRelay(() => ({
			ops: serve,
			vector: {},
			authLog: [],
			rotations: [],
			grants: [],
			lacksAuth: [],
			lacksRotations: [],
		}));
		try {
			await syncWithRelay(s1, url);
			assert.equal(s1.store.allOps().filter((o) => o.deviceId === s2.deviceId).length, 0);
			serve = genuine;
			await syncWithRelay(s1, url);
			assert.equal(getItem(s1, "real")!.fields.username, "genuine");
		} finally {
			server.close();
		}
		for (const st of stores) st.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("sync pushes only what the relay reports missing", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		const { url, server, pushes } = await stubRelay(() => ({
			ops: [],
			vector: {},
			authLog: [],
			rotations: [],
			grants: [],
			lacksAuth: [],
			lacksRotations: [],
		}));
		try {
			await syncWithRelay(s, url);
			const push = pushes[0] as { authLog: unknown[]; rotations: unknown[] };
			assert.equal(push.authLog.length, 0);
			assert.equal(push.rotations.length, 0);
		} finally {
			server.close();
		}
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("a removed device's ops are kept so the vector covers them", async () => {
	const dir = await tmp();
	try {
		const { s1, s2, stores } = await twoDevices(dir);
		addItem(s2, "old", { username: "x" });
		const ops = s2.store.allOps().filter((o) => o.deviceId === s2.deviceId);
		removeDevice(s1, s2.deviceId);
		const { url, server, pushes } = await stubRelay(() => ({
			ops,
			vector: {},
			authLog: [],
			rotations: [],
			grants: [],
			lacksAuth: [],
			lacksRotations: [],
		}));
		try {
			await syncWithRelay(s1, url);
			assert.equal(s1.store.versionVector()[s2.deviceId], ops.length);
			// ...but never pushed: the relay only accepts active devices' ops.
			const pushed = (pushes[0] as { ops: Array<{ deviceId: string }> }).ops;
			assert.equal(pushed.filter((o) => o.deviceId === s2.deviceId).length, 0);
		} finally {
			server.close();
		}
		for (const st of stores) st.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("a malformed auth entry can't lock the vault or fail a relay push", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		const bad = {
			parents: "abc",
			body: { type: "remove-user", userId: s.userId },
			signerId: s.deviceId,
			signerKind: "device",
			sig: "",
			hash: "",
		} as unknown as LogEntry;
		importAuthAndRotations(s, [bad], []);
		store.appendAuthEntry(bad);
		// A legacy row written before the shape check existed.
		store.db
			.prepare(`INSERT INTO authlog (hash, entry) VALUES (?, ?)`)
			.run("legacy", JSON.stringify(bad));
		await unlock(store, PASS); // must not throw

		const relay = memRelay();
		const r = await handle(
			{
				method: "POST",
				path: "/push",
				header: () => undefined,
				body: async () => ({ teamId: s.vaultId, ops: [], authLog: [{ parents: [] }, bad] }),
			},
			relay,
			{ authorize: async () => true },
		);
		assert.equal(r.status, 200);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("an unapplied remove entry does not force a catch-up rotation", async () => {
	const dir = await tmp();
	try {
		const { s1, s2, stores } = await twoDevices(dir);
		const log = s1.store.authLog();
		// Signed by a random key: replay skips it, so it must not count as a removal.
		const junk = makeEntry(
			heads(log),
			{ type: "remove-device", userId: s1.userId, deviceId: s2.deviceId },
			s2.deviceId,
			"device",
			cr.generateEd25519().privateKey,
		);
		importAuthAndRotations(s1, [junk], []);
		assert.equal(maybeCatchUp(s1), undefined);
		for (const st of stores) st.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("a relay drops ops past a gap, so skipping seq 1 can't force resends", async () => {
	const k = cr.generateEd25519().privateKey;
	const stored: number[] = [];
	const relay: RelayStorage = {
		...memRelay(),
		putOp: (_t, op) => (stored.push(op.seq), true),
	};
	const push = (seqs: number[]) =>
		handle(
			{
				method: "POST",
				path: "/push",
				header: () => undefined,
				body: async () => ({
					teamId: "t",
					ops: seqs.map((n) => makeEnvelope("dev", n, Buffer.from([n]), k)),
				}),
			},
			relay,
			{ authorize: async () => true },
		);
	const r = await push([2, 3, 4]);
	assert.deepEqual(r.body, { accepted: 0 });
	await push([3, 1, 2]); // out of order within one push is fine
	assert.deepEqual(stored, [1, 2, 3]);
});

test("a client does not store ops past a gap, so the missing op is asked for again", async () => {
	const dir = await tmp();
	try {
		const { s1, s2, stores } = await twoDevices(dir);
		addItem(s2, "a", { username: "x", note: "y" });
		const ops = s2.store.allOps().filter((o) => o.deviceId === s2.deviceId);
		const { url, server, syncs } = await stubRelay(() => ({
			ops: ops.filter((o) => o.seq !== 1),
			vector: {},
			authLog: [],
			rotations: [],
			grants: [],
			lacksAuth: [],
			lacksRotations: [],
		}));
		try {
			await syncWithRelay(s1, url);
			await syncWithRelay(s1, url);
			assert.equal(s1.store.maxSeqFor(s2.deviceId), 0);
			const vector = (syncs[1] as { vector: Record<string, number> }).vector;
			assert.equal(vector[s2.deviceId], undefined);
		} finally {
			server.close();
		}
		for (const st of stores) st.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("imported rotations must verify; malformed ones are skipped, not fatal", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		const key = cr.randomBytes(32);
		const unsigned: Omit<RotationRecord, "sig"> = {
			epoch: 2,
			baseEpoch: 1,
			hlc: encodeHLC({ millis: Date.now(), counter: 0, deviceId: s.deviceId }),
			deviceId: s.deviceId,
			keyCommit: keyCommit(key),
			grants: {},
			observed: [],
			signerId: s.deviceId,
		};
		const forged = JSON.stringify({
			...unsigned,
			sig: cr.sign(rotationBytes(unsigned), cr.generateEd25519().privateKey).toString("base64"),
		});
		const r = importAuthAndRotations(s, [], ["{", forged]);
		assert.equal(r.rotationsImported, 0);
		assert.equal(store.rotations().length, 1);
		// The genuine record for the same slot is still accepted afterwards.
		const real = JSON.stringify({
			...unsigned,
			sig: cr.sign(rotationBytes(unsigned), s.priv.deviceSign).toString("base64"),
		});
		assert.equal(importAuthAndRotations(s, [], [real]).rotationsImported, 1);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("device-confirm and join compute the same SAS the enroller shows", async () => {
	const dir = await tmp();
	try {
		const st1 = new Store(join(dir, "d1.db"));
		await init(st1, PASS);
		const s1 = await unlock(st1, PASS);
		const st2 = new Store(join(dir, "d2.db"));
		const tokenB = deviceAdd(s1, await authNewDevice(st2, PASS));
		const { sas } = await deviceConfirm(st2, PASS, tokenB);
		assert.equal(sas, enrollmentSas(s1, st2.getMeta("deviceSignPub")!));

		const st3 = new Store(join(dir, "d3.db"));
		const join3 = shareVault(s1, await inviteInit(st3, "b"));
		const r = await joinConfirm(st3, "b", join3);
		assert.equal(r.sas, enrollmentSas(s1, st3.getMeta("deviceSignPub")!));
		for (const st of [st1, st2, st3]) st.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("child processes do not inherit vault credentials", () => {
	const saved = process.env.VAULT_PASSPHRASE;
	const savedCf = process.env.CF_ACCESS_CLIENT_SECRET;
	const savedPin = process.env.VAULT_TPM2_PIN;
	process.env.VAULT_TPM2_PIN = "1234";
	process.env.VAULT_PASSPHRASE = "secret";
	process.env.CF_ACCESS_CLIENT_SECRET = "cf";
	try {
		const env = childBaseEnv();
		assert.equal(env.VAULT_PASSPHRASE, undefined);
		assert.equal(env.CF_ACCESS_CLIENT_SECRET, undefined);
		assert.equal(env.VAULT_TPM2_PIN, undefined);
		assert.equal(env.PATH, process.env.PATH);
	} finally {
		if (saved === undefined) delete process.env.VAULT_PASSPHRASE;
		else process.env.VAULT_PASSPHRASE = saved;
		if (savedPin === undefined) delete process.env.VAULT_TPM2_PIN;
		else process.env.VAULT_TPM2_PIN = savedPin;
		if (savedCf === undefined) delete process.env.CF_ACCESS_CLIENT_SECRET;
		else process.env.CF_ACCESS_CLIENT_SECRET = savedCf;
	}
});

test("run prefers a field named like the key over the password", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "API_KEY", { API_KEY: "abc", password: "xyz" });
		rebuildSession(s);
		assert.equal(resolveOne(s, { key: "API_KEY", value: "" }), "abc");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("JWKS is cached across verifications", async () => {
	const { privateKey, publicKey } = await import("node:crypto").then((c) =>
		c.generateKeyPairSync("rsa", { modulusLength: 2048 }),
	);
	const jwk = publicKey.export({ format: "jwk" }) as { n: string; e: string };
	let fetches = 0;
	const fetchJwks = async (): Promise<JwkSet> => {
		fetches++;
		return { keys: [{ kid: "k1", kty: "RSA", n: jwk.n, e: jwk.e }] };
	};
	const b64u = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
	const cfg = { teamDomain: "t.cloudflareaccess.com", audience: "aud", fetchJwks };
	const h = b64u({ alg: "RS256", kid: "k1" });
	const p = b64u({
		aud: "aud",
		iss: "https://t.cloudflareaccess.com",
		exp: Date.now() / 1000 + 60,
	});
	const { sign } = await import("node:crypto");
	const sig = sign("RSA-SHA256", Buffer.from(`${h}.${p}`), privateKey).toString("base64url");
	for (let i = 0; i < 3; i++) assert.ok(await verifyAccessJwt(`${h}.${p}.${sig}`, cfg));
	assert.equal(fetches, 1);
	// An unknown kid right after a fetch does not refetch (retry window).
	const h2 = b64u({ alg: "RS256", kid: "k2" });
	const sig2 = sign("RSA-SHA256", Buffer.from(`${h2}.${p}`), privateKey).toString("base64url");
	for (let i = 0; i < 3; i++)
		assert.equal(await verifyAccessJwt(`${h2}.${p}.${sig2}`, cfg), undefined);
	assert.equal(fetches, 1);
});

test("JWKS: concurrent cold lookups fetch once; a keyless response is not cached", async () => {
	let fetches = 0;
	const empty = async (): Promise<JwkSet> => {
		fetches++;
		await new Promise((r) => setTimeout(r, 10));
		return {} as JwkSet;
	};
	const b64u = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
	const cfg = { teamDomain: "u.cloudflareaccess.com", audience: "aud", fetchJwks: empty };
	const tok = `${b64u({ alg: "RS256", kid: "k1" })}.${b64u({
		aud: "aud",
		iss: "https://u.cloudflareaccess.com",
		exp: Date.now() / 1000 + 60,
	})}.sig`;
	const results = await Promise.allSettled([1, 2, 3].map(() => verifyAccessJwt(tok, cfg)));
	assert.equal(fetches, 1);
	assert.ok(results.every((r) => r.status === "rejected"));
	// Not cached as a key set; within the retry window it fails fast, after it
	// the endpoint is tried again.
	await assert.rejects(verifyAccessJwt(tok, cfg));
	assert.equal(fetches, 1);
	await withClockAhead(31_000, () => assert.rejects(verifyAccessJwt(tok, cfg)));
	assert.equal(fetches, 2);
});

test("a validly signed rotation with grants: null does not lock anyone out", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		const unsigned = {
			epoch: 2,
			baseEpoch: 1,
			hlc: encodeHLC({ millis: Date.now(), counter: 0, deviceId: s.deviceId }),
			deviceId: s.deviceId,
			keyCommit: keyCommit(cr.randomBytes(32)),
			grants: null,
			observed: [],
			signerId: s.deviceId,
		} as unknown as Omit<RotationRecord, "sig">;
		const rec = {
			...unsigned,
			sig: cr.sign(rotationBytes(unsigned), s.priv.deviceSign).toString("base64"),
		};
		store.putRotation(2, s.deviceId, JSON.stringify(rec)); // as if stored by an older client
		importAuthAndRotations(s, [], [JSON.stringify(rec)]);
		const again = await unlock(store, PASS);
		assert.equal(again.currentEpoch, 1);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("vault credentials are stripped from child env regardless of case", () => {
	process.env.vault_passphrase = "secret";
	try {
		assert.equal(childBaseEnv().vault_passphrase, undefined);
	} finally {
		delete process.env.vault_passphrase;
	}
});

test("an auth entry of an unknown (newer) type is stored and relayed, and replay skips it", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		const future = makeEntry(
			heads(store.authLog()),
			{ type: "set-role", userId: s.userId } as unknown as EntryBody,
			s.deviceId,
			"device",
			s.priv.deviceSign,
		);
		assert.equal(importAuthAndRotations(s, [future], []).authImported, 1);
		assert.ok(store.authLog().some((e) => e.hash === future.hash));
		await unlock(store, PASS); // replay skips it without throwing
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("a peer server doesn't count an unverifiable rotation as held", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		const bogus = {
			...JSON.parse(store.rotations()[0]!),
			epoch: 5,
			baseEpoch: 4,
			sig: cr.sign(Buffer.from("x"), cr.generateEd25519().privateKey).toString("base64"),
		};
		store.putRotation(5, s.deviceId, JSON.stringify(bogus));
		const peer = new PeerStore(store, s.vaultId);
		const id = `5:${s.deviceId}`;
		assert.deepEqual(peer.rotationsLacking(s.vaultId, [id]), [id]);
		assert.equal(peer.rotationsExcept(s.vaultId, new Set()).length, 1); // only the genuine one
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("JWKS: a fetcher that throws synchronously is retried, not stuck in flight", async () => {
	let calls = 0;
	const fetchJwks = ((): Promise<JwkSet> => {
		calls++;
		throw new Error("config error");
	}) as (url: string) => Promise<JwkSet>;
	const b64u = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
	const cfg = { teamDomain: "v.cloudflareaccess.com", audience: "aud", fetchJwks };
	const tok = `${b64u({ alg: "RS256", kid: "k1" })}.${b64u({
		aud: "aud",
		iss: "https://v.cloudflareaccess.com",
		exp: Date.now() / 1000 + 60,
	})}.sig`;
	await assert.rejects(verifyAccessJwt(tok, cfg));
	await withClockAhead(31_000, () => assert.rejects(verifyAccessJwt(tok, cfg)));
	assert.equal(calls, 2);
});

test("a relay replaces an unverifiable rotation instead of counting it as held", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		const { server, store: relay } = createRelay();
		try {
			for (const e of store.authLog()) {
				if (e.body.type === "genesis") relay.pinGenesis(s.vaultId, e);
				relay.putAuth(s.vaultId, e);
			}
			const genuine = JSON.parse(store.rotations()[0]!) as RotationRecord;
			const id = `${genuine.epoch}:${genuine.deviceId}`;
			// A legacy row with a bad signature sits in the genuine record's slot.
			relay.putRotation(s.vaultId, { ...genuine, sig: genuine.sig.replace(/^./, "A") });
			assert.deepEqual(relay.rotationsLacking(s.vaultId, [id]), [id]);
			assert.deepEqual(relay.rotationsExcept(s.vaultId, new Set()), []);
			relay.putRotation(s.vaultId, genuine);
			assert.deepEqual(relay.rotationsLacking(s.vaultId, [id]), []);
			assert.equal(relay.rotationsExcept(s.vaultId, new Set()).length, 1);
		} finally {
			server.close();
			relay.close();
		}
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("run ignores an empty field named like the key and uses the password", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "API_KEY", { API_KEY: "", password: "xyz" });
		assert.equal(resolveOne(s, { key: "API_KEY", value: "" }), "xyz");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("a join whose own device can't be activated fails instead of persisting", async () => {
	const dir = await tmp();
	try {
		const st1 = new Store(join(dir, "o.db"));
		await init(st1, PASS);
		const owner = await unlock(st1, PASS);
		const st2 = new Store(join(dir, "j.db"));
		const token = shareVault(owner, await inviteInit(st2, "b"));
		// Replay the token after the joiner already has a device in the log: the
		// self-signed first-device bootstrap is no longer allowed.
		const st3 = new Store(join(dir, "j2.db"));
		await joinConfirm(st2, "b", token);
		const used = { ...token, authLog: st2.authLog() };
		for (const [k, v] of [
			["pending", "invite"],
			...["kdfParams", "userId", "userSignPub", "userEncPub", "pendingInvitePriv"].map(
				(k) => [k, st2.getMeta(k)!] as [string, string],
			),
		] as Array<[string, string]>)
			st3.setMeta(k, v);
		// A second device identity for the same user (as if the invite were reused).
		const other = cr.generateEd25519();
		st3.setMeta("deviceSignPub", other.publicKey.toString("base64"));
		st3.setMeta("deviceId", deviceIdOf(other.publicKey.toString("base64")));
		st3.setMeta("deviceEncPub", cr.generateX25519().publicKey.toString("base64"));
		await assert.rejects(joinConfirm(st3, "b", used), /does not let this device join/);
		assert.equal(st3.getMeta("vaultId"), undefined);
		for (const st of [st1, st2, st3]) st.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
