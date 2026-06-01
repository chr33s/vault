import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	init,
	unlock,
	addItem,
	getItem,
	listItems,
	authNewDevice,
	deviceAdd,
	deviceConfirm,
} from "../cli/engine.ts";
import { createPeerServer } from "../cli/peerserver.ts";
import { PeerStore } from "../cli/peerstore.ts";
import { syncWithRelay } from "../cli/relayclient.ts";
import { parseStatus } from "../cli/tailnet.ts";
import { Store } from "../core/store.ts";

const tmp = (): Promise<string> => mkdtemp(join(tmpdir(), "vault-"));
const PASS = "test-passphrase";

test("parseStatus extracts self IPv4 and only online peers", () => {
	const json = JSON.stringify({
		Self: { TailscaleIPs: ["fd7a::1", "100.64.0.1"] },
		Peer: {
			a: { TailscaleIPs: ["100.64.0.2"], DNSName: "laptop.tail.ts.net.", Online: true },
			b: { TailscaleIPs: ["100.64.0.3"], HostName: "phone", Online: false },
			c: { TailscaleIPs: ["fd7a::9"], DNSName: "v6only.", Online: true }, // no IPv4 -> skipped
			d: { TailscaleIPs: ["100.64.0.4"], HostName: "desktop", Online: true },
		},
	});
	const st = parseStatus(json);
	assert.equal(st.selfIP, "100.64.0.1");
	assert.deepEqual(st.peers.map((p) => p.name).sort(), ["desktop", "laptop.tail.ts.net"]);
	// DNSName trailing dot stripped; falls back to HostName when no DNSName.
	assert.ok(st.peers.some((p) => p.name === "laptop.tail.ts.net" && p.ip === "100.64.0.2"));
	assert.ok(st.peers.some((p) => p.name === "desktop" && p.ip === "100.64.0.4"));
});

test("PeerStore refuses requests for a foreign vault", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "github", { username: "alice", password: "pw" });

		const peer = new PeerStore(store, s.vaultId);
		// Own vault: serves the real op-log.
		assert.ok(peer.allOps(s.vaultId).length > 0);
		assert.notDeepEqual(peer.vector(s.vaultId), {});
		// Foreign vault: empty / no-op across the board.
		assert.deepEqual(peer.allOps("other-vault"), []);
		assert.deepEqual(peer.vector("other-vault"), {});
		assert.deepEqual(peer.authExcept("other-vault", new Set()), []);
		assert.deepEqual(peer.rotationsExcept("other-vault", new Set()), []);
		assert.deepEqual(peer.allGrants("other-vault"), []);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("two replicas converge through a direct peer server", async () => {
	const dir = await tmp();
	try {
		// Device 1 creates the vault and enrolls device 2 via the QR handshake.
		const store1 = new Store(join(dir, "d1.db"));
		await init(store1, PASS);
		const s1 = await unlock(store1, PASS);
		addItem(s1, "github", { username: "alice", password: "pw1" });

		const store2 = new Store(join(dir, "d2.db"));
		const tokenA = await authNewDevice(store2, PASS);
		const tokenB = deviceAdd(s1, tokenA, { role: "admin" });
		await deviceConfirm(store2, PASS, tokenB);

		// Device 1 runs a peer server over its own replica (the §8.6 direct path).
		const server = createPeerServer(store1, s1.vaultId);
		await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
		const peerUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

		// Device 2 syncs against device 1 directly — no relay involved.
		const s2 = await unlock(store2, PASS);
		const r2 = await syncWithRelay(s2, peerUrl);
		assert.ok(r2.pulled > 0);
		assert.equal(getItem(s2, "github")!.fields.username, "alice");

		// Reverse direction converges too: device 2 adds, device 1's server accepts
		// the op into its backing store. Reload device 1 from disk to materialize it.
		addItem(s2, "aws", { username: "root", password: "pw2" });
		await syncWithRelay(s2, peerUrl);
		const s1Reloaded = await unlock(store1, PASS);
		assert.ok(getItem(s1Reloaded, "aws"), "device 1 should converge on device 2's item");
		assert.equal(listItems(s1Reloaded).length, 2);

		server.close();
		store1.close();
		store2.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("peer server with a token rejects unauthenticated sync", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "github", { username: "alice", password: "pw" });

		const server = createPeerServer(store, s.vaultId, { token: "s3cret" });
		await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
		const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

		// No token -> blocked at the access gate.
		await assert.rejects(syncWithRelay(s, url), /403|forbidden|unauthorized/i);
		// Correct token -> succeeds.
		await syncWithRelay(s, url, { token: "s3cret" });

		server.close();
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
