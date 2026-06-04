// relayclient transport error handling: non-2xx responses reject with the body,
// and malformed JSON rejects rather than silently resolving. Exercised end-to-end
// through a real syncWithRelay round against a tiny stub HTTP server.

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { init, unlock } from "../cli/engine.ts";
import { post, syncWithRelay } from "../cli/relayclient.ts";
import { Store } from "../core/store.ts";

const startStub = (
	handler: (req: unknown, res: import("node:http").ServerResponse) => void,
): Promise<{ url: string; server: Server }> =>
	new Promise((resolve) => {
		const server = createServer((_req, res) => handler(_req, res));
		server.listen(0, () =>
			resolve({ url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server }),
		);
	});

const withSession = async (
	fn: (s: import("../cli/engine.ts").Session) => Promise<void>,
): Promise<void> => {
	const dir = await mkdtemp(join(tmpdir(), "relayclient-"));
	const store = new Store(join(dir, "v.db"));
	try {
		await init(store, "pw");
		await fn(await unlock(store, "pw"));
	} finally {
		store.close();
		await rm(dir, { recursive: true, force: true });
	}
};

test("syncWithRelay rejects on a non-2xx relay response, surfacing the body", async () => {
	const { url, server } = await startStub((_req, res) => {
		res.writeHead(403, { "content-type": "application/json" });
		res.end(JSON.stringify({ error: "forbidden" }));
	});
	try {
		await withSession(async (s) => {
			await assert.rejects(syncWithRelay(s, url), /relay 403:.*forbidden/);
		});
	} finally {
		server.close();
	}
});

test("syncWithRelay rejects on malformed JSON from the relay", async () => {
	const { url, server } = await startStub((_req, res) => {
		res.writeHead(200, { "content-type": "application/json" });
		res.end("this is not json");
	});
	try {
		await withSession(async (s) => {
			await assert.rejects(syncWithRelay(s, url)); // JSON.parse throws -> reject
		});
	} finally {
		server.close();
	}
});

test("post aborts a relay response that exceeds the size cap", async () => {
	// A compromised/buggy relay streaming an unbounded body must not OOM the client.
	const { url, server } = await startStub((_req, res) => {
		res.writeHead(200, { "content-type": "application/json" });
		res.end("x".repeat(100_000)); // far over the tiny cap below
	});
	try {
		await assert.rejects(
			post(url, {}, {}, { maxBytes: 1024 }),
			/relay response exceeded 1024 bytes/,
		);
	} finally {
		server.close();
	}
});

test("post accepts a response within the size cap", async () => {
	const { url, server } = await startStub((_req, res) => {
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ ok: true }));
	});
	try {
		const body = await post<{ ok: boolean }>(url, {}, {}, { maxBytes: 1024 });
		assert.deepEqual(body, { ok: true });
	} finally {
		server.close();
	}
});
