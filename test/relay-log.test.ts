// Relay log hardening (relay/log.ts): the relay is zero-knowledge and must never
// echo a request — its headers carry the Cloudflare Access credential that
// authorizes it. On an unexpected error it returns a fixed, credential-free body
// and never reflects err.message (which previously could include parser detail
// or, via a stringified request, the Access token).

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { createRelay } from "../relay/main.ts";
import worker from "../relay/worker/worker.ts";

const rawPost = (
	port: number,
	path: string,
	body: string,
	headers: Record<string, string>,
): Promise<{ status: number; body: string }> =>
	new Promise((resolve, reject) => {
		const req = request(
			{
				host: "127.0.0.1",
				port,
				path,
				method: "POST",
				headers: { "content-type": "application/json", ...headers },
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (c: Buffer) => chunks.push(c));
				res.on("end", () =>
					resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }),
				);
			},
		);
		req.on("error", reject);
		req.end(body);
	});

test("Node relay: a malformed request yields a generic 500 that leaks nothing", async () => {
	const { server, store } = createRelay({ dbPath: ":memory:" });
	await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
	const port = (server.address() as AddressInfo).port;
	try {
		const SENTINEL = "cf-access-jwt-SENTINEL-0123456789";
		// Invalid JSON body makes readBody throw inside handle → the 500 catch.
		const resp = await rawPost(port, "/sync", "this is not json {", {
			"cf-access-jwt-assertion": SENTINEL,
		});
		assert.equal(resp.status, 500);
		assert.deepEqual(JSON.parse(resp.body), { error: "internal error" }, "fixed generic body");
		assert.ok(!resp.body.includes(SENTINEL), "Access token never echoed");
		assert.ok(!/json/i.test(resp.body), "no parser detail (old err.message) leaked");
	} finally {
		await new Promise<void>((r) => server.close(() => r()));
		store.close();
	}
});

test("Worker relay: an internal failure yields a generic 500, never the raw error", async () => {
	// Force the entry handler into its catch by making DO routing throw.
	const env = {
		RELAY_DO: {
			idFromName() {
				throw new Error("boom: cf-access-jwt-SENTINEL-0123456789");
			},
			get() {
				throw new Error("unused");
			},
		},
	} as unknown as Parameters<typeof worker.fetch>[1];

	const resp = await worker.fetch(
		new Request("https://relay.test/sync", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ teamId: "t" }),
		}),
		env,
	);
	assert.equal(resp.status, 500);
	const text = await resp.text();
	assert.deepEqual(JSON.parse(text), { error: "internal error" });
	assert.ok(!text.includes("SENTINEL"), "raw error (which could carry a credential) not surfaced");
});

test("installSafeFatalHandlers prints message + stack and exits 1, not the raw object", async () => {
	const logUrl = new URL("../relay/log.ts", import.meta.url).href;
	const prog =
		`import { installSafeFatalHandlers } from ${JSON.stringify(logUrl)};` +
		`installSafeFatalHandlers();` +
		`setTimeout(() => { throw new Error("relay-boom"); }, 0);`;
	const stderr = await new Promise<{ code: number; out: string }>((resolve) => {
		const child = spawn(process.execPath, ["--input-type=module", "-e", prog], {
			stdio: ["ignore", "ignore", "pipe"],
		});
		let out = "";
		child.stderr.on("data", (c: Buffer) => {
			out += c.toString();
		});
		child.on("exit", (code) => resolve({ code: code ?? 0, out }));
	});
	assert.equal(stderr.code, 1, "the safe fatal handler exits 1");
	assert.match(stderr.out, /relay fatal: relay-boom/, "prints the message via the safe handler");
});
