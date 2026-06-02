// `vault proxy` (spec §13): the agent USES a secret without SEEING it. These
// tests drive a stub upstream and assert the proxy injects on egress, enforces
// the egress allowlist + host-binding, never carries a credential across a
// cross-host redirect, and spawns a child with the secret absent from its env.

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, request, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { addItem, init, unlock, type Session } from "../cli/engine.ts";
import { createProxyServer, loadPolicies, proxy } from "../cli/proxy.ts";
import { Store } from "../core/store.ts";

const PASS = "proxy-pass";
const tmp = (): Promise<string> => mkdtemp(join(tmpdir(), "vault-proxy-"));

type Stub = { port: number; close: () => Promise<void> };

const startStub = async (
	onReq: (
		req: import("node:http").IncomingMessage,
		res: import("node:http").ServerResponse,
	) => void,
): Promise<Stub> => {
	const server = createServer(onReq);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	return {
		port: (server.address() as AddressInfo).port,
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
};

const listen = (server: Server): Promise<number> =>
	new Promise<number>((resolve, reject) => {
		server.on("error", reject);
		server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
	});

const httpGet = (port: number, path: string): Promise<{ status: number; body: string }> =>
	new Promise((resolve, reject) => {
		const req = request({ host: "127.0.0.1", port, path, method: "GET" }, (res) => {
			const chunks: Buffer[] = [];
			res.on("data", (c: Buffer) => chunks.push(c));
			res.on("end", () =>
				resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }),
			);
		});
		req.on("error", reject);
		req.end();
	});

const makeVault = async (dir: string): Promise<Session> => {
	const store = new Store(join(dir, "v.db"));
	await init(store, PASS);
	const s = await unlock(store, PASS);
	addItem(s, "anthropic", { key: "sk-secret" });
	return s;
};

test("proxy injects header + query secrets on egress and streams the response back", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);

		let seen: { url?: string; headers?: Record<string, unknown> } = {};
		stub = await startStub((req, res) => {
			seen = { url: req.url, headers: req.headers };
			res.writeHead(200, { "content-type": "text/plain" });
			res.end("ok");
		});

		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			[
				`UPSTREAM=http://127.0.0.1:${stub.port}`,
				"x-api-key=vault://personal/anthropic/key   # resolved, never seen by the agent",
				"anthropic-version=2023-06-01",
				"?trace=on",
				"",
			].join("\n"),
		);

		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "/v1/messages?foo=bar");
		assert.equal(resp.status, 200);
		assert.equal(resp.body, "ok", "upstream response streamed back verbatim");
		assert.equal(seen.headers?.["x-api-key"], "sk-secret", "vault secret injected as header");
		assert.equal(
			seen.headers?.["anthropic-version"],
			"2023-06-01",
			"literal header passes through",
		);
		assert.match(seen.url ?? "", /foo=bar/, "original query preserved");
		assert.match(seen.url ?? "", /trace=on/, "query-param injection applied");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("proxy rejects an absolute-form request to a non-allowlisted host (egress allowlist)", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		stub = await startStub((_req, res) => res.end("ok"));

		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "http://blocked.invalid/exfil");
		assert.equal(resp.status, 403, "a host with no policy is refused");
		assert.match(resp.body, /not allowlisted/);

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("proxy does not follow a cross-host redirect (credential never reaches the other host)", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let upstream: Stub | undefined;
	let other: Stub | undefined;
	try {
		const s = await makeVault(dir);

		let otherHits = 0;
		other = await startStub((_req, res) => {
			otherHits += 1;
			res.end("should-not-be-reached");
		});
		upstream = await startStub((req, res) => {
			// The upstream legitimately receives the credential, then 302s elsewhere.
			assert.equal(req.headers["x-api-key"], "sk-secret");
			res.writeHead(302, { location: `http://127.0.0.1:${other!.port}/next` });
			res.end();
		});

		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${upstream.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "/go");
		assert.equal(resp.status, 302, "the 3xx is passed back to the client, not followed");
		assert.equal(otherHits, 0, "proxy never re-sent the request (or credential) to the other host");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (upstream) await upstream.close();
		if (other) await other.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("proxy spawns the agent with the secret absent from its env and forwards the exit code", async () => {
	const dir = await tmp();
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		stub = await startStub((req, res) => {
			// The proxy must inject the secret; the agent itself never had it.
			assert.equal(req.headers["x-api-key"], "sk-secret");
			res.writeHead(200);
			res.end("ok");
		});

		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);

		// The child reaches the proxy via VAULT_PROXY_URL, confirms the secret is
		// nowhere in its env, and that the round-trip works. Exit 7 iff all hold.
		const child = `
			const base = process.env.VAULT_PROXY_URL;
			const leak = Object.values(process.env).includes('sk-secret');
			if (!base || !base.startsWith('http://127.0.0.1:') || leak) process.exit(3);
			const http = require('node:http');
			const req = http.request(base + '/v1/messages', (res) => {
				let b = ''; res.on('data', (c) => b += c);
				res.on('end', () => process.exit(res.statusCode === 200 && b === 'ok' ? 7 : 4));
			});
			req.on('error', () => process.exit(5));
			req.end();
		`;

		const code = await proxy(s, { configFiles: [policyFile], port: 0 }, process.execPath, [
			"-e",
			child,
		]);
		assert.equal(
			code,
			7,
			"secret absent from child env; proxy injected it on egress; exit forwarded",
		);

		s.store.close();
	} finally {
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});
