// `vault proxy` (spec §13): the agent USES a secret without SEEING it. These
// tests drive a stub upstream and assert the proxy injects on egress, enforces
// the egress allowlist + host-binding, never carries a credential across a
// cross-host redirect, and spawns a child with the secret absent from its env.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, request, type Server } from "node:http";
import { connect as netConnect, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connect as tlsConnect } from "node:tls";
import { gunzipSync, gzipSync } from "node:zlib";
import { addItem, init, unlock, type Session } from "../cli/engine.ts";
import { createProxyServer, loadPolicies, proxy } from "../cli/proxy.ts";
import { createCa } from "../cli/x509.ts";
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

const httpGet = (
	port: number,
	path: string,
): Promise<{
	status: number;
	body: string;
	headers: Record<string, string | string[] | undefined>;
}> =>
	new Promise((resolve, reject) => {
		const req = request({ host: "127.0.0.1", port, path, method: "GET" }, (res) => {
			const chunks: Buffer[] = [];
			res.on("data", (c: Buffer) => chunks.push(c));
			res.on("end", () =>
				resolve({
					status: res.statusCode ?? 0,
					body: Buffer.concat(chunks).toString("utf8"),
					headers: res.headers,
				}),
			);
		});
		req.on("error", reject);
		req.end();
	});

// Like httpGet but keeps the body as raw bytes (for binary/compressed responses).
const httpGetBuf = (
	port: number,
	path: string,
): Promise<{
	status: number;
	headers: Record<string, string | string[] | undefined>;
	body: Buffer;
}> =>
	new Promise((resolve, reject) => {
		const req = request({ host: "127.0.0.1", port, path, method: "GET" }, (res) => {
			const chunks: Buffer[] = [];
			res.on("data", (c: Buffer) => chunks.push(c));
			res.on("end", () =>
				resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }),
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

test("proxy scrubs the injected secret from relayed error responses (body + headers)", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);

		// A hostile-ish upstream that echoes the credential everywhere a real API
		// might: the error body (raw + Basic-auth base64) and response headers
		// (an echo header and a Location carrying it as a query param).
		stub = await startStub((req, res) => {
			const echoed = String(req.headers["x-api-key"]);
			res.writeHead(401, {
				"content-type": "application/json",
				"x-echo": echoed,
				location: `http://${req.headers.host}/login?key=${echoed}`,
			});
			res.end(
				JSON.stringify({
					error: `invalid api key ${echoed}`,
					basic: Buffer.from(echoed).toString("base64"),
				}),
			);
		});

		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "/v1/messages");
		assert.equal(resp.status, 401, "error status relayed");
		assert.ok(!resp.body.includes("sk-secret"), "raw secret scrubbed from the error body");
		assert.ok(
			!resp.body.includes(Buffer.from("sk-secret").toString("base64")),
			"base64 form scrubbed from the error body",
		);
		// The single [REDACTED] marker is used everywhere — body, headers, and the
		// base64 form in the body all redact to it.
		assert.match(resp.body, /invalid api key \[REDACTED\]/, "secret redacted in the error body");
		assert.match(resp.body, /"basic":"\[REDACTED\]"/, "base64 form redacted in the body");
		assert.equal(resp.headers["x-echo"], "[REDACTED]", "echo header scrubbed");
		assert.match(String(resp.headers.location), /key=\[REDACTED\]/, "Location query scrubbed");
		// A scrubbed body drops content-length (length changes) and is sent chunked;
		// confirm it's intact, parseable JSON.
		assert.doesNotThrow(() => JSON.parse(resp.body), "scrubbed body is still valid JSON");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("proxy reports an unreachable upstream as a wrapped, scrubbed 502", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	try {
		const s = await makeVault(dir);

		// Grab a port that is guaranteed closed: listen, note it, close it.
		const closed = await startStub(() => {});
		await closed.close();

		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${closed.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "/v1/messages");
		assert.equal(resp.status, 502);
		assert.match(resp.body, /proxy error: upstream /, "raw Node error re-wrapped minimally");
		assert.ok(!resp.body.includes("sk-secret"), "no secret in the error body");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		await rm(dir, { recursive: true, force: true });
	}
});

test("proxy refuses to start under NODE_DEBUG that would log request headers", async () => {
	const dir = await tmp();
	const prev = process.env.NODE_DEBUG;
	try {
		const s = await makeVault(dir);
		// Covers literal sections AND the glob forms Node honors that name no risky
		// section literally (NODE_DEBUG=* enables ALL sections; htt*/ht*p enable http).
		for (const v of ["http", "*", "htt*", "ht*p"]) {
			process.env.NODE_DEBUG = v;
			await assert.rejects(
				proxy(s, { configFiles: [join(dir, "unused.env")], port: 0 }),
				/NODE_DEBUG/,
				`NODE_DEBUG=${v} would print injected headers to stderr`,
			);
		}
		s.store.close();
	} finally {
		if (prev === undefined) delete process.env.NODE_DEBUG;
		else process.env.NODE_DEBUG = prev;
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

test("a malformed request target returns 400 and does not crash the proxy", async () => {
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

		// "//" makes `new URL("//", upstream)` throw; the old code let that throw
		// escape the request handler and crash the whole proxy. Now it's a clean 400.
		const bad = await httpGet(port, "//");
		assert.equal(bad.status, 400, "malformed target -> 400, not a crash");

		// Proxy is still alive and serving: a normal request succeeds afterwards.
		const ok = await httpGet(port, "/v1/messages");
		assert.equal(ok.status, 200, "proxy survived the malformed request");
		assert.equal(ok.body, "ok");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("the secret is scrubbed from a large (>64 KiB) error body, including past the cap and at chunk boundaries", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		// Emit the secret at the very start, deep past 64 KiB, and split across two
		// writes (chunk boundary) — the old overflow path streamed all of this raw.
		stub = await startStub((req, res) => {
			const sec = String(req.headers["x-api-key"]); // "sk-secret"
			res.writeHead(500, { "content-type": "text/plain" });
			res.write(`head ${sec} ` + "A".repeat(70_000) + ` mid ${sec} ` + "B".repeat(2000) + " sk-");
			res.end(`secret tail`); // "sk-" + "secret" straddles the write boundary
		});
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "/v1/messages");
		assert.equal(resp.status, 500);
		assert.ok(resp.body.length > 64 * 1024, "body really exceeds the old buffering cap");
		assert.ok(!resp.body.includes("sk-secret"), "no occurrence of the secret survives anywhere");
		assert.match(resp.body, /head \[REDACTED\] /, "leading occurrence redacted");
		assert.match(resp.body, /mid \[REDACTED\] /, "occurrence past 64 KiB redacted");
		assert.match(resp.body, /\[REDACTED\] tail/, "boundary-straddling occurrence redacted");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("the secret is scrubbed from a 2xx response body (not only error bodies)", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		// A 200 that reflects the injected credential in its body (OAuth-style echo).
		stub = await startStub((req, res) => {
			const sec = String(req.headers["x-api-key"]);
			res.writeHead(200, { "content-type": "application/json" });
			res.end(JSON.stringify({ ok: true, echoed: sec }));
		});
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "/v1/messages");
		assert.equal(resp.status, 200);
		assert.ok(!resp.body.includes("sk-secret"), "secret redacted even on a success body");
		assert.match(resp.body, /"echoed":"\[REDACTED\]"/, "redacted in the streaming body");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("a binary/non-textual response body is relayed byte-exact (masking would corrupt it)", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		// A non-textual body whose bytes happen to include the secret's byte run.
		// We must NOT mask it (that would corrupt the payload) — and a real secret
		// can't appear as plaintext in a genuine binary/compressed body anyway.
		const body = Buffer.concat([
			Buffer.from([0x00, 0x01, 0x02]),
			Buffer.from("sk-secret"),
			Buffer.from([0x03, 0x04]),
		]);
		stub = await startStub((_req, res) => {
			res.writeHead(200, { "content-type": "application/octet-stream" });
			res.end(body);
		});
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "/v1/messages");
		assert.equal(resp.status, 200);
		assert.equal(resp.body, body.toString("utf8"), "binary body passed through unchanged");
		assert.ok(!resp.body.includes("[REDACTED]"), "no redaction applied to a non-textual body");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

// Open a CONNECT tunnel to `connectHost` through the proxy, TLS-handshake
// trusting only `caPem`, then issue one GET through the tunnel. Resolves the
// CONNECT status (200 if established) and the tunneled response.
const throughConnect = (
	proxyPort: number,
	connectHost: string,
	caPem: string,
	path: string,
): Promise<{ connectStatus: number; status?: number; body?: string }> =>
	new Promise((resolve, reject) => {
		const tunnel = request({
			host: "127.0.0.1",
			port: proxyPort,
			method: "CONNECT",
			path: connectHost,
		});
		// Non-2xx CONNECT (e.g. the 403 allowlist refusal) arrives as a response.
		tunnel.on("response", (res) => {
			res.resume();
			resolve({ connectStatus: res.statusCode ?? 0 });
		});
		tunnel.on("connect", (res, socket) => {
			if ((res.statusCode ?? 0) !== 200) {
				socket.destroy();
				resolve({ connectStatus: res.statusCode ?? 0 });
				return;
			}
			// rejectUnauthorized stays on: a successful handshake proves the proxy
			// presented a cert chaining to our ephemeral CA. checkServerIdentity is
			// stubbed because the upstream here is an IP (name-matching is covered in
			// x509.test.ts); the chain is still enforced.
			const tls = tlsConnect({ socket, ca: [caPem], checkServerIdentity: () => undefined }, () => {
				const inner = request(
					{
						createConnection: () => tls,
						host: connectHost.split(":")[0],
						path,
						headers: { host: connectHost, connection: "close" },
					},
					(r) => {
						const chunks: Buffer[] = [];
						r.on("data", (c: Buffer) => chunks.push(c));
						r.on("end", () =>
							resolve({
								connectStatus: 200,
								status: r.statusCode ?? 0,
								body: Buffer.concat(chunks).toString("utf8"),
							}),
						);
					},
				);
				inner.on("error", reject);
				inner.end();
			});
			tls.on("error", reject);
		});
		tunnel.on("error", reject);
		tunnel.end();
	});

test("proxy --connect terminates TLS with the ephemeral CA and injects through the tunnel", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);

		let seen: Record<string, unknown> | undefined;
		stub = await startStub((req, res) => {
			seen = req.headers;
			res.writeHead(200, { "content-type": "text/plain" });
			res.end("tunneled-ok");
		});

		// Upstream is a plain-HTTP stub on 127.0.0.1: the agent's TLS terminates at
		// the proxy, which forwards over HTTP to the stub. CONNECT host hostname
		// (127.0.0.1) is what the leaf + allowlist key on.
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		const ca = await createCa();
		proxyServer = createProxyServer(policies, ca);
		const port = await listen(proxyServer);

		const r = await throughConnect(port, `127.0.0.1:${stub.port}`, ca.certPem, "/v1/messages");
		assert.equal(r.connectStatus, 200, "tunnel to an allowlisted host is established");
		assert.equal(r.status, 200);
		assert.equal(r.body, "tunneled-ok", "upstream response relayed through the tunnel");
		assert.equal(seen?.["x-api-key"], "sk-secret", "secret injected on the decrypted request");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("proxy --connect refuses a CONNECT tunnel to a non-allowlisted host", async () => {
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
		const ca = await createCa();
		proxyServer = createProxyServer(policies, ca);
		const port = await listen(proxyServer);

		// blocked.invalid is not in the policy → the tunnel (and any cert) is refused
		// before TLS starts, so the agent's secret-bearing session never begins.
		const r = await throughConnect(port, "blocked.invalid:443", ca.certPem, "/exfil");
		assert.equal(r.connectStatus, 403, "no tunnel is opened to an unconfigured host");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

// Spawn `node` on a small program and capture its exit code + stderr.
const runNode = (args: string[]): Promise<{ code: number; stderr: string }> =>
	new Promise((resolve) => {
		const child = spawn(process.execPath, args, { stdio: ["ignore", "ignore", "pipe"] });
		let stderr = "";
		child.stderr.on("data", (c: Buffer) => {
			stderr += c.toString();
		});
		child.on("exit", (code) => resolve({ code: code ?? 0, stderr }));
	});

test("a normal injection emits a value-free audit line, advertises loopback, and never logs the secret (spec §13.2)", async (t) => {
	const dir = await tmp();
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		stub = await startStub((_req, res) => {
			res.writeHead(200);
			res.end("ok");
		});
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);

		// Capture the proxy's own stderr (audit + listening notes go through
		// process.stderr.write; the spawned child uses inherited fds, so this only
		// sees the proxy's writes).
		const captured: string[] = [];
		t.mock.method(process.stderr, "write", (chunk: unknown): boolean => {
			captured.push(String(chunk));
			return true;
		});

		const child = `
			const http = require('node:http');
			const req = http.request(process.env.VAULT_PROXY_URL + '/v1/messages', (res) => {
				res.resume(); res.on('end', () => process.exit(0));
			});
			req.on('error', () => process.exit(1));
			req.end();
		`;
		const code = await proxy(s, { configFiles: [policyFile], port: 0 }, process.execPath, [
			"-e",
			child,
		]);
		assert.equal(code, 0, "child round-trip succeeded");

		const err = captured.join("");
		assert.match(
			err,
			/listening on http:\/\/127\.0\.0\.1:\d+ \(loopback only/,
			"advertises a loopback-only bind",
		);
		assert.match(
			err,
			/audit: .* injected \[x-api-key\] -> 127\.0\.0\.1:/,
			"per-injection audit line carries the rule name + upstream",
		);
		assert.ok(
			!err.includes("sk-secret"),
			"the secret value never reaches stderr (audit or otherwise)",
		);

		s.store.close();
	} finally {
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("a compressed (content-encoding) body is relayed byte-exact, not scrubbed or corrupted", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		// A gzip'd JSON body echoing the injected credential. The secret isn't
		// present as plaintext in the compressed bytes, so it must NOT be scrubbed
		// (which would corrupt the gzip stream) — relay byte-exact.
		stub = await startStub((req, res) => {
			const sec = String(req.headers["x-api-key"]);
			const gz = gzipSync(Buffer.from(`{"echoed":"${sec}"}`));
			res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" });
			res.end(gz);
		});
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGetBuf(port, "/v1/messages");
		assert.equal(resp.status, 200);
		assert.equal(resp.headers["content-encoding"], "gzip", "encoding relayed as-is");
		// The relayed gzip must be intact (decompresses) and uncorrupted by masking.
		assert.equal(
			gunzipSync(resp.body).toString("utf8"),
			'{"echoed":"sk-secret"}',
			"compressed body passed through byte-exact (not scrubbed/corrupted)",
		);

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("a scrubbed body drops content-length and is sent chunked", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		stub = await startStub((req, res) => {
			const body = `{"echoed":"${String(req.headers["x-api-key"])}","x":"ok"}`;
			// Upstream sends an explicit content-length (fixed-length framing).
			res.writeHead(200, {
				"content-type": "application/json",
				"content-length": String(Buffer.byteLength(body)),
			});
			res.end(body);
		});
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "/v1/messages");
		assert.equal(resp.status, 200);
		assert.equal(
			resp.headers["content-length"],
			undefined,
			"content-length dropped (length changed)",
		);
		assert.equal(resp.headers["transfer-encoding"], "chunked", "re-framed as chunked");
		assert.match(resp.body, /"echoed":"\[REDACTED\]"/, "secret redacted, body still valid");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("the secret is redacted from a 3xx response body, not just the Location header", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		stub = await startStub((req, res) => {
			const sec = String(req.headers["x-api-key"]);
			res.writeHead(302, {
				"content-type": "text/html",
				location: `http://127.0.0.1:1/next?key=${sec}`,
			});
			res.end(`<html>redirecting with ${sec}</html>`);
		});
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		proxyServer = createProxyServer(policies);
		const port = await listen(proxyServer);

		const resp = await httpGet(port, "/v1/messages");
		assert.equal(resp.status, 302, "the 3xx is passed back, not followed");
		assert.ok(!resp.body.includes("sk-secret"), "secret redacted from the 3xx body");
		assert.match(resp.body, /redirecting with \[REDACTED\]/, "body occurrence redacted");
		assert.match(String(resp.headers.location), /key=\[REDACTED\]/, "Location query redacted");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("the proxy tears down on child exit: its port stops accepting connections", async () => {
	const dir = await tmp();
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		stub = await startStub((_req, res) => res.end("ok"));
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);

		// The child records the proxy URL it was handed, then exits.
		const urlOut = join(dir, "url.txt");
		const child = `require('node:fs').writeFileSync(${JSON.stringify(urlOut)}, process.env.VAULT_PROXY_URL); process.exit(0);`;
		await proxy(s, { configFiles: [policyFile], port: 0 }, process.execPath, ["-e", child]);

		const port = Number(new URL((await readFile(urlOut, "utf8")).trim()).port);
		// The proxy must be gone now (torn down on child exit).
		await assert.rejects(httpGet(port, "/v1/messages"), /ECONNREFUSED|socket hang up/);

		s.store.close();
	} finally {
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("proxy --connect: the child trusts the ephemeral CA via env (public cert only) and the CA file is cleaned up", async () => {
	const dir = await tmp();
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		stub = await startStub((_req, res) => res.end("ok"));
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);

		const caOut = join(dir, "caout.txt");
		const child = `
			const fs = require('node:fs');
			const caFile = process.env.NODE_EXTRA_CA_CERTS;
			const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy;
			const leak = Object.values(process.env).includes('sk-secret');
			let ok = !leak && !!caFile && !!proxyUrl && proxyUrl.startsWith('http://127.0.0.1:');
			if (ok) {
				const pem = fs.readFileSync(caFile, 'utf8');
				// The child trusts ONLY the public cert; the CA private key never leaves the proxy.
				ok = pem.includes('BEGIN CERTIFICATE') && !pem.includes('PRIVATE KEY');
				fs.writeFileSync(${JSON.stringify(caOut)}, caFile);
			}
			process.exit(ok ? 7 : 3);
		`;
		const code = await proxy(
			s,
			{ configFiles: [policyFile], port: 0, connect: true },
			process.execPath,
			["-e", child],
		);
		assert.equal(
			code,
			7,
			"child saw HTTPS_PROXY + a CA cert (no private key), secret absent from env",
		);

		const caFilePath = (await readFile(caOut, "utf8")).trim();
		assert.ok(!existsSync(caFilePath), "the temp CA file is unlinked on teardown");

		s.store.close();
	} finally {
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("proxy --connect survives a client that aborts during the keygen/handshake window", async () => {
	const dir = await tmp();
	let proxyServer: Server | undefined;
	let stub: Stub | undefined;
	try {
		const s = await makeVault(dir);
		stub = await startStub((req, res) => {
			assert.equal(req.headers["x-api-key"], "sk-secret");
			res.writeHead(200, { "content-type": "text/plain" });
			res.end("tunneled-ok");
		});
		const policyFile = join(dir, "policy.env");
		await writeFile(
			policyFile,
			`UPSTREAM=http://127.0.0.1:${stub.port}\nx-api-key=vault://personal/anthropic/key\n`,
		);
		const policies = await loadPolicies(s, [policyFile]);
		const ca = await createCa();
		proxyServer = createProxyServer(policies, ca);
		const port = await listen(proxyServer);

		// Send a raw CONNECT then destroy the socket immediately — before the proxy
		// finishes minting the leaf and writes "200". This exercises the
		// dead-socket guard (the .then() must not write/wrap a destroyed socket).
		await new Promise<void>((resolve) => {
			const sock = netConnect(port, "127.0.0.1", () => {
				sock.write(
					`CONNECT 127.0.0.1:${stub!.port} HTTP/1.1\r\nHost: 127.0.0.1:${stub!.port}\r\n\r\n`,
				);
				sock.destroy();
				resolve();
			});
			sock.on("error", () => resolve());
		});

		// The proxy must still be alive and serve a fresh tunnel.
		const r = await throughConnect(port, `127.0.0.1:${stub.port}`, ca.certPem, "/v1/messages");
		assert.equal(r.connectStatus, 200, "proxy survived the aborted tunnel");
		assert.equal(r.body, "tunneled-ok");

		s.store.close();
	} finally {
		if (proxyServer) await new Promise<void>((r) => proxyServer!.close(() => r()));
		if (stub) await stub.close();
		await rm(dir, { recursive: true, force: true });
	}
});

test("installScrubbedFatalHandlers scrubs an uncaught exception dump (crash backstop)", async () => {
	const scrubUrl = new URL("../cli/scrub.ts", import.meta.url).href;
	const prog =
		`import { registerSecret, installScrubbedFatalHandlers } from ${JSON.stringify(scrubUrl)};` +
		`registerSecret("crash-secret-abcdef");` +
		`installScrubbedFatalHandlers();` +
		`setTimeout(() => { throw new Error("boom leaking crash-secret-abcdef now"); }, 0);`;
	const { code, stderr } = await runNode(["--input-type=module", "-e", prog]);
	assert.equal(code, 1, "the scrubbed fatal handler exits 1");
	assert.match(stderr, /fatal:/, "uses the scrubbed fatal dumper, not Node's default");
	assert.ok(!stderr.includes("crash-secret-abcdef"), "the secret is scrubbed from the crash dump");
	assert.match(stderr, /\[REDACTED\]/, "redaction marker present in the dump");
});
