// `vault proxy` — let an AI agent USE a secret without SEEING it (spec §13).
//
// Unlike `vault run` (plaintext into the child's env), the proxy keeps the
// credential out of the consumer: it injects on egress, only on requests bound
// for the policy's upstream. The agent points its SDK base-URL at us; we forward
// to the real upstream over genuine TLS and stream the response back. No TLS
// interception — CONNECT/MITM mode is deferred (spec §13.1, plan §13).
//
// Security (spec §13.2): bind 127.0.0.1 only; attach each secret to its upstream
// host only; allowlist egress (reject unconfigured hosts); don't follow redirects
// (a credential can't cross to another host); never log/persist the value; emit a
// per-injection audit entry.

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import {
	createServer,
	request as httpRequest,
	type IncomingMessage,
	type Server,
	type ServerResponse,
} from "node:http";
import { request as httpsRequest } from "node:https";
import { parseDotenv } from "./dotenv.ts";
import type { Session } from "./engine.ts";
import { resolveOne } from "./run.ts";

// An injected value resolved from the vault (or a literal pass-through). A header
// is set on the request headers; a query value is set on the upstream URL.
export type Injection =
	| { kind: "header"; name: string; value: string }
	| { kind: "query"; name: string; value: string };

// One upstream + the values to attach to requests bound for it.
export type Policy = {
	upstream: URL;
	injections: Injection[];
};

// Parsed policies, indexed by upstream host for the egress allowlist. The first
// file's policy is the default for origin-form requests (base-URL mode, where
// the client sends only a path and the host is implicit).
export type LoadedPolicies = {
	byHost: Map<string, Policy>;
	defaultPolicy: Policy;
};

export const DEFAULT_PROXY_PORT = 8788;

// SDK base-URL env vars to preset when spawning a child, keyed by upstream host
// so we only point the SDK that actually targets a configured upstream.
const BASE_URL_ENV: Record<string, string[]> = {
	"api.anthropic.com": ["ANTHROPIC_BASE_URL"],
	"api.openai.com": ["OPENAI_BASE_URL", "OPENAI_API_BASE"],
};

const RESERVED_UPSTREAM = "UPSTREAM";

// Parse one `.env`-format policy manifest. The reserved `UPSTREAM=` key names
// the destination (taken as a literal URL — never resolved from the vault); a
// `?name` key is a query-param injection; every other key is a request header.
// Injection values resolve with `run`'s precedence (ambient -> literal -> vault).
export const parseProxyPolicy = (s: Session, text: string): Policy => {
	const decls = parseDotenv(text);
	let upstream: URL | undefined;
	const injections: Injection[] = [];

	for (const decl of decls) {
		if (decl.key === RESERVED_UPSTREAM) {
			if (!decl.value) throw new Error("UPSTREAM= must be a literal http(s) URL");
			let u: URL;
			try {
				u = new URL(decl.value);
			} catch {
				throw new Error(`bad UPSTREAM URL: ${decl.value}`);
			}
			if (u.protocol !== "http:" && u.protocol !== "https:")
				throw new Error(`UPSTREAM must be http(s): ${decl.value}`);
			// Request paths replace the base path (origin-relative resolution), so a
			// base path on UPSTREAM would be silently dropped — reject it up front.
			if (u.pathname !== "/" || u.search || u.hash)
				throw new Error(`UPSTREAM must be an origin with no path/query: ${decl.value}`);
			upstream = u;
			continue;
		}

		const isQuery = decl.key.startsWith("?");
		const name = isQuery ? decl.key.slice(1) : decl.key;
		if (!name) throw new Error(`bad policy key: ${decl.key}`);
		const value = resolveOne(s, decl);
		// Fail fast: a proxy that can't resolve a declared secret must not start
		// (otherwise it would silently inject nothing — worse than an error).
		if (value === undefined)
			throw new Error(`cannot resolve policy entry "${decl.key}" from the vault`);
		// Node lowercases incoming request headers; lowercase injected header names
		// too so the injection always overrides a client-sent value (no duplicates).
		injections.push(
			isQuery
				? { kind: "query", name, value }
				: { kind: "header", name: name.toLowerCase(), value },
		);
	}

	if (!upstream) throw new Error("policy is missing a required UPSTREAM= line");
	return { upstream, injections };
};

// Load one-or-more policy files (repeated --config = multiple upstreams).
export const loadPolicies = async (s: Session, configFiles: string[]): Promise<LoadedPolicies> => {
	if (configFiles.length === 0) throw new Error("no --config policy file given");
	const byHost = new Map<string, Policy>();
	let defaultPolicy: Policy | undefined;
	for (const f of configFiles) {
		const text = await readFile(f, "utf8");
		const policy = parseProxyPolicy(s, text);
		byHost.set(policy.upstream.host, policy);
		defaultPolicy ??= policy;
	}
	return { byHost, defaultPolicy: defaultPolicy! };
};

// Per-injection audit (spec §13.2): upstream + rule names + timestamp, never the
// value. Operational, so it goes to stderr (keeps --json stdout clean).
const audit = (names: string[], host: string): void => {
	if (names.length === 0) return;
	process.stderr.write(
		`audit: ${new Date().toISOString()} injected [${names.join(", ")}] -> ${host}\n`,
	);
};

const reqFn = (protocol: string): typeof httpRequest =>
	protocol === "https:" ? (httpsRequest as typeof httpRequest) : httpRequest;

// Hop-by-hop / rewritten headers we never forward verbatim from the client.
const STRIP_HEADERS = new Set(["host", "connection", "proxy-connection"]);

const fail = (res: ServerResponse, status: number, msg: string): void => {
	res.writeHead(status, { "content-type": "text/plain" });
	res.end(msg);
};

const handleRequest = (
	policies: LoadedPolicies,
	req: IncomingMessage,
	res: ServerResponse,
): Promise<void> =>
	new Promise<void>((resolve, reject) => {
		const rawUrl = req.url ?? "/";

		// Resolve the policy + forward target. An absolute request-URI (forward-
		// proxy form) names a host explicitly — it MUST be in the allowlist. An
		// origin-form path (base-URL form) uses the default policy.
		let policy: Policy;
		if (/^https?:\/\//i.test(rawUrl)) {
			let asked: URL;
			try {
				asked = new URL(rawUrl);
			} catch {
				req.resume();
				fail(res, 400, "bad request URI");
				resolve();
				return;
			}
			const p = policies.byHost.get(asked.host);
			if (!p) {
				// Egress allowlist: refuse any host we hold no policy for (SSRF guard).
				req.resume();
				fail(res, 403, `host not allowlisted: ${asked.host}`);
				resolve();
				return;
			}
			policy = p;
		} else {
			policy = policies.defaultPolicy;
		}

		const path = rawUrl.replace(/^https?:\/\/[^/]+/i, "") || "/";
		const target = new URL(path, policy.upstream);

		// Host-binding (spec §13.2): the secret is attached only to its upstream.
		// By construction we forward to policy.upstream; assert it defensively so a
		// future refactor can't silently break the invariant.
		if (target.host !== policy.upstream.host) {
			req.resume();
			fail(res, 403, "host-binding violation");
			resolve();
			return;
		}

		// Forward client headers (minus host/hop-by-hop), then inject ours.
		const headers: Record<string, string | string[]> = {};
		for (const [k, v] of Object.entries(req.headers)) {
			if (v === undefined) continue;
			if (STRIP_HEADERS.has(k.toLowerCase())) continue;
			headers[k] = v;
		}
		const injectedNames: string[] = [];
		for (const inj of policy.injections) {
			if (inj.kind === "header") {
				headers[inj.name] = inj.value;
				injectedNames.push(inj.name);
			} else {
				target.searchParams.set(inj.name, inj.value);
				injectedNames.push(`?${inj.name}`);
			}
		}
		headers.host = target.host;
		audit(injectedNames, target.host);

		const upstreamReq = reqFn(target.protocol)(
			target,
			{ method: req.method, headers },
			(upstreamRes) => {
				// Stream the upstream response straight back. We deliberately do NOT
				// follow redirects: the injected credential is confined to this one
				// request, so a 3xx to another host can never carry it (spec §13.2).
				res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
				upstreamRes.pipe(res);
				upstreamRes.on("end", resolve);
				upstreamRes.on("error", reject);
			},
		);
		upstreamReq.on("error", reject);
		req.pipe(upstreamReq);
	});

// Build (but don't listen on) the proxy server over the given policies.
export const createProxyServer = (policies: LoadedPolicies): Server =>
	createServer((req, res) => {
		handleRequest(policies, req, res).catch((err) => {
			if (!res.headersSent)
				fail(res, 502, `proxy error: ${err instanceof Error ? err.message : "error"}`);
			else res.end();
		});
	});

// Env to preset on a spawned child so its SDK targets the proxy. Always sets
// VAULT_PROXY_URL; additionally sets the known base-URL var for each configured
// upstream host (so e.g. an Anthropic SDK picks ANTHROPIC_BASE_URL). The real
// secret is never added here — it lives only inside the proxy.
const childBaseUrlEnv = (policies: LoadedPolicies, proxyUrl: string): Record<string, string> => {
	const env: Record<string, string> = { VAULT_PROXY_URL: proxyUrl };
	let known = false;
	for (const host of policies.byHost.keys()) {
		for (const name of BASE_URL_ENV[host] ?? []) {
			env[name] = proxyUrl;
			known = true;
		}
	}
	if (!known)
		process.stderr.write(
			`note: no known base-URL env var for the configured upstream(s); point the agent's SDK at ${proxyUrl} (VAULT_PROXY_URL) manually\n`,
		);
	return env;
};

export type ProxyOptions = { configFiles: string[]; port: number };

// Load policies, stand up the loopback proxy, and either spawn the agent (with
// the base-URL env preset and the secret absent) or run in the foreground for an
// externally-launched agent. Returns the child's exit code (0 in foreground).
export const proxy = async (
	s: Session,
	opts: ProxyOptions,
	command?: string,
	args: string[] = [],
): Promise<number> => {
	const policies = await loadPolicies(s, opts.configFiles);
	const server = createProxyServer(policies);

	// Loopback only (spec §13.2): never reachable off this host.
	const host = "127.0.0.1";
	await new Promise<void>((resolve, reject) => {
		server.on("error", reject);
		server.listen(opts.port, host, resolve);
	});
	const addr = server.address();
	const port = typeof addr === "object" && addr ? addr.port : opts.port;
	const proxyUrl = `http://${host}:${port}`;
	process.stderr.write(`vault proxy listening on ${proxyUrl} (loopback only)\n`);

	if (!command) {
		// Foreground: run until signalled, for an agent launched separately.
		const env = childBaseUrlEnv(policies, proxyUrl); // also prints the manual-pointing note
		for (const [k, v] of Object.entries(env)) process.stderr.write(`  export ${k}=${v}\n`);
		await new Promise<void>((resolve) => {
			const shut = (): void => {
				server.closeAllConnections(); // don't wait on idle keep-alive sockets
				server.close(() => resolve());
			};
			process.on("SIGINT", shut);
			process.on("SIGTERM", shut);
		});
		return 0;
	}

	// Spawn the agent with the proxy preset and the real secret absent from env.
	const childEnv = { ...process.env, ...childBaseUrlEnv(policies, proxyUrl) };
	return await new Promise<number>((resolve, reject) => {
		const child = spawn(command, args, { env: childEnv, stdio: "inherit" });
		child.on("error", (err) => {
			server.closeAllConnections();
			server.close();
			reject(err);
		});
		child.on("exit", (code, signal) => {
			server.closeAllConnections();
			server.close(); // tear the proxy down when the agent exits
			if (signal) {
				process.kill(process.pid, signal);
				return;
			}
			resolve(code ?? 0);
		});
	});
};
