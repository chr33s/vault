// `vault proxy` — let an AI agent USE a secret without SEEING it (spec §13).
//
// Unlike `vault run` (plaintext into the child's env), the proxy keeps the
// credential out of the consumer: it injects on egress, only on requests bound
// for the policy's upstream. The agent points its SDK base-URL at us; we forward
// to the real upstream over genuine TLS and stream the response back.
//
// Two ingress shapes (spec §13.1): the default base-URL / reverse-proxy form
// (no TLS interception, no CA), and the opt-in `--connect` forward-proxy form
// for clients that only honor HTTPS_PROXY — there we terminate TLS with a leaf
// minted by an ephemeral, in-memory CA (cli/x509.ts) and run the decrypted
// request through the identical injection/scrubbing path.
//
// Security (spec §13.2): bind 127.0.0.1 only; attach each secret to its upstream
// host only; allowlist egress (reject unconfigured hosts); don't follow redirects
// (a credential can't cross to another host); never log/persist the value; emit a
// per-injection audit entry. As a backstop, every resolved value is registered
// with the scrubber (scrub.ts) so error paths we don't author — Node error
// messages, crash dumps, upstreams echoing the request — get redacted too.

import { spawn } from "node:child_process";
import { unlink, writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import {
	createServer,
	request as httpRequest,
	type IncomingHttpHeaders,
	type IncomingMessage,
	type Server,
	type ServerResponse,
} from "node:http";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pipeline } from "node:stream";
import { createSecureContext, type SecureContext, TLSSocket } from "node:tls";
import { parseDotenv } from "./dotenv.ts";
import type { Session } from "./engine.ts";
import { resolveOne } from "./run.ts";
import { installScrubbedFatalHandlers, makeScrubStream, registerSecret, scrub } from "./scrub.ts";
import { type Ca, createCa, issueLeaf } from "./x509.ts";

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
// the client sends only a path and the host is implicit). `byHostname` keys on
// the bare hostname (no port) for matching a CONNECT target's "host:port".
export type LoadedPolicies = {
	byHost: Map<string, Policy>;
	byHostname: Map<string, Policy>;
	defaultPolicy: Policy;
};

export const DEFAULT_PROXY_PORT = 8788;

// Drop a CONNECT tunnel whose TLS handshake doesn't complete in this window, so
// a client that was told "200" but never speaks TLS can't pin a socket open.
const HANDSHAKE_TIMEOUT_MS = 10_000;

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
		// Every resolved value is registered with the scrubber the moment it exists,
		// so no later error/log path can print it (spec §13.2: never log the value).
		registerSecret(value);
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
	const byHostname = new Map<string, Policy>();
	let defaultPolicy: Policy | undefined;
	for (const f of configFiles) {
		const text = await readFile(f, "utf8");
		const policy = parseProxyPolicy(s, text);
		byHost.set(policy.upstream.host, policy);
		byHostname.set(policy.upstream.hostname, policy);
		defaultPolicy ??= policy;
	}
	return { byHost, byHostname, defaultPolicy: defaultPolicy! };
};

// Per-injection audit (spec §13.2): upstream + rule names + timestamp, never the
// value. Operational, so it goes to stderr (keeps --json stdout clean).
const audit = (names: string[], host: string): void => {
	if (names.length === 0) return;
	process.stderr.write(
		scrub(`audit: ${new Date().toISOString()} injected [${names.join(", ")}] -> ${host}\n`),
	);
};

const reqFn = (protocol: string): typeof httpRequest =>
	protocol === "https:" ? (httpsRequest as typeof httpRequest) : httpRequest;

// Hop-by-hop / rewritten headers we never forward verbatim from the client.
const STRIP_HEADERS = new Set(["host", "connection", "proxy-connection"]);

// All client-visible error text is scrubbed: the agent prints what we send it
// (e.g. an SDK dumping a failed response to the console), so a secret in an
// error message here would leak via the agent's own logging.
const fail = (res: ServerResponse, status: number, msg: string): void => {
	res.writeHead(status, { "content-type": "text/plain" });
	res.end(scrub(msg));
};

// Scrub every relayed response-header value: an upstream 3xx Location (or an
// echo header) can reproduce the request URL including an injected query param.
const scrubHeaders = (h: IncomingHttpHeaders): Record<string, string | string[]> => {
	const out: Record<string, string | string[]> = {};
	for (const [k, v] of Object.entries(h)) {
		if (v === undefined) continue;
		out[k] = Array.isArray(v) ? v.map(scrub) : scrub(v);
	}
	return out;
};

// Only mask the body when it's textual and uncompressed. A compressed
// (content-encoding) or binary body can't be scrubbed without risking
// corruption, and a secret isn't present as plaintext there anyway — so we relay
// those byte-exact (header scrubbing still covers an echoed Location/query
// param). Best-effort, per spec §13.2: a textual echo with no content-type, or
// an exotic encoding, passes through.
const TEXTUAL_BODY =
	/^(?:text\/|application\/(?:json|xml|x-www-form-urlencoded|[\w.-]+\+(?:json|xml)))/i;
const isScrubbableBody = (h: IncomingHttpHeaders): boolean => {
	const enc = h["content-encoding"];
	if (typeof enc === "string" && enc.trim() !== "" && enc.trim().toLowerCase() !== "identity")
		return false;
	const ct = h["content-type"];
	return typeof ct === "string" && TEXTUAL_BODY.test(ct);
};

// Inject the policy's secrets, forward to the upstream over a real connection,
// and relay the (scrubbed) response. Shared by both ingress shapes: origin-form
// / base-URL requests and TLS-terminated CONNECT requests — so the host-binding,
// redirect, and scrubbing guarantees are identical on both paths.
const forwardToUpstream = (
	policy: Policy,
	req: IncomingMessage,
	res: ServerResponse,
	path: string,
): Promise<void> =>
	new Promise<void>((resolve, reject) => {
		// Resolve the target here, inside the executor: a malformed request-target
		// (e.g. "//") makes `new URL` throw, and inside the Promise that becomes a
		// clean 400 instead of a synchronous throw that would escape the caller's
		// .catch and crash the whole proxy.
		let target: URL;
		try {
			target = new URL(path, policy.upstream);
		} catch {
			req.resume();
			fail(res, 400, "bad request target");
			resolve();
			return;
		}

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
				// Relay the upstream response. We deliberately do NOT follow redirects:
				// the injected credential is confined to this one request, so a 3xx to
				// another host can never carry it (spec §13.2). Headers are scrubbed on
				// every status (Location can echo an injected query param).
				const status = upstreamRes.statusCode ?? 502;
				const resHeaders = scrubHeaders(upstreamRes.headers);

				// Scrub the body when it's textual, uncompressed, and the status/method
				// can carry one — a secret can be echoed in a 2xx/3xx body as readily as
				// in a 4xx. Binary/compressed bodies relay byte-exact (redaction could
				// corrupt them and a plaintext secret can't appear). Redaction changes
				// the body length, so drop content-length and let Node frame the relayed
				// body as chunked.
				const bodyless = req.method === "HEAD" || status === 204 || status === 304 || status < 200;
				const scrubBody = !bodyless && isScrubbableBody(upstreamRes.headers);
				if (scrubBody) delete resHeaders["content-length"];
				res.writeHead(status, resHeaders);

				// `pipeline` supplies backpressure, error propagation, and
				// end-of-stream/flush, so a mid-stream upstream failure aborts the
				// response chain rather than being patched by hand. Headers are already
				// sent, so we resolve regardless of error (the status can't change).
				if (scrubBody) pipeline(upstreamRes, makeScrubStream(), res, () => resolve());
				else pipeline(upstreamRes, res, () => resolve());
			},
		);
		upstreamReq.on("error", (err) => {
			// Never propagate the raw Node error: it can reference the request options
			// (injected headers included), and some codes echo the offending value in
			// their message (e.g. ERR_HTTP_INVALID_HEADER_VALUE). Re-wrap minimally.
			const code = (err as NodeJS.ErrnoException).code;
			reject(new Error(scrub(`upstream ${code ?? "error"}: ${err.message}`)));
		});
		// A client abort emits 'error' on req/res; unhandled, Node would crash the
		// proxy and dump the error unscrubbed. Tear down the upstream leg quietly.
		req.on("error", () => {
			upstreamReq.destroy();
			resolve();
		});
		res.on("error", () => {
			upstreamReq.destroy();
			resolve();
		});
		req.pipe(upstreamReq);
	});

// Origin-form / base-URL ingress. An absolute request-URI (forward-proxy form)
// names a host explicitly — it MUST be in the allowlist. An origin-form path
// (base-URL form) uses the default policy.
const handleRequest = (
	policies: LoadedPolicies,
	req: IncomingMessage,
	res: ServerResponse,
): Promise<void> => {
	const rawUrl = req.url ?? "/";
	let policy: Policy;
	if (/^https?:\/\//i.test(rawUrl)) {
		let asked: URL;
		try {
			asked = new URL(rawUrl);
		} catch {
			req.resume();
			fail(res, 400, "bad request URI");
			return Promise.resolve();
		}
		const p = policies.byHost.get(asked.host);
		if (!p) {
			// Egress allowlist: refuse any host we hold no policy for (SSRF guard).
			req.resume();
			fail(res, 403, `host not allowlisted: ${asked.host}`);
			return Promise.resolve();
		}
		policy = p;
	} else {
		policy = policies.defaultPolicy;
	}
	const path = rawUrl.replace(/^https?:\/\/[^/]+/i, "") || "/";
	return forwardToUpstream(policy, req, res, path);
};

// CONNECT inner ingress: the client has TLS-terminated against us and now sends
// origin-form requests carrying a Host header naming the upstream. Resolve the
// policy by that hostname against the allowlist (the tunnel was already gated on
// it, but match defensively) and forward through the identical path.
const handleTunneledRequest = (
	policies: LoadedPolicies,
	req: IncomingMessage,
	res: ServerResponse,
): Promise<void> => {
	const hostname = (req.headers.host ?? "").replace(/:\d+$/, "");
	const policy = policies.byHostname.get(hostname);
	if (!policy) {
		req.resume();
		fail(res, 403, `host not allowlisted: ${hostname}`);
		return Promise.resolve();
	}
	return forwardToUpstream(policy, req, res, req.url ?? "/");
};

const onError = (res: ServerResponse, err: unknown): void => {
	if (!res.headersSent)
		fail(res, 502, `proxy error: ${err instanceof Error ? err.message : "error"}`);
	else res.end();
};

// Attach forward-proxy (CONNECT) handling to a server. For clients that only
// honor HTTPS_PROXY (no base-URL override), we terminate TLS with a leaf minted
// by the ephemeral CA, then feed the decrypted stream into an inner HTTP parser
// that runs the SAME injection/forwarding/scrubbing as base-URL mode. We only
// ever mint certs for — and open tunnels to — allowlisted hosts, so the egress
// boundary and host-binding hold exactly as in the reverse-proxy path.
const attachConnect = (server: Server, policies: LoadedPolicies, ca: Ca): void => {
	const inner = createServer((req, res) => {
		handleTunneledRequest(policies, req, res).catch((err) => onError(res, err));
	});

	// Cache one SecureContext per host. Keyed on the Promise so two concurrent
	// first-connects to the same host don't mint two leaves; issueLeaf's RSA
	// keygen is async, so the event loop is never blocked while minting.
	const contexts = new Map<string, Promise<SecureContext>>();
	const ctxFor = (hostname: string): Promise<SecureContext> => {
		let c = contexts.get(hostname);
		if (!c) {
			c = issueLeaf(ca, hostname).then((leaf) =>
				createSecureContext({ key: leaf.keyPem, cert: leaf.certPem }),
			);
			// Don't memoize a failure: a transient keygen error must not blackhole
			// the host for the proxy's lifetime — drop it so the next connect retries.
			c.catch(() => contexts.delete(hostname));
			contexts.set(hostname, c);
		}
		return c;
	};

	server.on("connect", (req, clientSocket, head) => {
		const hostname = (req.url ?? "").replace(/:\d+$/, "");
		clientSocket.on("error", () => clientSocket.destroy());
		if (!policies.byHostname.has(hostname)) {
			// Egress allowlist for the tunnel: refuse to open it (and never present a
			// cert) for a host we hold no policy for, so the agent's secret-bearing
			// TLS session never even starts.
			clientSocket.end(
				`HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\nhost not allowlisted: ${hostname}\n`,
			);
			return;
		}
		ctxFor(hostname).then(
			(ctx) => {
				// The client may have gone away during the async keygen window; don't
				// write/wrap a dead socket.
				if (clientSocket.destroyed) return;
				clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
				if (head?.length) clientSocket.unshift(head); // any pre-read TLS bytes
				const tlsSocket = new TLSSocket(clientSocket, { isServer: true, secureContext: ctx });
				// Bound the handshake: a tunnel told "200" that never completes TLS
				// (a stalled or cert-pinning client) must not linger. Destroy on
				// timeout, and tear the underlying socket down whenever the TLS leg
				// closes, so half-open tunnels can't accumulate.
				const timer = setTimeout(() => tlsSocket.destroy(), HANDSHAKE_TIMEOUT_MS);
				timer.unref();
				tlsSocket.once("secure", () => {
					clearTimeout(timer);
					inner.emit("connection", tlsSocket); // decrypted duplex -> inner parser
				});
				tlsSocket.on("error", () => tlsSocket.destroy());
				tlsSocket.on("close", () => clientSocket.destroy());
			},
			() => clientSocket.destroy(), // cert minting failed: drop the tunnel
		);
	});
};

// Build (but don't listen on) the proxy server over the given policies. With a
// CA, additionally enables forward-proxy (CONNECT) mode (spec §13.1).
export const createProxyServer = (policies: LoadedPolicies, ca?: Ca): Server => {
	const server = createServer((req, res) => {
		handleRequest(policies, req, res).catch((err) => onError(res, err));
	});
	if (ca) attachConnect(server, policies, ca);
	return server;
};

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

// Extra env for CONNECT mode: route the child's HTTPS through us and make it
// trust the ephemeral CA via every common trust-store override. Scoped to the
// spawned child and this session only — the CA private key never leaves memory;
// `caFile` holds only the public cert.
const connectEnv = (proxyUrl: string, caFile: string): Record<string, string> => ({
	HTTPS_PROXY: proxyUrl,
	https_proxy: proxyUrl,
	NODE_EXTRA_CA_CERTS: caFile, // node
	SSL_CERT_FILE: caFile, // openssl / most TLS libs
	REQUESTS_CA_BUNDLE: caFile, // python requests / httpx
	CURL_CA_BUNDLE: caFile, // curl
});

export type ProxyOptions = { configFiles: string[]; port: number; connect?: boolean };

// Load policies, stand up the loopback proxy, and either spawn the agent (with
// the base-URL env preset and the secret absent) or run in the foreground for an
// externally-launched agent. Returns the child's exit code (0 in foreground).
export const proxy = async (
	s: Session,
	opts: ProxyOptions,
	command?: string,
	args: string[] = [],
): Promise<number> => {
	// NODE_DEBUG=http (and friends) makes Node's internals print outgoing request
	// headers — injected secrets included — to stderr, beneath any scrubbing we
	// can do. Refuse to start rather than leak. The `\*` alternative also catches
	// the glob forms Node honors (NODE_DEBUG=* enables ALL sections; `htt*`/`ht*p`
	// enable http) which name no risky section literally.
	const nodeDebug = process.env.NODE_DEBUG ?? "";
	if (/http|net|tls|stream|\*/i.test(nodeDebug))
		throw new Error(
			`refusing to start: NODE_DEBUG="${nodeDebug}" would log injected secrets to stderr`,
		);

	const policies = await loadPolicies(s, opts.configFiles);
	// From here on, resolved secrets are in memory: replace Node's default crash
	// dumpers with scrubbed ones for the proxy's lifetime.
	const unscrub = installScrubbedFatalHandlers();

	// CONNECT mode mints an in-memory ephemeral CA; only its public cert is
	// written to disk (for the child to trust), and only for this session. The
	// private key never leaves memory and ceases to exist when the proxy exits.
	let ca: Ca | undefined;
	let caFile: string | undefined;
	if (opts.connect) {
		ca = await createCa(); // async RSA keygen: doesn't block the event loop
		caFile = join(tmpdir(), `vault-proxy-ca-${process.pid}-${Date.now()}.pem`);
		await writeFile(caFile, ca.certPem, { mode: 0o600 });
	}
	const teardown = (): void => {
		unscrub();
		if (caFile) void unlink(caFile).catch(() => {}); // best-effort cleanup
	};
	const server = createProxyServer(policies, ca);

	// Loopback only (spec §13.2): never reachable off this host.
	const host = "127.0.0.1";
	await new Promise<void>((resolve, reject) => {
		server.on("error", reject);
		server.listen(opts.port, host, resolve);
	});
	const addr = server.address();
	const port = typeof addr === "object" && addr ? addr.port : opts.port;
	const proxyUrl = `http://${host}:${port}`;
	process.stderr.write(
		`vault proxy listening on ${proxyUrl} (loopback only${opts.connect ? "; CONNECT/HTTPS_PROXY mode" : ""})\n`,
	);

	// Base-URL env (always) plus, in CONNECT mode, the HTTPS_PROXY + CA-trust env.
	const childEnvExtra = (): Record<string, string> => ({
		...childBaseUrlEnv(policies, proxyUrl),
		...(caFile ? connectEnv(proxyUrl, caFile) : {}),
	});

	if (!command) {
		// Foreground: run until signalled, for an agent launched separately.
		const env = childEnvExtra(); // also prints the manual-pointing note
		for (const [k, v] of Object.entries(env)) process.stderr.write(`  export ${k}=${v}\n`);
		await new Promise<void>((resolve) => {
			const shut = (): void => {
				server.closeAllConnections(); // don't wait on idle keep-alive sockets
				server.close(() => {
					// Remove our own signal handlers so repeated foreground proxy() calls
					// in one process don't accumulate listeners or fire against a closed
					// server.
					process.removeListener("SIGINT", shut);
					process.removeListener("SIGTERM", shut);
					teardown();
					resolve();
				});
			};
			process.on("SIGINT", shut);
			process.on("SIGTERM", shut);
		});
		return 0;
	}

	// Spawn the agent with the proxy preset and the real secret absent from env.
	const childEnv = { ...process.env, ...childEnvExtra() };
	return await new Promise<number>((resolve, reject) => {
		const child = spawn(command, args, { env: childEnv, stdio: "inherit" });
		child.on("error", (err) => {
			server.closeAllConnections();
			server.close();
			teardown();
			reject(err);
		});
		child.on("exit", (code, signal) => {
			server.closeAllConnections();
			server.close(); // tear the proxy down when the agent exits
			teardown();
			if (signal) {
				process.kill(process.pid, signal);
				return;
			}
			resolve(code ?? 0);
		});
	});
};
