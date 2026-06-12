// Allowlist log hardening for the relay (spec §8: zero-knowledge).
//
// The relay never holds a *vault* secret — payloads are opaque ciphertext it
// cannot read — so the proxy's value-registry scrubber (cli/scrub.ts) has
// nothing to register here. But the relay does see a different credential class
// on every request: the Cloudflare Access JWT / service-token headers that
// authorize it. The failure mode is the same one we closed in the proxy — an
// error echoing the request to a log or a 500 body.
//
// The relay's defense is stronger than scrubbing precisely because it knows it
// never legitimately needs to log a header or body: it logs an *allowlist* of
// safe fields and nothing else. A credential can't leak through a sink that
// takes no header/body argument.
//
// Node-only (uses `process`); never imported by handler.ts, which must stay
// free of node:* so it still bundles into the Workers runtime.

// The single body we ever return on an unexpected server error. Clients are our
// own CLI, which needs no server-side diagnostics in the response (unlike the
// proxy, whose client is an opaque agent — hence the proxy scrubs rather than
// blanks). An echoed err.message could carry an Access token; this can't.
export const GENERIC_500 = { error: "internal error" } as const;

// Replace Node's default fatal dumpers, which print the whole error object —
// and any request it transitively references (credential headers included) —
// with a handler that prints only message + stack (code locations, not data).
export const installSafeFatalHandlers = (): void => {
	const fatal = (err: unknown): void => {
		const e = err instanceof Error ? err : new Error(String(err));
		process.stderr.write(`relay fatal: ${e.message}\n${e.stack ?? ""}\n`);
		process.exit(1);
	};
	process.on("uncaughtException", fatal);
	process.on("unhandledRejection", fatal);
};
