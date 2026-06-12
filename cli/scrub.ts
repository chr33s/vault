// Last-line-of-defense secret scrubbing (spec §13.2: never log the value).
//
// The primary rule everywhere stays "never put a secret into a message". This
// registry is the backstop for the paths we don't author: a Node error that
// echoes an offending header value (ERR_HTTP_INVALID_HEADER_VALUE prints the
// value verbatim), an upstream 4xx that echoes the request URL including an
// injected query param, or a crash dump from the default uncaughtException
// handler. Every value the proxy resolves is registered here, and every
// console/client egress point redacts registered values before writing.
//
// Best-effort by design: exotic encodings (hex, compressed bodies) and values
// shorter than MIN_LEN pass through — consistent with the repo's accepted
// "no key-memory zeroing in JS" posture (plan §M8 known issues).

import { Transform } from "node:stream";
import { inspect } from "node:util";

// Below this, redaction would fire on too many innocent substrings to be useful.
const MIN_LEN = 6;
// One uniform marker everywhere — messages, headers, audit lines, crash dumps,
// AND response bodies — so "redacted" is a single greppable token, not a
// path-dependent spelling. Body framing is decoupled from this (the proxy drops
// content-length for a scrubbed body and lets Node chunk it), so the marker need
// not be length-preserving.
const REDACTION = "[REDACTED]";

// One record per registered form holds both the utf8 string (to match JS-string
// inputs: messages, headers) and its latin1 byte-form (to match raw response
// bytes decoded 1:1). Keeping both on a single record makes them structurally
// inseparable — there are no parallel collections to fall out of sync. The
// `firstBytes`/`maxPatternBytes` indexes are aggregates maintained by the one
// mutator (addPattern), used only to size the streaming carry window.
type Pattern = { utf8: string; latin1: string };
const patterns: Pattern[] = [];
const seen = new Set<string>(); // dedup guard, keyed by utf8 form
const firstBytes = new Set<string>(); // latin1 first byte of each pattern
let maxPatternBytes = 0; // longest pattern's latin1 byte length

const addPattern = (utf8: string): void => {
	if (seen.has(utf8)) return;
	seen.add(utf8);
	const latin1 = Buffer.from(utf8, "utf8").toString("latin1");
	patterns.push({ utf8, latin1 });
	if (latin1.length > 0) firstBytes.add(latin1[0]!);
	if (latin1.length > maxPatternBytes) maxPatternBytes = latin1.length;
};

// Register a resolved value plus the encodings it commonly travels under.
export const registerSecret = (value: string): void => {
	if (value.length < MIN_LEN) return;
	addPattern(value);
	addPattern(encodeURIComponent(value)); // URL / query-string form
	addPattern(JSON.stringify(value).slice(1, -1)); // JSON-escaped form
	addPattern(Buffer.from(value, "utf8").toString("base64")); // Basic-auth form
};

// Replace each registered secret with REDACTION. `form` selects which byte-view
// to match against: "utf8" for JS-string inputs (messages, headers, logs),
// "latin1" for raw response bytes decoded 1:1.
const redact = (text: string, form: "utf8" | "latin1"): string => {
	let out = text;
	for (const p of patterns) {
		const needle = form === "utf8" ? p.utf8 : p.latin1;
		if (out.includes(needle)) out = out.split(needle).join(REDACTION);
	}
	return out;
};

// Scrub a short string — error messages, header values, audit/log lines.
export const scrub = (text: string): string => redact(text, "utf8");

// A streaming, binary-safe scrubber for relayed response bodies, as a
// node:stream Transform — so callers get backpressure, error propagation, and
// end-of-stream/flush from `pipeline` rather than wiring them by hand. Unlike
// scrub(), it never buffers the whole body and never corrupts multibyte/binary
// content (latin1 is a 1:1 byte<->char map).
//
// It holds back only the *minimal* tail that could be the start of an as-yet
// incomplete match — the earliest position, within the last (maxPatternBytes-1)
// bytes, holding a byte that begins some pattern. When the tail can't start a
// secret (the common case) it holds back nothing, so streaming stays responsive
// instead of always lagging a full max-pattern window. A complete match is
// already redacted (so its bytes are the marker, not raw secret), and the
// held-back tail is re-examined when the next chunk arrives.
export const makeScrubStream = (): Transform => {
	let carry = "";
	return new Transform({
		transform(chunk: Buffer, _enc, cb): void {
			// No registered secrets -> pure passthrough, zero per-chunk work.
			if (patterns.length === 0) {
				cb(null, chunk);
				return;
			}
			const hadCarry = carry.length > 0;
			const input = carry + chunk.toString("latin1");
			const redacted = redact(input, "latin1");
			// Read maxPatternBytes now (not at construction) so a secret registered
			// after this stream was created still sizes the window correctly.
			const keep = maxPatternBytes > 1 ? maxPatternBytes - 1 : 0;
			const windowStart = Math.max(0, redacted.length - keep);
			let cut = redacted.length;
			for (let i = windowStart; i < redacted.length; i++) {
				if (firstBytes.has(redacted[i]!)) {
					cut = i;
					break;
				}
			}
			carry = redacted.slice(cut); // settled-but-incomplete tail
			// Fast path: nothing redacted and nothing held back -> forward the
			// original chunk, avoiding a re-encode of bytes that didn't change.
			if (!hadCarry && cut === redacted.length && redacted === input) {
				cb(null, chunk);
				return;
			}
			cb(null, Buffer.from(redacted.slice(0, cut), "latin1"));
		},
		flush(cb): void {
			const out = carry;
			carry = "";
			cb(null, out.length > 0 ? Buffer.from(out, "latin1") : undefined);
		},
	});
};

// Replace Node's default fatal dumpers while secrets are registered: the
// default handler prints the raw error object, which can reference the request
// options (injected headers included) via its properties or message. Returns
// an uninstaller so a finished `vault proxy` restores normal crash behavior.
export const installScrubbedFatalHandlers = (): (() => void) => {
	const fatal = (err: unknown): void => {
		process.stderr.write(`fatal: ${scrub(inspect(err))}\n`);
		process.exit(1);
	};
	process.on("uncaughtException", fatal);
	process.on("unhandledRejection", fatal);
	return () => {
		process.removeListener("uncaughtException", fatal);
		process.removeListener("unhandledRejection", fatal);
	};
};
