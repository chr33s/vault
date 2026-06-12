// scrub.ts: the last-line-of-defense redaction registry behind `vault proxy`
// (spec §13.2 "never log the value"). Registered values — and the encodings
// they commonly travel under — must never survive into console or CLI output.

import assert from "node:assert/strict";
import type { Transform } from "node:stream";
import { test } from "node:test";
import { emit, emitError } from "../cli/output.ts";
import { makeScrubStream, registerSecret, scrub } from "../cli/scrub.ts";

// Drive the scrubber Transform over the given chunks and collect its output.
const runScrub = (stream: Transform, chunks: Buffer[]): Promise<Buffer> =>
	new Promise((resolve, reject) => {
		const out: Buffer[] = [];
		stream.on("data", (c: Buffer) => out.push(c));
		stream.on("end", () => resolve(Buffer.concat(out)));
		stream.on("error", reject);
		for (const c of chunks) stream.write(c);
		stream.end();
	});

test("scrub redacts a registered secret and its common encodings", () => {
	const secret = 'p@ss "word"/2+x';
	registerSecret(secret);

	assert.equal(scrub(`bad credential: ${secret}!`), "bad credential: [REDACTED]!", "raw form");
	assert.equal(
		scrub(`GET /login?key=${encodeURIComponent(secret)}&a=b`),
		"GET /login?key=[REDACTED]&a=b",
		"URL-encoded form",
	);
	assert.equal(
		scrub(JSON.stringify({ error: `invalid key ${secret}` })),
		'{"error":"invalid key [REDACTED]"}',
		"JSON-escaped form (stays valid JSON)",
	);
	assert.equal(
		scrub(`authorization: Basic ${Buffer.from(secret).toString("base64")}`),
		"authorization: Basic [REDACTED]",
		"base64 (Basic-auth) form",
	);
	assert.equal(scrub("nothing sensitive here"), "nothing sensitive here");
});

test("values below the length threshold are not registered (no over-redaction)", () => {
	registerSecret("abc");
	assert.equal(scrub("abc is a common substring"), "abc is a common substring");
});

test("emitError scrubs registered secrets from CLI error output", (t) => {
	const secret = "sk-ant-test-0123456789";
	registerSecret(secret);

	const captured: string[] = [];
	t.mock.method(process.stderr, "write", (chunk: unknown): boolean => {
		captured.push(String(chunk));
		return true;
	}); // auto-restored when the test ends

	emitError(`upstream rejected key ${secret}`);

	const out = captured.join("");
	assert.ok(!out.includes(secret), "secret absent from stderr");
	assert.match(out, /error: upstream rejected key \[REDACTED\]/);
});

test("emit does NOT scrub: a command's deliberate output (e.g. vault get) is verbatim", (t) => {
	// A retrieved secret that happens to equal a registered proxy value must still
	// print — scrubbing belongs on the error path, not on intended success output.
	const secret = "retrieved-secret-value-123";
	registerSecret(secret);

	const captured: string[] = [];
	t.mock.method(process.stdout, "write", (chunk: unknown): boolean => {
		captured.push(String(chunk));
		return true;
	});

	emit(`${secret}\n`, { value: secret });
	assert.equal(captured.join(""), `${secret}\n`, "emit prints the value unredacted");
});

test("makeScrubStream redacts across chunk boundaries with the [REDACTED] marker", async () => {
	const secret = "boundary-secret-xyz";
	registerSecret(secret);

	// Feed the secret split across many tiny chunks; the scrubber must still
	// redact it (binary-safe latin1), reassembling to the same marker bodies use.
	const text = `prefix ${secret} suffix`;
	const chunks: Buffer[] = [];
	for (let i = 0; i < text.length; i += 3) chunks.push(Buffer.from(text.slice(i, i + 3), "latin1"));
	const result = (await runScrub(makeScrubStream(), chunks)).toString("latin1");

	assert.ok(!result.includes(secret), "secret redacted even when split across chunks");
	assert.equal(result, "prefix [REDACTED] suffix");
});

test("makeScrubStream emits promptly when the tail cannot start a secret (no full-window lag)", () => {
	registerSecret("responsive-stream-secret");
	const ss = makeScrubStream();
	// End the chunk in a long run of NUL bytes: no registered pattern (printable
	// secret, URL/JSON/base64 form) can start with NUL, so the whole tail window
	// is "settled" and nothing is held back — the entire chunk emits synchronously
	// in the very next read. The old code always held back maxPatternBytes-1 bytes.
	const padded = Buffer.concat([
		Buffer.from("visible streamed content", "latin1"),
		Buffer.alloc(300),
	]);
	ss.write(padded);
	const out = ss.read() as Buffer;
	assert.equal(out.length, padded.length, "no holdback when the tail can't begin a secret");
	assert.equal(out.subarray(0, 24).toString("latin1"), "visible streamed content");
});
