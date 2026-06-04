// Output mode contract (cli/output.ts): text mode writes verbatim to stdout and
// "error: …" to stderr; --json mode writes exactly one {"ok":…} object to stdout
// for both success and error (so wrappers parse a single stream).

import assert from "node:assert/strict";
import { test } from "node:test";
import { setJsonOutput, isJsonOutput, emit, emitError } from "../cli/output.ts";

// Capture everything written to a stream while fn runs.
const capture = (stream: NodeJS.WriteStream, fn: () => void): string => {
	const orig = stream.write.bind(stream);
	let out = "";
	(stream as unknown as { write: (c: unknown) => boolean }).write = (chunk: unknown) => {
		out += String(chunk);
		return true;
	};
	try {
		fn();
	} finally {
		(stream as unknown as { write: typeof orig }).write = orig;
	}
	return out;
};

test("text mode: emit writes the text verbatim, emitError goes to stderr", () => {
	setJsonOutput(false);
	assert.equal(isJsonOutput(), false);
	const out = capture(process.stdout, () => emit("hello\n", { ignored: true }));
	assert.equal(out, "hello\n");
	const err = capture(process.stderr, () => emitError("boom"));
	assert.equal(err, "error: boom\n");
});

test("json mode: emit and emitError each write one object to stdout", () => {
	setJsonOutput(true);
	try {
		assert.equal(isJsonOutput(), true);
		const ok = capture(process.stdout, () => emit("ignored text", { a: 1, b: "x" }));
		assert.deepEqual(JSON.parse(ok), { ok: true, a: 1, b: "x" });
		assert.ok(ok.endsWith("\n"));
		const errOut = capture(process.stdout, () => emitError("nope"));
		assert.deepEqual(JSON.parse(errOut), { ok: false, error: "nope" });
	} finally {
		setJsonOutput(false); // restore module global for any later test
	}
});
