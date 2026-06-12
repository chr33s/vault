// Output mode for the CLI. Default is human-readable text (unchanged, so the
// existing UX and the SEA smoke test keep working). With `--json`, every command
// emits exactly one JSON object on stdout — a stable machine contract for GUI/
// native wrappers and automation. Errors in JSON mode are emitted as
// {"ok":false,"error":"..."} on stdout too (so callers parse one stream).

import { scrub } from "./scrub.ts";

let json = false;

export const setJsonOutput = (on: boolean): void => {
	json = on;
};
export const isJsonOutput = (): boolean => json;

// Emit a successful result. In text mode, `text` is written verbatim (the caller
// includes its own trailing newline, matching the prior behavior). In JSON mode,
// `data` is written as {"ok":true, ...data}.
//
// NOT scrubbed: success output is the command's deliberate result — `vault get`
// legitimately prints a secret, and the scrub registry is process-global, so
// scrubbing here would redact a retrieved value that happens to equal a value a
// proxy registered earlier in the same (embedded/REPL) process. Error output is
// where accidental secret interpolation happens, so only emitError scrubs.
export const emit = (text: string, data: Record<string, unknown>): void => {
	if (json) process.stdout.write(JSON.stringify({ ok: true, ...data }) + "\n");
	else process.stdout.write(text);
};

// Emit an error. Text mode -> stderr "error: msg"; JSON mode -> stdout object.
// Scrubbed: an error message must never carry a registered secret (e.g. a proxy
// injection value surfaced via a bubbled-up exception in main()'s catch).
export const emitError = (message: string): void => {
	if (json) process.stdout.write(scrub(JSON.stringify({ ok: false, error: message })) + "\n");
	else process.stderr.write(`error: ${scrub(message)}\n`);
};
