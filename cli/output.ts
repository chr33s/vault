// Output mode for the CLI. Default is human-readable text (unchanged, so the
// existing UX and the SEA smoke test keep working). With `--json`, every command
// emits exactly one JSON object on stdout — a stable machine contract for GUI/
// native wrappers and automation. Errors in JSON mode are emitted as
// {"ok":false,"error":"..."} on stdout too (so callers parse one stream).

import { scrub } from "./scrub.ts";

let json = false;

// Control characters that a terminal interprets as escape/format sequences.
// Keeps \t (09) and \n (0A); escapes ESC, CR, C0/C1 and DEL so a field value or
// item title synced from another (possibly hostile) member can't smuggle e.g.
// OSC-52 clipboard writes or cursor/erase sequences into the viewer's terminal.
// oxlint-disable-next-line no-control-regex -- matching control chars is the point
const TTY_UNSAFE = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/g;
const sanitizeForTty = (s: string): string =>
	s.replace(TTY_UNSAFE, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);

// Only interactive terminals interpret escapes; a pipe/redirect gets the raw
// bytes so `vault get x | …` scripting still sees the exact stored value.
const forStdout = (text: string): string => (process.stdout.isTTY ? sanitizeForTty(text) : text);
const forStderr = (text: string): string => (process.stderr.isTTY ? sanitizeForTty(text) : text);

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
// Text-mode output to an interactive terminal is control-char-sanitized (see
// forStdout) so untrusted synced content can't drive the viewer's terminal; JSON
// output is left raw for machine consumers.
export const emit = (text: string, data: Record<string, unknown>): void => {
	if (json) process.stdout.write(JSON.stringify({ ok: true, ...data }) + "\n");
	else process.stdout.write(forStdout(text));
};

// Emit an error. Text mode -> stderr "error: msg"; JSON mode -> stdout object.
// Scrubbed: an error message must never carry a registered secret (e.g. a proxy
// injection value surfaced via a bubbled-up exception in main()'s catch).
export const emitError = (message: string): void => {
	if (json) process.stdout.write(scrub(JSON.stringify({ ok: false, error: message })) + "\n");
	else process.stderr.write(`error: ${forStderr(scrub(message))}\n`);
};
