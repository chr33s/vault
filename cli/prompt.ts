// Passphrase input (plan §5). Three sources, in priority order:
//   1. stdin protocol  — when enabled (setPassphraseSource("stdin")), each call
//      consumes ONE newline-terminated line from stdin. Used by GUI/native
//      wrappers and automation: secrets cross the process boundary over stdin,
//      never argv (world-readable) or env (leaks to children, shell history).
//      Multiple prompts in one command read successive lines (account passphrase
//      first, then e.g. an item password).
//   2. $VAULT_PASSPHRASE — non-interactive single secret (tests/CI, scripts).
//   3. muted TTY prompt — interactive default.
// This only sources the passphrase. An OS keystore can fold in a second at-rest
// factor (see keystore.ts); per-access biometric unlock is future native-wrapper
// work. None of these read the keystore here — that happens in the engine.

import { createInterface, type Interface } from "node:readline";

type Source = "auto" | "stdin";
let source: Source = "auto";

// Select where readPassphrase() reads from. Call once at startup.
export const setPassphraseSource = (s: Source): void => {
	source = s;
};

// Lazily-opened line iterator over stdin (shared across multiple prompts).
let rl: Interface | undefined;
let lines: AsyncIterableIterator<string> | undefined;
const nextStdinLine = async (): Promise<string> => {
	if (!lines) {
		rl = createInterface({ input: process.stdin });
		lines = rl[Symbol.asyncIterator]();
	}
	const { value, done } = await lines.next();
	if (done) throw new Error("expected a passphrase on stdin (one secret per line)");
	return value;
};

// Close the stdin reader so the process can exit cleanly (no-op if unused).
export const closePassphraseSource = (): void => {
	rl?.close();
	rl = undefined;
	lines = undefined;
};

export const readPassphrase = async (prompt = "Passphrase: "): Promise<string> => {
	if (source === "stdin") return nextStdinLine();

	const fromEnv = process.env.VAULT_PASSPHRASE;
	if (fromEnv !== undefined) return fromEnv;
	if (!process.stdin.isTTY) {
		throw new Error("no TTY and VAULT_PASSPHRASE unset; cannot read passphrase");
	}

	const rli = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
	// Mute echo while typing.
	const out = process.stdout;
	const origWrite = out.write.bind(out);
	let muted = false;
	(out as unknown as { write: typeof out.write }).write = ((
		chunk: string | Uint8Array,
		...rest: unknown[]
	) => {
		if (muted && typeof chunk === "string" && !chunk.includes(prompt)) return true;
		return origWrite(chunk as string, ...(rest as []));
	}) as typeof out.write;

	return await new Promise<string>((resolve) => {
		rli.question(prompt, (answer) => {
			(out as unknown as { write: typeof out.write }).write = origWrite;
			out.write("\n");
			rli.close();
			resolve(answer);
		});
		muted = true;
	});
};
