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

// Read one raw line from the stdin protocol. Used for `--field-stdin` values,
// which travel over stdin like passphrases so item field secrets (PINs, security
// answers) never appear on argv (world-readable via `ps`). Only valid in stdin
// mode — the GUI/native wrapper that sends fields this way always sets it.
export const readStdinLine = async (): Promise<string> => {
	if (source !== "stdin") throw new Error("--field-stdin requires --passphrase-stdin");
	return nextStdinLine();
};

// Close the stdin reader so the process can exit cleanly (no-op if unused).
export const closePassphraseSource = (): void => {
	rl?.close();
	rl = undefined;
	lines = undefined;
};

// `useEnv` gates the $VAULT_PASSPHRASE fallback. It is the account-unlock secret,
// so secondary prompts (e.g. an item's own password) MUST pass useEnv:false — a
// single exported VAULT_PASSPHRASE would otherwise be silently stored as the
// item's password (wrong credential saved, master passphrase now retrievable).
export const readPassphrase = async (
	prompt = "Passphrase: ",
	opts: { useEnv?: boolean } = {},
): Promise<string> => {
	if (source === "stdin") return nextStdinLine();

	const fromEnv = process.env.VAULT_PASSPHRASE;
	if ((opts.useEnv ?? true) && fromEnv !== undefined) return fromEnv;
	if (!process.stdin.isTTY) {
		throw new Error("no TTY and VAULT_PASSPHRASE unset; cannot read passphrase");
	}

	const rli = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
	const out = process.stdout;
	const origWrite = out.write.bind(out);
	const restore = (): void => {
		(out as unknown as { write: typeof out.write }).write = origWrite;
	};
	// Fully suppress terminal output while the secret is entered. A prompt-substring
	// filter is unsafe: readline's line refresh (backspace, arrow keys, Ctrl-U,
	// resize, wrap) rewrites `prompt + line`, which contains the prompt and would
	// echo the typed passphrase. Instead we print the prompt ourselves, then swallow
	// everything readline writes until the answer is in.
	let muted = false;
	(out as unknown as { write: typeof out.write }).write = ((
		chunk: string | Uint8Array,
		...rest: unknown[]
	) => {
		if (muted) return true;
		return origWrite(chunk as string, ...(rest as []));
	}) as typeof out.write;
	origWrite(prompt);

	return await new Promise<string>((resolve, reject) => {
		let settled = false;
		const finish = (fn: () => void): void => {
			if (settled) return;
			settled = true;
			restore();
			rli.close();
			fn();
		};
		// Ctrl-C (SIGINT) and Ctrl-D (EOF, surfaced as `close` before any answer)
		// must abort with an error and a non-zero exit — never resolve to an empty or
		// partial secret, which a scripted `vault run` would misread as success.
		rli.on("SIGINT", () => {
			origWrite("\n");
			finish(() => reject(new Error("passphrase entry cancelled")));
		});
		rli.on("close", () => finish(() => reject(new Error("passphrase entry cancelled"))));
		rli.question("", (answer) => {
			origWrite("\n");
			finish(() => resolve(answer));
		});
		muted = true;
	});
};
