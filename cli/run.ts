// `vault run` — resolve declared env vars from the vault and inject them into a
// child process (plan §5). Resolved secrets never touch disk: the .env stays a
// secret-free manifest. Resolution reads the local replica only (offline/instant).

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { finished } from "node:stream/promises";
import type { ItemView } from "../core/crdt.ts";
import { parseDotenv, parseVaultRef, type EnvDecl } from "./dotenv.ts";
import { getItem, type Session } from "./engine.ts";
import { installScrubbedFatalHandlers, makeScrubStream, registerSecret } from "./scrub.ts";

export type ResolveOptions = {
	envFile: string;
	defaultVault: string;
	allowMissing: boolean;
	// --mask: pipe the child's stdout/stderr through the secret scrubber so a
	// child that echoes an injected value gets it redacted (plan §11). Opt-in
	// because piping (vs inheriting) forgoes a TTY on the child's output streams.
	mask?: boolean;
};

export type Resolution = {
	env: Record<string, string>;
	missing: string[];
};

// Pull a field value out of a materialized item. The password multi-value
// register exposes its (single, resolved) value; ambiguity is surfaced.
const fieldValue = (item: ItemView, field: string): string | undefined => {
	if (field === "password") {
		if (item.passwords.length === 1) return item.passwords[0];
		if (item.passwords.length === 0) return undefined;
		throw new Error(
			`item "${item.fields.title}" has ${item.passwords.length} unresolved password values; resolve the conflict first`,
		);
	}
	return item.fields[field];
};

// Resolve a single declaration against ambient env + the vault. Exported so
// `vault proxy` resolves its injection values with the identical precedence
// (ambient non-empty -> literal -> vault lookup), per spec §13.1 / plan §5.
export const resolveOne = (s: Session, decl: EnvDecl): string | undefined => {
	const ambient = process.env[decl.key];

	// 1. Ambient non-empty value always wins (local override).
	if (ambient !== undefined && ambient !== "") return ambient;

	// 4. Explicit vault:// reference — resolve regardless of emptiness.
	if (decl.value && decl.value.startsWith("vault://")) {
		const ref = parseVaultRef(decl.value);
		if (!ref) throw new Error(`bad vault reference for ${decl.key}: ${decl.value}`);
		const item = getItem(s, ref.item);
		if (!item) return undefined;
		return fieldValue(item, ref.field ?? "password");
	}

	// 2. Literal non-empty value passes through verbatim.
	if (decl.value !== undefined && decl.value !== "") return decl.value;

	// 3. Bare/empty key — resolve from the vault by name (item titled KEY).
	const item = getItem(s, decl.key);
	if (!item) return undefined;
	// Prefer a field literally named like the key, else the password.
	return fieldValue(item, "password") ?? item.fields[decl.key];
};

export const resolveEnv = async (s: Session, opts: ResolveOptions): Promise<Resolution> => {
	const text = await readFile(opts.envFile, "utf8");
	const decls = parseDotenv(text);
	const env: Record<string, string> = {};
	const missing: string[] = [];
	for (const decl of decls) {
		const v = resolveOne(s, decl);
		if (v === undefined) missing.push(decl.key);
		else env[decl.key] = v;
	}
	return { env, missing };
};

// Resolve and spawn. Forwards the child's exit code; resolved secrets live only
// in the child's in-memory environment for the process lifetime.
//
// Unlike `vault proxy`, `run` does NOT disable core dumps. The two have different
// exposures: `proxy` keeps the secret OUT of the child and holds it only in its
// own memory, so a core dump of that process is the one place it could leak;
// `run` deliberately hands the plaintext to the child's environment, where it is
// already readable (e.g. /proc/<child>/environ) for the child's lifetime — so a
// core dump is not the weak link, and re-exec'ing to zero the limit would buy
// little. Operators who want it can launch `vault run` under `ulimit -c 0`.
export const run = async (
	s: Session,
	opts: ResolveOptions,
	command: string,
	args: string[],
): Promise<number> => {
	const { env, missing } = await resolveEnv(s, opts);
	if (missing.length > 0) {
		const msg = `unresolved variables: ${missing.join(", ")}`;
		if (!opts.allowMissing) throw new Error(`${msg} (use --allow-missing to proceed)`);
		process.stderr.write(`warning: ${msg}\n`);
	}

	// One per-access audit entry (parity with `vault proxy`, spec §13.2): names
	// the injected variables + the command, never the values. Operational, so it
	// goes to stderr (keeps --json stdout clean).
	const injected = Object.keys(env);
	if (injected.length > 0)
		process.stderr.write(
			`audit: ${new Date().toISOString()} injected [${injected.join(", ")}] -> ${command}\n`,
		);

	const merged = { ...process.env, ...env };

	// --mask: defense-in-depth against a child that echoes an injected secret.
	// Register each value with the scrubber and pipe the child's stdout/stderr
	// through the streaming redactor; also scrub our own crash dumps. stdin stays
	// inherited so interactive prompts still reach the terminal.
	let restore: (() => void) | undefined;
	if (opts.mask) {
		for (const v of Object.values(env)) registerSecret(v);
		restore = installScrubbedFatalHandlers();
	}

	return await new Promise<number>((resolve, reject) => {
		const child = spawn(command, args, {
			env: merged,
			stdio: opts.mask ? ["inherit", "pipe", "pipe"] : "inherit",
		});
		// In mask mode the child's output is piped through the scrubber rather than
		// inherited; wait for both streams to flush before settling so no scrubbed
		// output is truncated when the child exits (`end:false` keeps our own
		// stdout/stderr open). Non-mask mode inherits the fds, so there's nothing
		// to drain.
		let drained: Promise<unknown> = Promise.resolve();
		if (opts.mask) {
			const so = makeScrubStream();
			const se = makeScrubStream();
			child.stdout!.pipe(so).pipe(process.stdout, { end: false });
			child.stderr!.pipe(se).pipe(process.stderr, { end: false });
			drained = Promise.allSettled([finished(so), finished(se)]);
		}
		child.on("error", reject);
		child.on("exit", (code, signal) => {
			void drained.then(() => {
				restore?.();
				if (signal) {
					process.kill(process.pid, signal);
					return;
				}
				resolve(code ?? 0);
			});
		});
	});
};
