// `vault run` — resolve declared env vars from the vault and inject them into a
// child process (plan §5). Resolved secrets never touch disk: the .env stays a
// secret-free manifest. Resolution reads the local replica only (offline/instant).

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import type { ItemView } from "../core/crdt.ts";
import { parseDotenv, parseVaultRef, type EnvDecl } from "./dotenv.ts";
import { getItem, type Session } from "./engine.ts";

export type ResolveOptions = {
	envFile: string;
	defaultVault: string;
	allowMissing: boolean;
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

	const merged = { ...process.env, ...env };
	return await new Promise<number>((resolve, reject) => {
		const child = spawn(command, args, { env: merged, stdio: "inherit" });
		child.on("error", reject);
		child.on("exit", (code, signal) => {
			if (signal) {
				process.kill(process.pid, signal);
				return;
			}
			resolve(code ?? 0);
		});
	});
};
