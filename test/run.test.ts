import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { init, unlock, addItem } from "../cli/engine.ts";
import { run } from "../cli/run.ts";
import { Store } from "../core/store.ts";

const tmp = (): Promise<string> => mkdtemp(join(tmpdir(), "vault-run-"));
const PASS = "run-pass";

test("vault run injects resolved secrets and forwards the child exit code", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "TOKEN", { password: "s3cr3t" });

		const envFile = join(dir, ".env");
		await writeFile(envFile, "TOKEN=\nPLAIN=hi\n"); // TOKEN resolves from vault; PLAIN literal

		// Child exits 7 iff both vars arrived correctly in its environment.
		const code = await run(
			s,
			{ envFile, defaultVault: s.vaultId, allowMissing: false },
			process.execPath,
			["-e", "process.exit(process.env.TOKEN === 's3cr3t' && process.env.PLAIN === 'hi' ? 7 : 8)"],
		);
		assert.equal(code, 7, "resolved + literal env injected; child exit code forwarded");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("vault run fails before spawning when a required var is unresolved", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);

		const envFile = join(dir, ".env");
		await writeFile(envFile, "MISSING=\n"); // no such item in the vault

		// A side-effect file the child would create — must NOT exist if we fail first.
		const marker = join(dir, "spawned.marker");
		await assert.rejects(
			run(s, { envFile, defaultVault: s.vaultId, allowMissing: false }, process.execPath, [
				"-e",
				`require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'x')`,
			]),
			/unresolved variables: MISSING/,
		);
		await assert.rejects(rm(marker), /ENOENT/, "child must not have spawned");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("vault run --mask redacts an injected secret echoed by the child", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "TOKEN", { password: "supersecretvalue" });

		const envFile = join(dir, ".env");
		await writeFile(envFile, "TOKEN=\n");

		// Capture this process's stdout while the child echoes the secret. With
		// --mask the child's stdout is piped through the scrubber, so the value
		// must come out [REDACTED] rather than verbatim.
		const chunks: string[] = [];
		const realWrite = process.stdout.write.bind(process.stdout);
		(process.stdout as { write: unknown }).write = (c: string | Uint8Array): boolean => {
			chunks.push(typeof c === "string" ? c : Buffer.from(c).toString());
			return true;
		};
		let code: number;
		try {
			code = await run(
				s,
				{ envFile, defaultVault: s.vaultId, allowMissing: false, mask: true },
				process.execPath,
				["-e", "process.stdout.write(process.env.TOKEN + '\\n')"],
			);
		} finally {
			(process.stdout as { write: unknown }).write = realWrite;
		}
		const out = chunks.join("");
		assert.equal(code, 0);
		assert.ok(!out.includes("supersecretvalue"), "the echoed secret is scrubbed from child stdout");
		assert.ok(out.includes("[REDACTED]"), "the redaction marker replaces it");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("vault run emits a per-access audit line naming vars, never values", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);
		addItem(s, "APIKEY", { password: "do-not-leak-me" });

		const envFile = join(dir, ".env");
		await writeFile(envFile, "APIKEY=\n");

		const errs: string[] = [];
		const realWrite = process.stderr.write.bind(process.stderr);
		(process.stderr as { write: unknown }).write = (c: string | Uint8Array): boolean => {
			errs.push(typeof c === "string" ? c : Buffer.from(c).toString());
			return true;
		};
		try {
			await run(s, { envFile, defaultVault: s.vaultId, allowMissing: false }, process.execPath, [
				"-e",
				"0",
			]);
		} finally {
			(process.stderr as { write: unknown }).write = realWrite;
		}
		const err = errs.join("");
		assert.match(err, /audit: .* injected \[APIKEY\]/, "audit names the injected var");
		assert.ok(!err.includes("do-not-leak-me"), "audit never contains the value");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("vault run --allow-missing proceeds despite an unresolved var", async () => {
	const dir = await tmp();
	try {
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS);
		const s = await unlock(store, PASS);

		const envFile = join(dir, ".env");
		await writeFile(envFile, "MISSING=\n");
		const code = await run(
			s,
			{ envFile, defaultVault: s.vaultId, allowMissing: true },
			process.execPath,
			["-e", "process.exit(process.env.MISSING === undefined ? 0 : 1)"],
		);
		assert.equal(code, 0, "spawns with the var simply absent");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
