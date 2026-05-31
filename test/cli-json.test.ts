// The machine contract for GUI/native wrappers and automation (the "step 1"
// enablers behind the macOS UI wrapper): --json structured output and
// --passphrase-stdin (secrets over stdin, never argv/env). Drives the source CLI
// via `node cli/main.ts` with an isolated VAULT_HOME, asserting the JSON shapes
// and the stdin multi-prompt protocol.

import assert from "node:assert/strict";
import { execFile as execFileCb } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const execFile = (
	args: string[],
	opts: { home: string; input?: string; env?: Record<string, string> },
) =>
	new Promise<{ stdout: string; code: number }>((resolve, reject) => {
		const child = execFileCb(
			process.execPath,
			[join(process.cwd(), "cli", "main.ts"), ...args],
			{ env: { ...process.env, VAULT_HOME: opts.home, ...opts.env }, encoding: "utf8" },
			(err, stdout) => {
				// Non-zero exit is fine — we assert on the JSON body; only reject on spawn errors.
				if (err && typeof (err as { code?: unknown }).code !== "number") return reject(err);
				resolve({ stdout: stdout as string, code: (err as { code?: number } | null)?.code ?? 0 });
			},
		);
		if (opts.input !== undefined) child.stdin!.end(opts.input);
	});

const lastJson = (stdout: string): Record<string, unknown> => {
	const lines = stdout.trim().split("\n").filter(Boolean);
	return JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
};

const withHome = async (fn: (home: string) => Promise<void>): Promise<void> => {
	const home = await mkdtemp(join(tmpdir(), "vault-cli-"));
	try {
		await fn(home);
	} finally {
		await rm(home, { recursive: true, force: true });
	}
};

test("--json emits one structured object per command", async () => {
	await withHome(async (home) => {
		const env = { VAULT_PASSPHRASE: "pw" };
		const init = lastJson((await execFile(["--json", "init"], { home, env })).stdout);
		assert.equal(init.ok, true);
		assert.match(init.vaultId as string, /^[0-9a-f]{32}$/);

		await execFile(
			["--json", "add", "github", "--field", "username=alice", "--field", "password=s3cr3t"],
			{ home, env },
		);

		const list = lastJson((await execFile(["--json", "list"], { home, env })).stdout);
		assert.deepEqual(
			(list.items as Array<{ title: string }>).map((i) => i.title),
			["github"],
		);

		const get = lastJson((await execFile(["--json", "get", "github"], { home, env })).stdout);
		assert.equal((get.fields as Record<string, string>).username, "alice");
		assert.deepEqual(get.passwords, ["s3cr3t"]);

		const field = lastJson(
			(await execFile(["--json", "get", "github", "--name", "password"], { home, env })).stdout,
		);
		assert.equal(field.value, "s3cr3t");
	});
});

test("--json device-add returns the SAS + Token B (enrollment contract for the UI)", async () => {
	await withHome(async (home) => {
		const env = { VAULT_PASSPHRASE: "pw" };
		await execFile(["--json", "init"], { home, env });

		// A second device (separate home) prints Token A; the first authorizes it.
		await withHome(async (home2) => {
			const auth = lastJson((await execFile(["--json", "auth"], { home: home2, env })).stdout);
			const tokenA = auth.tokenA as string;
			const added = lastJson(
				(
					await execFile(["--json", "device-add", "--token", tokenA, "--role", "admin"], {
						home,
						env,
					})
				).stdout,
			);
			assert.equal(added.ok, true);
			assert.match(added.sas as string, /\S/);
			assert.match(added.tokenB as string, /\S/);
		});
	});
});

test("--json reports errors as {ok:false,error} on stdout with non-zero exit", async () => {
	await withHome(async (home) => {
		const env = { VAULT_PASSPHRASE: "pw" };
		await execFile(["--json", "init"], { home, env });
		const res = await execFile(["--json", "get", "nope"], { home, env });
		const obj = lastJson(res.stdout);
		assert.equal(obj.ok, false);
		assert.match(obj.error as string, /no item titled/);
		assert.equal(res.code, 1);
	});
});

test("--passphrase-stdin reads secrets from stdin (one line per prompt)", async () => {
	await withHome(async (home) => {
		// No VAULT_PASSPHRASE: the passphrase must come from stdin.
		const env = { VAULT_PASSPHRASE: "" } as Record<string, string>;
		delete (env as Record<string, string>).VAULT_PASSPHRASE;

		const init = lastJson(
			(await execFile(["--json", "--passphrase-stdin", "init"], { home, input: "mypass\n" }))
				.stdout,
		);
		assert.equal(init.ok, true);

		// `add --password` prompts twice: account passphrase, then the item password.
		await execFile(
			["--json", "--passphrase-stdin", "add", "gh", "--field", "username=bob", "--password"],
			{
				home,
				input: "mypass\nitemsecret\n",
			},
		);

		const got = lastJson(
			(
				await execFile(["--json", "--passphrase-stdin", "get", "gh", "--name", "password"], {
					home,
					input: "mypass\n",
				})
			).stdout,
		);
		assert.equal(got.value, "itemsecret");
	});
});

test("--passphrase-stdin: wrong passphrase yields an error envelope", async () => {
	await withHome(async (home) => {
		await execFile(["--json", "--passphrase-stdin", "init"], { home, input: "right\n" });
		const res = await execFile(["--json", "--passphrase-stdin", "list"], {
			home,
			input: "wrong\n",
		});
		assert.equal(lastJson(res.stdout).ok, false);
		assert.match(lastJson(res.stdout).error as string, /incorrect passphrase/);
	});
});
