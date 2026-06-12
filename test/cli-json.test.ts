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

test("--type assigns and surfaces the item type; invalid is rejected", async () => {
	await withHome(async (home) => {
		const env = { VAULT_PASSPHRASE: "pw" };
		await execFile(["--json", "init"], { home, env });

		// Default type when --type is omitted.
		const added = lastJson(
			(await execFile(["--json", "add", "gh", "--field", "username=alice"], { home, env })).stdout,
		);
		assert.equal(added.itemType, "login");

		// Explicit type round-trips through get + list JSON.
		const card = lastJson(
			(
				await execFile(["--json", "add", "visa", "--type", "card", "--field", "number=4111"], {
					home,
					env,
				})
			).stdout,
		);
		assert.equal(card.itemType, "card");
		const got = lastJson((await execFile(["--json", "get", "visa"], { home, env })).stdout);
		assert.equal(got.itemType, "card");
		const list = lastJson((await execFile(["--json", "list"], { home, env })).stdout);
		const visa = (list.items as Array<{ title: string; itemType: string }>).find(
			(i) => i.title === "visa",
		);
		assert.equal(visa?.itemType, "card");

		// edit --type changes it.
		await execFile(["--json", "edit", "visa", "--type", "identity"], { home, env });
		const edited = lastJson((await execFile(["--json", "get", "visa"], { home, env })).stdout);
		assert.equal(edited.itemType, "identity");

		// An invalid type fails (and never creates the item).
		const bad = lastJson(
			(await execFile(["--json", "add", "x", "--type", "bogus"], { home, env })).stdout,
		);
		assert.equal(bad.ok, false);
		assert.match(bad.error as string, /invalid --type/);
	});
});

test("totp: `vault totp` and `get` surface a live RFC-6238 code", async () => {
	await withHome(async (home) => {
		const env = { VAULT_PASSPHRASE: "pw" };
		await execFile(["--json", "init"], { home, env });
		// Store the RFC 6238 sample secret (base32) in the conventional `totp` field.
		await execFile(["--json", "add", "gh", "--field", "totp=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"], {
			home,
			env,
		});

		const otp = lastJson((await execFile(["--json", "totp", "gh"], { home, env })).stdout);
		assert.equal(otp.ok, true);
		assert.match(otp.code as string, /^\d{6}$/, "6-digit code");
		assert.equal(otp.period, 30);
		assert.equal(otp.digits, 6);
		assert.equal(otp.algorithm, "sha1");
		assert.ok((otp.expiresIn as number) >= 1 && (otp.expiresIn as number) <= 30);

		// `get` exposes the same derived code under `otp` (the raw secret stays a field).
		const got = lastJson((await execFile(["--json", "get", "gh"], { home, env })).stdout);
		assert.match((got.otp as { code: string }).code, /^\d{6}$/);
		assert.equal((got.fields as Record<string, string>).totp, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

		// No totp field -> a clear error.
		await execFile(["--json", "add", "plain", "--field", "username=x"], { home, env });
		const none = lastJson((await execFile(["--json", "totp", "plain"], { home, env })).stdout);
		assert.equal(none.ok, false);
		assert.match(none.error as string, /no "totp" field/);
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
