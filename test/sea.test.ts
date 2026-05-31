// Smoke test for the generated single-file binary (plan §10: "build the binary
// per platform and run `vault --version` + an init/add/list cycle against a
// local relay"). Skips automatically when the binary hasn't been built; CI's
// `sea` job builds it first and points VAULT_BIN at it.

import assert from "node:assert/strict";
import { execFile as execFileCb } from "node:child_process";
import { mkdtemp, rm, access } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { createRelay } from "../relay/main.ts";

const execFile = promisify(execFileCb);
const BIN = process.env.VAULT_BIN ?? join(process.cwd(), "dist", "vault");
// Async existence check (fs/promises) — top-level await gates the test.
const skip = await access(BIN).then(
	() => false,
	() => `binary not built at ${BIN} (run: npm run build:sea)`,
);

test("SEA binary: version + init/add/list/get + relay sync round-trip", { skip }, async () => {
	const home = await mkdtemp(join(tmpdir(), "vault-sea-"));
	// The binary talks to an in-process relay; async execFile keeps the event
	// loop free so the relay can answer while a binary command is in flight.
	const { server } = createRelay();
	await new Promise<void>((r) => server.listen(0, r));
	const relay = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

	const runIn =
		(h: string) =>
		async (...args: string[]): Promise<string> => {
			const { stdout } = await execFile(BIN, args, {
				env: { ...process.env, VAULT_HOME: h, VAULT_PASSPHRASE: "smoke-pass" },
				encoding: "utf8",
			});
			return stdout;
		};
	const run = runIn(home);

	try {
		assert.equal((await run("--version")).trim(), "0.1.0");

		assert.match(await run("init"), /Initialized vault/);
		await run("add", "github", "--field", "username=alice", "--field", "password=s3cr3t");
		assert.match(await run("list"), /github/);
		assert.equal((await run("get", "github", "--name", "username")).trim(), "alice");
		assert.equal((await run("get", "github", "--name", "password")).trim(), "s3cr3t");

		assert.match(await run("sync", "--relay", relay), /Synced/);

		// Second device of the same user (separate VAULT_HOME) enrolls and converges.
		const home2 = await mkdtemp(join(tmpdir(), "vault-sea2-"));
		const run2 = runIn(home2);
		try {
			const tokenA = (await run2("auth")).trim().split("\n").pop()!;
			const tokenB = (await run("device-add", "--token", tokenA, "--role", "admin"))
				.trim()
				.split("\n")
				.pop()!;
			await run2("device-confirm", "--token", tokenB);
			await run2("sync", "--relay", relay);
			assert.equal(
				(await run2("get", "github", "--name", "username")).trim(),
				"alice",
				"device 2 converged via binary + relay",
			);
		} finally {
			await rm(home2, { recursive: true, force: true });
		}
	} finally {
		server.close();
		await rm(home, { recursive: true, force: true });
	}
});
