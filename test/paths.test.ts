// configDir resolution precedence (VAULT_HOME > XDG_CONFIG_HOME > platform
// default) and the named-vault path helpers.

import assert from "node:assert/strict";
import { homedir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { configDir, dbPath, DEFAULT_VAULT } from "../cli/paths.ts";

// Snapshot + restore the env vars configDir reads.
const withEnv = (env: Record<string, string | undefined>, fn: () => void): void => {
	const keys = ["VAULT_HOME", "XDG_CONFIG_HOME"];
	const prev = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
	try {
		for (const k of keys) {
			if (env[k] === undefined) delete process.env[k];
			else process.env[k] = env[k];
		}
		fn();
	} finally {
		for (const k of keys) {
			if (prev[k] === undefined) delete process.env[k];
			else process.env[k] = prev[k];
		}
	}
};

test("configDir: VAULT_HOME takes precedence", () => {
	withEnv({ VAULT_HOME: "/tmp/vh", XDG_CONFIG_HOME: "/tmp/xdg" }, () => {
		assert.equal(configDir(), "/tmp/vh");
	});
});

test("configDir: XDG_CONFIG_HOME when VAULT_HOME is unset", () => {
	withEnv({ VAULT_HOME: undefined, XDG_CONFIG_HOME: "/tmp/xdg" }, () => {
		assert.equal(configDir(), join("/tmp/xdg", "vault"));
	});
});

test("configDir: platform default when neither is set", () => {
	withEnv({ VAULT_HOME: undefined, XDG_CONFIG_HOME: undefined }, () => {
		const dir = configDir();
		// Matches one of the documented platform defaults under the home dir.
		const home = homedir();
		const expected = [
			join(home, ".config", "vault"), // linux
			join(home, "Library", "Application Support", "vault"), // darwin
			join(process.env.APPDATA ?? join(home, "AppData", "Roaming"), "vault"), // win
		];
		assert.ok(expected.includes(dir), `${dir} should be a platform default`);
	});
});

test("dbPath: default vault and named vaults live under <config>/vaults", async () => {
	const prev = process.env.VAULT_HOME;
	const prevXdg = process.env.XDG_CONFIG_HOME;
	process.env.VAULT_HOME = "/tmp/vh-paths";
	delete process.env.XDG_CONFIG_HOME;
	try {
		assert.equal(await dbPath(), join("/tmp/vh-paths", "vaults", `${DEFAULT_VAULT}.db`));
		assert.equal(await dbPath("work"), join("/tmp/vh-paths", "vaults", "work.db"));
		await assert.rejects(dbPath("../escape"), /invalid vault name/);
		await assert.rejects(dbPath("a/b"), /invalid vault name/);
	} finally {
		if (prev === undefined) delete process.env.VAULT_HOME;
		else process.env.VAULT_HOME = prev;
		if (prevXdg !== undefined) process.env.XDG_CONFIG_HOME = prevXdg;
	}
});
