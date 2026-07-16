import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { powerShellArgs, siblingOfExecutable, spawnCollect } from "../cli/spawn.ts";

// spawnCollect drives every keystore transport; a killed child must NOT look like
// a clean exit 0, or a `put` interrupted mid-write would report success and leave
// a vault sealed under a DUK that was never stored.

test("spawnCollect maps a signal-killed child to a non-zero code", async () => {
	// The shell kills ITSELF with SIGKILL: the child terminates by signal, so
	// node's 'close' reports code=null — which the old `code ?? 0` mapped to
	// success. Self-contained (no external kill / timers), deterministic.
	const { code } = await spawnCollect("sh", ["-c", "kill -9 $$"]);
	assert.notEqual(code, 0, "a signal-terminated child must report failure, not exit 0");
});

test("spawnCollect resolves code 0 and captures stdout on a clean exit", async () => {
	const { code, stdout } = await spawnCollect("printf", ["%s", "hello"]);
	assert.equal(code, 0);
	assert.equal(stdout.toString("utf8"), "hello");
});

test("spawnCollect reports a non-zero exit via code, not a rejection", async () => {
	const { code } = await spawnCollect("sh", ["-c", "exit 3"]);
	assert.equal(code, 3);
});

test("spawnCollect rejects only on a spawn error (missing binary)", async () => {
	await assert.rejects(spawnCollect(join(tmpdir(), "no-such-binary-xyz"), []));
});

test("powerShellArgs pins the shared PowerShell flag list", () => {
	assert.deepEqual(powerShellArgs("$x=1"), ["-NoProfile", "-NonInteractive", "-Command", "$x=1"]);
});

test("siblingOfExecutable resolves a name beside the running executable", () => {
	const sib = siblingOfExecutable("vault-helper");
	assert.ok(sib.endsWith("vault-helper"));
	assert.ok(sib.length > "vault-helper".length, "includes the executable's directory");
});
