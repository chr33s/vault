// Passphrase sourcing (cli/prompt.ts), non-TTY branches. The interactive muted
// TTY path and the stdin-line protocol are exercised end-to-end by the CLI
// smoke/json tests; here we unit-test the env fallback and the hard failure when
// neither a TTY nor $VAULT_PASSPHRASE is available.

import assert from "node:assert/strict";
import { test } from "node:test";
import { readPassphrase, setPassphraseSource } from "../cli/prompt.ts";

test("readPassphrase returns $VAULT_PASSPHRASE in auto mode", async () => {
	setPassphraseSource("auto");
	const prev = process.env.VAULT_PASSPHRASE;
	process.env.VAULT_PASSPHRASE = "hunter2";
	try {
		assert.equal(await readPassphrase(), "hunter2");
		assert.equal(await readPassphrase("Different prompt: "), "hunter2"); // prompt ignored
	} finally {
		if (prev === undefined) delete process.env.VAULT_PASSPHRASE;
		else process.env.VAULT_PASSPHRASE = prev;
	}
});

test("readPassphrase rejects when there is no TTY and no env passphrase", async () => {
	setPassphraseSource("auto");
	const prev = process.env.VAULT_PASSPHRASE;
	delete process.env.VAULT_PASSPHRASE;
	const prevTTY = process.stdin.isTTY;
	(process.stdin as { isTTY?: boolean }).isTTY = false;
	try {
		await assert.rejects(readPassphrase(), /no TTY and VAULT_PASSPHRASE unset/);
	} finally {
		(process.stdin as { isTTY?: boolean }).isTTY = prevTTY;
		if (prev !== undefined) process.env.VAULT_PASSPHRASE = prev;
	}
});
