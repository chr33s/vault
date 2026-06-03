import assert from "node:assert/strict";
import { execFile as execFileCb } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { init, unlock, addItem, getItem, keystoreStatus } from "../cli/engine.ts";
import {
	keyStoreByName,
	makeBlobKeyStore,
	makeSystemdCredsCipher,
	systemdCredsKeyMode,
	type BlobCipher,
} from "../cli/keystore.ts";
import { Store } from "../core/store.ts";

// Point VAULT_HOME at a temp dir so configDir() (where blobs live) is isolated.
const withHome = async (fn: () => Promise<void>): Promise<void> => {
	const home = await mkdtemp(join(tmpdir(), "vault-systemd-"));
	const prev = process.env.VAULT_HOME;
	process.env.VAULT_HOME = home;
	try {
		await fn();
	} finally {
		if (prev === undefined) delete process.env.VAULT_HOME;
		else process.env.VAULT_HOME = prev;
		await rm(home, { recursive: true, force: true });
	}
};

// ---- makeBlobKeyStore: the generalized store logic (cipher injected) ----
//
// A fake cipher that threads `name` through: the blob records (tag, name) so we
// can assert both the round-trip and that the keystore id reaches the cipher.
const fakeCipher = (tag: string): BlobCipher => ({
	async available() {
		return true;
	},
	async protect(plaintext: Buffer, name?: string) {
		return Buffer.concat([Buffer.from(`${tag}|${name}|`), plaintext]);
	},
	async unprotect(blob: Buffer, name?: string) {
		const prefix = Buffer.from(`${tag}|${name}|`);
		if (!blob.subarray(0, prefix.length).equals(prefix)) throw new Error("wrong tag/name");
		return blob.subarray(prefix.length);
	},
});

test("makeBlobKeyStore: round-trips, threads the id as name, and deletes", async () => {
	await withHome(async () => {
		const ks = makeBlobKeyStore({
			name: "fake",
			subdir: "fake",
			ext: "bin",
			cipher: fakeCipher("userA"),
		});
		assert.equal(ks.name, "fake");
		assert.equal(await ks.available(), true);

		await ks.put("vault-1", Buffer.from("device-unlock-key"));
		assert.equal((await ks.get("vault-1"))!.toString(), "device-unlock-key");

		await ks.del("vault-1");
		assert.equal(await ks.get("vault-1"), undefined, "deleted blob is gone");
	});
});

test("makeBlobKeyStore: a blob from a different binding cannot be opened", async () => {
	await withHome(async () => {
		const a = makeBlobKeyStore({
			name: "fake",
			subdir: "fake",
			ext: "bin",
			cipher: fakeCipher("userA"),
		});
		await a.put("vault-1", Buffer.from("secret"));
		const b = makeBlobKeyStore({
			name: "fake",
			subdir: "fake",
			ext: "bin",
			cipher: fakeCipher("userB"),
		});
		assert.equal(await b.get("vault-1"), undefined, "cross-binding open fails -> undefined");
		assert.equal((await a.get("vault-1"))!.toString(), "secret");
	});
});

// ---- makeSystemdCredsCipher: argv construction (run injected) ----

test("systemd-creds cipher builds encrypt/decrypt argv and passes the secret on stdin", async () => {
	const calls: { args: string[]; input: Buffer }[] = [];
	const cipher = makeSystemdCredsCipher({
		run: async (args, input) => {
			calls.push({ args, input });
			return Buffer.from("blob");
		},
	});

	const secret = Buffer.from("device-unlock-key");
	await cipher.protect(secret, "vault-7");
	assert.deepEqual(calls[0]!.args, ["encrypt", "--name=vault-7", "--with-key=host", "-", "-"]);
	assert.ok(calls[0]!.input.equals(secret), "secret rides stdin, not argv");

	await cipher.unprotect(Buffer.from("blob"), "vault-7");
	assert.deepEqual(calls[1]!.args, ["decrypt", "--name=vault-7", "-", "-"]);
});

test("systemd-creds cipher: keyMode option selects --with-key (TPM on-ramp)", async () => {
	const calls: string[][] = [];
	const cipher = makeSystemdCredsCipher({
		keyMode: "tpm2",
		run: async (args) => {
			calls.push(args);
			return Buffer.alloc(0);
		},
	});
	await cipher.protect(Buffer.from("x"), "v");
	assert.ok(calls[0]!.includes("--with-key=tpm2"));
});

test("systemd-creds cipher: VAULT_SYSTEMD_CREDS_KEY is read at call time", async () => {
	const calls: string[][] = [];
	// No explicit keyMode -> falls back to the env, resolved per call (so the
	// default provider honors a mode set just before `keystore enable`).
	const cipher = makeSystemdCredsCipher({
		run: async (args) => {
			calls.push(args);
			return Buffer.alloc(0);
		},
	});
	const prev = process.env.VAULT_SYSTEMD_CREDS_KEY;
	try {
		process.env.VAULT_SYSTEMD_CREDS_KEY = "auto"; // set AFTER construction
		await cipher.protect(Buffer.from("x"), "v");
		assert.ok(calls[0]!.includes("--with-key=auto"), "env mode is picked up at call time");
		assert.equal(systemdCredsKeyMode(), "auto");
	} finally {
		if (prev === undefined) delete process.env.VAULT_SYSTEMD_CREDS_KEY;
		else process.env.VAULT_SYSTEMD_CREDS_KEY = prev;
	}
});

// ---- runSystemdCreds transport via a stub binary on PATH (Linux only) ----
//
// We can't run real systemd-creds in CI, but a stub `systemd-creds` that echoes
// stdin (an identity cipher) exercises the real spawn/stream/exit-code paths.
const stubLinuxOnly = process.platform !== "linux" ? "systemd-creds path is linux-only" : false;

const withStubSystemdCreds = async (fail = false): Promise<{ restore: () => Promise<void> }> => {
	const dir = await mkdtemp(join(tmpdir(), "systemd-creds-stub-"));
	const bin = join(dir, "systemd-creds");
	const body = fail ? `#!/bin/sh\necho "boom" 1>&2\nexit 4\n` : `#!/bin/sh\ncat\n`; // identity: stdout = stdin
	await writeFile(bin, body);
	await chmod(bin, 0o755);
	const prev = process.env.VAULT_SYSTEMD_CREDS;
	process.env.VAULT_SYSTEMD_CREDS = bin;
	return {
		restore: async () => {
			if (prev === undefined) delete process.env.VAULT_SYSTEMD_CREDS;
			else process.env.VAULT_SYSTEMD_CREDS = prev;
			await rm(dir, { recursive: true, force: true });
		},
	};
};

test(
	"runSystemdCreds: round-trip + available() via an identity stub",
	{ skip: stubLinuxOnly },
	async () => {
		const { restore } = await withStubSystemdCreds(false);
		try {
			const cipher = makeSystemdCredsCipher();
			assert.equal(await cipher.available(), true, "probe round-trips through the stub");
			const secret = Buffer.from("device-unlock-key");
			const blob = await cipher.protect(secret, "vault-1");
			assert.ok(blob.equals(secret), "identity stub returns the input bytes");
			assert.ok((await cipher.unprotect(blob, "vault-1")).equals(secret));
		} finally {
			await restore();
		}
	},
);

test("runSystemdCreds: non-zero exit rejects with stderr", { skip: stubLinuxOnly }, async () => {
	const { restore } = await withStubSystemdCreds(true);
	try {
		const cipher = makeSystemdCredsCipher();
		assert.equal(await cipher.available(), false, "a failing binary -> unavailable");
		await assert.rejects(cipher.protect(Buffer.from("x"), "v"), /systemd-creds exited 4: boom/);
	} finally {
		await restore();
	}
});

// ---- CLI: `--with-key` flag (sugar over $VAULT_SYSTEMD_CREDS_KEY) ----

const pexec = promisify(execFileCb);

// Run `node cli/main.ts <args>` with an isolated VAULT_HOME and extra env;
// non-zero exit is tolerated (we assert on output), only spawn errors throw.
const runCli = (args: string[], env: Record<string, string>): Promise<{ stdout: string }> =>
	pexec(process.execPath, [join(process.cwd(), "cli", "main.ts"), ...args], {
		env: { ...process.env, ...env },
		encoding: "utf8",
	}).then(
		(r) => ({ stdout: r.stdout }),
		(e: { stdout?: string }) => ({ stdout: e.stdout ?? "" }),
	);

test(
	"CLI: --with-key selects the systemd-creds binding shown in status",
	{ skip: stubLinuxOnly },
	async () => {
		const { restore } = await withStubSystemdCreds(false); // identity stub: available for any mode
		const home = await mkdtemp(join(tmpdir(), "vault-cli-wk-"));
		try {
			const { stdout } = await runCli(["--json", "keystore", "status", "--with-key=tpm2"], {
				VAULT_HOME: home,
			});
			const json = JSON.parse(stdout.trim().split("\n").filter(Boolean).pop()!);
			assert.equal(json.platformKeystore, "systemd-creds");
			assert.equal(json.platformKeyMode, "tpm2", "the flag drives the reported mode");
		} finally {
			await rm(home, { recursive: true, force: true });
			await restore();
		}
	},
);

test(
	"CLI: --with-key reaches systemd-creds at seal time (init --keychain)",
	{ skip: stubLinuxOnly },
	async () => {
		const dir = await mkdtemp(join(tmpdir(), "systemd-creds-rec-"));
		const bin = join(dir, "systemd-creds");
		const record = join(dir, "argv.log");
		// Identity cipher that also appends each invocation's argv to a log file.
		await writeFile(bin, `#!/bin/sh\nprintf '%s\\n' "$*" >> "${record}"\ncat\n`);
		await chmod(bin, 0o755);
		const home = await mkdtemp(join(tmpdir(), "vault-cli-init-"));
		try {
			await runCli(["--json", "init", "--keychain", "--with-key=tpm2"], {
				VAULT_HOME: home,
				VAULT_SYSTEMD_CREDS: bin,
				VAULT_PASSPHRASE: "pw",
			});
			const log = await readFile(record, "utf8");
			// Anchor to the SEAL's credential name (vault-<hex>), not the availability
			// probe's "vault-probe" — otherwise the probe line alone satisfies the match
			// and a seal that ignored the mode would pass green.
			assert.match(
				log,
				/encrypt --name=vault-[0-9a-f]+ --with-key=tpm2/,
				"the DUK itself is sealed with the chosen mode",
			);
		} finally {
			await rm(dir, { recursive: true, force: true });
			await rm(home, { recursive: true, force: true });
		}
	},
);

// ---- engine end-to-end through the systemd-creds tier (identity stub) ----

test(
	"systemd-creds keystore protects a real vault end-to-end",
	{ skip: stubLinuxOnly },
	async () => {
		const { restore } = await withStubSystemdCreds(false);
		try {
			await withHome(async () => {
				const dir = await mkdtemp(join(tmpdir(), "vault-systemd-e2e-"));
				try {
					const ks = makeBlobKeyStore({
						name: "systemd-creds",
						subdir: "systemd-creds",
						ext: "cred",
						cipher: makeSystemdCredsCipher(),
					});
					const store = new Store(join(dir, "v.db"));
					await init(store, "pw", ks);
					assert.equal(store.getMeta("keystoreProvider"), "systemd-creds");

					const s = await unlock(store, "pw", ks);
					addItem(s, "github", { username: "alice", password: "pw" });
					const fresh = await unlock(store, "pw", ks);
					assert.equal(getItem(fresh, "github")!.fields.username, "alice");
					store.close();
				} finally {
					await rm(dir, { recursive: true, force: true });
				}
			});
		} finally {
			await restore(); // always restore env + remove the stub dir, even on assert failure
		}
	},
);

// ---- seal mode is persisted and pinned on unlock (the review fix) ----

test(
	"systemd-creds: seal mode is persisted in meta and surfaced by keystoreStatus",
	{ skip: stubLinuxOnly },
	async () => {
		const { restore } = await withStubSystemdCreds(false);
		try {
			await withHome(async () => {
				const dir = await mkdtemp(join(tmpdir(), "vault-systemd-mode-"));
				try {
					const store = new Store(join(dir, "v.db"));
					const ks = makeBlobKeyStore({
						name: "systemd-creds",
						subdir: "systemd-creds",
						ext: "cred",
						cipher: makeSystemdCredsCipher({ keyMode: "tpm2" }),
					});
					await init(store, "pw", ks);
					assert.equal(store.getMeta("keystoreKeyMode"), "tpm2", "seal mode persisted in meta");
					assert.equal(keystoreStatus(store).keyMode, "tpm2");
					store.close();
				} finally {
					await rm(dir, { recursive: true, force: true });
				}
			});
		} finally {
			await restore();
		}
	},
);

test(
	"keyStoreByName pins the requested mode for the availability probe",
	{ skip: stubLinuxOnly },
	async () => {
		const dir = await mkdtemp(join(tmpdir(), "systemd-creds-pin-"));
		const bin = join(dir, "systemd-creds");
		const record = join(dir, "argv.log");
		await writeFile(bin, `#!/bin/sh\nprintf '%s\\n' "$*" >> "${record}"\ncat\n`);
		await chmod(bin, 0o755);
		const prevBin = process.env.VAULT_SYSTEMD_CREDS;
		const prevMode = process.env.VAULT_SYSTEMD_CREDS_KEY;
		process.env.VAULT_SYSTEMD_CREDS = bin;
		delete process.env.VAULT_SYSTEMD_CREDS_KEY; // env default would be "host"
		try {
			const ks = await keyStoreByName("systemd-creds", "tpm2");
			assert.ok(ks, "resolved the systemd-creds provider");
			const log = await readFile(record, "utf8");
			assert.match(
				log,
				/encrypt --name=vault-probe --with-key=tpm2/,
				"probe pinned to the mode arg",
			);
			assert.doesNotMatch(log, /--with-key=host/, "ignored the env default host");
		} finally {
			if (prevBin === undefined) delete process.env.VAULT_SYSTEMD_CREDS;
			else process.env.VAULT_SYSTEMD_CREDS = prevBin;
			if (prevMode !== undefined) process.env.VAULT_SYSTEMD_CREDS_KEY = prevMode;
			await rm(dir, { recursive: true, force: true });
		}
	},
);

test(
	"CLI: unlock pins the persisted seal mode, not the env default",
	{ skip: stubLinuxOnly },
	async () => {
		const dir = await mkdtemp(join(tmpdir(), "systemd-creds-unlock-"));
		const bin = join(dir, "systemd-creds");
		const record = join(dir, "argv.log");
		await writeFile(bin, `#!/bin/sh\nprintf '%s\\n' "$*" >> "${record}"\ncat\n`);
		await chmod(bin, 0o755);
		const home = await mkdtemp(join(tmpdir(), "vault-cli-unlock-"));
		try {
			// Seal with tpm2.
			await runCli(["--json", "init", "--keychain", "--with-key=tpm2"], {
				VAULT_HOME: home,
				VAULT_SYSTEMD_CREDS: bin,
				VAULT_PASSPHRASE: "pw",
			});
			await writeFile(record, ""); // capture only the unlock phase next
			// Unlock with NO --with-key: the env default is "host", but the vault was
			// sealed tpm2, so the persisted mode must drive the availability probe.
			await runCli(["--json", "list"], {
				VAULT_HOME: home,
				VAULT_SYSTEMD_CREDS: bin,
				VAULT_PASSPHRASE: "pw",
			});
			const log = await readFile(record, "utf8");
			assert.match(log, /encrypt --name=vault-probe --with-key=tpm2/, "unlock probed in tpm2");
			assert.doesNotMatch(log, /--with-key=host/, "did not fall back to the env default host");
		} finally {
			await rm(dir, { recursive: true, force: true });
			await rm(home, { recursive: true, force: true });
		}
	},
);
