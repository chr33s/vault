// Windows Hello strong tier (plan §12b, spec §3.5) — the off-Windows-testable
// half: the blob format + HKDF/AES-GCM wrap against a fake-sign oracle, the
// enrollment determinism self-test, the never-mint-on-unlock rule, and the
// helper spawn transport against a stub speaking the same wire protocol. The
// real WinRT paths (gestures, credential lifecycle) live in native/hello-helper
// and are exercised on a real Windows host; CI's Windows runner validates the
// projection script and the compiled helper answer `available` cleanly.

import assert from "node:assert/strict";
import { execFile as execFileCb } from "node:child_process";
import { createHmac } from "node:crypto";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { addItem, getItem, init, unlock } from "../cli/engine.ts";
import {
	HELLO_CREDENTIAL,
	PS_HELLO_AVAILABLE,
	defaultHelloSigner,
	helperHelloSigner,
	makeHelloCipher,
	powerShellHelloSigner,
	psHelloSign,
	type HelloSigner,
} from "../cli/hello.ts";
import { keyStoreByName, makeHelloKeyStore } from "../cli/keystore.ts";
import { powerShellArgs } from "../cli/spawn.ts";
import { Store } from "../core/store.ts";

const execFile = promisify(execFileCb);

// A fake Hello signer: the "credential" is an HMAC key, so signatures are
// deterministic per (key, challenge) — the property the real RSA-2048/PKCS#1
// v1.5 KeyCredential provides. Tracks gestures (each sign = one Hello prompt)
// and models the credential lifecycle: sign without an enrolled credential
// fails unless { create: true }.
const fakeSigner = (
	key: string,
	opts: { enrolled?: boolean } = {},
): HelloSigner & { gestures: number; enrolled: boolean } => ({
	gestures: 0,
	enrolled: opts.enrolled ?? false,
	async available() {
		return true;
	},
	async sign(challenge: Buffer, o?: { create?: boolean }) {
		if (!this.enrolled) {
			if (!o?.create) throw new Error("hello: NotFound");
			this.enrolled = true; // RequestCreateAsync
		}
		this.gestures++;
		return createHmac("sha256", key).update(challenge).digest();
	},
});

// Save/patch/restore a set of env vars around fn (undefined = unset). One place
// for the prev-capture/finally-restore dance, so an early throw can't leak a
// stale var into later tests.
const withEnv = async (
	patch: Record<string, string | undefined>,
	fn: () => Promise<void>,
): Promise<void> => {
	const prev = new Map(Object.keys(patch).map((k) => [k, process.env[k]]));
	for (const [k, v] of Object.entries(patch)) {
		if (v === undefined) delete process.env[k];
		else process.env[k] = v;
	}
	try {
		await fn();
	} finally {
		for (const [k, v] of prev) {
			if (v === undefined) delete process.env[k];
			else process.env[k] = v;
		}
	}
};

// A fresh temp dir as VAULT_HOME for the duration of fn (which receives the dir),
// cleaned up after. Built on withEnv so env restoration lives in exactly one place.
const withHome = async (fn: (home: string) => Promise<void>): Promise<void> => {
	const home = await mkdtemp(join(tmpdir(), "vault-hello-"));
	try {
		await withEnv({ VAULT_HOME: home }, () => fn(home));
	} finally {
		await rm(home, { recursive: true, force: true });
	}
};

test("hello store: wrap/store/retrieve round-trip, one gesture per get", async () => {
	await withHome(async () => {
		const signer = fakeSigner("device-credential");
		const ks = makeHelloKeyStore(signer);
		assert.equal(ks.name, "windows-hello");
		assert.equal(await ks.available(), true);

		const secret = Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef", "hex");
		await ks.put("vault-1", secret);
		assert.equal(signer.enrolled, true, "enrollment minted the credential");
		assert.equal(signer.gestures, 2, "enrollment signs twice (determinism self-test)");

		assert.deepEqual(await ks.get("vault-1"), secret, "round-trips the exact bytes");
		assert.equal(signer.gestures, 3, "each get is exactly one gesture");

		await ks.del("vault-1");
		assert.equal(await ks.get("vault-1"), undefined, "deleted blob is gone");
	});
});

test("hello cipher: refuses a non-deterministic (RSA-PSS-like) credential", async () => {
	let n = 0;
	const randomized: HelloSigner = {
		async available() {
			return true;
		},
		async sign(challenge: Buffer) {
			// Same challenge, different signature each call — the PSS failure mode.
			return createHmac("sha256", `salt-${n++}`).update(challenge).digest();
		},
	};
	await assert.rejects(
		makeHelloCipher(randomized).protect(Buffer.from("duk")),
		/non-deterministically/,
		"the enrollment self-test must refuse the tier, not write a dead blob",
	);
});

test("hello store: the unlock path never mints a credential", async () => {
	await withHome(async () => {
		const signer = fakeSigner("device-credential");
		const ks = makeHelloKeyStore(signer);
		await ks.put("vault-1", Buffer.from("duk"));

		// Hello/PIN reset: the credential is gone. get must report "no secret"
		// (undefined), and must NOT create a fresh credential that could never
		// decrypt this blob.
		signer.enrolled = false;
		assert.equal(await ks.get("vault-1"), undefined);
		assert.equal(signer.enrolled, false, "get did not RequestCreateAsync");
	});
});

test("hello store: a blob wrapped under another credential cannot be opened", async () => {
	await withHome(async () => {
		const a = makeHelloKeyStore(fakeSigner("credential-A"));
		await a.put("vault-1", Buffer.from("secret"));
		// Same disk, different device/credential (stolen-disk model).
		const b = makeHelloKeyStore(fakeSigner("credential-B"));
		assert.equal(await b.get("vault-1"), undefined, "cross-credential unwrap fails -> undefined");
		assert.equal((await a.get("vault-1"))!.toString(), "secret");
	});
});

test("hello cipher: the blob is bound to its keystore id (AAD)", async () => {
	const cipher = makeHelloCipher(fakeSigner("device-credential"));
	const blob = await cipher.protect(Buffer.from("duk"), "vault-a");
	assert.deepEqual(await cipher.unprotect(blob, "vault-a"), Buffer.from("duk"));
	// A blob renamed/copied under another id must not open under it.
	await assert.rejects(cipher.unprotect(blob, "vault-b"));
});

test("hello cipher: tampered or foreign blobs fail closed", async () => {
	const cipher = makeHelloCipher(fakeSigner("device-credential"));
	const blob = await cipher.protect(Buffer.from("duk"));
	assert.equal(blob.subarray(0, 4).toString(), "VHW1", "versioned magic header");

	const flipped = Buffer.from(blob);
	flipped.writeUInt8(flipped.readUInt8(flipped.length - 1) ^ 0x01, flipped.length - 1); // corrupt the ciphertext
	await assert.rejects(cipher.unprotect(flipped));

	await assert.rejects(cipher.unprotect(Buffer.from("not a blob")), /not a hello-sealed blob/);
});

test("hello keystore protects a real vault end-to-end (engine round-trip)", () =>
	withHome(async (home) => {
		const ks = makeHelloKeyStore(fakeSigner("this-device"));
		const store = new Store(join(home, "v.db")); // hello blobs live under configDir()
		await init(store, "pw", ks);
		assert.equal(store.getMeta("keystoreProvider"), "windows-hello");

		const s = await unlock(store, "pw", ks);
		addItem(s, "github", { username: "alice", password: "pw" });
		const fresh = await unlock(store, "pw", ks);
		assert.equal(getItem(fresh, "github")!.fields.username, "alice");

		// Stolen disk: correct passphrase but no Hello credential to re-derive the
		// wrap key -> the engine's standard keystore failure, at any passphrase
		// strength.
		await assert.rejects(unlock(store, "pw", undefined), /protected by keystore "windows-hello"/);
		const attacker = makeHelloKeyStore(fakeSigner("attacker-device"));
		await assert.rejects(unlock(store, "pw", attacker), /did not return this device's unlock key/);
		store.close();
	}));

// ---- helper spawn transport (stub helper; no real WinRT) ----
//
// A shell stub speaks the exact wire protocol of native/hello-helper
// (argv command + base64 challenge on stdin -> base64 signature on stdout),
// deterministic via openssl HMAC — so the spawn/encode/exit-code paths of
// helperHelloSigner are exercised without Windows. POSIX-shell stubs can't
// spawn on win32; there the real helper/projection tests below cover it.

const STUB_HELPER = (key: string, markerDir: string): string => `#!/bin/sh
cmd="$1"
case "$cmd" in
  available) echo 1 ;;
  sign)
    [ "$2" = "--create" ] && : > "${markerDir}/created"
    printf '%s' "$(cat)" | openssl base64 -d -A \\
      | openssl dgst -sha256 -hmac "${key}" -binary | openssl base64 -A
    ;;
  *) exit 2 ;;
esac
`;

const FAIL_HELPER = `#!/bin/sh
echo "hello: UserCanceled" >&2
exit 1
`;

const writeHelper = async (dir: string, body: string): Promise<string> => {
	const p = join(dir, "hello-helper.sh");
	await writeFile(p, body);
	await chmod(p, 0o755);
	return p;
};

test(
	"helper transport: signs through the wire protocol and round-trips a DUK",
	{ skip: platform() === "win32" },
	async () => {
		const dir = await mkdtemp(join(tmpdir(), "vault-hello-stub-"));
		try {
			await withEnv({ VAULT_HOME: join(dir, "home") }, async () => {
				const signer = helperHelloSigner(await writeHelper(dir, STUB_HELPER("stub-key", dir)));
				assert.equal(await signer.available(), true);

				const ks = makeHelloKeyStore(signer);
				const secret = Buffer.from("device-unlock-key");
				await ks.put("vault-1", secret);
				assert.deepEqual(await ks.get("vault-1"), secret);

				// Enrollment passed --create to the helper; the stub left a marker.
				await execFile("test", ["-f", join(dir, "created")]);
				// The signature the stub produced matches an independent HMAC — i.e. the
				// challenge/signature really crossed the boundary base64-clean.
				const sig = await signer.sign(Buffer.from("probe"));
				assert.deepEqual(sig, createHmac("sha256", "stub-key").update("probe").digest());
			});
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	},
);

test(
	"helper transport: a denied gesture surfaces stderr and fails closed",
	{ skip: platform() === "win32" },
	async () => {
		const dir = await mkdtemp(join(tmpdir(), "vault-hello-stub-"));
		try {
			const signer = helperHelloSigner(await writeHelper(dir, FAIL_HELPER));
			assert.equal(await signer.available(), false, "a failing helper is not available");
			await assert.rejects(signer.sign(Buffer.from("c")), /hello: UserCanceled/);

			// Through the keystore: a denied gesture on get is "no secret", not a throw.
			await withEnv({ VAULT_HOME: join(dir, "home") }, async () => {
				const ks = makeHelloKeyStore(signer);
				assert.equal(await ks.get("anything"), undefined);
			});
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	},
);

test("helper transport: available() is false when the helper isn't installed", async () => {
	const signer = helperHelloSigner(join(tmpdir(), "vault-no-such-helper"));
	assert.equal(await signer.available(), false);
});

// ---- default signer discovery ----

test("windows-hello is unavailable by default off Windows", async () => {
	await withEnv({ VAULT_HELLO_HELPER: undefined, VAULT_HELLO_PS: undefined }, async () => {
		if (platform() === "win32") return; // covered by the real-Windows probes below
		assert.equal(await makeHelloKeyStore().available(), false);
		assert.equal(await keyStoreByName("windows-hello"), undefined);
		await assert.rejects(defaultHelloSigner().sign(Buffer.from("c")), /no signer available/);
	});
});

test(
	"VAULT_HELLO_HELPER drives discovery end-to-end (defaultKeyStore -> keyStoreByName)",
	{ skip: platform() === "win32" },
	async () => {
		const dir = await mkdtemp(join(tmpdir(), "vault-hello-disc-"));
		try {
			const helper = await writeHelper(dir, STUB_HELPER("k", dir));
			await withEnv({ VAULT_HELLO_HELPER: helper, VAULT_HOME: join(dir, "home") }, async () => {
				// An explicit helper path is trusted as-is (how a dev box or the app
				// wires the tier), so the provider resolves even off win32 — exactly
				// like pointing VAULT_TPM2_SOCKET at swtpm.
				const ks = await keyStoreByName("windows-hello");
				assert.ok(ks, "provider resolves when the helper is wired up");
				const secret = Buffer.from("duk-bytes");
				await ks!.put("v", secret);
				assert.deepEqual(await ks!.get("v"), secret);
			});
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	},
);

test("powerShellHelloSigner is win32-only", async () => {
	if (platform() === "win32") return;
	assert.equal(await powerShellHelloSigner().available(), false);
});

// ---- real-Windows probes (run on the Windows CI leg; skipped elsewhere) ----
//
// The CI runner has no Hello enrolled, so `available` legitimately answers
// "no" — what these validate is that the WinRT projection script and the
// compiled helper load, run, and exit cleanly (a syntax/projection error would
// reject loudly instead of reading as "unavailable").

test(
	"windows: the WinRT projection availability script runs cleanly",
	{ skip: platform() !== "win32" },
	async () => {
		const { stdout } = await execFile("powershell.exe", powerShellArgs(PS_HELLO_AVAILABLE));
		assert.match(stdout.trim(), /^[01]$/, "IsSupportedAsync answered");
		assert.equal(typeof (await powerShellHelloSigner().available()), "boolean");
	},
);

test(
	"windows: the WinRT projection sign script runs cleanly (NotFound path)",
	{ skip: platform() !== "win32" },
	async () => {
		// Probe a NEVER-enrolled credential with create=false. On the normal path
		// OpenAsync answers NotFound and the script exits 1 with its own
		// "hello: <Status>" marker before any Hello prompt; on a host where the
		// NGC/Passport WinRT call faults (service disabled, no TPM), OpenAsync
		// instead THROWS, which $ErrorActionPreference='Stop' turns into a .NET
		// "...Exception" on stderr. Accept either — both prove the parse/projection/
		// Await/OpenAsync plumbing ran — but a bare PowerShell ParserError (a real
		// syntax bug in the sign script) matches neither and still fails the test.
		// The availability test above independently covers that the projection loads.
		const probe = execFile(
			"powershell.exe",
			powerShellArgs(psHelloSign(false, "dev.vault.ci-probe")),
		);
		probe.child.stdin?.end(Buffer.from("probe-challenge").toString("base64"));
		await assert.rejects(probe, /hello: \w+|Exception/i);
	},
);

const realHelper = process.env.VAULT_HELLO_HELPER;
test(
	"windows: the compiled helper answers `available` cleanly",
	{ skip: platform() !== "win32" || !realHelper },
	async () => {
		// Exit 0 ("1" on stdout) with Hello enrolled, exit 1 without — anything
		// else (crash, missing WinRT, bad projection) rejects and fails the test.
		await execFile(realHelper!, ["available"]).catch((e: { code?: number }) => {
			if (e.code !== 1) throw e;
		});
		assert.equal(typeof (await helperHelloSigner(realHelper!).available()), "boolean");
	},
);

// The credential name is wire-protocol surface shared with the native helper;
// pin it so a rename is a deliberate, cross-artifact change.
test("the per-device credential name is pinned", () => {
	assert.equal(HELLO_CREDENTIAL, "dev.vault.unlock");
});

// psHelloSign interpolates the credential into a single-quoted PowerShell string;
// it must reject anything with a quote/metachar so an exported-builder caller
// can't inject script. The default constant and plain names are accepted.
test("psHelloSign rejects credential names that could break out of the PS literal", () => {
	assert.ok(psHelloSign(false).includes(`OpenAsync('${HELLO_CREDENTIAL}')`));
	assert.ok(psHelloSign(true, "dev.vault.ci-probe").includes("dev.vault.ci-probe"));
	for (const bad of ["x') ; iex $env:P ; ('", "a b", "a;b", 'a"b', "a`b", "a$b", ""]) {
		assert.throws(() => psHelloSign(false, bad), /invalid credential name/);
	}
});
