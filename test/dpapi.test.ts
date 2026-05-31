import assert from "node:assert/strict";
import { execFile as execFileCb } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { init, unlock, addItem, getItem } from "../cli/engine.ts";
import { makeDpapiKeyStore, type Dpapi } from "../cli/keystore.ts";
import { Store } from "../core/store.ts";

const execFile = promisify(execFileCb);

// A fake DPAPI transport: "encryption" = prefix the blob with a user/machine tag
// so unprotect only succeeds for the same tag (models CurrentUser binding).
const fakeDpapi = (tag: string): Dpapi => ({
	async available() {
		return true;
	},
	async protect(plaintext: Buffer) {
		return Buffer.concat([Buffer.from(`${tag}:`), plaintext]);
	},
	async unprotect(blob: Buffer) {
		const prefix = Buffer.from(`${tag}:`);
		if (!blob.subarray(0, prefix.length).equals(prefix)) throw new Error("wrong user/machine");
		return blob.subarray(prefix.length);
	},
});

const withHome = async (fn: () => Promise<void>): Promise<void> => {
	const home = await mkdtemp(join(tmpdir(), "vault-dpapi-"));
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

test("DPAPI store: protect/store/retrieve round-trip", async () => {
	await withHome(async () => {
		const ks = makeDpapiKeyStore(fakeDpapi("userA"));
		assert.equal(ks.name, "windows-dpapi");
		assert.equal(await ks.available(), true);
		await ks.put("vault-1", Buffer.from("device-unlock-key"));
		const got = await ks.get("vault-1");
		assert.ok(got);
		assert.equal(got!.toString(), "device-unlock-key");
		await ks.del("vault-1");
		assert.equal(await ks.get("vault-1"), undefined, "deleted blob is gone");
	});
});

test("DPAPI store: a blob from another user cannot be unprotected", async () => {
	await withHome(async () => {
		// userA writes the blob; userB (different DPAPI binding) tries to read it.
		const a = makeDpapiKeyStore(fakeDpapi("userA"));
		await a.put("vault-1", Buffer.from("secret"));
		const b = makeDpapiKeyStore(fakeDpapi("userB"));
		assert.equal(await b.get("vault-1"), undefined, "cross-user unprotect fails -> undefined");
		// The original user still reads it fine.
		assert.equal((await a.get("vault-1"))!.toString(), "secret");
	});
});

test("DPAPI keystore protects a real vault end-to-end (engine round-trip)", async () => {
	const dir = await mkdtemp(join(tmpdir(), "vault-dpapi-e2e-"));
	const prev = process.env.VAULT_HOME;
	process.env.VAULT_HOME = dir; // dpapi blobs live under configDir()
	try {
		const ks = makeDpapiKeyStore(fakeDpapi("thisuser"));
		const store = new Store(join(dir, "v.db"));
		await init(store, "pw", ks);
		assert.equal(store.getMeta("keystoreProvider"), "windows-dpapi");

		const s = await unlock(store, "pw", ks);
		addItem(s, "github", { username: "alice", password: "pw" });
		const fresh = await unlock(store, "pw", ks);
		assert.equal(getItem(fresh, "github")!.fields.username, "alice");

		// Stolen disk without the DPAPI binding (different user) cannot unlock.
		const otherUser = makeDpapiKeyStore(fakeDpapi("attacker"));
		await assert.rejects(unlock(store, "pw", otherUser), /keystore secret missing/);
		store.close();
	} finally {
		if (prev === undefined) delete process.env.VAULT_HOME;
		else process.env.VAULT_HOME = prev;
		await rm(dir, { recursive: true, force: true });
	}
});

// Real PowerShell ProtectedData round-trip. Auto-skips where PowerShell is
// absent (e.g. Linux CI without pwsh); runs on Windows and on dev boxes with
// pwsh installed. Set VAULT_POWERSHELL to point at a specific pwsh/powershell.
const psBin =
	process.env.VAULT_POWERSHELL ?? (process.platform === "win32" ? "powershell.exe" : "pwsh");
const psAvailable = await execFile(psBin, [
	"-NoProfile",
	"-Command",
	"$PSVersionTable.PSVersion.Major",
]).then(
	() => true,
	() => false,
);

test(
	"real PowerShell DPAPI protect/unprotect round-trip",
	{ skip: psAvailable ? false : `PowerShell (${psBin}) not available` },
	async () => {
		// Only meaningful on Windows (ProtectedData throws PlatformNotSupported on
		// non-Windows pwsh); skip the assertion off-Windows but prove the transport
		// spawns and errors cleanly there.
		const { powerShellDpapi } = await import("../cli/keystore.ts");
		if (process.platform === "win32") {
			const secret = Buffer.from("real-dpapi-secret");
			const blob = await powerShellDpapi.protect(secret);
			assert.ok(blob.length > secret.length, "DPAPI blob is larger than plaintext");
			assert.equal((await powerShellDpapi.unprotect(blob)).toString(), "real-dpapi-secret");
		} else {
			await assert.rejects(
				powerShellDpapi.protect(Buffer.from("x")),
				/powershell exited|PlatformNotSupported/,
			);
		}
	},
);

// ---- runPowerShell transport coverage (via a stub interpreter on PATH) ----
// We can't run real PowerShell here, but we can point VAULT_POWERSHELL at a
// stub that reads base64 on stdin and writes base64 on stdout, exercising the
// real spawn/stream/exit-code paths of runPowerShell + powerShellDpapi.

import { writeFile, chmod } from "node:fs/promises";
import { powerShellDpapi } from "../cli/keystore.ts";

// Build a stub "pwsh": echoes stdin verbatim (an identity ProtectedData), or
// exits non-zero when STUB_FAIL is set — to cover the error branch.
const withStubPwsh = async (fail = false): Promise<{ restore: () => Promise<void> }> => {
	const dir = await mkdtemp(join(tmpdir(), "pwsh-"));
	const bin = join(dir, "pwsh");
	const body = fail ? `#!/bin/sh\necho "boom" 1>&2\nexit 3\n` : `#!/bin/sh\ncat\n`; // identity: stdout = stdin (both base64)
	await writeFile(bin, body);
	await chmod(bin, 0o755);
	const prevPs = process.env.VAULT_POWERSHELL;
	const prevPlat = process.env.VAULT_FORCE_PLATFORM;
	process.env.VAULT_POWERSHELL = bin;
	return {
		restore: async () => {
			if (prevPs === undefined) delete process.env.VAULT_POWERSHELL;
			else process.env.VAULT_POWERSHELL = prevPs;
			if (prevPlat === undefined) delete process.env.VAULT_FORCE_PLATFORM;
			else process.env.VAULT_FORCE_PLATFORM = prevPlat;
			await rm(dir, { recursive: true, force: true });
		},
	};
};

test("runPowerShell: protect/unprotect round-trip via a stub interpreter", async () => {
	const { restore } = await withStubPwsh(false);
	try {
		// The stub is identity, so protect then unprotect returns the input bytes.
		const secret = Buffer.from("device-unlock-key");
		const blob = await powerShellDpapi.protect(secret);
		assert.ok(blob.equals(secret), "identity stub returns the input");
		const back = await powerShellDpapi.unprotect(blob);
		assert.ok(back.equals(secret));
	} finally {
		await restore();
	}
});

test("runPowerShell: non-zero exit rejects with stderr", async () => {
	const { restore } = await withStubPwsh(true);
	try {
		await assert.rejects(powerShellDpapi.protect(Buffer.from("x")), /powershell exited 3: boom/);
	} finally {
		await restore();
	}
});
