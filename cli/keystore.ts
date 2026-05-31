// Optional keystore second factor for at-rest key wrapping (spec §3.4, plan §11).
//
// By default the at-rest private keys are sealed under the scrypt-derived account
// key alone, so a stolen disk + a weak passphrase is brute-forceable offline. A
// keystore binds an additional high-entropy secret (a per-device "unlock key")
// to an OS-protected store, and the wrapping key becomes HKDF(accountKey, DUK).
// Disk-only theft then can't decrypt at any passphrase strength, because the DUK
// lives in the OS keychain (itself encrypted at rest, on Apple silicon under the
// Secure Enclave).
//
// TIERS / honest scope:
//   - secure-enclave (implemented; macOS, strong tier): spawns the signed
//     `vault-helper` (native/, Sources/Helper), which seals the DUK to a
//     NON-EXPORTABLE Secure-Enclave key gated by Touch ID (.userPresence). This
//     is true per-access user verification — the key never leaves hardware and
//     `get` forces a biometric prompt. It is the LocalAuthentication/Security
//     shim the interface below was always shaped to accept.
//   - macos-keychain (implemented): stores the DUK as a login-keychain generic
//     password via /usr/bin/security. This is at-rest protection (the keychain
//     is unlocked at login). It is NOT per-access Touch ID and NOT a
//     non-exportable Secure-Enclave key — for that, prefer secure-enclave above.
//   - windows-dpapi (implemented): DPAPI-encrypts the DUK to the current Windows
//     user (via PowerShell's System.Security.Cryptography.ProtectedData) and
//     stores the resulting blob on disk. At-rest protection bound to the user
//     account — a disk copied to another machine/user can't unprotect it. It is
//     NOT Windows Hello / TPM per-access UV (that needs a WinRT KeyCredential
//     shim, the strong tier).
//   - none: passphrase-only (the default).
//
// Against a live, unlocked, root/admin host a keystore gives nothing (root reads
// the keychain/DPAPI master key too); its value is offline disk theft, backups,
// and weak-passphrase resistance. See the README threat model.

import { execFile as execFileCb, spawn } from "node:child_process";
import { access, mkdir, readFile, writeFile, unlink } from "node:fs/promises";
import { platform } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { configDir } from "./paths.ts";

const execFile = promisify(execFileCb);

export type KeyStore = {
	readonly name: string;
	available(): Promise<boolean>;
	put(id: string, secret: Buffer): Promise<void>;
	get(id: string): Promise<Buffer | undefined>;
	del(id: string): Promise<void>;
};

const SECURITY = "/usr/bin/security";
const SERVICE = "dev.vault.unlock-key";

// macOS login-keychain provider via the `security` CLI.
export const macKeychain: KeyStore = {
	name: "macos-keychain",
	async available(): Promise<boolean> {
		if (platform() !== "darwin") return false;
		try {
			await access(SECURITY);
			return true;
		} catch {
			return false;
		}
	},
	async put(id: string, secret: Buffer): Promise<void> {
		// -U updates in place if the item already exists.
		await execFile(SECURITY, [
			"add-generic-password",
			"-U",
			"-a",
			id,
			"-s",
			SERVICE,
			"-w",
			secret.toString("base64"),
		]);
	},
	async get(id: string): Promise<Buffer | undefined> {
		try {
			const { stdout } = await execFile(SECURITY, [
				"find-generic-password",
				"-a",
				id,
				"-s",
				SERVICE,
				"-w",
			]);
			const v = stdout.trim();
			return v ? Buffer.from(v, "base64") : undefined;
		} catch {
			return undefined; // not found / locked
		}
	},
	async del(id: string): Promise<void> {
		try {
			await execFile(SECURITY, ["delete-generic-password", "-a", id, "-s", SERVICE]);
		} catch {
			/* already gone */
		}
	},
};

// ---- Windows DPAPI provider ----
//
// DPAPI doesn't "store and return" a secret; it encrypts a blob bound to the
// current user (CurrentUser scope). So this provider keeps the DPAPI-protected
// DUK as a file under the config dir — safe at rest because only the same
// Windows user (on the same machine) can unprotect it. The transport is the
// `ProtectedData` API reached through PowerShell; it's injectable so the store
// logic is testable off-Windows.

export type Dpapi = {
	available(): Promise<boolean>;
	protect(plaintext: Buffer): Promise<Buffer>; // -> DPAPI blob
	unprotect(blob: Buffer): Promise<Buffer>; // -> plaintext
};

// Run a PowerShell script that reads base64 on stdin and writes base64 on
// stdout. Avoids putting secrets on the command line / in the process table.
const runPowerShell = (script: string, input: Buffer): Promise<Buffer> =>
	new Promise<Buffer>((resolve, reject) => {
		const ps = platform() === "win32" ? "powershell.exe" : (process.env.VAULT_POWERSHELL ?? "pwsh"); // allow pwsh for testing
		const child = spawn(ps, ["-NoProfile", "-NonInteractive", "-Command", script], {
			stdio: ["pipe", "pipe", "pipe"],
		});
		const out: Buffer[] = [];
		const err: Buffer[] = [];
		child.stdout.on("data", (c: Buffer) => out.push(c));
		child.stderr.on("data", (c: Buffer) => err.push(c));
		child.on("error", reject);
		child.on("close", (code) => {
			if (code !== 0) {
				reject(new Error(`powershell exited ${code}: ${Buffer.concat(err).toString().trim()}`));
				return;
			}
			const text = Buffer.concat(out).toString("utf8").trim();
			try {
				resolve(Buffer.from(text, "base64"));
			} catch (e) {
				reject(e instanceof Error ? e : new Error(String(e)));
			}
		});
		// Writing the input can EPIPE if the child exited before reading stdin (e.g.
		// it errored early). That's not fatal here — the exit code is surfaced by the
		// `close` handler above — so swallow the write error rather than let it throw.
		child.stdin.on("error", () => {});
		child.stdin.end(input.toString("base64"));
	});

// Read all of stdin as base64, run f(bytes), write the base64 result.
const psPipe = (transform: string): string =>
	`$ErrorActionPreference='Stop';` +
	`$in=[Console]::In.ReadToEnd().Trim();` +
	`$bytes=[Convert]::FromBase64String($in);` +
	`Add-Type -AssemblyName System.Security;` +
	`$out=${transform};` +
	`[Console]::Out.Write([Convert]::ToBase64String($out));`;

export const powerShellDpapi: Dpapi = {
	async available(): Promise<boolean> {
		if (platform() !== "win32") return false;
		try {
			// Round-trip a probe byte to confirm ProtectedData actually works.
			const blob = await this.protect(Buffer.from([0x01]));
			const back = await this.unprotect(blob);
			return back.length === 1 && back[0] === 0x01;
		} catch {
			return false;
		}
	},
	protect(plaintext: Buffer): Promise<Buffer> {
		return runPowerShell(
			psPipe(
				"[System.Security.Cryptography.ProtectedData]::Protect($bytes,$null," +
					"[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
			),
			plaintext,
		);
	},
	unprotect(blob: Buffer): Promise<Buffer> {
		return runPowerShell(
			psPipe(
				"[System.Security.Cryptography.ProtectedData]::Unprotect($bytes,$null," +
					"[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
			),
			blob,
		);
	},
};

const dpapiDir = async (): Promise<string> => {
	const dir = join(configDir(), "dpapi");
	await mkdir(dir, { recursive: true });
	return dir;
};

const blobPath = async (id: string): Promise<string> => {
	if (!/^[A-Za-z0-9._-]+$/.test(id)) throw new Error(`invalid keystore id: ${id}`);
	return join(await dpapiDir(), `${id}.dpapi`);
};

// Build a DPAPI-backed KeyStore over a given transport (injectable for tests).
export const makeDpapiKeyStore = (dpapi: Dpapi = powerShellDpapi): KeyStore => ({
	name: "windows-dpapi",
	available: () => dpapi.available(),
	async put(id: string, secret: Buffer): Promise<void> {
		const blob = await dpapi.protect(secret);
		await writeFile(await blobPath(id), blob);
	},
	async get(id: string): Promise<Buffer | undefined> {
		let blob: Buffer;
		try {
			blob = await readFile(await blobPath(id));
		} catch {
			return undefined; // no such blob
		}
		try {
			return await dpapi.unprotect(blob);
		} catch {
			return undefined; // different user/machine -> can't unprotect
		}
	},
	async del(id: string): Promise<void> {
		try {
			await unlink(await blobPath(id));
		} catch {
			/* already gone */
		}
	},
});

export const windowsDpapi: KeyStore = makeDpapiKeyStore();

// ---- macOS Secure Enclave provider (strong tier) ----
//
// Spawns the signed `vault-helper` (native/, Sources/Helper), which seals the
// DUK to a non-exportable Secure-Enclave key gated by Touch ID. `get` triggers
// the biometric prompt; `available`/`put` do not. Like windows-dpapi, the
// transport is base64 over stdin/stdout (the id, not secret, rides argv); the
// helper path and store dir are injectable so the spawn/encode logic is testable
// off real hardware with a stub helper.
//
// Helper discovery: VAULT_HELPER if set (used by the macOS app / dev), else a
// `vault-helper` sitting beside the running executable (the SEA binary ships
// it as a sibling). Sealed blobs live under <configDir>/se, passed to the helper
// as VAULT_SE_DIR so it stays in sync with the CLI's config dir.

const SE_HELPER_ENV = "VAULT_HELPER";
const SE_DIR_ENV = "VAULT_SE_DIR";

export type SecureEnclaveOptions = { helperPath?: string; storeDir?: string };

type HelperResult = { code: number; stdout: Buffer; stderr: Buffer };

const runSeHelper = (
	helperPath: string,
	storeDir: string,
	args: string[],
	input?: Buffer,
): Promise<HelperResult> =>
	new Promise<HelperResult>((resolve, reject) => {
		const child = spawn(helperPath, args, {
			stdio: ["pipe", "pipe", "pipe"],
			env: { ...process.env, [SE_DIR_ENV]: storeDir },
		});
		const out: Buffer[] = [];
		const err: Buffer[] = [];
		child.stdout.on("data", (c: Buffer) => out.push(c));
		child.stderr.on("data", (c: Buffer) => err.push(c));
		child.on("error", reject);
		child.on("close", (code) =>
			resolve({ code: code ?? 0, stdout: Buffer.concat(out), stderr: Buffer.concat(err) }),
		);
		// A put may close before reading all of stdin; swallow EPIPE (the exit code
		// is authoritative, surfaced by `close`).
		child.stdin.on("error", () => {});
		if (input) child.stdin.end(input.toString("base64"));
		else child.stdin.end();
	});

export const makeSecureEnclaveKeyStore = (opts: SecureEnclaveOptions = {}): KeyStore => {
	const helper = (): string =>
		opts.helperPath ??
		process.env[SE_HELPER_ENV] ??
		join(dirname(process.execPath), "vault-helper");
	const dir = (): string => opts.storeDir ?? join(configDir(), "se");
	return {
		name: "secure-enclave",
		async available(): Promise<boolean> {
			if (platform() !== "darwin") return false;
			const h = helper();
			try {
				await access(h);
			} catch {
				return false; // helper not installed here
			}
			try {
				const { code, stdout } = await runSeHelper(h, dir(), ["available"]);
				return code === 0 && stdout.toString("utf8").trim() === "1";
			} catch {
				return false;
			}
		},
		async put(id: string, secret: Buffer): Promise<void> {
			const { code, stderr } = await runSeHelper(helper(), dir(), ["put", id], secret);
			if (code !== 0)
				throw new Error(`secure-enclave put failed: ${stderr.toString("utf8").trim()}`);
		},
		async get(id: string): Promise<Buffer | undefined> {
			// Non-zero exit = missing blob or denied biometric -> treated as "no
			// secret", so the engine surfaces a clean "cannot unlock" rather than a
			// spawn error.
			const { code, stdout } = await runSeHelper(helper(), dir(), ["get", id]).catch(
				() => ({ code: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }) as HelperResult,
			);
			if (code !== 0) return undefined;
			const v = stdout.toString("utf8").trim();
			return v ? Buffer.from(v, "base64") : undefined;
		},
		async del(id: string): Promise<void> {
			await runSeHelper(helper(), dir(), ["del", id]).catch(() => {});
		},
	};
};

export const secureEnclave: KeyStore = makeSecureEnclaveKeyStore();

// All known providers, in preference order (strongest first).
const PROVIDERS: readonly KeyStore[] = [secureEnclave, macKeychain, windowsDpapi];

// The best keystore available on this platform, or undefined (passphrase-only).
// Used when MINTING protection for a new/re-keyed vault (init, enrollment,
// `keystore enable`) — picks the strongest tier the device offers.
export const defaultKeyStore = async (): Promise<KeyStore | undefined> => {
	for (const ks of PROVIDERS) if (await ks.available()) return ks;
	return undefined;
};

// Resolve the specific provider a vault was sealed under (by its recorded
// `keystoreProvider` name). UNLOCK paths must use this, not defaultKeyStore():
// once both macOS providers can be present, "best available" may not match the
// one that actually holds the vault's DUK. Returns undefined if that provider
// isn't available here (the engine then raises a precise "protected by …" error).
export const keyStoreByName = async (name: string): Promise<KeyStore | undefined> => {
	for (const ks of PROVIDERS) if (ks.name === name && (await ks.available())) return ks;
	return undefined;
};
