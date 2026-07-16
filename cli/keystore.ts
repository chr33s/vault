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
//     NOT per-access UV — for that, prefer windows-hello above it.
//   - windows-hello (implemented; Windows, strong tier): wraps the DUK under a
//     key derived from a Windows Hello-gated KeyCredential signature
//     (HKDF(RequestSignAsync(challenge), salt=challenge) -> AES-256-GCM, see
//     cli/hello.ts). True per-access user verification — `get` forces a Hello
//     gesture (PIN/face/fingerprint) releasing a non-exportable TPM-backed key.
//     Discovered via the signed native/hello-helper (VAULT_HELLO_HELPER or a
//     sibling vault-hello-helper.exe); $VAULT_HELLO_PS=1 opts into an unsigned
//     PowerShell WinRT fallback for dev.
//   - systemd-creds (implemented; Linux): seals the DUK with `systemd-creds
//     encrypt --with-key=host` and stores the blob on disk — the Linux analog of
//     windows-dpapi. Machine-scoped (the host secret is root-only), NOT per-user
//     and NOT per-access UV; `--with-key=auto|tpm2` upgrades the same provider to
//     TPM-bound at rest. Needs systemd (~v250+) and host-key access, else it
//     reports unavailable and the vault falls back to passphrase-only.
//   - tpm2 (implemented; Linux, opt-in via $VAULT_TPM2=1, strong tier): seals the
//     DUK directly to the TPM through /dev/tpmrm0 with a dependency-free TPM2 codec
//     (cli/tpm2/). With $VAULT_TPM2_PIN set this is true per-access UV — unseal
//     requires the PIN and the TPM enforces dictionary-attack lockout; without a
//     PIN it is at-rest TPM binding. Uses SALTED HMAC sessions with parameter
//     encryption, so the DUK and PIN never cross the CPU↔TPM bus in the clear
//     (defeats passive bus sniffing). Validated against the swtpm emulator.
//   - none: passphrase-only (the default).
//
// Against a live, unlocked, root/admin host a keystore gives nothing (root reads
// the keychain/DPAPI master key too); its value is offline disk theft, backups,
// and weak-passphrase resistance. See the README threat model.

import { execFile as execFileCb } from "node:child_process";
import { access, mkdir, readFile, writeFile, unlink, chmod } from "node:fs/promises";
import { platform } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { type BlobCipher } from "./blobcipher.ts";
import { defaultHelloSigner, makeHelloCipher, type HelloSigner } from "./hello.ts";
import { configDir } from "./paths.ts";
import { powerShellArgs, siblingOfExecutable, spawnCollect, type SpawnResult } from "./spawn.ts";
import { makeTpm2Cipher } from "./tpm2/provider.ts";

// Every keystore transport (DPAPI/systemd-creds/SE helper — and hello.ts's
// helper) drives its child process through the one shared spawnCollect
// (cli/spawn.ts); every tier implements the one shared BlobCipher shape
// (cli/blobcipher.ts, re-exported here for existing importers).
export type { BlobCipher } from "./blobcipher.ts";

const execFile = promisify(execFileCb);

export type KeyStore = {
	readonly name: string;
	available(): Promise<boolean>;
	put(id: string, secret: Buffer): Promise<void>;
	get(id: string): Promise<Buffer | undefined>;
	del(id: string): Promise<void>;
	// Provider-specific binding the caller should PERSIST alongside provider/id, so
	// unlock can resolve the keystore in the same binding the DUK was sealed under
	// (systemd-creds --with-key mode). Undefined for providers with no such knob.
	bindingMode?(): string | undefined;
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
		// Feed the DUK over stdin, NOT on argv: `-w <value>` puts the base64 DUK in
		// the process table (`ps`, /proc/<pid>/cmdline) for every local user during
		// the write, degrading the keystore back to passphrase-only strength — the
		// exact co-resident threat the DUK defends against. Passing `-w` with no
		// value makes `security` read the secret (and its confirmation) from stdin.
		// -U updates in place if the item already exists.
		const b64 = `${secret.toString("base64")}\n`;
		const { code, stderr } = await spawnCollect(
			SECURITY,
			["add-generic-password", "-U", "-a", id, "-s", SERVICE, "-w"],
			{ input: Buffer.from(b64 + b64) }, // value + confirmation prompt
		);
		if (code !== 0)
			throw new Error(`security add-generic-password failed: ${stderr.toString().trim()}`);
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

// DPAPI is exactly a BlobCipher (aliased, not hand-mirrored, so future BlobCipher
// evolution surfaces here too rather than silently skipping this tier). Its
// CurrentUser binding takes no per-id parameter: unlike systemd-creds (--name) or
// hello (AEAD AAD), windows-dpapi does NOT bind the blob to the keystore id. That
// gap is deliberate — the blobs live in the owner-only 0700 config tree and DPAPI
// already scopes to the current Windows user (a same-user attacker can call
// ProtectedData directly regardless), and threading the id into ProtectedData's
// optionalEntropy would change the sealed format and break every existing
// windows-dpapi vault without a migration read-path. powerShellDpapi's one-arg
// protect/unprotect ignore the extra `name` makeBlobKeyStore passes.
export type Dpapi = BlobCipher;

// Run a PowerShell script that reads base64 on stdin and writes base64 on
// stdout. Avoids putting secrets on the command line / in the process table.
const runPowerShell = async (script: string, input: Buffer): Promise<Buffer> => {
	const ps = platform() === "win32" ? "powershell.exe" : (process.env.VAULT_POWERSHELL ?? "pwsh"); // allow pwsh for testing
	// PowerShell reads/writes base64 text (keeps secrets off argv and binary-clean).
	const { code, stdout, stderr } = await spawnCollect(ps, powerShellArgs(script), {
		input: Buffer.from(input.toString("base64")),
	});
	if (code !== 0) throw new Error(`powershell exited ${code}: ${stderr.toString().trim()}`);
	return Buffer.from(stdout.toString("utf8").trim(), "base64");
};

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

// ---- generalized blob-backed KeyStore ----
//
// DPAPI (Windows) and systemd-creds (Linux) are the same SHAPE of tier: an OS
// facility that seals bytes bound to this machine/user and hands back a blob we
// persist on disk — at-rest protection, no per-access prompt, no extra hardware.
// `BlobCipher` (cli/blobcipher.ts) captures that shape; the old `Dpapi` type is a
// structural subset (its one-arg protect/unprotect is assignable), so existing
// callers keep working.

const blobDir = async (subdir: string): Promise<string> => {
	const dir = join(configDir(), subdir);
	await mkdir(dir, { recursive: true, mode: 0o700 });
	await chmod(dir, 0o700).catch(() => {});
	return dir;
};

const blobPath = async (subdir: string, ext: string, id: string): Promise<string> => {
	if (!/^[A-Za-z0-9._-]+$/.test(id)) throw new Error(`invalid keystore id: ${id}`);
	return join(await blobDir(subdir), `${id}.${ext}`);
};

type BlobStoreOptions = { name: string; subdir: string; ext: string; cipher: BlobCipher };

// One KeyStore over any BlobCipher: seal on put + persist the blob; reload + open
// on get (a failed open -> undefined, i.e. wrong machine/user/key). The cipher is
// injectable for tests.
export const makeBlobKeyStore = ({ name, subdir, ext, cipher }: BlobStoreOptions): KeyStore => ({
	name,
	available: () => cipher.available(),
	...(cipher.bindingMode ? { bindingMode: () => cipher.bindingMode!() } : {}),
	async put(id: string, secret: Buffer): Promise<void> {
		// 0600: the blob is the at-rest-wrapped DUK; never leave it world-readable.
		await writeFile(await blobPath(subdir, ext, id), await cipher.protect(secret, id), {
			mode: 0o600,
		});
	},
	async get(id: string): Promise<Buffer | undefined> {
		let blob: Buffer;
		try {
			blob = await readFile(await blobPath(subdir, ext, id));
		} catch {
			return undefined; // no such blob
		}
		try {
			return await cipher.unprotect(blob, id);
		} catch {
			return undefined; // different machine/user/key -> can't open
		}
	},
	async del(id: string): Promise<void> {
		try {
			await unlink(await blobPath(subdir, ext, id));
		} catch {
			/* already gone */
		}
	},
});

// Windows DPAPI tier, now expressed over the shared helper. Behavior is unchanged:
// name "windows-dpapi", blobs under <configDir>/dpapi/<id>.dpapi.
export const makeDpapiKeyStore = (dpapi: Dpapi = powerShellDpapi): KeyStore =>
	makeBlobKeyStore({ name: "windows-dpapi", subdir: "dpapi", ext: "dpapi", cipher: dpapi });

export const windowsDpapi: KeyStore = makeDpapiKeyStore();

// ---- Windows Hello tier (strong tier over windows-dpapi) ----
//
// The cipher (cli/hello.ts) wraps the DUK under a key derived from a
// Hello-gated, deterministic KeyCredential signature; the wrapped blob lands on
// disk through the same shared plumbing. `get` re-signs the blob's challenge —
// that private-key operation is what forces the Hello gesture. The signer is
// injectable so the blob format + HKDF/AES-GCM wrap are testable off Windows
// with a fake-sign oracle (test/hello.test.ts).
export const makeHelloKeyStore = (signer: HelloSigner = defaultHelloSigner()): KeyStore =>
	makeBlobKeyStore({
		name: "windows-hello",
		subdir: "hello",
		ext: "hello",
		cipher: makeHelloCipher(signer),
	});

export const windowsHello: KeyStore = makeHelloKeyStore();

// ---- Linux systemd-creds provider (the DPAPI-equivalent at-rest tier) ----
//
// systemd-creds encrypt/decrypt is the Linux analog of DPAPI: it seals bytes to a
// machine-bound key and returns a blob we persist. `--with-key=host` is software,
// machine-scoped (the host secret in /var/lib/systemd/credential.secret — the
// DPAPI LocalMachine analog, typically root-only); "auto"/"tpm2" upgrades the SAME
// provider to TPM-bound at rest with no hand-rolled marshaling. Unlike the
// PowerShell transport, systemd-creds takes/returns RAW bytes on stdin/stdout, so
// there is no base64 hop; the secret rides stdin, only --name/--with-key ride argv.
//
// Honest scope (mirrors the DPAPI/keychain caveats above): machine scope, not
// per-user; needs systemd (~v250+) and host-key read access; against a live root
// host it gives nothing. `available()` probes a round-trip and fails closed to
// passphrase-only where systemd-creds is absent or unpermitted.

const SYSTEMD_CREDS_ENV = "VAULT_SYSTEMD_CREDS"; // override binary path (tests/custom)

// Spawn systemd-creds with `input` on stdin, resolve its stdout as a Buffer.
// Binary in/out (no base64). Pointing SYSTEMD_CREDS_ENV at a stub on PATH
// exercises the real spawn/stream/exit-code paths in tests.
const runSystemdCreds = async (args: string[], input: Buffer): Promise<Buffer> => {
	const bin = process.env[SYSTEMD_CREDS_ENV] ?? "systemd-creds";
	const { code, stdout, stderr } = await spawnCollect(bin, args, { input });
	if (code !== 0) throw new Error(`systemd-creds exited ${code}: ${stderr.toString().trim()}`);
	return stdout;
};

export type SystemdCredsOptions = {
	keyMode?: string; // --with-key: "host" (default), "auto", "tpm2", …
	run?: (args: string[], input: Buffer) => Promise<Buffer>; // injectable for tests
};

// The --with-key mode the default provider uses: $VAULT_SYSTEMD_CREDS_KEY ("host"
// software/machine-bound by default; "auto"/"tpm2" binds the DUK to the TPM).
// Resolved at call time so it can be set just before `keystore enable`.
export const systemdCredsKeyMode = (): string => process.env.VAULT_SYSTEMD_CREDS_KEY ?? "host";

// systemd-creds as a BlobCipher. The DUK rides stdin; the keystore id becomes the
// credential --name so a blob can't be reused under another id.
export const makeSystemdCredsCipher = (opts: SystemdCredsOptions = {}): BlobCipher => {
	const run = opts.run ?? runSystemdCreds;
	// Read the env each call (not at construction) so the singleton honors a
	// VAULT_SYSTEMD_CREDS_KEY set later in the process; an explicit opt pins it.
	const keyMode = (): string => opts.keyMode ?? systemdCredsKeyMode();
	return {
		async available(): Promise<boolean> {
			if (platform() !== "linux") return false;
			try {
				// Round-trip a probe byte; also confirms key access (host key is root-only).
				// The probe encrypts in keyMode(). On the UNLOCK path the seal mode is
				// pinned (keyStoreByName builds the cipher with the persisted keystoreKeyMode
				// via bindingMode below), so the probe matches how the DUK was sealed rather
				// than the ambient env default — a tpm2/auto-sealed vault probes in tpm2.
				const blob = await this.protect(Buffer.from([0x01]), "vault-probe");
				const back = await this.unprotect(blob, "vault-probe");
				return back.length === 1 && back[0] === 0x01;
			} catch {
				return false; // absent / unpermitted -> passphrase-only
			}
		},
		protect(plaintext: Buffer, name = "vault"): Promise<Buffer> {
			return run(["encrypt", `--name=${name}`, `--with-key=${keyMode()}`, "-", "-"], plaintext);
		},
		unprotect(blob: Buffer, name = "vault"): Promise<Buffer> {
			return run(["decrypt", `--name=${name}`, "-", "-"], blob);
		},
		bindingMode: () => keyMode(), // persisted at mint, pinned on unlock
	};
};

// Shared on-disk layout for the systemd-creds tier (reused by keyStoreByName when
// it pins the persisted mode, so the name/subdir/ext can't drift between them).
const SYSTEMD_STORE = { name: "systemd-creds", subdir: "systemd-creds", ext: "cred" } as const;

export const linuxSystemdCreds: KeyStore = makeBlobKeyStore({
	...SYSTEMD_STORE,
	cipher: makeSystemdCredsCipher(),
});

// TPM2 strong tier (opt-in via $VAULT_TPM2=1): seals the DUK to the TPM with a
// hand-rolled, dependency-free TPM2 codec (cli/tpm2/) over salted HMAC + parameter-
// encrypted sessions. Transport is platform-chosen — Linux /dev/tpmrm0, Windows TBS
// (tbs.dll via PowerShell). With $VAULT_TPM2_PIN set it is per-access (TPM
// dictionary-attack lockout); without, at-rest TPM binding. Inert unless opted in,
// so it never displaces systemd-creds by default. Just another BlobCipher, so it
// reuses the on-disk blob plumbing. (The Linux codec path is validated against
// swtpm; the Windows tbs.dll call is untested off-Windows — see cli/tpm2/transport.)
export const tpm2Store: KeyStore = makeBlobKeyStore({
	name: "tpm2",
	subdir: "tpm2",
	ext: "tpm2",
	cipher: makeTpm2Cipher(),
});

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

// The helper exchanges base64 over stdin/stdout (the id, not the secret, rides
// argv) and gets the store dir via VAULT_SE_DIR. Like the other transports it
// reports a non-zero exit via `code` rather than rejecting.
const runSeHelper = (
	helperPath: string,
	storeDir: string,
	args: string[],
	input?: Buffer,
): Promise<SpawnResult> =>
	spawnCollect(helperPath, args, {
		input: input ? Buffer.from(input.toString("base64")) : undefined,
		env: { ...process.env, [SE_DIR_ENV]: storeDir },
	});

export const makeSecureEnclaveKeyStore = (opts: SecureEnclaveOptions = {}): KeyStore => {
	const helper = (): string =>
		opts.helperPath ?? process.env[SE_HELPER_ENV] ?? siblingOfExecutable("vault-helper");
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
				() => ({ code: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) }) as SpawnResult,
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

// All known providers, in preference order (strongest first). windowsHello
// precedes windowsDpapi (per-access UV over at-rest, like secureEnclave over
// macKeychain) but only reports available when its helper is installed (or the
// PowerShell fallback is opted in), so a stock Windows box still gets DPAPI.
// tpm2Store precedes linuxSystemdCreds so an opted-in TPM (per-access) wins over
// the at-rest tier, but it is inert ($VAULT_TPM2 unset -> available() false), so
// the default is unchanged.
const PROVIDERS: readonly KeyStore[] = [
	secureEnclave,
	macKeychain,
	windowsHello,
	windowsDpapi,
	tpm2Store,
	linuxSystemdCreds,
];

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
export const keyStoreByName = async (
	name: string,
	mode?: string,
): Promise<KeyStore | undefined> => {
	// systemd-creds: pin the persisted seal mode so the availability probe encrypts
	// in the same mode the DUK was sealed under (the ambient env default may differ
	// on the unlock path, which would falsely reject a tpm2/auto-sealed vault).
	if (name === SYSTEMD_STORE.name && mode) {
		const ks = makeBlobKeyStore({
			...SYSTEMD_STORE,
			cipher: makeSystemdCredsCipher({ keyMode: mode }),
		});
		return (await ks.available()) ? ks : undefined;
	}
	for (const ks of PROVIDERS) if (ks.name === name && (await ks.available())) return ks;
	return undefined;
};
