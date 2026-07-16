// The Windows Hello "strong tier" as a BlobCipher (spec §3.5, plan §12b): per-access
// user verification — every unlock requires a Hello gesture (PIN/face/fingerprint)
// releasing a non-exportable TPM-backed key. makeBlobKeyStore (cli/keystore.ts)
// handles the on-disk blob exactly like the DPAPI/systemd-creds/tpm2 tiers.
//
// KeyCredential exposes SIGN only, not decrypt — so the DUK is never held in the
// Hello key; it is WRAPPED under a key derived from a signature:
//
//   wrapKey = HKDF-SHA256(RequestSignAsync(challenge), salt=challenge)
//   blob    = "VHW1" || challenge(32) || iv(12) || tag(16) || AES-256-GCM(wrapKey, DUK)
//
// The challenge is random per blob and rides inside it; the keystore id is bound
// as AEAD additional data, so a blob renamed to another id fails to open. `get`
// re-signs the stored challenge (the moment that triggers the Hello gesture) and
// re-derives wrapKey.
//
// LOAD-BEARING PREREQUISITE (spec §3.5): the signature must be DETERMINISTIC for
// a fixed challenge, or wrapKey is irrecoverable. KeyCredentialManager keys are
// RSA-2048 / PKCS#1 v1.5 (deterministic) — the same mechanism Bitwarden/KeePassXC
// use for Hello unlock — but protect() SELF-TESTS at enrollment (signs the
// challenge twice, asserts equal) and refuses the tier if a platform ever signs
// with a randomized scheme (RSA-PSS); the documented fallback is a CNG/NCrypt
// helper (a Hello-gated key that actually decrypts), not this module.
//
// Signer transports (injectable; the cipher/blob logic is testable off-Windows
// with a fake-sign oracle):
//   - helperHelloSigner: production. Spawns the signed C# helper
//     (native/hello-helper, vault-hello-helper.exe) — discovered via
//     $VAULT_HELLO_HELPER or as a sibling of the running executable. The helper
//     verifies its caller by Authenticode (WinVerifyTrust), the analog of the
//     macOS helper's Team-ID check.
//   - powerShellHelloSigner: dev fallback, opt-in via $VAULT_HELLO_PS=1. The same
//     WinRT calls reached through Windows PowerShell's WinRT projection — no
//     binary to build, but unsigned (no caller-auth), so it never participates in
//     provider discovery unless opted in.
//
// One per-device credential (dev.vault.unlock) is reused across vaults (per-blob
// challenges keep wrap keys distinct). The unlock path NEVER mints a credential:
// a lost credential (TPM clear / Hello reset) must surface as "cannot unlock —
// re-enroll", not as a fresh key that silently fails to decrypt existing blobs.
// Per-user and interactive-session only — no headless unlock (inherent to
// per-access UV). Lifecycle: losing the credential makes blobs unrecoverable ⇒
// re-enroll the device (as for a lost Secure-Enclave blob).

import { access } from "node:fs/promises";
import { platform } from "node:os";
import { aeadDecrypt, aeadEncrypt, hkdf, randomBytes } from "../core/crypto.ts";
import type { BlobCipher } from "./blobcipher.ts";
import { powerShellArgs, siblingOfExecutable, spawnCollect, type SpawnResult } from "./spawn.ts";

// The per-device Hello credential name (spec §3.5). Shared across vaults; the
// per-blob random challenge keeps every wrap key distinct.
export const HELLO_CREDENTIAL = "dev.vault.unlock";

const HELLO_HELPER_ENV = "VAULT_HELLO_HELPER";
const HELLO_PS_OPTIN_ENV = "VAULT_HELLO_PS";
const HELPER_SIBLING = "vault-hello-helper.exe";

const MAGIC = Buffer.from("VHW1"); // versioned blob header
const CHALLENGE_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;
const HKDF_INFO = "credvault/hello/v1";
const aad = (name: string): Buffer => Buffer.from(`${HKDF_INFO}:${name}`);

export type HelloSignOptions = { create?: boolean };

// The Hello-gated signing oracle the cipher wraps. sign() is the gesture moment.
// create=true may mint the per-device credential (RequestCreateAsync) — only the
// enrollment path passes it; create=false must fail on a missing credential.
export type HelloSigner = {
	available(): Promise<boolean>;
	sign(challenge: Buffer, opts?: HelloSignOptions): Promise<Buffer>;
};

export const makeHelloCipher = (signer: HelloSigner): BlobCipher => ({
	available: () => signer.available(),
	async protect(plaintext: Buffer, name = "vault"): Promise<Buffer> {
		const challenge = randomBytes(CHALLENGE_LEN);
		// First sign may mint the credential; the second is the enrollment self-test
		// (spec §3.5): a randomized scheme (RSA-PSS) would yield an irrecoverable
		// wrapKey, so refuse the tier outright rather than write a dead blob. Two
		// gestures at enrollment, one per unlock.
		const sig = await signer.sign(challenge, { create: true });
		const again = await signer.sign(challenge);
		if (sig.length === 0 || !sig.equals(again)) {
			throw new Error(
				"windows-hello: the credential signs non-deterministically (RSA-PSS?); " +
					"this platform cannot use the Hello tier — use windows-dpapi or tpm2 instead",
			);
		}
		const wrapKey = hkdf(sig, challenge, HKDF_INFO, 32);
		const { iv, ct, tag } = aeadEncrypt(wrapKey, plaintext, aad(name));
		return Buffer.concat([MAGIC, challenge, iv, tag, ct]);
	},
	async unprotect(blob: Buffer, name = "vault"): Promise<Buffer> {
		const headerLen = MAGIC.length + CHALLENGE_LEN + IV_LEN + TAG_LEN;
		if (blob.length < headerLen || !blob.subarray(0, MAGIC.length).equals(MAGIC)) {
			throw new Error("windows-hello: not a hello-sealed blob");
		}
		let off = MAGIC.length;
		const challenge = blob.subarray(off, (off += CHALLENGE_LEN));
		const iv = blob.subarray(off, (off += IV_LEN));
		const tag = blob.subarray(off, (off += TAG_LEN));
		const ct = blob.subarray(off);
		// Never { create: true } here: minting a fresh credential could not decrypt
		// this blob — a missing credential must surface as "cannot unlock".
		const sig = await signer.sign(challenge);
		const wrapKey = hkdf(sig, challenge, HKDF_INFO, 32);
		return aeadDecrypt(wrapKey, { iv, ct, tag }, aad(name)); // throws -> get() undefined
	},
});

// ---- helper transport (production) ----
//
// Wire protocol (mirrors the secure-enclave helper: base64 on stdin/stdout,
// nothing secret on argv):
//
//   vault-hello-helper available                  -> "1", exit 0 if Hello usable
//   vault-hello-helper sign [--create] <name>     <- base64(challenge) on stdin
//                                                 -> base64(signature) on stdout
//                                                    (the Hello gesture happens here)
//
// Like the other keystore transports (shared spawnCollect, cli/spawn.ts), a
// non-zero exit is reported via the code, not a rejection — only a spawn
// failure rejects.

// Shared tail of both signer transports. Non-Success Hello statuses
// (UserCanceled, NotFound, SecurityDeviceLocked, UserPrefersPassword) arrive as
// a non-zero exit with "hello: <Status>" on stderr; the thrown error is caught
// by unprotect()'s caller (get() -> undefined -> the engine's standard
// "couldn't unlock" path) and surfaced verbatim on the enrollment path.
const decodeSignResult = ({ code, stdout, stderr }: SpawnResult): Buffer => {
	if (code !== 0) {
		throw new Error(
			`windows-hello sign failed: ${stderr.toString("utf8").trim() || `exit ${code}`}`,
		);
	}
	const sig = Buffer.from(stdout.toString("utf8").trim(), "base64");
	if (sig.length === 0) throw new Error("windows-hello: signer returned an empty signature");
	return sig;
};

export const helperHelloSigner = (helperPath: string): HelloSigner => ({
	async available(): Promise<boolean> {
		try {
			await access(helperPath);
		} catch {
			return false; // helper not installed here
		}
		try {
			const { code, stdout } = await spawnCollect(helperPath, ["available"]);
			return code === 0 && stdout.toString("utf8").trim() === "1";
		} catch {
			return false;
		}
	},
	async sign(challenge: Buffer, opts: HelloSignOptions = {}): Promise<Buffer> {
		const args = ["sign", ...(opts.create ? ["--create"] : []), HELLO_CREDENTIAL];
		return decodeSignResult(
			await spawnCollect(helperPath, args, {
				input: Buffer.from(challenge.toString("base64")),
			}),
		);
	},
});

// ---- PowerShell WinRT-projection signer (dev fallback, opt-in) ----
//
// Windows PowerShell 5.1 can project WinRT types directly, so the same
// KeyCredentialManager calls work with no compiled helper — handy for developing
// and validating the tier on a Windows box before the signed helper is built.
// It is UNSIGNED (no Authenticode identity, so no caller-auth) and therefore
// excluded from provider discovery unless $VAULT_HELLO_PS=1. powershell.exe, not
// pwsh: PowerShell 7 dropped implicit WinRT projection.
//
// PS_HELLO_AVAILABLE and the psHelloSign builder are exported so the Windows CI
// leg (test/hello.test.ts) can execute BOTH scripts directly and fail loudly on
// a projection/syntax error (available() by design swallows errors into
// "unavailable"). The sign script is probed there against a never-enrolled
// credential name, which exits on the NotFound path before any Hello prompt —
// so the parse/projection/Await/OpenAsync plumbing is CI-covered; only the
// gesture path (RequestCreateAsync/RequestSignAsync/CopyToByteArray) still
// needs a Hello-enrolled host.

// WinRT IAsyncOperation -> .NET Task bridge, the standard projection incantation.
const PS_AWAIT = `$ErrorActionPreference='Stop'
[Windows.Security.Credentials.KeyCredentialManager,Windows.Security.Credentials,ContentType=WindowsRuntime] | Out-Null
[Windows.Security.Cryptography.CryptographicBuffer,Windows.Security.Cryptography,ContentType=WindowsRuntime] | Out-Null
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation\`1' })[0]
function Await($op, $t) { $task = $asTaskGeneric.MakeGenericMethod($t).Invoke($null, @($op)); $task.Wait(-1) | Out-Null; $task.Result }
`;

export const PS_HELLO_AVAILABLE = `${PS_AWAIT}
$ok = Await ([Windows.Security.Credentials.KeyCredentialManager]::IsSupportedAsync()) ([bool])
if ($ok) { [Console]::Out.Write('1') } else { [Console]::Out.Write('0') }
`;

// Build the sign script with `create` and the credential name baked in as
// literals. The credential is interpolated into a single-quoted PowerShell
// string, so it is VALIDATED against the same charset the keystore allows for
// ids — no quote/metachar can reach the interpreter, closing the injection this
// exported builder would otherwise expose (both production callers pass the
// constant HELLO_CREDENTIAL; the CI probe passes a plain never-enrolled name).
// Reads base64(challenge) on stdin, writes base64(signature) on stdout; any
// non-Success status exits 1 with the status name on stderr.
export const psHelloSign = (create: boolean, credential: string = HELLO_CREDENTIAL): string => {
	if (!/^[A-Za-z0-9._-]+$/.test(credential)) {
		throw new Error(`windows-hello: invalid credential name: ${credential}`);
	}
	return `
$create = $${create ? "true" : "false"}
${PS_AWAIT}
$challenge = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())
$res = Await ([Windows.Security.Credentials.KeyCredentialManager]::OpenAsync('${credential}')) ([Windows.Security.Credentials.KeyCredentialRetrievalResult])
if ($res.Status -eq [Windows.Security.Credentials.KeyCredentialStatus]::NotFound -and $create) {
  $res = Await ([Windows.Security.Credentials.KeyCredentialManager]::RequestCreateAsync('${credential}', [Windows.Security.Credentials.KeyCredentialCreationOption]::FailIfExists)) ([Windows.Security.Credentials.KeyCredentialRetrievalResult])
}
if ($res.Status -ne [Windows.Security.Credentials.KeyCredentialStatus]::Success) { [Console]::Error.Write('hello: ' + $res.Status); exit 1 }
$buf = [Windows.Security.Cryptography.CryptographicBuffer]::CreateFromByteArray($challenge)
$sig = Await ($res.Credential.RequestSignAsync($buf)) ([Windows.Security.Credentials.KeyCredentialOperationResult])
if ($sig.Status -ne [Windows.Security.Credentials.KeyCredentialStatus]::Success) { [Console]::Error.Write('hello: ' + $sig.Status); exit 1 }
$bytes = New-Object byte[] 0
[Windows.Security.Cryptography.CryptographicBuffer]::CopyToByteArray($sig.Result, [ref]$bytes)
[Console]::Out.Write([Convert]::ToBase64String($bytes))
`;
};

const runPowerShell = async (script: string, input?: Buffer): Promise<SpawnResult> =>
	spawnCollect("powershell.exe", powerShellArgs(script), input ? { input } : {});

export const powerShellHelloSigner = (): HelloSigner => ({
	async available(): Promise<boolean> {
		if (platform() !== "win32") return false; // WinRT projection is Windows-only
		try {
			const { code, stdout } = await runPowerShell(PS_HELLO_AVAILABLE);
			return code === 0 && stdout.toString("utf8").trim() === "1";
		} catch {
			return false;
		}
	},
	async sign(challenge: Buffer, opts: HelloSignOptions = {}): Promise<Buffer> {
		return decodeSignResult(
			await runPowerShell(
				psHelloSign(opts.create === true),
				Buffer.from(challenge.toString("base64")),
			),
		);
	},
});

// ---- signer discovery ----
//
// Resolved at CALL time (not module load) so env set just before `keystore
// enable` is honored, mirroring the systemd-creds key-mode resolution:
//   1. $VAULT_HELLO_HELPER — an explicit helper path is trusted as-is (also how
//      tests drive a stub through the full default chain, like $VAULT_TPM2_SOCKET).
//   2. vault-hello-helper.exe beside the running executable (the SEA binary ships
//      it as a sibling, like vault-helper on macOS) — Windows only.
//   3. $VAULT_HELLO_PS=1 — the PowerShell dev fallback, explicit opt-in only, so
//      a stock Windows box keeps choosing windows-dpapi on `keystore enable`
//      until the signed helper is actually installed (deliberate: presence of the
//      strong tier should be an install action, not a silent default flip).
const resolveSigner = async (): Promise<HelloSigner | undefined> => {
	const explicit = process.env[HELLO_HELPER_ENV];
	if (explicit) return helperHelloSigner(explicit);
	if (platform() !== "win32") return undefined;
	const sibling = siblingOfExecutable(HELPER_SIBLING);
	try {
		await access(sibling);
		return helperHelloSigner(sibling);
	} catch {
		/* not shipped alongside; fall through */
	}
	if (process.env[HELLO_PS_OPTIN_ENV] === "1") return powerShellHelloSigner();
	return undefined;
};

export const defaultHelloSigner = (): HelloSigner => ({
	async available(): Promise<boolean> {
		const signer = await resolveSigner();
		return signer ? signer.available() : false;
	},
	async sign(challenge: Buffer, opts?: HelloSignOptions): Promise<Buffer> {
		const signer = await resolveSigner();
		if (!signer) throw new Error("windows-hello: no signer available on this host");
		return signer.sign(challenge, opts);
	},
});
