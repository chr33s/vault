# vault-hello-helper — Windows Hello keystore shim (plan §12b)

A separately-built, separately-signed artifact that gives the CLI its
`windows-hello` **strong keystore tier**: per-access user verification, where
every vault unlock requires a Windows Hello gesture (PIN/face/fingerprint)
releasing a non-exportable, TPM-backed key. Like the macOS `vault-helper`
(plan §12a), it is **not** an npm dependency — the runtime stays zero-dependency
and `check:deps` stays green.

## How it works

`KeyCredential` exposes **sign only, not decrypt**, so the Device Unlock Key
(DUK) never touches this helper. The CLI (`cli/hello.ts`) wraps the DUK itself:

```
wrapKey = HKDF-SHA256(RequestSignAsync(challenge), salt=challenge)
blob    = "VHW1" || challenge || iv || tag || AES-256-GCM(wrapKey, DUK)
```

The helper only signs the per-blob challenge with the per-device credential
(`dev.vault.unlock`); `RequestSignAsync` is the moment Windows shows the Hello
gesture. This depends on KeyCredential signatures being **deterministic**
(RSA-2048 / PKCS#1 v1.5 — the same mechanism Bitwarden/KeePassXC use); the CLI
self-tests this at enrollment by signing twice and refuses the tier if a
platform ever signs with a randomized scheme (RSA-PSS). The documented fallback
in that case is a CNG/NCrypt helper that actually decrypts — not built, since no
current platform needs it.

## Wire protocol

Base64 on stdin/stdout, nothing secret on argv (mirrors the macOS helper):

```
vault-hello-helper available                -> "1", exit 0 if Hello is set up
vault-hello-helper sign [--create] <name>   <- base64(challenge) on stdin
                                            -> base64(signature) on stdout
```

`--create` (enrollment only) may mint the credential via
`RequestCreateAsync(FailIfExists)`. Without it a missing credential is an error:
the unlock path surfaces "cannot unlock — re-enroll" instead of minting a fresh
key that could never decrypt existing blobs. A lost credential (TPM clear, Hello
or PIN reset) makes existing blobs unrecoverable ⇒ re-enroll the device, as for
a lost Secure-Enclave blob.

## Build

Requires the .NET 8+ SDK (the `net8.0-windows10.0.19041.0` TFM restores the
Windows SDK projections from NuGet at build time). Publish **self-contained,
single-file** so the one `.exe` is a standalone drop-in — like the macOS
`vault-helper` — that runs with no .NET runtime installed on the user's box (a
plain framework-dependent publish emits an apphost stub that can't run without
its sibling `.dll`/`.runtimeconfig.json`):

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
# single binary at bin/Release/net8.0-windows10.0.19041.0/win-x64/publish/vault-hello-helper.exe
```

Wire it to the CLI in dev with `VAULT_HELLO_HELPER`:

```powershell
$env:VAULT_HELLO_HELPER = "$PWD\bin\...\publish\vault-hello-helper.exe"
node ..\..\cli\main.ts keystore enable      # picks windows-hello when Hello is set up
```

In production, place that single `vault-hello-helper.exe` beside `vault.exe` —
the CLI discovers a sibling helper automatically (like `vault-helper` on macOS).

Alternatively, `VAULT_HELLO_PS=1` opts into a **PowerShell WinRT-projection
fallback** (`cli/hello.ts`) that needs no compiled helper — dev only: it is
unsigned, so there is no caller authentication.

## Signing and caller authentication

Sign the published binary (and the `vault.exe` that spawns it) with
**Authenticode** for the caller-auth gate to hold:

```powershell
signtool sign /fd SHA256 /a /tv http://timestamp.digicert.com vault-hello-helper.exe
```

On every `sign`, the helper resolves its parent process (Toolhelp32 snapshot),
validates the parent executable's Authenticode signature (`WinVerifyTrust`),
and requires the signer certificate to match its own — the analog of the macOS
helper's Team-ID check. An unsigned (dev) helper has no identity to bind to and
fails **open**, unless `VAULT_HELLO_STRICT` is set (then it fails **closed**).

Scope (same honest caveat as the macOS helper): the Hello credential is
per-user, not per-caller — a same-user process can bypass the helper and call
`KeyCredentialManager` itself with its own prompt. The load-bearing protection
is the Hello **user-presence gesture**; caller-auth is defense-in-depth.

## Validation status

- The CLI-side blob format, wrap crypto, enrollment determinism self-test, and
  spawn protocol are unit-tested off Windows (`test/hello.test.ts`: fake-sign
  oracle + a stub helper speaking this wire protocol).
- CI compiles this helper and runs `available` on a real Windows runner (which
  has no Hello, so it answers "not available" — exercising the WinRT projection
  and exit-code paths).
- The gesture paths (`sign`, `--create`, cancellation statuses) and the
  Authenticode caller gate **must be verified on a real Windows host with Hello
  enrolled** before relying on them — same status the TBS transport ships with
  (`cli/tpm2/transport.ts`).
