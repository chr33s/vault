# vault-hello-helper — Windows Hello keystore shim

A separately-built, separately-signed artifact that gives the CLI its
`windows-hello` **strong keystore tier**: per-access user verification, where
every vault unlock requires a Windows Hello gesture (PIN/face/fingerprint)
releasing a non-exportable, TPM-backed key. It is the only non-Swift piece of the
local client (vault.spec.md §15.8): a narrow shim that only ever signs a challenge.

## How it works

`KeyCredential` exposes **sign only, not decrypt**, so the Device Unlock Key
(DUK) never touches this helper. The Swift engine (`HelloCipher` in `VaultCore/Keystore/Windows.swift`) wraps the DUK itself:

```
wrapKey = HKDF-SHA256(RequestSignAsync(challenge), salt=challenge)
blob    = "VHW1" || challenge || iv || tag || AES-256-GCM(wrapKey, DUK)
```

The helper only signs the per-blob challenge with the per-device credential
(`dev.vault.unlock`); `RequestSignAsync` is the moment Windows shows the Hello
gesture. This depends on KeyCredential signatures being **deterministic**
(RSA-2048 / PKCS#1 v1.5 — the same mechanism Bitwarden/KeePassXC use); the engine
self-tests this at enrollment by signing twice and refuses the tier if a
platform ever signs with a randomized scheme (RSA-PSS). The documented fallback
in that case is a CNG/NCrypt helper that actually decrypts — not built, since no
current platform needs it.

## Wire protocol

Base64 on stdin/stdout, nothing secret on argv:

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
single-file** so the one `.exe` is a standalone drop-in that runs with no .NET runtime installed on the user's box (a
plain framework-dependent publish emits an apphost stub that can't run without
its sibling `.dll`/`.runtimeconfig.json`):

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
# single binary at bin/Release/net8.0-windows10.0.19041.0/win-x64/publish/vault-hello-helper.exe
```

Wire it to the `vault` CLI in dev with `VAULT_HELLO_HELPER`:

```powershell
$env:VAULT_HELLO_HELPER = "$PWD\bin\...\publish\vault-hello-helper.exe"
vault keystore enable      # picks windows-hello when Hello is set up
```

In production, place that single `vault-hello-helper.exe` beside `vault.exe`;
the Windows platform layer discovers a sibling helper automatically.

## Signing and caller authentication

Sign the published binary (and the `vault.exe` that spawns it) with
**Authenticode** for the caller-auth gate to hold:

```powershell
signtool sign /fd SHA256 /a /tv http://timestamp.digicert.com vault-hello-helper.exe
```

On every `sign`, the helper resolves its parent process (Toolhelp32 snapshot),
validates the parent executable's Authenticode signature (`WinVerifyTrust`),
and requires the signer certificate to match its own — An unsigned (dev) helper has no identity to bind to and
fails **open**, unless `VAULT_HELLO_STRICT` is set (then it fails **closed**).

Scope: the Hello credential is
per-user, not per-caller — a same-user process can bypass the helper and call
`KeyCredentialManager` itself with its own prompt. The load-bearing protection
is the Hello **user-presence gesture**; caller-auth is defense-in-depth.

## Validation status

- The engine-side blob format, wrap crypto, enrollment determinism self-test and
  helper protocol are unit-tested off Windows (`HelloTests` in the Swift suite: a
  fake-sign oracle, and a blob produced by the earlier implementation).
- CI compiles this helper and the Swift Windows job builds the engine; a Windows
  runner has no Hello, so the helper legitimately answers "not available".
- The gesture paths (`sign`, `--create`, cancellation statuses) and the
  Authenticode caller gate **must be verified on a real Windows host with Hello
  enrolled** before relying on them.
