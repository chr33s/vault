# Native macOS wrapper (plan §12a)

Two separately-built, separately-signed artifacts that wrap the portable CLI. They
are **not** npm dependencies — the runtime stays zero-dependency and `check:deps`
stays green. Both are arm64-only, matching the SEA target (plan §1/§7).

```
./             Two artifacts, two build systems:
  vault.xcodeproj   Step 3 — Vault.app: a SwiftUI shell over `vault --json`
    vault/            its sources (auto-included; PBXFileSystemSynchronizedRootGroup)
  Package.swift     Step 2 — vault-helper: the Secure-Enclave KeyStore shim
    vault-helper/     its sources
  hello-helper/  (not macOS) the Windows analog — the `windows-hello`
                 KeyCredential signer, plan §12b; see its own README
```

`Vault.app` is built by `vault.xcodeproj` (via `build.sh`), which embeds the
helper through its "Embed Helper" copy phase. The helper also builds standalone
— `swift build --product vault-helper` — so the CLI's `secure-enclave` tier can
spawn it without the app (it's spawned by `vault`, not just `Vault.app`).

## How it fits together

The CLI is the engine (plan §0). Neither artifact re-implements any crypto:

- **`vault-helper`** is spawned by the CLI's `secure-enclave` KeyStore provider
  (`cli/keystore.ts`). It seals the per-vault Device Unlock Key (DUK) to a
  **non-exportable Secure-Enclave key gated by Touch ID** and hands it back on
  `get` (the moment that triggers the biometric prompt). The engine folds the DUK
  into the at-rest wrap key as `HKDF(accountKey, DUK)` — so a stolen disk can't be
  brute-forced at any passphrase strength, and there is no passphrase to keylog
  for the second factor. This is the **strong tier** above `macos-keychain`.
- **`Vault.app`** spawns `vault --json --passphrase-stdin` for every action:
  vault lifecycle (create, multi-vault selection, unlock/lock), item list/add/
  edit/remove, sync, in-app keystore enable, the §9 device-enrollment token
  handshake, and §5 people-sharing (invite/share/join) — all with QR rendering
  and camera scanning (plus a paste fallback for tokens too large to scan). It
  points the CLI at the bundled helper via `VAULT_HELPER`, so a Secure-Enclave-
  protected vault prompts for Touch ID during unlock. Relay coordinates (§8) are
  configured in-app and passed to each `sync`/`device-add`/`share` invocation.

## Build

### Secure-Enclave helper

```sh
swift build -c release --arch arm64 --product vault-helper
# binary at .build/release/vault-helper
```

Wire it to the CLI in dev with `VAULT_HELPER`:

```sh
export VAULT_HELPER="$PWD/.build/release/vault-helper"; \
  node ../cli/main.ts init --keychain         # picks the secure-enclave tier when present
```

Everything lives under `$VAULT_SE_DIR` (the CLI passes its config dir,
`~/Library/Application Support/vault/se`): the per-device Enclave key as a
`device.sekey` blob (CryptoKit's `dataRepresentation` — an opaque blob encrypted
by this Enclave, useless without it + Touch ID) and one `<id>.se` per sealed DUK.
No keychain item and no entitlement are involved — that's deliberate, so the
helper works under plain ad-hoc signing (a permanent keychain Enclave key would
need the `keychain-access-groups` entitlement + a provisioning profile).

### App

```sh
# dev: open in Xcode and run (uses $VAULT_BIN / $VAULT_HELPER from the scheme), or
xcodebuild -project vault.xcodeproj -scheme vault -configuration Debug build
# assemble a signed .app bundle:
CODESIGN_ID="Developer ID Application: You (TEAMID)" ./build.sh
```

`build.sh` builds the app (via `xcodebuild`, which embeds the helper), copies the SEA `vault` binary
(`npm run build:sea` → `dist/vault`) and `vault-helper` into
`Vault.app/Contents/Resources`, then code-signs inside-out with the **hardened
runtime** and the camera entitlement. With no `CODESIGN_ID` it ad-hoc signs (runs
locally, cannot be notarized).

## Notarization (for distribution)

```sh
# one-time credential setup
xcrun notarytool store-credentials VAULT_NOTARY \
  --apple-id you@example.com --team-id TEAMID --password <app-specific-password>

# per release
ditto -c -k --keepParent Vault.app Vault.zip
xcrun notarytool submit Vault.zip --keychain-profile VAULT_NOTARY --wait
xcrun stapler staple Vault.app
```

## Scope & threat model

- The App Sandbox is intentionally off: the app spawns the CLI/helper and the CLI
  reads/writes `~/Library/Application Support/vault`, which a sandbox container
  would break. Distribution is Developer-ID + hardened runtime + notarization, not
  the Mac App Store.
- The app holds the account passphrase in memory for the session and re-supplies
  it to each (stateless) CLI invocation. Like the CLI, it does **not** protect
  against a compromised-while-unlocked host (see the root README threat model).
- Vault secrets (the passphrase, item passwords) cross on stdin only
  (`--passphrase-stdin`), never argv (world-readable via `ps`) or env (inherited
  by children). The one deliberate exception is **relay credentials** (bearer
  token / Cloudflare Access ID+secret): these cross via env, because they gate
  reachability and metadata at the relay (§8.3), not vault confidentiality — the
  relay is zero-knowledge regardless. The relay **URL** rides argv (it's not a
  secret); the relay file path stays out of the process table.
- Secure Keyboard Entry (`EnableSecureEventInput`) is active while a passphrase
  field is on screen — the app-layer hardening the CLI can't do itself.

### Secure-Enclave keystore: caller authentication

`.userPresence` authenticates the **human** (Touch ID), not the **calling code** — so
on its own, any process running as you could spawn `vault-helper` and unseal the DUK
on a single reflexive tap. The helper therefore also authenticates its caller: before
`get`/`put`/`del` (not the side-effect-free `available`) it requires the **parent
process** to be signed by the **same Apple Developer Team** as the helper itself
(`anchor apple generic and certificate leaf[subject.OU] = <our team>`). Code signed by
another identity — or unsigned malware — that goes **through the helper** is rejected
_before_ the Touch ID prompt is ever shown.

> **Scope — this is defense-in-depth, not a boundary.** The enclave key is stored as a
> plain `dataRepresentation` file (`device.sekey`), because a keychain-backed permanent
> key needs entitlements an unprofiled helper can't carry. That blob is bound to this
> enclave and to `.userPresence`, but **not** to any calling code — so a same-user
> process can **bypass the helper entirely**, load the key with its own CryptoKit call,
> and show its own Touch ID prompt. Caller authentication only guards the helper's front
> door; it does **not** make the on-disk key unusable by other local code. The
> protection that still holds against such an attacker is the **user-presence tap**
> itself (you must approve each unseal), not code identity. Fully closing this needs a
> keychain ACL / access group — i.e. a provisioned, entitled build.

Caveats (all deliberate):

- **Only enforceable under real signing.** Ad-hoc / unsigned builds carry no Team
  identity to bind to, so the check **fails open** by default — preserving the
  supported "Sign to Run Locally" and `swift build` dev flows. For the guarantee to
  actually hold, ship the CLI **and** helper Developer-ID signed (`build.sh` does this
  when `CODESIGN_ID` is set). Set **`VAULT_SE_STRICT=1`** to make an unsigned helper
  **fail closed** instead of open.
- **Binds to Team, not a single binary** — any of your own signed code qualifies,
  which is fine for a personal vault. Pin with `identifier "…"` if you ever want to
  restrict it to one executable.
- The Touch ID prompt **names the verified requester** (`"Unlock your vault — requested
by <identifier>"`) as a second human signal; the name is read from the caller's
  signature _after_ `SecCodeCheckValidity` passes, so it can't be spoofed. Unsigned/dev
  builds have no verified caller, so the prompt stays generic there.
- A theoretical `getppid()` PID-reuse TOCTOU remains, sound in practice because the
  parent stays alive for the whole call.

### Losing the Enclave key (recovery)

The `device.sekey` blob is the keystore second factor for this device. It is **safe
in backups** — an Enclave-encrypted blob is useless on any other machine — but it is
also the single thing that unwraps this device's at-rest keys. Treat it like any
second factor:

- It is bound to **this** Mac's Secure Enclave; it cannot be copied to another
  machine, and a wiped/replaced Enclave (or erased Mac) loses it permanently.
- If it is deleted while the vault replica remains, **this device can no longer
  unlock** — `get` reports "device key missing" rather than minting a useless new
  key. Your data is unaffected on other devices and the relay.
- **Recovery is re-enrollment**, not file restore: `vault auth` → `device-add`
  (from a device that can still unlock) → `device-confirm` rebuilds this device's
  replica with a fresh keystore factor. If you simply no longer want the factor on
  a device you _can_ still unlock, run `vault keystore disable` there.
