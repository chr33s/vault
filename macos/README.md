# macOS app

```
macos/
  vault.xcodeproj   Vault.app — a SwiftUI shell over the linked Swift engine
                    (local package ../swift, product VaultCommands)
    vault/            its sources (auto-included; PBXFileSystemSynchronizedRootGroup)
  build.sh          build + code-sign Vault.app
```

The Windows counterpart, the C# Windows Hello KeyCredential signer, lives in
`../windows/hello-helper` (see its README).

## How it fits together

`Vault.app` links the Swift engine directly (`VaultCommands` → `VaultCore`, see
`../swift`) per `vault.spec.md` §15.8. There is no subprocess, no passphrase IPC
(secrets are handed to the engine as values, never through a pipe, argv or the
environment) and no embedded helper. Every action is a `--json` command run in-process
via `VaultCommands.execute`: vault lifecycle (create, multi-vault selection, unlock/lock),
item list/add/edit/remove, sync, in-app keystore enable, device enrollment and
people-sharing (invite/share/join) with QR rendering and camera scanning (plus a paste
fallback for tokens too large to scan). Relay coordinates are configured in-app and passed
to each `sync`/`device-add`/`share` command as an environment overlay for that one command.

The Secure Enclave keystore runs in-process (`VaultPlatformDarwin.SecureEnclaveKeyStore`):
the per-vault device unlock key is sealed to a **non-exportable Secure Enclave key gated by
Touch ID**, and unsealing is the moment that prompts. The engine folds it into the at-rest
wrap key as `HKDF(accountKey, DUK)`, so a stolen disk cannot be brute-forced at any
passphrase strength. Files live under `~/Library/Application Support/vault/se`:
`device.sekey` (CryptoKit's opaque `dataRepresentation`, useless without this enclave and
Touch ID) and one `<id>.se` per sealed key. No keychain item or entitlement is involved,
so it works under plain signing. Where an enclave key cannot be minted (an unsigned or
unentitled host) the engine falls back to the Keychain tier.

## Build

```sh
# dev: open in Xcode and run, or
xcodebuild -project vault.xcodeproj -scheme vault -configuration Debug build
# assemble a signed .app bundle:
CODESIGN_ID="Developer ID Application: You (TEAMID)" ./build.sh
```

`build.sh` builds the app (via `xcodebuild`, which links `../swift`) and code-signs it with
the hardened runtime and the camera entitlement. With no `CODESIGN_ID` it ad-hoc signs (runs
locally, cannot be notarized). arm64 only.

## Notarization (for distribution)

```sh
# one-time credential setup
xcrun notarytool store-credentials VAULT_NOTARY \
  --apple-id you@example.com --team-id TEAMID --password <app-specific-password>

# per release
ditto -c -k --keepParent vault.app vault.zip
xcrun notarytool submit vault.zip --keychain-profile VAULT_NOTARY --wait
xcrun stapler staple vault.app
```

## Scope & threat model

- The App Sandbox is intentionally off: the engine reads and writes
  `~/Library/Application Support/vault`, which is shared with the `vault` CLI, and a sandbox
  container would split them. Distribution is Developer-ID + hardened runtime +
  notarization, not the Mac App Store.
- The app holds the account passphrase in memory for the session and hands it to each
  (stateless) command. It does **not** protect against a compromised-while-unlocked host.
- Relay credentials (bearer token / Cloudflare Access ID+secret) cross as a per-command
  environment overlay because they gate reachability and metadata at the relay, not vault
  confidentiality; the relay is zero-knowledge regardless.
- Secure Keyboard Entry (`EnableSecureEventInput`) is active while a passphrase field is on
  screen.
- The enclave key blob is a plain file bound to this enclave and to user presence, not to any
  calling code: a same-user process could load it with its own CryptoKit call and show its own
  Touch ID prompt. The protection that holds is the user-presence tap on every unseal.
  Closing this fully needs a keychain ACL / access group, i.e. a provisioned, entitled build.
