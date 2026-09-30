# vault — Swift local stack

Implementation of [`vault.spec.md` §15](../vault.spec.md): the trusted local
client in Swift 6. It is wire- and storage-compatible with the earlier TypeScript
client, and the frozen golden vectors in `protocol/vectors/` pin that compatibility.
The Cloudflare Worker relay stays TypeScript (`worker/`).

```text
swift/
├── Package.swift
├── Sources/
│   ├── CSQLite/               system-library shim for libsqlite3
│   ├── VaultCore/             portable engine (no UI imports)
│   │   ├── Crypto/  KDF/  CRDT/  Auth/  Rotation/  Protocol/  Store/
│   │   ├── Keystore/          at-rest key ciphers (DPAPI, Hello, systemd-creds, tpm2-tools)
│   │   ├── Run/               .env parsing, output Scrubber
│   │   ├── Secrets/           SecureBytes (mlock + zero-on-free), TOTP
│   │   ├── Engine/            VaultEngine actor, typed VaultError
│   │   └── Util/              order-preserving JSON, lenient base64, OrderedMap
│   ├── VaultNet/              SwiftNIO: relay + peer servers, tailnet sync, proxy, Access (JWT) verifier
│   ├── VaultCommands/         the command layer; runs in the `vault` binary AND in-process (Vault.app)
│   ├── VaultCLI/              `vault` — thin executable over VaultCommands
│   └── VaultPlatform{Darwin,Linux,Windows}/   narrow per-OS seams
└── Tests/VaultCoreTests/      swift-testing; golden vectors from ../protocol/vectors
```

## Build & test

```sh
cd swift
swift build -c release          # .build/.../vault
swift test                      # unit + golden-vector tests
```

Linux needs `libsqlite3-dev` and `pkg-config`.

## Compatibility

- **Vectors** (`protocol/vectors/`) were frozen from the former TypeScript implementation
  (the generator is gone with it) and cover crypto, KDFs (Argon2id, plus scrypt KATs), TOTP, HLC/CRDT (incl. shuffled replay), the
  auth DAG (forks, invalid/forged/unknown entries, rival genesis, transitive device
  revocation), rotation winner selection, envelopes, grants, gap-free ingest, and a
  TypeScript-written SQLite replica.
- **Stored replicas.** A TypeScript-written replica (`protocol/vectors/store/ts-replica.db`)
  must open and read back correctly in Swift (`ProtocolStoreTests`); the live two-CLI
  interop test was removed with the TS client.
- **Ed25519 signatures are not byte-identical** across implementations: swift-crypto
  signs with hedged randomness. Everything that is hashed or signed (canonical entry
  bytes, envelope hashes, rotation/grant bytes) _is_ byte-identical, and signatures
  cross-verify in both directions. Auth-entry hashes exclude the signature.
- **KDF.** New Swift vaults use scrypt (`N=2^17, r=8, p=1`); Argon2id vaults remain
  readable (spec §15.6). The retired TypeScript client never learned scrypt, so
  it could not open Swift-created vaults.

## Status against the spec's phases

| Phase                         | State                                                                                                                                                                                                                            |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 Freeze behavior             | Done — `protocol/vectors/` (frozen fixtures produced by the former TS reference)                                                                                                                                                 |
| 1 Deterministic core          | Done — HLC, CRDT, auth DAG, rotation, protocol models                                                                                                                                                                            |
| 2 Crypto interop              | Done — SHA-256, X25519, Ed25519, AES-GCM, HKDF, sealed box, scrypt, Argon2id                                                                                                                                                     |
| 3 SQLite                      | Done — same schema; TS-written databases open in Swift (the reverse no longer applies)                                                                                                                                           |
| 4 CLI                         | Done — every command: `init add get list edit rm totp vaults rotate device-remove sync serve relay auth device-add device-confirm invite share join recovery-enable recover keystore run proxy`                                  |
| 5 Platform keystores          | macOS Secure Enclave (in-process) + Keychain, Linux `systemd-creds`, Windows DPAPI + Hello-helper adapter — wire-compatible with the former TS tiers. opt-in `tpm2-tools` TPM tier with PIN and lockout                          |
| 6 macOS app links `VaultCore` | Done — `macos/vault.xcodeproj` links the local package (`VaultCommands`); no Node subprocess, no passphrase IPC, no embedded helper                                                                                              |
| 7 Sync parity                 | Done — relay sync and direct tailnet peer sync (`serve`, `sync --tailnet`), tested between Swift replicas through the Swift relay and peer server                                                                                |
| 8 Proxy                       | Done — `vault proxy` (base-URL and `--connect` modes) on SwiftNIO + AsyncHTTPClient, ephemeral in-memory CA via swift-certificates                                                                                               |
| 9 Remove Node                 | Done — the Node SEA build, the legacy TS client (`cli/`, most of `core/`, its tests), the Node relay and the TS↔Swift interop tests are removed. TypeScript remains only for the Cloudflare Worker (`worker/src`, `worker/test`) |

## Self-hosted relay (spec §15.14)

`vault relay` is the supported self-hosted relay (spec §15.14), replacing the former Node
relay: same HTTP protocol, same SQLite schema, same environment variables,
service-token and Cloudflare Access JWT gates (RS256 pinned; `iss`/`exp` required; JWKS
cached with bounded staleness). Beyond the earlier Node relay it refuses to persist
unauthenticated auth-log entries. Swift clients converge through it in
the Swift test suite. The Cloudflare Worker
(`worker/`) stays TypeScript by design.

## TPM key store (`tpm2`, opt-in)

The retired Node CLI hand-rolled a TPM2 codec. The Swift client instead drives the
`tpm2-tools` binaries (`Tpm2ToolsCipher`), which own all TPM marshalling, sessions and
transport (`/dev/tpmrm0`, or `swtpm` through `TPM2TOOLS_TCTI`). The device unlock key is
sealed to a `fixedtpm|fixedparent|userwithauth` data object under an owner-hierarchy
primary that is re-derived on every call, so nothing about the primary is persisted.
Dictionary-attack protection stays on, so with `VAULT_TPM2_PIN` set this is per-access
user verification with TPM lockout; without it, at-rest TPM binding. The PIN and the key
never appear on argv (stdin and a 0600 file in a private work dir), and the blob is bound to
its keystore id.

```sh
export VAULT_TPM2=1 VAULT_TPM2_PIN=…      # opt in; the PIN is required again at every unlock
vault init --keychain                     # or: vault keystore enable
```

Unit tests use a stub double of the tools (including proof that the PIN never reaches
argv). A CI job (`tpm2`) runs the same cipher against `swtpm`; it was not run locally.
`--with-key=tpm2` (systemd-creds) remains the simpler at-rest option.

## Sensitive memory (spec §15.7)

`SecureBytes` holds long-lived keys in manually allocated, `mlock`ed storage that is
zeroed before release; passphrases and derived keys are wiped after use; the CLI
disables core dumps at startup. swift-crypto's API takes `Data`, so a short-lived
copy exists whenever a key is used (`SecureBytes.withData` scrubs it afterwards).
This narrows the exposure window; it cannot eliminate compiler-introduced copies.

## Not verified locally

Only macOS arm64 was built and tested. The Linux and Windows platform modules, the
`CSQLite` shim off macOS, and the CI matrix entries for them are unexercised. The
`systemd-creds` and Hello ciphers are tested against stub binaries and a
TS-generated blob, not against real systemd, a TPM, or a Hello-enrolled host; DPAPI
is only checked to report unavailable off Windows. The in-process Secure Enclave keystore is tested for its blob format with a software P-256 key; minting a real enclave key needs a signed, entitled host, and an unsigned CLI correctly falls back to Keychain — the enclave path and its Touch ID prompt were not exercised. Windows CI is advisory until
sqlite3 is provisioned there.
