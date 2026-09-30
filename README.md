# vault

End-to-end encrypted, **local-first** credential vault (Architecture C, see
[`vault.spec.md`](./vault.spec.md), §15): a native **Swift** client that owns all
plaintext, keys and local storage, plus an always-on, **zero-knowledge** relay that stores and
forwards ciphertext and signed metadata only. A malicious or buggy relay can cost availability
and metadata privacy, never integrity or confidentiality.

## Layout

```
swift/      the whole local stack (Swift 6): VaultCore engine, `vault` CLI, relay + peer
            servers, credential-injecting proxy, per-OS platform modules — see swift/README.md
macos/      Vault.app (SwiftUI, links the engine in-process)
windows/    the Windows Hello helper (C#)
worker/     the Cloudflare Worker + Durable Object relay (TypeScript): src/ (worker, shared
            handler, Access JWT verification, core/ auth log + sync protocol + rotation),
            test/ (node:test), scripts/
deploy/     relay deploy runbooks (self-hosted systemd + cloudflared, Worker)
protocol/   frozen golden vectors the Swift tests check
```

## What's implemented

| Area                         | Notes                                                                                                                                                                                      |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Local CLI                    | `init add get list edit rm totp vaults rotate`, typed items and TOTP, `run` against the local replica                                                                                      |
| Sync                         | relay sync (op log **and** signed auth log, rotation records, recovery grants); direct tailnet peer sync (`serve`, `sync --tailnet`)                                                       |
| Devices and people           | `auth` / `device-add` / `device-confirm`; `invite` / `share` / `join`; `device-remove`; recovery escrow (`recovery-enable`, `recover`); multi-vault (`--vault`)                            |
| Rotation and revocation      | conflict-free epochs with security catch-up; removed members are locked out of new data                                                                                                    |
| Agent secret-use proxy (§13) | `vault proxy`: a loopback egress proxy injects a vault secret into an AI agent's API calls so the agent **uses** a credential without **seeing** it; host-bound, allowlisted, no redirects |
| Relays                       | self-hosted `vault relay` (Swift) behind Cloudflare Tunnel + Access, or the serverless Worker + Durable Object; both gated by service tokens and Access JWT verification                   |
| Key stores (second factor)   | macOS Secure Enclave (Touch ID) and Keychain, Windows Hello and DPAPI, Linux `systemd-creds` and the opt-in `tpm2-tools` TPM tier                                                          |
| macOS app                    | `Vault.app` links the engine directly (no subprocess), QR enrollment and sharing, Secure Keyboard Entry                                                                                    |

## Crypto

X25519 key agreement, Ed25519 signing, AES-256-GCM, HKDF-SHA256 and a CSPRNG, via swift-crypto.
A **sealed box** (ephemeral X25519 → ECDH → HKDF → AES-256-GCM) carries grants and Token B. The
password KDF is **scrypt** (N=2^17, r=8, p=1) for new vaults; Argon2id vaults created by earlier
builds stay readable. Cost parameters and the algorithm live in the vault's `kdfParams`, so they
can be raised later.

## Running (dev)

```bash
cd swift
swift build -c release && swift test     # binary at .build/release/vault

# CLI (passphrase via prompt or $VAULT_PASSPHRASE)
export VAULT_PASSPHRASE='correct horse battery staple'
vault init
vault add github --field username=alice --field password=s3cr3t
vault list
vault get github

# Items are typed (login|note|card|identity; default login) and support TOTP:
vault add github --type login --field totp=JBSWY3DPEHPK3PXP
vault totp github   # -> current 6-digit code on stdout (countdown on stderr)

# Self-hosted relay
vault relay          # listens on 127.0.0.1:8731
```

The Worker-side TypeScript is checked with `npm test`, `npm run typecheck`, `npm run check`
and `npm run check:deps`.

## Typed items & TOTP

Every item carries an `itemType` (`login` | `note` | `card` | `identity`,
default `login`; set with `add`/`edit --type`). A `totp` field holding a
**base32 secret** or an **`otpauth://totp/...` URI** is recognized as a
one-time-password source:

- `vault totp <title>` prints the current RFC 6238 code to **stdout** (pipeable,
  e.g. `vault totp gh | pbcopy`) with the countdown on stderr; `--name <field>`
  selects a different field.
- `vault get <title>` also shows the live code inline (`otp: 123456 (expires in
17s)`) next to the item's fields.

Generation is HMAC (swift-crypto) plus a small base32 decoder:
SHA1/SHA256/SHA512 and custom digits/period via the otpauth URI, KAT-checked
against the RFC 6238 test vectors. Both the type (a reserved `__type__` field)
and the TOTP secret live **inside the encrypted item content** — never plaintext
metadata to the relay.

## `vault run` — secrets into a command, `.env` stays secret-free

Treats a `.env` file as a _manifest of required variables_: bare/empty keys are
resolved from the local encrypted replica at runtime and injected into the child
process. **Resolved secrets never touch disk.** Precedence per variable:

1. ambient non-empty `KEY` wins (local override);
2. else `KEY=vault://<vault>/<item>[/<field>]` → resolve that specific entry
   (field defaults to `password`; a ref to a vault other than the open one fails);
3. else a `KEY=<literal>` non-empty value passes through;
4. else (`KEY=` / bare `KEY`) → resolve `KEY` from the vault by item name.

Unresolved required vars fail _before_ spawning (`--allow-missing` downgrades to
a warning). Resolution is offline/instant (reads the local SQLite replica).

```bash
# .env:  DATABASE_URL=  (empty → resolved from the vault)
vault run --env .env -- ./server
```

Every `run` emits a per-access **audit** line to stderr naming the injected
variables and the command (never the values), for parity with `vault proxy`.
Pass `--mask` to pipe the child's stdout/stderr through the same secret scrubber
(the `Scrubber`) the proxy uses, so a secret the child echoes is redacted to
`[REDACTED]`. `--mask` is opt-in because piping (rather than inheriting) the
child's output forgoes a TTY on those streams; stdin stays inherited, so
interactive prompts still work.

## `vault proxy` — let an AI agent USE a secret without SEEING it

Where `vault run` hands the plaintext to the child's environment, `proxy` keeps
the credential _out_ of the consumer entirely. It stands up a loopback
(`127.0.0.1`-only) HTTP proxy that injects the secret on **egress** — only on
requests bound for the policy's upstream — then forwards to the real upstream
over genuine TLS and streams the response back. The agent points its SDK's
base-URL at the proxy; the secret never enters its env, argv, or memory.

The policy is a `.env`-format manifest: a reserved `UPSTREAM=` line names the
destination, `?name` lines inject query params, and every other key injects a
request header. Injection values resolve with the same precedence as `run`
(ambient → literal → `vault://` ref), so the real key lives only in the vault.
The proxy fails to start if a declared secret can't be resolved (no silent
no-op injection).

```bash
# policy.env:
#   UPSTREAM=https://api.anthropic.com
#   x-api-key=vault://personal/anthropic    # resolved from the vault
vault proxy --config policy.env -- claude   # spawn the agent, base-URL preset, key absent
vault proxy --config policy.env             # foreground, for an externally-launched agent
```

Hardening: binds loopback only; each secret is attached to its
upstream host only; egress is allowlisted (an unconfigured host gets `403`);
redirects are **not** followed (a credential can't hop to another host); the
value is never logged or persisted; and every injection emits a stderr audit
line (upstream + rule names + timestamp, never the value). **Core dumps are
disabled** for the process at startup (`RLIMIT_CORE` 0 on macOS and Linux; not yet on Windows) so
the injected secret can't be recovered from a crash image, and long-lived keys sit in
page-locked, zeroed buffers where practical. Pass
`--config` repeatedly for multiple upstreams. For known SDKs the spawned child's base-URL
env is preset automatically (`ANTHROPIC_BASE_URL`,
`OPENAI_BASE_URL`/`OPENAI_API_BASE`); otherwise point the agent at
`$VAULT_PROXY_URL`.

For clients that have no base-URL override and only honor `HTTPS_PROXY`, pass
`--connect` to additionally enable forward-proxy (CONNECT) mode.
The proxy mints an **ephemeral, in-memory CA** (P-256, built with
swift-certificates) and, per allowlisted host, a leaf cert; it terminates
the agent's TLS and runs the decrypted request through the **same** injection /
host-binding / scrubbing path as base-URL mode. Only the public CA cert is ever
written to disk, only the spawned child trusts it (via `NODE_EXTRA_CA_CERTS` /
`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`), and the CA private
key never leaves memory — so there is no system trust store to install or clean
up, and a captured cert is useless next session. A CONNECT to a non-allowlisted
host is refused **before** TLS starts (no cert is minted), preserving the egress
boundary. Cert-pinning clients will correctly refuse; HTTP/1.1 only for now.

As a backstop to "never logged", every resolved value is registered with a
scrubber that redacts it — plus its URL-encoded, JSON-escaped,
and base64 forms — to a single uniform `[REDACTED]` marker across **every** egress
path: proxy error messages, relayed response headers (e.g. a `Location` echoing
an injected query param), CLI error output and response bodies. Relayed
**textual, uncompressed** response bodies (on every status, success included — a
2xx/3xx can echo an injected credential too) run through a streaming scrubber
(`Scrubber.Stream`) that never
buffers the whole body: SSE/streaming stays responsive — it holds back only the
minimal tail that could begin a secret, not a fixed window — and re-examines a
carry-over across chunk boundaries so a secret split across packets is still
caught. Because redaction changes the body length, a scrubbed body drops
`content-length` and is sent chunked. **Compressed or binary bodies are relayed
byte-exact** (gated on `content-type`/`content-encoding`): redaction can't help
there — a secret isn't present as plaintext — and would risk corrupting the
payload. Best-effort by design: compressed bodies, exotic
encodings (hex), textual echoes with no `content-type`, and values shorter than
6 chars pass through.

The **relay** closes the same "an error dumps the request" leak from the other
direction. It holds no vault secret (payloads are opaque ciphertext), so there
is nothing to register with the scrubber — but it does see the Cloudflare Access
credential on every request. Being zero-knowledge, it never needs to log a
header or body, so instead of a blocklist scrubber it uses an **allowlist**: an
unexpected error always returns a fixed `{"error":"internal error"}` (never the
raw `err.message`), and the relay never echoes error text. On the
Worker placement the same blanket-500 keeps raw exceptions out of Workers Logs /
`wrangler tail`.

## Device enrollment

A two-way out-of-band handshake that doubles as public-key trust establishment.
The CLI prints tokens as base64 text (`--token-file <f>` reads one from a file instead of
argv); the macOS app shows and scans them as QR codes:

```bash
# New device:
vault auth                                   # prints Token A
# Authorized device:
vault device-add --token <A>                 # prints Token B + a SAS to compare
# New device:
vault device-confirm --token <B>             # unseals the vault key, builds the replica
VAULT_RELAY_TOKEN=<service-token> vault sync --relay https://vault.example.com
```

## Sharing a vault with another person

A different person joins with their own user identity (not a device subkey).
An admin signs an `add-user` entry and seals the epoch key(s) to the joiner's
device; the joiner appends their own signed `add-device`. All of it — the auth
log, rotation records, and grants — propagates over the relay.

```bash
# Joiner (own machine):
vault invite                                 # prints an Invite Token
# Admin:
vault share --token <invite> --role member   # prints a Join Token + a SAS
# Joiner:
vault join --token <join>
vault sync --relay <url>                      # publish your device, pull history
```

Revoking access — `vault device-remove`:

- `--device <id>` revokes a single device subkey (e.g. a lost laptop), leaving
  the owning user and their other devices intact;
- `--user <id>` revokes a whole person (their entire device set).

Either appends a signed removal and issues a conflict-free rotation; after sync
the revoked device/member cannot read data written afterward (they keep what
they already cached — spec §10).

### Membership is a signed Merkle DAG (deterministic fork reconciliation)

The auth log isn't a single linear chain — each entry references the heads it
observed (`parents`) and is signed over its content + parents, not a global
index. So two admins (or two devices of one user) editing membership concurrently
**fork** the DAG instead of conflicting, and every replica reconciles the fork
identically:

- **deterministic linearization** — a hash-ordered topological sort yields the
  same canonical order on every node, with no coordination;
- **causal authority** — entries fold in that order and each is judged against
  the state before it, so concurrent removals of different members both take
  effect, while a bad/unauthorized entry is skipped, not fatal;
- **tamper-evidence** — an entry's hash covers its parents, so editing any
  ancestor orphans its descendants (the Merkle property the linear chain gave).

The rotation security-catch-up rule uses the same model: a rotation records the
set of auth-entry hashes it observed, so an unobserved concurrent removal is
detected precisely and triggers one more conflict-free rotation.

**Rotation records are signature-verified.** A `RotationRecord` is only trusted
(for winner selection and key recovery) if its signature verifies against the
signing key of an authorized device from the auth log. A forged rotation from a
non-key-holder — e.g. a malicious relay trying to make clients adopt an
attacker-known key — is rejected.

## Recovery escrow

Opt-in admin-assisted recovery. The owner mints an org keypair; each member
seals their identity keys to the org **public** key; the org **private** key is
held offline. The tradeoff is explicit: the org _can_ reconstruct a member's
keys, so this is zero-knowledge against the infrastructure, **not** against the
org-level recovery authority.

```bash
vault recovery-enable                       # owner: prints the org PRIVATE key (store offline)
# ...members sync, contributing their sealed recovery material...
# Locked-out member, on a fresh device:
vault auth                                   # prints Token A
# Owner:
vault recover --user <id> --org-key-file <f> --token <A>   # prints Token B + SAS (or VAULT_ORG_KEY)
# Member:
vault device-confirm --token <B>             # new passphrase; then sync and device-remove the lost devices
```

The owner's device signs the new device's enrollment (the auth log lets an **owner** device
enroll a device for another member; a user identity key alone still can't enroll past the first
device, so a removed device can't re-enroll itself), and seals the vault keys and the member's
escrowed identity keys to it. Every recovery emits a stderr audit line. Without `--token`,
`recover` prints the recovered identity keys instead.

## Direct tailnet fallback

The relay is the always-on hub, but it's only one replica. The **same** op-log
also flows directly between devices over the user's [Tailscale](https://tailscale.com)
tailnet, so a down, throttled, or eclipsing hub can't isolate two devices that
can reach each other. The tailnet is the transport + access gate, **never** the
confidentiality boundary — ops stay end-to-end encrypted and signed; a peer sees
only ciphertext plus the membership metadata it already gossips through the hub.

```bash
# On an always-on device: serve this vault's replica to the tailnet.
vault serve                                  # binds to this device's Tailscale IP
vault serve --peer-token-file <f>            # gate it with a shared token (recommended; or VAULT_PEER_TOKEN)

# On another device: reconcile with the hub AND online tailnet peers...
vault sync --tailnet --relay <url>
# ...or skip the hub entirely (e.g. it's unreachable):
vault sync --tailnet-only --peer-token-file <f>
```

`vault serve` holds no keys and runs while the vault is locked — it's a dumb
store-and-forward replica. Tailscale is the user's own OS install (shelled out
to via its CLI, not bundled). Set `VAULT_TAILNET=1` to
enable the tailnet leg of every `sync` without the flag.

**Control plane is your choice.** Because the CLI only shells out to your local
`tailscale` and never talks to a control plane directly, the tailnet leg works
unchanged against the **Tailscale-hosted** control plane (the default, lowest
operational burden) or a **self-hosted [Headscale](https://github.com/juanfont/headscale)**
(no third-party control plane). This is purely an operator deployment choice —
the control plane gates access and sees device metadata but **never** vault
confidentiality (ops stay end-to-end encrypted regardless).

## Multiple vaults

A user can belong to many vaults; each is an independent local replica.

```bash
vault --vault work init
vault --vault work add ...
vault vaults                                 # list local vaults (default: personal)
```

## Machine interface (for wrappers & automation)

Two global flags give a stable, scriptable contract — the foundation a native UI
(e.g. a macOS app) or automation builds on, without screen-scraping:

- `--json` — every command emits exactly one JSON object on stdout:
  `{"ok":true, ...}` on success (e.g. `get` → `{ok,title,itemId,itemType,fields,passwords[,otp]}`),
  or `{"ok":false,"error":"..."}` on failure (with a non-zero exit). Human text
  output is unchanged when the flag is absent.
- `--passphrase-stdin` — read each passphrase as one newline-terminated line from
  stdin instead of a TTY prompt. These secrets (the passphrase and item
  passwords) cross the process boundary over **stdin only** — never argv
  (world-readable) or env (leaks to children, shell history).
  Commands that prompt more than once (e.g. `add --password`) read successive
  lines: account passphrase first, then the item password.

```bash
printf 'mypass\n'            | vault --json --passphrase-stdin list
printf 'mypass\nitemsecret\n'| vault --json --passphrase-stdin add gh --password
```

The macOS app (`macos/vault.app`) runs the same commands **in-process** through
`VaultCommands.execute`, using these same flags and JSON contract but handing secrets over as
values rather than a pipe. It covers vault creation and multi-vault selection, item
add/edit/remove, sync, device enrollment and people sharing (QR + camera, with a paste
fallback), and relay configuration, and adds the app-layer hardening the CLI can't do itself:
`EnableSecureEventInput()` while a passphrase field is on screen, and Touch ID + Secure Enclave
unlock via the `secure-enclave` keystore tier (`VaultPlatformDarwin`, usable from the signed app).

## Options & environment

`vault help` prints the full command list; `vault version` (or `--version`) the build.
Secrets are never taken on argv: every secret-bearing flag is a `*-file` path or an env var.

| Scope          | Flags                                                                                               | Env                                                                                                    |
| -------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Global         | `--vault <name>`, `--db <path>`, `--json`, `--passphrase-stdin`                                     | `VAULT_PASSPHRASE`, `VAULT_HOME` (else `XDG_CONFIG_HOME/vault`, else the OS config dir)                |
| Items          | `add`/`edit --field k=v`, `--field-stdin <name>` (value from stdin), `--type`, `--password`         |                                                                                                        |
| Tokens         | `device-add`/`device-confirm`/`share`/`join --token <t>` or `--token-file <f>`                      |                                                                                                        |
| Relay sync     | `sync --relay <url> --relay-token-file <f> --access-id <id> --access-secret-file <f>`               | `VAULT_RELAY_TOKEN`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`                                  |
| Tailnet        | `serve [--host] [--port] [--peer-token-file]`; `sync --tailnet[-only] [--peer <name\|ip>] [--port]` | `VAULT_TAILNET`, `VAULT_PEER_TOKEN`, `VAULT_PEER_ALLOW` (comma list), `VAULT_PEER_PORT` (default 8732) |
| Relay server   | `relay [--host 127.0.0.1] [--port 8731] [--db <file>]`                                              | `PORT`, `RELAY_DB`, `VAULT_RELAY_TOKENS`, `CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_AUD`, `REQUIRE_ACCESS`   |
| Proxy          | `proxy --config <f> [--port 8788] [--connect]`                                                      | child gets `VAULT_PROXY_URL` + known SDK base-URL vars                                                 |
| Recovery       | `recover --user <id> --org-key-file <f> [--token <A>] [--relay <url>]`                              | `VAULT_ORG_KEY`                                                                                        |
| Keystore       | `init --keychain`, `keystore status\|enable\|disable`, `--with-key host\|tpm2\|auto`                | `VAULT_TPM2`, `VAULT_TPM2_PIN`, `VAULT_SYSTEMD_CREDS_KEY`, `VAULT_HELLO_HELPER`                        |
| Tool overrides |                                                                                                     | `VAULT_SYSTEMD_CREDS` (systemd-creds binary), `VAULT_POWERSHELL` (default `pwsh`), `TPM2TOOLS_TCTI`    |

## Threat model

What the cryptography **protects**, regardless of who runs it:

- **Network / relay / cloud operator** — sync carries only ciphertext + metadata
  (identity, op sizes, timing); a malicious relay can delay but never read,
  forge, or corrupt. Rotation records and membership are signed and
  verified.
- **At-rest / theft / backups** — the on-disk replica (and wrapped private keys)
  is meaningless without the passphrase; with `--keychain` it also requires the
  device's OS keystore secret (macOS keychain, Windows DPAPI, or Linux
  `systemd-creds`), or — on the **strong tier** — a Touch-ID-gated,
  non-exportable **Secure Enclave** key (`macos/vault.app`) or a
  **Windows Hello**-gated `KeyCredential` (`windows/hello-helper`). Covers a
  stolen/copied disk, Time Machine, and a vault file synced to iCloud/Dropbox.
- **Plaintext sprawl** — secrets aren't in `.env`/dotfiles; `vault run` decrypts
  them only transiently into a child's environment, and `vault proxy` keeps them
  out of the consumer entirely (injected on egress, so an AI agent never even
  holds the key).
- **Cross-device / cross-person sharing** — gated by sealed grants + the signed
  auth log.

What it **does not** (and cannot) protect — anything with code execution as the
unlocked user:

- A **compromised-while-unlocked host**, a **keylogger** capturing the
  passphrase, or **malware/root** on the account. Keys live in process memory
  while unlocked; `SecureBytes` zeroes them on release, but transient copies can't be
  fully ruled out.
- **The local admin themselves.** On macOS an **admin account is one `sudo` from
  root**, and root can read any file and any process's memory — so there is no
  in-host confidentiality boundary from that user. The vault's value on an admin
  account is at-rest/theft/network protection, not protection from the admin.

**Hardening that actually shifts this** (in order): use a **standard, non-admin**
account for daily work (so the root boundary is real); enable **FileVault**
(at-rest disk + encrypted swap); `vault keystore enable` (offline-theft /
weak-passphrase resistance); prefer the TTY passphrase prompt over
`$VAULT_PASSPHRASE`; set a short OS screen-lock timeout. See `vault keystore status`.

### Passphrase-entry hardening (the keylogger window)

The vault can't stop a keylogger that's already running as your user — but you
can narrow the typing window. Best to worst: **don't type a passphrase at all**
(`vault keystore enable`, or the Touch-ID `secure-enclave` unlock in
`macos/vault.app` — no keystroke to capture); avoid `$VAULT_PASSPHRASE` (readable by your own child processes and
saved in shell history — usually a bigger leak than keystroke risk). Beyond that,
terminal-level "secure input" exists but is narrow and platform-specific:

- **macOS** — enable **Secure Keyboard Entry** in Terminal.app / iTerm2 before
  unlocking. It calls `EnableSecureEventInput()`, blocking userland event-tap
  keyloggers (modern macOS already gates these via TCC Input Monitoring). It does
  **not** stop root/kernel/HID-level or hardware keyloggers, and only covers the
  typing window — keys are in process memory once unlocked. The CLI can't toggle
  it (it needs a window-server connection); `macos/vault.app` calls it directly
  while a passphrase field is on screen.
- **Linux** — there is no toggle. Under **Wayland** you get this _structurally_
  (the compositor mediates input; apps can't sniff each other's keystrokes), so
  prefer it. **X11 has no such isolation** — any X client can read the keyboard.
  Better still, skip typing: `vault keystore enable` uses `systemd-creds`
  (machine-bound; `VAULT_SYSTEMD_CREDS_KEY=tpm2` binds the unlock key to the TPM).
- **Windows** — **no app-usable equivalent**; low-level keyboard hooks aren't
  blockable per-process. Lean on the keystore path instead of typing: DPAPI at
  rest, or the `windows-hello` strong tier (a Hello gesture instead of a
  passphrase — nothing to keylog; see `windows/hello-helper`).

## Security notes

- **Key memory.** Long-lived keys sit in `mlock`ed buffers that are zeroed before release
  (`SecureBytes`; `mlock` is skipped on Windows), passphrases and derived keys are wiped after
  use, and core dumps are disabled on macOS and Linux. Item values themselves are Swift
  `String`s once decrypted. swift-crypto takes `Data`, so a short-lived copy exists whenever a key is used; this
  narrows the exposure window, it does not eliminate compiler-introduced copies.
- **At-rest keys** are sealed under the account key (scrypt-derived). Optionally,
  `vault init --keychain` / `vault keystore enable` folds an OS keystore second factor into the
  wrap key (`HKDF(accountKey, device-unlock-key)`), so a stolen disk can't be brute-forced offline
  at any passphrase strength. Tiers: **macOS** Secure Enclave (Touch ID on every unlock, a
  non-exportable key) or the login Keychain; **Windows** Hello (a Hello gesture on every unlock,
  via the signed `vault-hello-helper`) or DPAPI; **Linux** `systemd-creds` (`--with-key=host`, or
  `tpm2`/`auto` to bind to the TPM at rest) and the opt-in `tpm2-tools` tier (`VAULT_TPM2=1`),
  which seals the key to the TPM and, with `VAULT_TPM2_PIN` set, requires the PIN with TPM
  lockout. See `swift/README.md` for details and what has and hasn't been verified.
- **Untrusted relay**: signatures + version vectors +
  order-independent CRDT mean the relay can delay but never forge, read, or
  corrupt. It sees metadata (identity, op sizes, timing), never plaintext.
- **`vault run` exposure:** injected secrets are visible to the spawned process
  tree and same-user introspection (`/proc/<pid>/environ`) — the inherent
  tradeoff of env injection. Never persisted, never logged.
- **Revocation** carries a non-crypto obligation: if a device was compromised,
  rotate the _actual_ credentials, not just the vault key.

## Known limitations

- **The CLI prints tokens as base64 text, not rendered QR.** The plan permits
  printing the payload string; Join/Token-B bundles also exceed the ~3 KB QR cap
  by design (bulk history flows over sync, not the token). `macos/vault.app`
  renders/scans QR for device enrollment and for invite/join sharing on top of the
  same text tokens.
- **Direct fallback is tailnet-only.** The §8.6 direct path ships as the Tailscale
  variant (`vault serve` + `vault sync --tailnet`, see above); the pure-LAN/mDNS
  discovery variant is not built, so the direct path needs a working tailnet.

## Keychain approach: this vault vs. fnox

[fnox's keychain provider](https://fnox.jdx.dev/providers/keychain) uses the OS
credential store as a **primary secret storage backend** — plaintext values are
written directly into the macOS Keychain, Windows Credential Manager, or Linux
Secret Service, and `fnox.toml` holds pointer names rather than values.

This vault uses the OS secure store differently: the keychain **never holds a
user secret**. It holds a high-entropy **Device Unlock Key (DUK)** that is
folded into the at-rest encryption key as `HKDF(accountKey, DUK)`. Actual
secrets live only in the end-to-end-encrypted, locally-replicated vault.

|                                   | fnox keychain                      | this vault                                                        |
| --------------------------------- | ---------------------------------- | ----------------------------------------------------------------- |
| **What's stored in the OS store** | The plaintext secret value         | A random Device Unlock Key                                        |
| **Purpose**                       | Primary secret storage             | Second factor for offline-theft resistance                        |
| **macOS strong tier**             | Login Keychain (unlocked at login) | Secure Enclave — non-exportable key, Touch ID required per access |
| **Sync across devices**           | Per-machine, not portable          | Vault syncs end-to-end; each device gets its own independent DUK  |

fnox also recommends storing a single `age` private key in the keychain (rather
than each secret directly) to avoid repeated macOS permission dialogs — the same
layered pattern this vault uses by default: one OS-protected key unlocks many
encrypted items.
