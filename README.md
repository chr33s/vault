# vault

End-to-end encrypted, **local-first** credential vault — Architecture C from the
[design spec](./vault.spec.md): a dependency-free core + an always-on,
zero-knowledge Cloudflare relay. Implemented in TypeScript on Node, with the CLI
shipped as a single native executable and the relay as a long-lived Node process
behind Cloudflare Tunnel + Access. See the [implementation plan](./vault.plan.md).

**Guiding constraint: zero runtime dependencies.** Everything resolves to
`node:*` built-ins (crypto, sqlite, http, test, type-stripping, SEA). The only
non-runtime tooling is a bundler (`esbuild`), the type-checker (`typescript`),
and the linter/formatter (`oxlint`/`oxfmt`) — none of which ship inside the
binary. A CI check (`npm run check:deps`) fails the build if any `package.json`
declares runtime `dependencies`.

## Layout

```
core/    dependency-free library: crypto, sealed-box, KDF, HLC, CRDT,
         signed auth-log, conflict-free rotation, sync protocol, sqlite store
cli/     the device client (engine + commands); ships as a single SEA binary
relay/   the always-on zero-knowledge store-and-forward hub (Node + Worker)
         handler.ts (shared logic) · main.ts (Node) · worker/ (Cloudflare) · deploy/
build/   esbuild bundle + SEA pipeline + zero-dep check
test/    node:test specs
```

## What's implemented

| Milestone                      | Status | Notes                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------ | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M1 core + tests                | ✅     | crypto, sealed-box, Argon2id KDF (legacy scrypt read path), HLC, field-level CRDT with password MV-register, signed Merkle-DAG auth log with deterministic fork reconciliation, conflict-free epochs, anti-entropy protocol, sqlite store                                                                                                                                         |
| M2 local CLI                   | ✅     | `init/add/get/list/edit/rm` + `run` against the local replica, no network                                                                                                                                                                                                                                                                                                         |
| M3 relay + sync                | ✅     | `node:http` relay (`/sync`, `/push`); the op log **and** the signed auth log, rotation records, and recovery grants all propagate; two CLIs converge through a relay                                                                                                                                                                                                              |
| M4 enrollment                  | ✅     | `auth` / `device-add` / `device-confirm` token handshake, auth-log validation, user-with-device-subkeys                                                                                                                                                                                                                                                                           |
| M5 rotation/revocation         | ✅     | conflict-free epochs + security catch-up; `device-remove` (rotation propagates over the relay; removed members are locked out of new data)                                                                                                                                                                                                                                        |
| Cross-user sharing             | ✅     | `invite` / `share` / `join`: a different person joins a vault (`add-user` + sealed grants); multi-user removal verified end-to-end                                                                                                                                                                                                                                                |
| Recovery escrow                | ✅     | `recovery-enable` / `recover` (spec §5/§13): per-vault org key; members seal their identity to it; owner reconstructs a locked-out member                                                                                                                                                                                                                                         |
| Multi-vault                    | ✅     | `--vault <name>` selects independent named replicas; `vaults` lists them                                                                                                                                                                                                                                                                                                          |
| M6 SEA packaging               | ✅     | `build/` bundle + `node --build-sea` + signing + CI matrix; produces a working single-file `dist/vault` on Node 26                                                                                                                                                                                                                                                                |
| M7 Cloudflare deploy           | ✅     | **both** §8.2 placements: self-hosted Node behind `cloudflared` (systemd + Tunnel) **and** serverless Worker + Durable Object (`relay/worker/` + `wrangler.toml`); shared `relay/handler.ts`, Access JWT verification, runbook for both (`relay/deploy/`)                                                                                                                         |
| M8 direct fallback / native UI | ✅     | **direct tailnet fallback (§8.6) shipped** — `vault serve` replica peer + `vault sync --tailnet` over Tailscale; **native macOS UI shipped** — `secure-enclave` Touch-ID keystore tier + `Vault.app` SwiftUI wrapper over `vault --json` (see `native/`); **Windows Hello strong tier shipped** — `windows-hello` KeyCredential keystore (`cli/hello.ts` + `native/hello-helper`) |
| Agent secret-use proxy (§13)   | ✅     | `vault proxy` — a loopback egress proxy injects a vault secret into an AI agent's API calls so the agent **uses** a credential without **seeing** it; host-bound, egress-allowlisted, no redirect-follow, per-injection audit                                                                                                                                                     |

## Crypto (all `node:crypto`, plan §8)

- X25519 key agreement, Ed25519 signing, AES-256-GCM AEAD, HKDF, CSPRNG.
- **Sealed-box** (`crypto_box_seal` analog): ephemeral X25519 → ECDH → HKDF →
  AES-256-GCM, used for grants and Token B.
- **Password KDF: Argon2id** (async `crypto.argon2`, threadpool-offloaded) — the
  spec's preferred primitive, native in Node 26 so it stays zero-dep with no WASM
  asset (plan §2). New vaults use 64 MiB / 3 passes / 1 lane; cost params + the
  algorithm live in `kdfParams` so they can be raised later. **Legacy scrypt
  vaults still unlock** (no migration): `kdfParams.algo` discriminates and the
  scrypt path is retained, KAT-locked in tests.

## Running (dev)

**Node 26 is the baseline** (plan §1): native type stripping is the default,
`node:sqlite` is stable, and `node --build-sea` is built in — so the TS sources
run and the binary builds with **no experimental flags**.

```bash
npm install                 # build-time tooling only (esbuild, typescript, oxlint, oxfmt, @types/node)
npm test                    # node:test suite (node --test)
npm run typecheck           # tsc --noEmit (also enforces erasable TS)
npm run check               # oxlint (type-aware) + oxfmt --check
npm run check:deps          # zero-runtime-dependency guard

# CLI (passphrase via prompt or $VAULT_PASSPHRASE)
export VAULT_PASSPHRASE='correct horse battery staple'
npm run cli -- init
npm run cli -- add github --field username=alice --field password=s3cr3t
npm run cli -- list
npm run cli -- get github

# Items are typed (login|note|card|identity; default login) and support TOTP:
npm run cli -- add github --type login --field totp=JBSWY3DPEHPK3PXP
npm run cli -- totp github   # -> current 6-digit code on stdout (countdown on stderr)

# Relay
npm run relay               # listens on :8731

# Single-file binary (node --build-sea)
npm run build:sea           # -> dist/vault (+ dist/vault.sha256)
npm run test:sea            # smoke-test the generated binary (skips if not built)
```

The `node:test` suite covers crypto round-trips, CRDT convergence/idempotence,
auth-log fork reconciliation, anti-entropy + rotation (including **two concurrent
admin rotations converging on one winning key** and the **security catch-up**
firing when a removal is unobserved), cross-user sharing with removal lockout,
recovery escrow, multi-vault isolation, and a **smoke test that drives the
generated single-file binary** through `init/add/list/get`, a relay sync round,
and a second-device enrollment.

## Typed items & TOTP (spec §4)

Every item carries an `itemType` (`login` | `note` | `card` | `identity`,
default `login`; set with `add`/`edit --type`). A `totp` field holding a
**base32 secret** or an **`otpauth://totp/...` URI** is recognized as a
one-time-password source:

- `vault totp <title>` prints the current RFC 6238 code to **stdout** (pipeable,
  e.g. `vault totp gh | pbcopy`) with the countdown on stderr; `--name <field>`
  selects a different field.
- `vault get <title>` also shows the live code inline (`otp: 123456 (expires in
17s)`) next to the item's fields.

Generation is dependency-free (`node:crypto` HMAC + a small base32 decoder):
SHA1/SHA256/SHA512 and custom digits/period via the otpauth URI, KAT-checked
against the RFC 6238 test vectors. Both the type (a reserved `__type__` field)
and the TOTP secret live **inside the encrypted item content** — never plaintext
metadata to the relay.

## `vault run` — secrets into a command, `.env` stays secret-free

Treats a `.env` file as a _manifest of required variables_: bare/empty keys are
resolved from the local encrypted replica at runtime and injected into the child
process. **Resolved secrets never touch disk.** Precedence per variable:

1. ambient non-empty `KEY` wins (local override);
2. else a `KEY=<literal>` non-empty value passes through;
3. else (`KEY=` / bare `KEY`) → resolve `KEY` from the vault by item name;
4. `KEY=vault://<vault>/<item>[/<field>]` → resolve that specific entry.

Unresolved required vars fail _before_ spawning (`--allow-missing` downgrades to
a warning). Resolution is offline/instant (reads the local SQLite replica).

```bash
# .env:  DATABASE_URL=  (empty → resolved from the vault)
vault run --env .env -- ./server
```

Every `run` emits a per-access **audit** line to stderr naming the injected
variables and the command (never the values), for parity with `vault proxy`.
Pass `--mask` to pipe the child's stdout/stderr through the same secret scrubber
(`cli/scrub.ts`) the proxy uses, so a secret the child echoes is redacted to
`[REDACTED]`. `--mask` is opt-in because piping (rather than inheriting) the
child's output forgoes a TTY on those streams; stdin stays inherited, so
interactive prompts still work.

## `vault proxy` — let an AI agent USE a secret without SEEING it (spec §13)

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

Hardening (spec §13.2): binds loopback only; each secret is attached to its
upstream host only; egress is allowlisted (an unconfigured host gets `403`);
redirects are **not** followed (a credential can't hop to another host); the
value is never logged or persisted; and every injection emits a stderr audit
line (upstream + rule names + timestamp, never the value). **Core dumps are
disabled** for the proxy process before it unlocks anything, so the injected
secret can't be recovered from a crash image: since zero-dep Node can't
`setrlimit` in-process, `vault proxy` re-execs itself once under `ulimit -c 0`
(skipped when dumps are already off, e.g. a systemd `LimitCORE=0` unit; the
short-lived supervising parent never loads key material; set
`VAULT_PROXY_ALLOW_CORE=1` to opt out while debugging). mlock'ing the pages or
zeroing the secret string remains out of reach in JS (accepted posture). Pass
`--config` repeatedly for multiple upstreams. For known SDKs the spawned child's base-URL
env is preset automatically (`ANTHROPIC_BASE_URL`,
`OPENAI_BASE_URL`/`OPENAI_API_BASE`); otherwise point the agent at
`$VAULT_PROXY_URL`.

For clients that have no base-URL override and only honor `HTTPS_PROXY`, pass
`--connect` to additionally enable forward-proxy (CONNECT) mode (spec §13.1).
The proxy mints an **ephemeral, in-memory CA** (`cli/x509.ts`, hand-rolled on
`node:crypto` — zero deps) and, per allowlisted host, a leaf cert; it terminates
the agent's TLS and runs the decrypted request through the **same** injection /
host-binding / scrubbing path as base-URL mode. Only the public CA cert is ever
written to disk, only the spawned child trusts it (via `NODE_EXTRA_CA_CERTS` /
`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`), and the CA private
key never leaves memory — so there is no system trust store to install or clean
up, and a captured cert is useless next session. A CONNECT to a non-allowlisted
host is refused **before** TLS starts (no cert is minted), preserving the egress
boundary. Cert-pinning clients will correctly refuse; HTTP/1.1 only for now.

As a backstop to "never logged", every resolved value is registered with a
scrubber (`cli/scrub.ts`) that redacts it — plus its URL-encoded, JSON-escaped,
and base64 forms — to a single uniform `[REDACTED]` marker across **every** egress
path: proxy error messages, relayed response headers (e.g. a `Location` echoing
an injected query param), CLI error output, crash dumps (scrubbed
`uncaughtException`/`unhandledRejection` handlers), and response bodies. Relayed
**textual, uncompressed** response bodies (on every status, success included — a
2xx/3xx can echo an injected credential too) run through a streaming scrubber
(`makeScrubStream`, a `node:stream` Transform driven by `pipeline`) that never
buffers the whole body: SSE/streaming stays responsive — it holds back only the
minimal tail that could begin a secret, not a fixed window — and re-examines a
carry-over across chunk boundaries so a secret split across packets is still
caught. Because redaction changes the body length, a scrubbed body drops
`content-length` and is sent chunked. **Compressed or binary bodies are relayed
byte-exact** (gated on `content-type`/`content-encoding`): redaction can't help
there — a secret isn't present as plaintext — and would risk corrupting the
payload. The proxy refuses to start under `NODE_DEBUG` values that would enable
Node's internal http/net/tls logging (including the `*` and `htt*` glob forms)
beneath any scrubbing. Best-effort by design: compressed bodies, exotic
encodings (hex), textual echoes with no `content-type`, and values shorter than
6 chars pass through.

The **relay** closes the same "an error dumps the request" leak from the other
direction. It holds no vault secret (payloads are opaque ciphertext), so there
is nothing to register with the scrubber — but it does see the Cloudflare Access
credential on every request. Being zero-knowledge, it never needs to log a
header or body, so instead of a blocklist scrubber it uses an **allowlist**: an
unexpected error always returns a fixed `{"error":"internal error"}` (never the
raw `err.message`), and the Node relay installs message-only fatal handlers in
place of Node's default object-dumping crash handler (`relay/log.ts`). On the
Worker placement the same blanket-500 keeps raw exceptions out of Workers Logs /
`wrangler tail`.

## Device enrollment (spec §9)

A two-way out-of-band handshake that doubles as public-key trust establishment.
Tokens are base64 today (a QR is an encoding detail, deferred):

```bash
# New device:
vault auth                                   # prints Token A
# Authorized device:
vault device-add --token <A> --role member   # prints Token B + a SAS to compare
# New device:
vault device-confirm --token <B>             # unseals the vault key, builds the replica
vault sync --relay https://vault.example.com --token <service-token>
```

## Sharing a vault with another person (spec §4, §5, §9)

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
  the owning user and their other devices intact (spec §9);
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
  effect (spec §10.2), while a bad/unauthorized entry is skipped, not fatal;
- **tamper-evidence** — an entry's hash covers its parents, so editing any
  ancestor orphans its descendants (the Merkle property the linear chain gave).

The rotation security-catch-up rule uses the same model: a rotation records the
set of auth-entry hashes it observed, so an unobserved concurrent removal is
detected precisely and triggers one more conflict-free rotation.

**Rotation records are signature-verified.** A `RotationRecord` is only trusted
(for winner selection and key recovery) if its signature verifies against the
signing key of an authorized device from the auth log. A forged rotation from a
non-key-holder — e.g. a malicious relay trying to make clients adopt an
attacker-known key — is rejected (spec §8.4).

## Recovery escrow (spec §5, §13 — per-vault policy)

Opt-in admin-assisted recovery. The owner mints an org keypair; each member
seals their identity keys to the org **public** key; the org **private** key is
held offline. The tradeoff is explicit: the org _can_ reconstruct a member's
keys, so this is zero-knowledge against the infrastructure, **not** against the
org-level recovery authority.

```bash
vault recovery-enable                       # owner: prints the org PRIVATE key (store offline)
# ...members sync, contributing their sealed recovery material...
vault recover --user <id> --org-key <k>     # owner: reconstruct a locked-out member
```

## Direct tailnet fallback (spec §8.6)

The relay is the always-on hub, but it's only one replica. The **same** op-log
also flows directly between devices over the user's [Tailscale](https://tailscale.com)
tailnet, so a down, throttled, or eclipsing hub can't isolate two devices that
can reach each other. The tailnet is the transport + access gate, **never** the
confidentiality boundary — ops stay end-to-end encrypted and signed; a peer sees
only ciphertext plus the membership metadata it already gossips through the hub.

```bash
# On an always-on device: serve this vault's replica to the tailnet.
vault serve                                  # binds to this device's Tailscale IP
vault serve --peer-token <t>                 # gate it with a shared token (recommended)

# On another device: reconcile with the hub AND online tailnet peers...
vault sync --tailnet --relay <url>
# ...or skip the hub entirely (e.g. it's unreachable):
vault sync --tailnet-only --peer-token <t>
```

`vault serve` holds no keys and runs while the vault is locked — it's a dumb
store-and-forward replica. Tailscale is the user's own OS install (shelled out
to via its CLI, not bundled, not an npm dependency). Set `VAULT_TAILNET=1` to
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
  `{"ok":true, ...}` on success (e.g. `get` → `{ok,title,itemId,fields,passwords}`),
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

A native macOS wrapper (`native/Vault.app`) spawns the SEA binary with these
flags for its whole feature set — vault creation and multi-vault selection,
item add/edit/remove, sync, device enrollment and people sharing (QR + camera,
with a paste fallback), and relay configuration — and adds the app-layer
hardening the CLI can't do itself: `EnableSecureEventInput()` while a passphrase
field is on screen, and Touch ID + Secure Enclave unlock via the
`secure-enclave` keystore tier (`native/`). See the threat model for why those
belong in the wrapper, not the CLI.

## Threat model

What the cryptography **protects**, regardless of who runs it:

- **Network / relay / cloud operator** — sync carries only ciphertext + metadata
  (identity, op sizes, timing); a malicious relay can delay but never read,
  forge, or corrupt (spec §8.4). Rotation records and membership are signed and
  verified.
- **At-rest / theft / backups** — the on-disk replica (and wrapped private keys)
  is meaningless without the passphrase; with `--keychain` it also requires the
  device's OS keystore secret (macOS keychain, Windows DPAPI, or Linux
  `systemd-creds`), or — on the **strong tier** — a Touch-ID-gated,
  non-exportable **Secure Enclave** key (`native/Vault.app`) or a
  **Windows Hello**-gated `KeyCredential` (`native/hello-helper`). Covers a
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
  while unlocked and JS/V8 can't reliably zero them.
- **The local admin themselves.** On macOS an **admin account is one `sudo` from
  root**, and root can read any file and any process's memory — so there is no
  in-host confidentiality boundary from that user. The vault's value on an admin
  account is at-rest/theft/network protection, not protection from the admin.

**Hardening that actually shifts this** (in order): use a **standard, non-admin**
account for daily work (so the root boundary is real); enable **FileVault**
(at-rest disk + encrypted swap); `vault keystore enable` (offline-theft /
weak-passphrase resistance); prefer the TTY passphrase prompt over
`$VAULT_PASSPHRASE`; auto-lock and disable core dumps. See `vault keystore status`.

### Passphrase-entry hardening (the keylogger window)

The vault can't stop a keylogger that's already running as your user — but you
can narrow the typing window. Best to worst: **don't type a passphrase at all**
(`vault keystore enable`, or the Touch-ID `secure-enclave` unlock in
`native/Vault.app` — no keystroke to capture); avoid `$VAULT_PASSPHRASE` (readable by your own child processes and
saved in shell history — usually a bigger leak than keystroke risk). Beyond that,
terminal-level "secure input" exists but is narrow and platform-specific:

- **macOS** — enable **Secure Keyboard Entry** in Terminal.app / iTerm2 before
  unlocking. It calls `EnableSecureEventInput()`, blocking userland event-tap
  keyloggers (modern macOS already gates these via TCC Input Monitoring). It does
  **not** stop root/kernel/HID-level or hardware keyloggers, and only covers the
  typing window — keys are in process memory once unlocked. The CLI can't toggle
  it (it needs a window-server connection); `native/Vault.app` calls it directly
  while a passphrase field is on screen.
- **Linux** — there is no toggle. Under **Wayland** you get this _structurally_
  (the compositor mediates input; apps can't sniff each other's keystrokes), so
  prefer it. **X11 has no such isolation** — any X client can read the keyboard.
  Better still, skip typing: `vault keystore enable` uses `systemd-creds`
  (machine-bound; `VAULT_SYSTEMD_CREDS_KEY=tpm2` binds the unlock key to the TPM).
- **Windows** — **no app-usable equivalent**; low-level keyboard hooks aren't
  blockable per-process. Lean on the keystore path instead of typing: DPAPI at
  rest, or the `windows-hello` strong tier (a Hello gesture instead of a
  passphrase — nothing to keylog; see `native/hello-helper`), with TPM-via-TBS
  as the non-biometric alternative.

## Security notes (plan §11)

- **No reliable key-memory zeroing in JS/V8** — accepted KNOWN ISSUE, not a
  defect. Mitigated by minimizing key lifetime and never logging secrets.
- **At-rest keys** are sealed under the account key (Argon2id-derived; scrypt for
  legacy vaults). Optionally,
  `vault init --keychain` / `vault keystore enable` folds an OS keystore second
  factor into the wrap key (`HKDF(accountKey, device-unlock-key)`), so a stolen
  disk can't be brute-forced offline at any passphrase strength. Providers:
  **macOS** login keychain (`security`), **Windows** DPAPI (`ProtectedData`,
  CurrentUser scope, via PowerShell), and **Linux** `systemd-creds`
  (`--with-key=host`; set `VAULT_SYSTEMD_CREDS_KEY=tpm2` to bind the DUK to the
  TPM) — all _at-rest_ protection bound to the OS user or machine. The **strong
  tier** adds true per-access user verification: on macOS,
  **Touch ID + Secure Enclave** via the `secure-enclave` provider (a small signed
  `vault-helper` the CLI spawns; the DUK is sealed to a non-exportable Enclave
  key, so `get` triggers a biometric prompt and a stolen disk can't be
  brute-forced at any passphrase strength — see `native/`); on **Linux**, the
  opt-in `tpm2` provider (`VAULT_TPM2=1`) seals the DUK straight to the TPM via
  `/dev/tpmrm0` with a dependency-free, in-tree TPM2 codec (`cli/tpm2/`) — with
  `VAULT_TPM2_PIN` set, unseal requires the PIN and the TPM enforces
  dictionary-attack lockout (per-access UV); without it, at-rest TPM binding. It
  uses **salted HMAC sessions with parameter encryption**, so the DUK and PIN
  never cross the CPU↔TPM bus in the clear (defeats passive bus sniffing on
  discrete TPMs); validated against the swtpm emulator. The same `tpm2` provider
  also drives **Windows TPMs over TBS** (`tbs.dll` via a persistent PowerShell
  helper) — the transport framing + codec are validated against swtpm on Linux,
  but the literal `tbs.dll` call is untested off-Windows and should be verified on
  a real Windows host. On **Windows**, the biometric **Windows Hello** tier
  (`windows-hello`, spec §3.5): `KeyCredential` keys sign but don't decrypt, so
  the DUK is wrapped under `HKDF(RequestSignAsync(challenge), salt=challenge)` →
  AES-256-GCM (`cli/hello.ts`), and every unlock is a Hello gesture
  (PIN/face/fingerprint) releasing a non-exportable TPM-backed key. Enrollment
  self-tests that signatures are deterministic and refuses the tier otherwise.
  The signer is the signed `vault-hello-helper` (C#/CsWinRT, `native/hello-helper`
  — discovered via `$VAULT_HELLO_HELPER` or as a sibling of `vault.exe`, with
  Authenticode caller-auth via `WinVerifyTrust`); `$VAULT_HELLO_PS=1` opts into
  an unsigned PowerShell WinRT fallback for dev. The wrap crypto + protocol are
  unit-tested off-Windows with a fake-sign oracle, and CI builds the helper and
  probes availability on a Windows runner; the gesture paths should be verified
  on a real Hello-enrolled host before relying on them.
- **Untrusted relay** (spec §8.4): signatures + version vectors +
  order-independent CRDT mean the relay can delay but never forge, read, or
  corrupt. It sees metadata (identity, op sizes, timing), never plaintext.
- **`vault run` exposure:** injected secrets are visible to the spawned process
  tree and same-user introspection (`/proc/<pid>/environ`) — the inherent
  tradeoff of env injection. Never persisted, never logged.
- **Revocation** carries a non-crypto obligation: if a device was compromised,
  rotate the _actual_ credentials, not just the vault key (spec §10).

## Known limitations

- **The CLI prints tokens as base64 text, not rendered QR.** The plan permits
  printing the payload string; Join/Token-B bundles also exceed the ~3 KB QR cap
  by design (bulk history flows over sync, not the token). `native/Vault.app`
  renders/scans QR for the device-enrollment handshake on top of the same text
  tokens.
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

|                                   | fnox keychain                      | this vault                                                               |
| --------------------------------- | ---------------------------------- | ------------------------------------------------------------------------ |
| **What's stored in the OS store** | The plaintext secret value         | A random Device Unlock Key                                               |
| **Purpose**                       | Primary secret storage             | Second factor for offline-theft resistance                               |
| **macOS strong tier**             | Login Keychain (unlocked at login) | Secure Enclave — non-exportable key, Touch ID required per access        |
| **Caller authentication**         | None                               | Helper verifies caller's Developer Team signature before Touch ID prompt |
| **Sync across devices**           | Per-machine, not portable          | Vault syncs end-to-end; each device gets its own independent DUK         |

fnox also recommends storing a single `age` private key in the keychain (rather
than each secret directly) to avoid repeated macOS permission dialogs — the same
layered pattern this vault uses by default: one OS-protected key unlocks many
encrypted items.

## Stability caveats

SEA (Stability 1.1) and `node:sqlite` are still maturing — pin Node's exact
patch version per release and re-run the full test matrix on every bump. Source
is kept **erasable** (no `enum`/`namespace`/decorators/parameter properties),
enforced by `tsconfig`'s `erasableSyntaxOnly` so it runs under type stripping
without a transform.
