# Implementation Plan — Architecture C (Node 26 + TypeScript)

**Target:** the credential vault’s **Architecture C** (local-first core + always-on Cloudflare relay), implemented in TypeScript on **Node.js 26**, with the **CLI compiled to a single executable** via `node --build-sea`, and the **relay** as a Node process behind **Cloudflare Tunnel + Access**.

**Guiding constraint:** _minimize external dependencies._ Node 26’s built-ins now cover crypto, SQLite, HTTP, testing, and TypeScript execution, so the design targets **zero runtime dependencies** — only build-time tooling.

This plan references the design spec (`spec.md`); section numbers like §8 point there.

---

## 0. What gets built

1. **`core`** — a dependency-free TypeScript library: crypto, sealed-box, CRDT op-log, signed auth-log, conflict-free rotation, anti-entropy protocol, SQLite store. Shared by both binaries.
1. **`cli`** — the device client. Holds the local encrypted replica, performs all crypto, talks to the relay. **Shipped as a single-file native executable** per platform.
1. **`relay`** — the always-on hub from §8.2 (self-hosted-Node placement). A dumb, zero-knowledge store-and-forward replica exposed via `cloudflared`, gated by Cloudflare Access. Runs as a long-lived Node process.

The CLI is the portable engine; a native Swift/macOS UI (the original framing) can later wrap it by spawning the binary or linking a thin library. Not required for v1.

---

## 1. Platform baseline — why Node 26 fits the “minimal deps” goal

| Need               | Node 26 built-in                                                                      | Removes the need for                    |
| ------------------ | ------------------------------------------------------------------------------------- | --------------------------------------- |
| Run TypeScript     | Native **type stripping** (stable since 25.2, default) via Amaro                      | ts-node, tsx, babel (for dev/run)       |
| Crypto             | `node:crypto` — X25519, Ed25519, AES-256-GCM, ChaCha20-Poly1305, HKDF, scrypt, CSPRNG | libsodium, tweetnacl (mostly — see §8)  |
| Local DB           | `node:sqlite` (`DatabaseSync`)                                                        | better-sqlite3, native bindings         |
| HTTP server/client | `node:http` / `node:https` / `fetch`                                                  | express, axios, undici                  |
| Tests              | `node:test` + `node:assert`                                                           | jest, vitest, mocha                     |
| Single binary      | `node --build-sea` (built-in since 25.5)                                              | pkg, nexe; even postject (now optional) |
| File watch (dev)   | `node --watch`                                                                        | nodemon                                 |

Net result: **no runtime dependencies**; build-time deps are just a bundler and the type-checker.

Caveats to respect (documented, not blockers):

- Type stripping runs **erasable** TS only — no `enum`, `namespace`, legacy decorators, or parameter properties in `core`/`cli`/`relay` source. It ignores `tsconfig.json` at runtime and **does not type-check** (that’s `tsc --noEmit`’s job in CI).
- SEA is **Stability 1.1 (active development)**; pin the exact Node version used to build (the SEA blob must be injected into the same Node version).
- SEA is CI-tested on **macOS arm64 only** (x64 not currently covered), Windows, and most Linux. **Decision: macOS ships arm64 only** — no x64 macOS build.

---

## 2. Dependency posture

- **Runtime dependencies: none.** Everything resolves to `node:*` built-ins. This is a hard rule enforced by a CI check that fails if `dependencies` in any `package.json` is non-empty.
- **Build/dev dependencies (never shipped in the binary):**
  - `esbuild` — bundle the TS entry + `core` into one JS file for SEA (the injected main can only load built-ins, so a single bundled file is required). Also strips types as a side effect.
  - `typescript` — `tsc --noEmit` for type checking in the editor and CI only.
- **Password KDF — DECIDED: scrypt (§3.1).** `node:crypto` provides **scrypt** but not Argon2id, so v1 uses `crypto.scryptSync` (memory-hard, native, zero-dep), taking the spec’s documented fallback in place of Argon2id. This keeps the zero-runtime-dependency rule with no WASM asset to bundle. Tune cost parameters (`N`, `r`, `p`) at a documented target and store them in `kdfParams` so they can be raised over time without breaking existing vaults.

---

## 3. Repository layout (monorepo, no workspace tooling required)

```
vault/
  package.json            # "type":"module"; no "dependencies"
  tsconfig.json           # for tsc --noEmit + editor only (ignored at runtime)
  core/
    crypto.ts             # node:crypto wrappers (§8)
    sealedbox.ts          # ECIES seal/unseal to an X25519 pubkey
    kdf.ts                # scrypt — decided KDF (§2)
    crdt.ts               # field-level LWW + HLC, tombstones (§7.1, §13)
    authlog.ts            # signed, hash-chained membership log (§5)
    rotation.ts           # conflict-free epoch scheme (§10.2)
    protocol.ts           # OpEnvelope, VersionVector, sync messages (§7.4)
    store.ts              # node:sqlite schema + queries (§9 below)
    index.ts
  cli/
    main.ts               # arg parsing (node:util parseArgs), command dispatch
    commands/*.ts         # auth, device-add, device-confirm, add, get, list, sync, rotate, device-remove, run
  relay/
    main.ts               # node:http server, anti-entropy endpoints (§7.4)
    access.ts             # verify Cloudflare Access JWT
    deploy/               # systemd unit, cloudflared config, Access policy notes
  build/
    bundle.mjs            # esbuild → dist/cli.cjs
    sea-config.json
    make-sea.sh           # node --build-sea + codesign
  test/                   # node:test specs
```

Arg parsing uses `node:util`’s `parseArgs` — no commander/yargs.

---

## 4. `core` — shared library (maps spec → code)

- **`crypto.ts` / `sealedbox.ts` (§3.2):** all primitives via `node:crypto` (details in §8). `sealedbox` implements the spec’s “seal a key to a public key” as ECIES over X25519 + HKDF + AES-256-GCM.
- **`kdf.ts` (§3.1, §3.3):** derive the master key from the password (scrypt), then split into the account key (encryption branch) and `authVerifier` (auth branch) via two distinct HKDF `info` labels so neither yields the other.
- **`crdt.ts` (§7.1, §13 decision):** vault = map of items; each item = map of fields; each field a **last-writer-wins register keyed by HLC**; tombstones for deletes. The **password field is a multi-value register** so divergent concurrent edits surface instead of being lost (per §13).
- **`authlog.ts` (§5):** append-only, hash-chained, Ed25519-signed entries; user-with-device-subkeys identity model (§9 decision) — a user key signs device subkeys; the log lists people, each with a device set.
- **`rotation.ts` (§10.2):** the conflict-free epoch scheme — `RotationRecord`, the `(epoch, hlc, deviceID)` total-order tiebreak, idempotent loser re-apply, and the security catch-up rotation.
- **`protocol.ts` (§7.4):** `OpEnvelope { deviceID, seq, hash, sig, payload(opaque ciphertext) }`, `VersionVector`, and the pull/push message shapes.
- **`store.ts` (§9 below):** `node:sqlite` schema and queries.

`core` imports only `node:*` and is unit-tested in isolation.

---

## 5. `cli` — the device client

Commands (mapping to spec):

| Command                          | Does                                                                                                      | Spec     |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- | -------- |
| `vault init`                     | Create a vault + personal keys; bootstrap the auth log                                                    | §5, §8   |
| `vault auth`                     | Generate this device’s keypair + `deviceId`; print **Token A** QR                                         | §9.2–9.3 |
| `vault device-add`               | Scan Token A; seal vault key to it; sign auth-log entry; print **Token B** QR                             | §9.4–9.6 |
| `vault device-confirm`           | Scan Token B; unseal vault key; validate chain; build local replica                                       | §9.7–9.9 |
| `vault add/get/list/edit/rm`     | Local CRUD → CRDT ops, encrypted under the vault key                                                      | §4, §7.1 |
| `vault sync`                     | Anti-entropy round with the relay (and any direct peers)                                                  | §7.4, §8 |
| `vault rotate` / `device-remove` | Conflict-free epoch rotation; signed removal                                                              | §10.2    |
| `vault run [.env] -- <cmd>`      | Resolve empty/declared env vars from the vault; inject into the child process env; never persists secrets | new      |

Local state lives under the OS config dir (`$XDG_CONFIG_HOME` / `~/Library/Application Support`):

- `vault.db` — `node:sqlite` replica (ciphertext + op log).
- Wrapped private keys at rest: `encryptedPrivKeys` sealed under the account key (§3.1); the account key is derived on unlock and never persisted. Where the platform offers it, store an OS-keychain-gated copy for biometric unlock (deferred to a native wrapper; v1 = passphrase unlock).

QR rendering for Tokens A/B: encode as text and render in-terminal (a tiny self-contained QR encoder lives in `core`, or print the payload string for the user to scan with another mechanism) — no QR npm dependency.

### `vault run` — inject vault secrets into a command (keep `.env` secret-free)

`vault run [.env] -- <cmd> [args…]` turns a `.env` file into a _manifest of required variables_ rather than a secret store: variables that are declared but empty are resolved from the local encrypted vault at runtime and injected into the child process’s environment. **Resolved secrets never touch disk**, so the `.env` itself stays safe to commit.

**Resolution & precedence** (per variable `KEY`):

1. If the ambient environment already has a **non-empty** `KEY`, keep it — a local override always wins.
1. Else if `.env` gives `KEY=<literal>` a non-empty value, use it verbatim (ordinary non-secret config passes straight through).
1. Else (`KEY=` empty, or a bare `KEY`) → **resolve `KEY` from the vault by name** in the selected vault.
1. Explicit form: `KEY=vault://<vault>/<item>[/<field>]` resolves that specific entry regardless of emptiness (mirrors the `op://` reference pattern).

Any declared variable left unresolved makes `run` **fail fast before spawning** (default; `--allow-missing` downgrades to a warning).

**Injection.** Spawn the command with `node:child_process.spawn(cmd, args, { env: merged, stdio: 'inherit' })`, then forward the child’s exit code and signals. The resolved secrets exist only in the child’s in-memory environment for the lifetime of the process — they are never written back to `.env`, never logged.

**Local-first payoff.** Resolution reads the **local SQLite replica**, so it is offline and instant — no network round-trip; sync is orthogonal. It does require the vault to be **unlocked**: `run` prompts for the passphrase (or uses the keychain/biometric unlock when available) and fails in a non-interactive locked context.

**Zero-dependency.** The dotenv parser is ~30 lines in `core` (no `dotenv` package); `spawn` and flag parsing (`node:util` `parseArgs`) are built-ins.

**Flags.** `--env <file>` (default `./.env`), `--vault <name>` (which vault names resolve against; default vault), `--allow-missing` (warn instead of failing on unresolved vars).

Security exposure of env injection is covered in §11.

---

## 6. `relay` — the always-on hub (§8.2 self-hosted placement)

A dumb store-and-forward replica. **It never holds keys and enforces no content policy** (§8.4).

- **Transport:** `node:http` server (no framework). Endpoints implement §7.4:
  - `POST /sync` — body = caller’s `VersionVector`; returns ops past it + the relay’s own vector.
  - `POST /push` — body = `OpEnvelope[]`; appended to the opaque op store.
- **Storage:** `node:sqlite` table of `OpEnvelope`s keyed by `(deviceID, seq)`, deduped by `hash`. No decryption — payloads are opaque blobs.
- **Access control (§8.3):** Cloudflare Access gates the tunnel; the relay additionally verifies the `Cf-Access-Jwt-Assertion` header against Cloudflare’s JWKS (using `node:crypto`/WebCrypto) — defense in depth. Optionally do a cheap signature check on incoming ops to reject junk, but correctness never depends on it (clients validate).
- **Deployment:**
  - Run as a `systemd` service (or a container) on a small always-on box.
  - `cloudflared tunnel` exposes it at a hostname with **no inbound ports**.
  - A Cloudflare Access policy issues **per-device service tokens** at enrollment; revoking a token is the §8.5 fast network cutoff.
- **Compaction:** periodic CRDT op-log snapshotting so storage stays bounded (low priority — credential write volume is tiny).

The relay can also run on Node behind the Tunnel _or_ be swapped for the serverless Worker+DO placement later (§8.2) without changing the wire protocol.

---

## 7. SEA build pipeline (the single-binary CLI)

Three steps, all built-in except the bundle.

**1. Bundle to one file** (`build/bundle.mjs`):

```js
import { build } from "esbuild";
await build({
	entryPoints: ["cli/main.ts"],
	bundle: true,
	platform: "node",
	format: "cjs", // simplest SEA target; ESM also supported via mainFormat:"module"
	target: "node26",
	outfile: "dist/cli.cjs",
	external: ["node:*"], // keep built-ins external
});
```

**2. SEA config** (`build/sea-config.json`):

```json
{
	"main": "dist/cli.cjs",
	"output": "dist/vault",
	"disableExperimentalSEAWarning": true,
	"useCodeCache": false,
	"useSnapshot": false
}
```

> `useCodeCache`/`useSnapshot` stay `false` so the same bundle can target other platforms (code cache/snapshots are platform-specific).

**3. Build + sign** (`build/make-sea.sh`):

```bash
node --build-sea build/sea-config.json     # generates dist/vault directly (no postject)
codesign --sign - dist/vault               # macOS only; Windows: signtool (optional)
```

**Per-platform / CI matrix:**

- Build on each target OS/arch in CI (the Node binary that produces the blob must match the one it’s injected into — `--build-sea` uses the running Node).
- Targets: `linux-x64`, `linux-arm64`, `darwin-arm64`, `win-x64`. **macOS is arm64 only** — no `darwin-x64` build (not in Node SEA CI).
- Output: one signed binary per target, attached to the release.

Dev loop needs none of this: `node cli/main.ts <cmd>` runs the TypeScript directly via type stripping; `node --watch` for iteration; `node --test` for tests.

---

## 8. Crypto implementation (node:crypto → spec primitives)

All zero-dependency:

- **X25519 keypair / ECDH:** `generateKeyPairSync('x25519')`; shared secret via `crypto.diffieHellman({ privateKey, publicKey })`.
- **Ed25519 sign/verify:** `generateKeyPairSync('ed25519')`; `crypto.sign(null, msg, priv)` / `crypto.verify(null, msg, pub, sig)`.
- **AEAD:** `createCipheriv('aes-256-gcm', key, iv)` (+ `getAuthTag`), or `'chacha20-poly1305'`.
- **HKDF:** `crypto.hkdfSync('sha256', ikm, salt, info, len)`.
- **Password KDF:** `crypto.scryptSync(pw, salt, 32, { N, r, p })` — scrypt is the decided KDF (§2).
- **CSPRNG:** `crypto.randomBytes`.

**Sealed-box (`crypto_box_seal` analog), the heart of grants/Token B (§3.2, §8):**

```
seal(plain, recipientX25519Pub):
  eph = generateKeyPairSync('x25519')
  shared = diffieHellman({ privateKey: eph.priv, publicKey: recipientPub })
  wrapKey = hkdfSync('sha256', shared, ephPubBytes, 'credvault/seal/v1', 32)
  iv = randomBytes(12); ct = AES-256-GCM(wrapKey, iv, plain)
  return { ephPub: ephPubBytes, iv, ct, tag }
unseal(box, myX25519Priv):  # reverse; recompute shared from box.ephPub
```

No libsodium required. (If a vetted `crypto_box_seal` byte-compatibility is later needed, that’s the only candidate for a single audited dep.)

---

## 9. Storage schema (`node:sqlite`, both CLI and relay)

CLI replica (ciphertext + op log):

```sql
CREATE TABLE ops(        -- the CRDT op log (source of truth)
  device_id TEXT, seq INTEGER, hash TEXT PRIMARY KEY,
  sig BLOB, payload BLOB,            -- payload = opaque ciphertext
  UNIQUE(device_id, seq));
CREATE TABLE items(      -- materialized view, rebuilt from ops on merge
  item_id TEXT PRIMARY KEY, team_id TEXT, key_version INTEGER,
  ciphertext BLOB, revision INTEGER, deleted INTEGER);
CREATE TABLE authlog(    -- signed, hash-chained membership entries
  idx INTEGER PRIMARY KEY, prev_hash TEXT, entry BLOB, sig BLOB);
CREATE TABLE grants(team_id TEXT, principal TEXT, key_version INTEGER, wrapped BLOB);
CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB);   -- vault id, current epoch, account-key salt
```

Relay store is just `ops` (opaque) + a per-`(team)` version-vector view. The relay has no `items`/`grants`/keys.

---

## 10. Testing (`node:test`)

- **Crypto round-trips:** seal/unseal, sign/verify, KDF determinism.
- **CRDT convergence:** randomized concurrent edit sequences must converge to one state regardless of apply order (property-style); password multi-value register surfaces divergent edits.
- **Rotation:** simulate two concurrent admin rotations → assert all nodes converge on the `(hlc, deviceID)` winner; assert the security catch-up fires when a removal isn’t observed (§10.2).
- **Anti-entropy:** two in-memory stores reconcile to identical op sets in one round; partition then heal.
- **`vault run`:** a `.env` manifest mixing ambient-set, literal, empty, and `vault://` variables resolves with the correct precedence; the child receives the merged env; an unresolved required var fails _before_ spawn; the child’s exit code is propagated; resolved values are never written to disk.
- **SEA smoke test:** in CI, build the binary per platform and run `vault --version` + an init/add/list cycle against a local relay.

---

## 11. Security checklist & Node-specific caveats

- **KNOWN ISSUE — no reliable key-memory zeroing in JS/V8.** Key material cannot be guaranteed wiped from memory on this stack; this is a tracked, **accepted known issue**, not a defect to be fixed. Mitigate by minimizing key lifetime, never logging secrets, and preferring `KeyObject`s (which hold key bytes in C++ land, not JS strings). Call it out explicitly in the security review and release notes.
- **At-rest keys:** private keys stored only as `encryptedPrivKeys` (sealed under the account key). v1 unlock = passphrase; OS-keychain/biometric unlock deferred to a native wrapper.
- **Binary integrity:** sign every released SEA binary (`codesign` on macOS; Authenticode on Windows). Publish checksums.
- **Relay trust:** per §8.4 the relay is untrusted — signatures + version vectors + order-independent CRDT mean it can delay but not forge/read/corrupt. Keep a direct fallback path (§8.6) to prevent eclipse, even if deferred past v1.
- **Env-var injection exposure (`vault run`).** Injected secrets are visible to the spawned process, its descendant processes, and same-user process introspection (e.g. `/proc/<pid>/environ`), and can surface in crash dumps. This is the inherent tradeoff of env injection — accepted because it keeps real secrets out of on-disk `.env` files. `vault run` never persists or logs resolved values; output masking (requires piping stdio rather than inheriting) and a per-access audit entry are candidate hardening steps.
- **Stability flags:** SEA (1.1) and `node:sqlite` are still maturing — pin Node’s exact patch version per release and re-run the full test matrix on every Node bump.
- **Type-stripping discipline:** lint-ban `enum`/`namespace`/decorators so all source stays erasable and runnable without a transform.

---

## 12. Milestones

1. **M1 — `core` + tests.** Crypto, sealed-box, CRDT (with password MV-register), HLC, op-log, store. Pure, zero-dep, fully tested. _(De-risks the hardest parts first.)_
1. **M2 — local CLI.** `init/auth/add/get/list` plus **`run`** (resolve secrets from the local replica and inject them into a child process) against the local SQLite replica, no networking. Runnable via `node cli/main.ts`.
1. **M3 — relay + sync.** `node:http` relay, `/sync` + `/push`, `vault sync`. Two CLIs converge through a local relay.
1. **M4 — enrollment.** `device-add` / `device-confirm` QR handshake; auth-log validation; user-with-device-subkeys.
1. **M5 — rotation/revocation.** Conflict-free epochs + catch-up; `device-remove`.
1. **M6 — SEA packaging.** `--build-sea` pipeline + signing + CI matrix; release artifacts.
1. **M7 — Cloudflare deployment.** `cloudflared` tunnel + Access service-token enrollment; relay JWT verification; ops/runbook.
1. **M8 (optional) — direct fallback path** (§8.6) and/or native UI wrapper.

---

## 12a. Native UI wrapper roadmap (M8 — macOS)

The CLI is the portable engine (§0); a native macOS app wraps it by **spawning the
SEA binary** with the machine-contract flags (no engine fork, preserves zero-dep).
Sequenced so the testable foundation lands first.

- [x] **Step 1 — machine interface (DONE, in-repo).** `--json` (one structured
      object per command; `{ok:false,error}` on failure) and `--passphrase-stdin`
      (secrets cross the process boundary on stdin only — never argv/env). This is
      the contract any wrapper/automation builds on. Implemented + tested in the CLI.
- [x] **Step 2 — `secure-enclave` KeyStore provider (DONE).** A small signed Swift
      helper (`native/Sources/Helper`, `vault-helper`) the CLI spawns, exposing
      the existing `KeyStore` `available/put/get/del` interface — but backed by a
      **non-exportable Secure Enclave key** (`kSecAttrTokenIDSecureEnclave`) gated by
      **Touch ID** (`LAContext`). Slots in beside `macos-keychain`/`windows-dpapi`
      via provider-aware resolution (`cli/keystore.ts`); biggest threat-model upgrade
      (no passphrase to keylog; key never leaves hardware).
- [x] **Step 3 — SwiftUI app (DONE).** `native/` (`Vault.app`) spawns
      `dist/vault --json --passphrase-stdin`; item list/edit, Touch-ID unlock (via the
      Step-2 shim), **QR rendering + camera scan** for the §9 enrollment tokens, sync
      status. App-layer concerns handled here, not in the CLI: `EnableSecureEventInput()`
      (Secure Keyboard Entry, §11 passphrase-entry note); `build.sh` does codesign +
      hardened-runtime/camera entitlements and documents **notarization**; arm64-only.

Constraints: the Swift app + Enclave shim are separately-built/-signed artifacts
(not npm deps, so `check:deps` stays green); secret handling must stay on stdin;
neither protects against a compromised-while-unlocked host (threat model).

---

## 13. Decisions & open items specific to this stack

### Resolved in this revision

- **Password KDF: scrypt** (§2, §8) — native `node:crypto` scrypt; no Argon2id, no WASM asset in v1.
- **macOS: arm64 only** (§1, §7) — no x64 macOS build.
- **Key-memory zeroing: accepted KNOWN ISSUE** (§11) — not fixable on the Node/V8 stack; mitigated, documented, and surfaced in the security review.

### Still open

- **SEA module format** — CommonJS (simplest) vs ESM (`mainFormat:"module"`); CJS recommended for v1.
- **Relay placement** — RESOLVED: **both** shipped off one `relay/handler.ts` (self-hosted Node behind Tunnel _and_ Worker+Durable-Object); identical protocol, pick per deployment (see `relay/deploy/README.md`). The Worker reuses `core`/`relay/access` `node:crypto` via `nodejs_compat` (only `node:crypto` is pulled into the edge bundle; never `node:http`/`node:sqlite`).
- **Direct fallback path (§8.6)** — ship in v1 or defer past it.
- **Verify on the pinned Node 26 patch** — re-confirm SEA flags, `node:sqlite`, and type-stripping limits against the exact version used (these are actively evolving; see `spec.md` §13).
