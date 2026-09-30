# Credential Vault — Design Specification

**Status:** Draft · **Scope:** End-to-end encrypted credential vault with multi-vault sharing, evaluated under three deployment architectures (centralized, decentralized, and hybrid); **Architecture C (hybrid) is the selected direction and is implemented as a Swift local client plus a TypeScript Cloudflare relay (§15).**

This document consolidates the design decisions for a native Swift (macOS) credential vault that synchronizes encrypted credentials across devices and between people. It covers the cryptographic core, data model, three candidate sync architectures, device enrollment, and a coordinator-free key-rotation scheme.

---

## Table of Contents

1. [Goals and Non-Goals](#1-goals-and-non-goals)
1. [Threat Model and Security Properties](#2-threat-model-and-security-properties)
1. [Cryptographic Design](#3-cryptographic-design)
1. [Data Model and Schema](#4-data-model-and-schema)
1. [Identity and Access Control](#5-identity-and-access-control)
1. [Architecture A — Centralized (Cloudflare)](#6-architecture-a--centralized-cloudflare)
1. [Architecture B — Decentralized (Local-First + Tailnet)](#7-architecture-b--decentralized-local-first--tailnet)
1. [Architecture C — Hybrid (Local-First + Cloudflare Relay)](#8-architecture-c--hybrid-local-first--cloudflare-relay)
1. [Device Enrollment (CLI + QR)](#9-device-enrollment-cli--qr)
1. [Key Rotation and Revocation](#10-key-rotation-and-revocation)
1. [Coordination Model](#11-coordination-model)
1. [Architecture Comparison](#12-architecture-comparison)
1. [Secret Consumption — Agent Proxy](#13-secret-consumption--agent-proxy)
1. [Decisions and Verification Notes](#14-decisions-and-verification-notes)
1. [Implementation Architecture — Swift Client + TypeScript Relay](#15-implementation-architecture--swift-client--typescript-relay)

---

## 1. Goals and Non-Goals

### Goals

- A native Swift macOS app storing credentials (logins, notes, cards, TOTP secrets, custom fields).
- **Zero-knowledge**: no sync intermediary ever holds plaintext or keys.
- **Whole-vault sharing** with **multi-vault** support: each team is a vault; a user may belong to many vaults; a personal vault is a team-of-one.
- Sync across a user’s own devices and between different people.
- Offline-capable, with deterministic conflict resolution.
- **Local secret-consumption surfaces that minimize plaintext exposure to the consuming program** — including an **agent proxy** that injects a credential into outbound requests so an AI agent (or any untrusted child process) can _use_ a secret without ever _seeing_ it (§13).

### Non-Goals

- Per-item (sub-vault) sharing. Whole-vault grants only; per-item multiplies key-management surface for little benefit.
- Hiding the existence/among-membership graph from infrastructure operators (see §2).
- Rolling custom cryptographic primitives. Use audited libraries (swift-crypto / CryptoKit) wherever they offer the primitive; the in-tree exceptions — Argon2id/BLAKE2b for reading older vaults, and the sealed-box composition of library primitives — are pinned by golden vectors (§15.6).

---

## 2. Threat Model and Security Properties

### Protected (cryptographically)

- **Item contents.** All payloads are encrypted under a vault key the infrastructure never sees.
- **Read access.** Only holders of a sealed vault-key grant can decrypt a vault.
- **Write authority** (decentralized model only — see §5). Every op is signed; peers reject ops from unauthorized authors.

### Visible to the sync layer (metadata, not protected)

- Membership graph, roles, item counts, timestamps, email addresses, vault names (unless explicitly encrypted).
- In the tailnet model (B), Tailscale’s control plane additionally sees the device graph and connection metadata.
- In the Cloudflare-relay model (C), the edge sees per-device connection identity, op sizes, and timing — never plaintext.

### Key principle

**Read confidentiality is enforced by cryptography; write/role/invite policy is enforced by an authority layer** (a server in Architecture A, a signed replicated auth log in Architectures B and C). Anyone holding a vault key can technically craft valid ciphertext, so write permissions are _policy_, not a cryptographic guarantee — except in the decentralized models, where signed ops + auth-log validation make write authority cryptographically checkable.

### Local secret-consumption boundary

Distinct from the sync-layer model above: once a secret is unlocked on a device, how it reaches the program that uses it is its own exposure surface. Env injection hands the plaintext to the consuming process; the **agent proxy** (§13) instead injects it only on egress, keeping the value out of an untrusted consumer (e.g. an AI agent) entirely. Neither defends against a compromised-while-unlocked host.

---

## 3. Cryptographic Design

### 3.1 Key hierarchy (three tiers)

1. **Account key** — derived from the master password via a memory-hard KDF: **scrypt** for new vaults (N=2^17, r=8, p=1, parameters stored per vault so they can be raised); vaults created with **Argon2id** stay readable (§15.6). Wraps only the user’s private identity keys.
1. **User private keys** — an **X25519** key (key agreement / sealing) and an **Ed25519** key (signing). Stored as ciphertext under the account key. A new device receives them sealed to its own X25519 key in Token B (§9) and re-wraps them under its own account key.
1. **Vault keys** — one symmetric key per vault epoch, delivered as _grants_: the epoch key sealed to each authorized **device’s** X25519 public key in the rotation record (§10.2), and carried to a newly enrolled device in Token B.

This indirection lets a user change their master password by re-wrapping their private keys, without re-encrypting any vault.

### 3.2 Primitives

- **Symmetric:** AES-256-GCM (swift-crypto / CryptoKit), authenticated.
- **Key agreement:** X25519 (`Curve25519.KeyAgreement`).
- **Signing:** Ed25519 (`Curve25519.Signing`).
- **KDF:** scrypt (new vaults); Argon2id read-compatibility for existing vaults.
- **Sealing a key to a public key** (envelope / sealed-box, ECIES pattern): generate an ephemeral keypair, X25519-ECDH against the recipient’s static public key, HKDF the shared secret into a wrapping key, AES-GCM the payload, and store `{ephPub, iv, ct, tag}`. As implemented: HKDF-SHA256 with salt = `ephPub‖recipientPub` and info `credvault/seal/v1`, AES-256-GCM with AAD = `ephPub`. (Same pattern as libsodium’s `crypto_box_seal`, but not wire-compatible with it.)

### 3.3 Master password: auth vs encryption split

The master password is stretched into a **master key**, then split into two branches that **cannot derive each other**:

- **Account key** (encryption branch) — never leaves the device; wraps the private keys.
- **authVerifier** (auth branch) — sent to the server (Architecture A) to authenticate login.

Storing a single hash that both authenticates and encrypts is a design failure: it would let the server decrypt the vault.

### 3.4 Local storage at rest

- Working store: **SQLite** (indices, transactions, per-row versioning). JSON reserved for export/backup and signed log entries.
- Items stored as ciphertext locally as well.
- Use the macOS **Keychain** + **Secure Enclave** for biometric-gated unlock material; do not place the whole vault in the system Keychain.

### 3.5 Keystore second factor — at-rest binding and per-access tiers

By default the at-rest private keys are sealed under the scrypt-derived account key alone (§3.4), so a stolen disk + a weak passphrase is brute-forceable offline. An optional **keystore** binds a high-entropy per-device **unlock key (DUK)** to an OS-protected store; the wrap key becomes `HKDF(ikm: accountKey, salt: DUK, info: "credvault/keystore/v1")`, so disk-only theft cannot decrypt at any passphrase strength. Two strengths, by platform:

| Platform | At-rest binding                                                            | Per-access UV (strong tier)                |
| -------- | -------------------------------------------------------------------------- | ------------------------------------------ |
| macOS    | login **Keychain** (Security framework `SecItem*`)                         | **Secure Enclave** + Touch ID              |
| Windows  | **DPAPI** (CurrentUser)                                                    | **Windows Hello** (`KeyCredentialManager`) |
| Linux    | **`systemd-creds`** (`--with-key=host`; `auto`/`tpm2` ⇒ TPM-bound at rest) | **TPM2** via `tpm2-tools` + PIN (opt-in)   |

The DPAPI, Windows Hello, `systemd-creds` and `tpm2-tools` providers are `BlobCipher`s: each wraps the DUK and the wrapped blob lives on disk; the binding key never leaves its store. The macOS Keychain and Secure Enclave stores are `PlatformKeyStore`s of their own. The recorded binding (e.g. the systemd-creds `--with-key` mode) is persisted and **pinned on unlock**, so the unlock-time probe matches how the DUK was sealed.

**TPM2 tier (Linux, opt-in `VAULT_TPM2=1`).** Implemented by driving the **`tpm2-tools`** binaries (`tpm2_createprimary`, `tpm2_create`, `tpm2_load`, `tpm2_unseal`) rather than a hand-written TPM2 codec: the tools own all marshalling, sessions and transport (`/dev/tpmrm0`, or `swtpm` via `TPM2TOOLS_TCTI`). The DUK is sealed to a `fixedtpm|fixedparent|userwithauth` data object under an owner-hierarchy ECC primary that is re-derived on every call, so nothing about the primary is persisted. Dictionary-attack protection stays on (no `noda`): with `VAULT_TPM2_PIN` set the TPM enforces lockout on bad PINs (per-access UV); without a PIN it is at-rest TPM binding. Neither the DUK nor the PIN appears on argv (the DUK goes over stdin, the PIN through a 0600 file in a private work dir), the sealed payload is prefixed with a hash of the keystore id so a copied blob is refused, and a vault sealed with a PIN refuses to unlock without one _before_ touching the TPM (so a forgotten PIN does not burn a lockout attempt). The earlier hand-rolled codec (salted HMAC sessions, parameter encryption) was retired because it could only be verified against an emulator. Windows TPMs are reached through the OS: DPAPI and Windows Hello are TPM-backed.

**Windows Hello tier (`KeyCredentialManager`).** Per-access UV: every unlock requires a Hello gesture (PIN/face/fingerprint) releasing a non-exportable TPM key.

- `KeyCredential` exposes **sign only, not decrypt** — so the DUK is not held in the key; it is **wrapped** under a key derived from a signature: `wrapKey = HKDF(RequestSignAsync(challenge), salt=challenge)`, persisted as `AES-256-GCM(wrapKey, DUK)` (a `BlobCipher`, like the other tiers; `get` triggers the gesture).
- **Load-bearing prerequisite:** the signature must be **deterministic** for a fixed challenge. KeyCredentialManager keys are RSA-2048 / PKCS#1 v1.5 (deterministic) — the same mechanism Bitwarden/KeePassXC use for Hello unlock. Verify per platform and **self-test at enrollment** (sign the challenge twice, assert equal); if a platform ever signs with RSA-PSS (randomized), this route is unusable and the fallback is **CNG/NCrypt** (a Hello-gated key that actually decrypts).
- Flow: `IsSupportedAsync` → `available()`; one per-device credential (`dev.vault.unlock`, reused across vaults, with a per-id random challenge in the blob) via `RequestCreateAsync`/`OpenAsync`; `RequestSignAsync` on every `get`. Non-`Success` statuses (`UserCanceled`, `NotFound`, `SecurityDeviceLocked`, `UserPrefersPassword`) map to "no secret" → the engine's standard "couldn't unlock (retry)" path.
- Caller authentication: the helper refuses callers whose Authenticode signature (`WinVerifyTrust`) does not chain to a trusted root with the same signer thumbprint as the helper itself; an unsigned (dev) helper skips the check unless `VAULT_HELLO_STRICT` is set. Not yet verified on a Hello-enrolled host.
- Lifecycle: a lost credential (TPM clear / Hello or PIN reset) makes the blob unrecoverable ⇒ **re-enroll the device** (as for a lost Secure-Enclave blob). Per-user, **interactive-session only** — no headless unlock (inherent to per-access UV).

---

## 4. Data Model and Schema

> This is the **logical model as designed for Architecture A** (§6). The implemented Architecture C client has no `Item`/`Membership`/`KeyGrant`/`Invitation` tables and no `revision` counter: items are CRDT field ops encrypted per epoch and tagged with `keyCommit`, membership lives in the signed auth log, epoch keys are sealed per device in rotation records, and the grants channel carries only `orgPublicKey` and `recovery:<userId>` rows. The implemented storage schema is §15.9; KDF parameters are `{algo,salt,N,r,p,length}` (scrypt) or `{algo,salt,memory,passes,parallelism}` (Argon2id). Item payloads are free-form field maps with a reserved `__type__` field and TOTP in a `totp` field.

Encryption annotations: `plain` (authority-readable), `public` (public-key material), `enc(K)` (ciphertext under key K), `sealed(pubkey)` (sealed-box to a public key).

```
User
  userID            uuid           plain   (PK)
  email             string         plain
  kdfParams         {algo,salt,mem,iters,parallelism}  plain
  authVerifier      blob           plain   (cannot yield the account key — §3.3)
  publicEncKey      X25519 pub     public
  publicSignKey     Ed25519 pub    public
  encryptedPrivKeys blob           enc(accountKey)
  createdAt/updatedAt              plain

Team  (= vault container)
  teamID            uuid           plain   (PK)
  name              string         plain   (encrypt under vaultKey to hide)
  currentKeyVersion int            plain
  settings          json           plain   (e.g. recoveryEnabled)
  createdAt                        plain
  -- if recoveryEnabled:
  orgPublicKey      X25519 pub     public

Membership
  membershipID      uuid           plain   (PK)
  teamID            uuid           plain
  userID            uuid           plain
  role              enum           plain   (owner | admin | member)
  status            enum           plain   (active | invited | revoked)
  createdAt                        plain

KeyGrant
  grantID           uuid                plain   (PK)
  teamID            uuid                plain
  userID            uuid                plain
  keyVersion        int                 plain
  wrappedVaultKey   {ephPub,nonce,ct}   sealed(recipient publicEncKey)
  grantedBy         uuid                plain
  signature         Ed25519 sig         plain   (over teamID|userID|keyVersion|wrappedVaultKey)
  createdAt                             plain

Item
  itemID            uuid              plain   (PK)
  teamID            uuid              plain
  keyVersion        int               plain
  itemType          enum              plain   (login|note|card|identity)
  ciphertext        {nonce,ct,tag}    enc(vaultKey)
  revision          int               plain   (sync/optimistic concurrency)
  deleted           bool              plain   (tombstone)
  createdAt/updatedAt                 plain

Invitation
  invitationID      uuid     plain   (PK)
  teamID            uuid     plain
  inviteeEmail      string   plain
  role              enum     plain
  invitedBy         uuid     plain
  status            enum     plain   (pending | accepted | revoked)
  expiresAt/createdAt       plain

RecoveryGrant  (only if recoveryEnabled)
  teamID            uuid              plain
  userID            uuid              plain
  encryptedRecovery {ephPub,nonce,ct} sealed(orgPublicKey)
```

**Decrypted `Item.ciphertext` payload** (never leaves the client):

```
ItemPayload { title, username, password, url, notes, totpSecret,
              customFields: [{name, value, hidden}] }
```

### Two distinct counters

- **`keyVersion`** — vault-key generation; changes only on rotation. A client must hold a grant whose `keyVersion` matches an item’s `keyVersion` to decrypt it.
- **`revision`** — per-item sync/optimistic-concurrency counter; changes on every edit.

### Notable rules

- **Moving an item between vaults is a re-encryption**, not a metadata change (different vault keys).
- **The infrastructure cannot re-encrypt or rotate** — it has no keys; a client performs it.

---

## 5. Identity and Access Control

- Each principal holds an X25519 + Ed25519 keypair. In the decentralized models the unit is a **user with subordinate device keys** (see §9).
- **Membership** is whole-vault: each member holds one `KeyGrant` per vault. The personal vault is a self-grant.
- **Public-key trust** is the hard problem without a trusted directory. Mitigations, increasing in strength: trust-on-first-use with change alerts, out-of-band fingerprint verification (achieved by the QR handshake in §9), key-transparency log.
- **Decentralized authority** (Architectures B and C): a **signed, replicated authorization log** rooted at the vault creator. Entries (“O added M as admin”, “A removed B”) are signed and independently validated by every peer. Because each item write is also a signed op validated against this log, **write authority becomes cryptographically enforced**, not merely server-trusted.

### Account recovery / escrow (decision point)

In a team product, “forgot master password = data loss” is usually unacceptable. Admin-assisted recovery requires **escrow**: an org keypair, with each member’s recovery key sealed to `orgPublicKey` (the `RecoveryGrant` record). The tradeoff is explicit: escrow means the org **can** reconstruct a member’s keys and therefore **can** access their data — which contradicts a naive “zero-knowledge, no one can ever see anything” claim. Offer it as a per-org policy toggle.

---

## 6. Architecture A — Centralized (Cloudflare)

The sync intermediary stores only ciphertext and enforces policy (roles, write/invite). All facts below should be re-verified against current Cloudflare docs.

### 6.1 Primitive mapping

- **Workers** — API surface; auth (`authVerifier`), ACL enforcement, routing.
- **Durable Object per vault** — the spine. SQLite-backed (GA; ~10 GB per object; WebSocket hibernation for cheap idle live-sync; 30-day point-in-time recovery). Holds the vault’s items, grants, `currentKeyVersion`, and a monotonic change cursor. Single-threaded → serializes writes and makes rotation atomic.
- **D1** (global) — identity, public-key directory, team metadata, membership/roles, invitations. ~10 GB per DB, up to 50,000 DBs, 2 MB max row/blob; designed for per-tenant horizontal sharding.
- **R2** — file attachments (exceed the 2 MB row cap); opaque ciphertext objects referenced by key.
- **KV** — read-heavy caches (public keys, session tokens, rate-limit counters).
- **Queues** — async side-effects (invitation email, audit shipping, push fan-out).
- **Turnstile** — abuse protection on auth endpoints.

### 6.2 Read / sync flow

1. Client → Worker: `{token, vaultID, sinceCursor}`.
1. Worker validates token → `userID`; checks D1 membership/role.
1. Worker routes to the vault DO.
1. DO returns `currentKeyVersion`, the caller’s grant, and items with `revision > cursor`.
1. Client unwraps the vault key, decrypts locally. Attachments fetched from R2 via a short-lived signed URL after the same ACL check. Live sync via a DO WebSocket.

### 6.3 Write flow

1. Client encrypts payload, sends `{itemID, ciphertext, baseRevision, keyVersion}`.
1. Worker validates token + write role.
1. DO (serialized): reject if `keyVersion < currentKeyVersion` (**stale key**, re-sync); reject if stored revision ≠ `baseRevision` (**conflict**); else store, `revision = ++cursor`, broadcast.

### 6.4 Rotation flow (member removal)

1. Worker checks admin role; sets membership `revoked`; DO drops the member’s connection.
1. Admin **client** reads all items at `keyVersion N` noting snapshot cursor `S`; generates key `N+1`; decrypts/re-encrypts each item; re-wraps the new key to remaining members.
1. Client commits to the DO with `S`. In one SQLite transaction the DO: re-verifies admin; **checks no item revision exceeds `S`** (else abort and have the admin re-fetch/re-encrypt changed items); bumps `currentKeyVersion`; swaps ciphertexts; replaces grants; commits; broadcasts.
1. Remaining clients adopt the new grant; in-flight `N` writes bounce as stale-key and retry.

Interrupted rotation is safe — the DO only flips at the atomic commit. For large vaults, stage re-encrypted blobs first (R2 / staging table) and keep the commit transaction to a pointer swap.

---

## 7. Architecture B — Decentralized (Local-First + Tailnet)

No central server. Each device holds a full encrypted replica, with Tailscale providing transport. This is the decentralized baseline; the **selected direction is Architecture C** (§8), which reuses this same local-first core and keeps B’s tailnet as an optional direct-path fallback (§8.6).

### 7.1 Local store and merge

- **SQLite** holds ciphertext + a CRDT op log; JSON for export and signed log entries.
- **CRDTs** replace the single writer: vault = map of items, each item a map of fields, each field a last-writer-wins register keyed by a **hybrid logical clock (HLC)**; tombstones for deletes. Libraries: Automerge / Yjs (verify current APIs).
- **Encryption × CRDT:** sync encrypted op-blobs; each peer decrypts locally, merges in the CRDT on plaintext, re-encrypts for storage. Relaying peers only ever forward opaque blobs. (Whole-item LWW is the simpler fallback if merge must run without decrypting.)

### 7.2 Transport via Tailscale (`tsnet`)

- Design option: embed a `tsnet` node (a full Tailscale node in-process). **As implemented** the CLI instead shells out to the user’s installed `tailscale` (`tailscale status --json`) for its tailnet IP and peers, and `vault serve` runs a plain-HTTP peer server bound to that IP, governed by Tailscale ACLs.
- **The tailnet solves discovery, NAT traversal, and transport encryption** — dropping the DHT, mDNS, STUN/TURN/ICE, and rendezvous server the pure-P2P design needed.
- **Critical invariant: tailnet membership ≠ vault membership.** Being on the tailnet must not grant decryption. All crypto layers (sealed grants, signed ops, auth log) remain. The tailnet is transport + access gate, never the confidentiality boundary.

### 7.3 ACL / tag policy

```hujson
{
  "tagOwners":     { "tag:credvault": ["autogroup:admin"] },
  "acls": [
    { "action": "accept", "src": ["tag:credvault"], "dst": ["tag:credvault:8732"] }
  ],
  "autoApprovers": { "tags": { "tag:credvault": ["autogroup:admin"] } }
}
```

Only tagged vault nodes can reach the peer port (8732 by default, `VAULT_PEER_PORT`). The design calls for an in-process `WhoIs` tag re-check; the implementation instead offers an optional shared peer token (`--peer-token-file` / `VAULT_PEER_TOKEN`) as the in-process gate.

### 7.4 Anti-entropy protocol (per pair, both directions, one round)

- Each op is an `OpEnvelope { deviceID, seq, hash, sig, payload(opaque ciphertext) }`.
- A **version vector** (`deviceID → highest seq held`) summarizes local state.
- Caller sends its vector → peer replies with ops past it **plus** the peer’s own vector → caller applies, then pushes whatever the peer lacks. Every node can run this against every reachable peer: a coordinator-free mesh. (As implemented, a round runs when `vault sync --tailnet` is invoked; there is no background timer.) Swap the flat vector for a Merkle summary for sublinear diffs on large histories.
- `Apply` is where each op’s signature is verified against the author key and the auth log **before** the CRDT merges it.

### 7.5 Availability

Run any node 24/7 (home server / small VM) as an always-reachable replica. It is just another tailnet node holding ciphertext — no special role, no relay infrastructure to design.

---

## 8. Architecture C — Hybrid (Local-First + Cloudflare Relay)

**Architecture C is the selected design.** It keeps Architecture B’s entire data, crypto, and trust model **unchanged** — CRDT field-level LWW, conflict-free epochs, the signed auth log, sealed grants, user-with-device-subkeys — and changes only **transport and availability**: an always-on, zero-knowledge Cloudflare relay/replica is the primary sync path, with B’s tailnet/LAN mesh retained as an optional direct fallback (§8.6). The defining distinction from Architecture A: the Cloudflare node here is **a dumb relay, not an authority**. Every device still holds a full replica, and write authority still lives in the signed auth log; Cloudflare only stores and forwards opaque ops while staying awake.

### 8.1 Topology — hub-and-spoke, async store-and-forward

- Each device makes an outbound HTTPS (443) connection to one always-on hub, pushes its ops, and pulls everyone else’s.
- Simpler than B’s mesh: no device-to-device NAT traversal, and outbound 443 works on restrictive networks where WireGuard/Tailscale UDP is often blocked.
- The hub is a persistent inbox, so two devices never need to be online simultaneously — closing B’s availability gap with no self-hosted 24/7 box.

### 8.2 The hub — two placements

- **Serverless (no Tunnel):** a Worker fronting a SQLite-backed Durable Object per vault. It stores the opaque `OpEnvelope` log and version vector, dedups by op hash, and could hold hibernatable WebSockets for live fan-out (not implemented; clients poll with `sync`). This is the §6 DO-per-vault stripped of its authority role — it stores ciphertext and serves “ops since your vector,” enforcing nothing about contents because it cannot read them.
- **Self-hosted behind Cloudflare Tunnel:** run the §7.4 anti-entropy service (the Swift `vault relay`, §15.14) on an always-on box or a Cloudflare Container, and expose it with `cloudflared` — a public hostname through the edge with no inbound ports. Tunnel is the mechanism for a node you control to be reachable; the serverless option needs no Tunnel.
- The wire protocol is unchanged: the §7.4 version-vector pull + push, as `GET /health`, `POST /sync` and `POST /push` with JSON bodies carrying `teamId` (§15.5).

### 8.3 Access control — network gate + crypto authority

- Front the hub with **Cloudflare Access**, using service tokens (mTLS client certs are a design option, not implemented). Tokens are provisioned by the operator, not issued by enrollment; `device-add`/`share --relay` only forward the relay URL and whatever relay credentials the enroller already holds. This is the network-layer gate, the analog of `tag:credvault` on the tailnet.
- The signed auth log remains the authority for _what a device may do_. Two cleanly separated layers: Cloudflare gates reachability and sees metadata; the crypto gates confidentiality and write authority.

### 8.4 Untrusted-relay security analysis

A malicious or buggy hub:

- cannot **forge** ops — it holds no signing keys, and peers reject anything not validly signed against the auth log;
- cannot **read** contents — payloads are sealed under a vault key it never sees;
- cannot **tamper** — signatures cover payload and metadata;
- **reordering** is harmless — CRDT merge is order-independent (HLCs set logical order, not arrival order);
- **replay** is harmless — idempotent, deduped by op hash;
- **withholding/dropping** is the only real risk — version-vector gaps make it detectable, but a consistently-lying hub can keep a device stale (an eclipse).

Net: a misbehaving hub can cost **availability and metadata privacy**, never integrity or confidentiality.

### 8.5 Revocation

Revoke the device’s Cloudflare Access service token or client cert for an instant network-layer cutoff (the analog of stripping the tailnet tag), on top of the usual crypto rotation.

### 8.6 Recommended — do not make it hub-only

Keep B’s direct path (the tailnet; pure-LAN/mDNS discovery is not built) alive alongside the hub. The hub gives universal reachability and 24/7 availability; the direct path means a down, throttled, or eclipsing hub can never fully isolate two devices that can see each other. Same op-log, two transports, with the hub as one (very reliable) replica among peers. “Cloudflare is down” then degrades to “sync only when devices meet directly,” rather than “no sync.”

---

## 9. Device Enrollment (CLI + QR)

A two-way out-of-band handshake that doubles as public-key trust establishment.

1. New device: download CLI.
1. `vault auth` generates the device keypair (X25519 + Ed25519) and `deviceId`; emits **Token A**.
1. New device shows Token A as a QR.
1. Authorized device: `vault device-add` scans Token A.
1. It seals the user identity keys and every epoch key it holds to Token A’s X25519 key and appends a signed `add-device` entry (signed by the user key for a user’s first device, by an existing device of the same user thereafter).
1. It shows **Token B** (the sealed grant bundle) as a QR.
1. New device: `vault device-confirm` scans Token B, unseals the keys, validates the auth log, and appends a signed `prove-device` entry (explicit proof of possession).
1. New device re-wraps the identity keys under its own account key (plus the optional keystore factor, §3.5), stores the epoch grants sealed to its device key in the local SQLite replica, and builds that replica.
1. `vault sync` pulls the encrypted history (relay or tailnet).
1. The signed auth-log entry gossips out; honest peers now accept the device.
1. Both sides show a 6-digit short authentication string over `sha256(enrollerSignPub‖newSignPub)`, derived locally (§15.11), for mutual verification.

### Token contents

All tokens are base64 of JSON with a fixed member order.

- **Token A:** `{deviceId, signPub, encPub}`. Small.
- **Token B:** `{vaultId, userId, authLog[], rotations[], epochGrants{keyCommit → sealed}, userPriv (sealed), relay?}`. It embeds the full auth log and rotation records, so it grows with the vault and can exceed a single QR (~3 KB); item history still flows over normal sync. The SAS is not carried in the token. In the tailnet model no bootstrap address is needed (MagicDNS); in Architecture C the optional `relay` carries the hub URL and any relay credentials the enroller holds.
- **Invite / Join tokens** (people sharing, `invite` → `share` → `join`) follow the same pattern: the Invite carries the joiner’s new user and device public keys; the Join carries the vault’s auth log, rotations, epoch grants sealed to the joiner’s device, and the optional relay.

### Security properties

- **The in-person QR is the trust anchor** that replaces the missing key-distribution authority — it’s the fingerprint-verification step baked into the UX, defeating MITM on public keys.
- **Implicit proof-of-possession:** only the holder of the matching private key can unseal Token B.
- In the tailnet model, Tailscale device authorization can act as a **second enrollment factor** (admit to tailnet _and_ complete pairing). In Architecture C, provisioning the device’s Cloudflare Access token could play the same second-factor role (operator-managed today).

### Identity layering (DECIDED: user-with-device-subkeys)

A **user identity key roots a set of device subkeys** (it signs the first device; later devices are signed by an existing device of the same user, or by an owner device during recovery); the auth log lists _people_, each carrying a device set. Epoch keys are sealed to device subkeys, while membership and grants are tracked per user. Revocation granularity follows directly: losing a laptop revokes a single device subkey, whereas removing a person revokes their whole device set in one signed entry. (The alternative — device-as-identity, where the log lists devices directly — is simpler but loses the person-level grouping; rejected for team use.)

---

## 10. Key Rotation and Revocation

Revocation always carries a non-cryptographic obligation: a removed party keeps whatever it already cached, so **if a device/member was compromised, rotate the actual credentials**, not just the vault key.

### 10.1 Centralized (Architecture A)

The DO serializes rotation atomically (see §6.4).

### 10.2 Decentralized conflict-free epoch scheme (Architectures B and C)

Avoids leader election by **decoupling membership (the signed auth DAG) from key material (single-valued epoch)**.

- **Membership** is the signed Merkle auth DAG (§15.10), replayed in a deterministic hash-ordered topological order. Concurrent removals both take effect. No coordinator, no lost intent.
- **Key material**: each rotation appends a signed record:

```
RotationRecord {
  epoch, baseEpoch, hlc, deviceID, signerId,
  keyCommit = hash(K_epoch),         // commitment, not the key
  grants    = { deviceEncPub(b64): sealed(K_epoch) },
  observed  = [auth-log entry hashes seen by initiator],  // for the security rule
  sig
}
```

`epoch`, `hlc`, `deviceID`, `keyCommit` are cleartext metadata, so every node evaluates the winner without holding the key.

**Total-order tiebreak.** Higher `epoch` always supersedes. Among records at the same epoch:

```
winner = argmax over candidates of (hlc, deviceID)   // hlc first; greater fingerprint breaks ties
```

Deterministic and computable from the records themselves → every honest node elects the same winner with no communication.

**Loser detects and re-applies** (idempotent). As implemented this is simpler: every verifiable epoch key is kept, ops decrypt by their `keyCommit`, the rotating admin eagerly re-encrypts and re-emits live items under the new epoch, and no rotation record is tombstoned. The design sketch:

```
W = winner(records at currentEpoch)
if activeKeyCommit != W.keyCommit:
    if myPubkey in W.grants:
        K = unseal(W.grants[myPubkey])
        adoptKey(currentEpoch, K)
        reencryptLocalItems(oldEpoch -> currentEpoch)   // lazy/sweep; items carry their epoch
        tombstone(myLosingRotationRecord)
    else:
        denyAccess()    // winning rotation removed me
```

Membership intent is never lost — it lives in the auth log, separate from the abandoned key bundle.

**Security catch-up.** Convergence guarantees consistency, but a removal’s _security_ requires a rotation that **causally follows** it. If the winning rotation `W` did not observe some removal (the removed member may have unsealed the new key during the race), any admin issues one more rotation that observes it. That catch-up is conflict-free by the same scheme, sits at a higher epoch (supersedes unconditionally), and necessarily observes the removal — as would any concurrent competitor. It terminates: finitely many removals → finitely many catch-ups. In the common case (one admin removes + rotates atomically), there is nothing to catch up; the path only covers concurrent admins.

### 10.3 Fast network revocation (B and C)

Stripping `tag:credvault` / removing the device from the tailnet (B), or revoking its Cloudflare Access service token (C), cuts network reachability near-instantly via the control plane — closing the _new-data_ exposure window before crypto rotation finishes propagating. The network gate handles “can’t reach”; rotation handles “couldn’t read even if it did.”

---

## 11. Coordination Model

“Coordinator” is several roles, most of which need none:

- **Writes:** leaderless by construction (CRDT).
- **Membership:** authority-by-signature (auth DAG), not authority-by-node.
- **Rendezvous/availability:** any online node; mesh anti-entropy. The always-on node is a convenience, not a designated leader.
- **Rotation:** conflict-free epochs (§10.2) avoid election entirely; a self-expiring **lease** is the lighter alternative if explicit serialization is wanted. Full Raft/Paxos is feasible but a poor fit — consensus needs a quorum online, which intermittently-connected personal devices rarely have. Architecture C’s always-on hub gives that optional lease a naturally reachable home, but correctness still rests on the conflict-free epochs.
- **The one genuinely central piece:** in B, Tailscale’s control plane (device auth + ACL push); in C, the Cloudflare edge / Access gate. Each gates access and sees metadata but never vault-content confidentiality. The tailnet piece can be **self-hosted (Headscale)**; the Cloudflare piece is Cloudflare-operated. Full elimination means returning to DHT/mDNS discovery — reopening the complexity these models removed — so keep a direct fallback path (§8.6) to avoid a single point of failure for sync.

---

## 12. Architecture Comparison

| Dimension            | A: Cloudflare (centralized)              | B: Local-first + Tailnet                         | C: Local-first + Cloudflare relay                    |
| -------------------- | ---------------------------------------- | ------------------------------------------------ | ---------------------------------------------------- |
| Confidentiality      | Ciphertext-only at server                | Ciphertext-only at every relay                   | Ciphertext-only at the relay                         |
| Write authority      | Server-enforced policy                   | Cryptographically enforced (signed ops)          | Cryptographically enforced (signed ops)              |
| Consistency          | Strong per vault (DO serializes)         | Eventual (CRDT)                                  | Eventual (CRDT)                                      |
| Conflict handling    | Optimistic concurrency + atomic rotation | CRDT merge + conflict-free epochs                | CRDT merge + conflict-free epochs                    |
| Revocation speed     | Immediate server-side                    | Fast network cutoff (tailnet) + rotation gossip  | Fast network cutoff (Access token) + rotation gossip |
| Availability         | High (managed)                           | Depends on peers; mitigate with always-on node   | High (always-on hub)                                 |
| Offline              | Limited                                  | First-class                                      | First-class                                          |
| Restrictive networks | Works (HTTPS)                            | Often blocked (WireGuard UDP)                    | Works (outbound 443)                                 |
| Metadata exposure    | Cloudflare sees `plain` fields           | Tailscale control plane sees device graph        | Cloudflare edge sees identity, op sizes, timing      |
| Operational burden   | Low (serverless)                         | Higher (CRDT, enrollment), simplified by tailnet | Higher (CRDT, enrollment) + relay to run/pay         |
| Trust                | Trust server for policy/availability     | Trustless data; control plane for access only    | Trustless data; relay for availability/access only   |

---

## 13. Secret Consumption — Agent Proxy

The vault is not only a store but a _secret-consumption surface_: a client ultimately has to feed a secret to a program that uses it. There are two such surfaces, with different exposure profiles:

- **Env injection (`vault run`, §15.13).** Resolves secrets into a child process’s environment. Simple and universal, but the **consuming process holds the plaintext** — it can read, log, or exfiltrate it. Appropriate when the consumer is trusted.
- **Agent proxy (`vault proxy`).** For consumers that are **not** fully trusted with the raw secret — chiefly **AI agents**, where prompt injection or an over-eager tool call could leak an API key, but also third-party CLIs of uncertain provenance. The agent’s outbound API calls are routed through a local, loopback-only proxy that injects the credential _on egress_; the secret is attached to the request only after it leaves the agent, and only when the request is bound for its designated upstream. **The agent never possesses the secret value.**

### 13.1 Model

- The proxy runs on `127.0.0.1` and is driven by a **policy** mapping upstreams → injection rules: `{ upstream host, where to inject (header / query param), which vault reference supplies the value }`. The policy reuses the **same `.env` manifest format as env injection** (`vault run`) rather than a separate config language — one parser, and a single `.env` can drive both surfaces. Grammar: a reserved `UPSTREAM=<url>` line names the destination (repeat `--config` for several upstreams), `?name=<value>` lines inject query parameters, and every other `KEY=<value>` injects a request header. Values resolve with the `vault run` precedence: ambient env → `vault://<vault>/<item>[/<field>]` → literal → item lookup by name.
- The agent is pointed at the proxy in one of two ways: as a **custom API base URL** (`http://127.0.0.1:<port>/…`, the default — no TLS interception, no CA install), or via `HTTPS_PROXY` (forward-proxy / `CONNECT` mode, `--connect`, which needs a locally-trusted MITM CA and is therefore optional; HTTP/1.1 only, and certificate-pinning clients will refuse it). The proxy listens on port 8788 by default; a spawned child gets `VAULT_PROXY_URL` plus the known base-URL variable for each configured upstream.
- On each request the proxy injects the secret, forwards to the real upstream over genuine TLS, and streams the response back. Resolution reads the **local encrypted replica** (offline, instant), exactly like `vault run`, and likewise requires an **unlocked** vault.

### 13.2 Security properties

The proxy is a strictly stronger boundary than env injection — but only if it enforces **host binding**:

- **Host-bound credentials.** A secret is bound to its configured upstream; the proxy refuses to attach it to any other destination. This is the decisive advantage over env injection: with `run`, a compromised agent holding the raw key can POST it anywhere; with the proxy, the agent can only _cause_ the key to be sent to its one legitimate upstream — never learn it, never redirect it.
- **Egress allowlist.** Requests to hosts not named in the policy are rejected — an exfiltration / SSRF guard.
- **No cross-host redirect carry-over.** The proxy will not follow a 3xx that would carry the injected credential to a different host (the host-binding rule, applied to redirects).
- **Loopback-only, no persistence.** Binds `127.0.0.1` only; never writes or logs the secret value; emits a per-injection **audit entry** (upstream, rule, timestamp — never the value).

### 13.3 Residual exposure

The proxy removes the secret’s _value_ from the agent but not the agent’s _ability to use it_: a compromised-while-running agent can still issue authenticated calls to the legitimate upstream for as long as the proxy is up (a confused-deputy use of the live capability). Containment is therefore **scope and lifetime** — narrow policy (one upstream, least-privilege key), run the proxy only for the agent’s session, and pair high-value keys with upstream-side rate/scope limits. This is the inherent ceiling of letting an untrusted consumer _use_ a secret it must not _see_; it is an accepted, documented tradeoff. It mirrors env injection, where the child holds the plaintext outright and it is additionally visible to same-user introspection (`/proc/<pid>/environ`).

---

## 14. Decisions and Verification Notes

### Resolved

- **Identity unit — DECIDED: user-with-device-subkeys** (§9). A user identity key roots its device keys (signing the first; later devices are signed by an existing device of the user, or by an owner device for recovery); the auth log lists _people_, each carrying a device set. Revocation is granular: losing a laptop revokes one device subkey; removing a person revokes their whole device set in a single signed entry. Implication: enrollment seals epoch keys to a _device_ subkey, while membership is tracked per _user_.
- **Recovery escrow — DECIDED: offer admin-assisted recovery** (§5). Each member’s identity keys are sealed to `orgPublicKey` (a `recovery:<userId>` grant); owners holding the org private key can reconstruct them (`vault recover`). The tradeoff is accepted and must be stated to users explicitly: the org _can_ therefore access member data, so this is zero-knowledge **against the infrastructure**, not against an org-level recovery authority. **As implemented:** escrow is on once an `orgPublicKey` grant exists (no separate policy flag). `vault recover --token <A>` re-enrolls the member on a fresh device: the owner’s device signs the `add-device` for that member (the auth log admits an active **owner** device enrolling a device for another member), checks the recovered keys against the member’s public keys in the log, and seals every epoch key plus the escrowed identity keys to the new device in a Token B for `device-confirm`. The owner-signed `add-device` for another user is the durable, signed record of the reset in the auth log; the CLI also emits a stderr audit line. A user identity key alone still cannot enroll past the first device, since Token B copies it to every device and a removed device could otherwise re-enroll itself.

- **Implementation language — DECIDED: Swift for everything local, TypeScript only for the Cloudflare Worker** (§15). The trusted computing base no longer includes Node/V8; one portable engine serves the CLI, the macOS app and the self-hosted relay.
- **Password KDF — DECIDED: scrypt for new vaults**, Argon2id kept readable (§15.6).
- **TPM — DECIDED: `tpm2-tools`-driven tier, not a hand-written codec** (§3.5).
- **Self-hosted relay — DECIDED: Swift `vault relay`** (§15.14); the Cloudflare Worker stays TypeScript.

### Recommended

- **CRDT granularity — RECOMMEND: field-level LWW** (merge after decrypt) (§7.1). The architecture already merges on-device after decryption — the sync layer only moves opaque blobs and never merges — so the “needs keys to merge” cost of field-level is _already paid_, and the key-free-merge advantage of whole-item LWW is therefore moot. Field-level prevents silent loss when two devices edit _different_ fields of one item concurrently; for credentials, silently dropping a freshly-rotated password would be severe, and the extra op/metadata cost is negligible at vault edit volumes. **Refinement:** keep ordinary fields as single-value LWW registers, but model the **password field as a multi-value register** so concurrent _divergent_ edits surface for the user to resolve rather than being silently overwritten.
- **Rotation serialization — RECOMMEND: conflict-free epochs as the correctness mechanism** (§10.2). The system is eventually-consistent and partition-tolerant, and a lease cannot provide true mutual exclusion across partitions — two admins offline from each other can each believe they hold the lease — so conflict-free resolution is required as a fallback regardless, making the lease redundant _as a correctness device_. A self-expiring lease may be layered purely as a **best-effort optimization** to avoid duplicate re-encryption when connectivity is good (e.g., all nodes currently on the tailnet, or reachable via the Architecture C hub), but it must never be relied on for correctness; the conflict-free epoch resolution always governs.

### Still open / verification

- **Transport choice — SELECTED: Architecture C** (Cloudflare relay for universal reach + 24/7 availability) as the primary path, with the tailnet direct fallback (§8.6) **shipped** (`vault serve`, `vault sync --tailnet`). A pure-LAN/mDNS direct path is not built.
- **Control plane ownership — DECIDED: agnostic.** The CLI only shells out to the local `tailscale`, so it works against the Tailscale-hosted control plane (default) or self-hosted Headscale; the Architecture C edge is Cloudflare-operated.
- **Scope confirmations:** no attachments / R2 in v1; no Linux biometric unlock.
- **Verify against current docs** (these evolve, re-check periodically): swift-crypto / CryptoKit APIs; Cloudflare Workers `nodejs_compat` `node:crypto` coverage, Durable Object limits and billing, Tunnel/Access; Tailscale CLI `status --json` output; Windows `KeyCredentialManager` signing behaviour.
- **Audited primitives.** Use swift-crypto / CryptoKit wherever they offer the primitive; keep the in-tree Argon2id/BLAKE2b and sealed-box composition pinned by the golden vectors.

---

## 15. Implementation Architecture — Swift Client + TypeScript Relay

This section is the implementation architecture for Architecture C (§8). It records the design as built; the frozen golden vectors in `protocol/vectors/` pin wire and storage compatibility with the earlier TypeScript client.

> **Swift owns the trusted local environment. TypeScript owns the untrusted zero-knowledge Cloudflare relay.**

```text
                       Cloudflare
             ┌──────────────────────────┐
             │ TypeScript Worker        │
             │ + Durable Objects        │   (or a self-hosted `vault relay`, Swift)
             │ Zero-knowledge relay     │
             └────────────┬─────────────┘
                          │  versioned wire protocol
      ┌───────────────────┼───────────────────┐
┌─────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
│ macOS      │     │ Windows     │     │ Linux       │
│ VaultCore  │     │ VaultCore   │     │ VaultCore   │
│ CLI + app  │     │ CLI         │     │ CLI         │
│ Sec.Enclave│     │ Hello/DPAPI │     │ systemd-creds/TPM │
└────────────┘     └─────────────┘     └─────────────┘
```

### 15.1 Goals and non-goals

The implementation places all code that handles plaintext secrets, private keys, local persistence and OS security facilities in Swift 6 on macOS, Windows and Linux; keeps TypeScript for the Cloudflare Worker (request handling, Durable Object storage, Access verification, opaque storage of ops, auth log, rotations and grants); removes Node/V8 from the local trusted computing base; lets the macOS app link the engine directly; and improves control over sensitive-memory lifecycle. It preserves item semantics, encrypted formats, sync behaviour, CRDT convergence, signed auth-log semantics, enrollment, sharing, rotation and revocation, and keeps a stable machine-oriented CLI contract (`--json`, `--passphrase-stdin`, `--vault`; secrets never on argv).

Non-goals: rewriting the Cloudflare Worker in Swift; changing the wire protocol because the language changed; a new storage format.

### 15.2 Repository layout

```text
swift/                 Swift package
  Sources/VaultCore/     portable engine — Crypto, KDF, CRDT, Auth, Rotation, Protocol,
                         Store, Secrets, Engine, Keystore, Run, Util
  Sources/VaultNet/      SwiftNIO: relay + peer servers, tailnet sync, Access (JWT) verifier,
                         credential-injecting proxy, ephemeral CA
  Sources/VaultCommands/ the command layer, usable by the executable AND in-process by the app
  Sources/VaultCLI/      `vault` — thin executable over VaultCommands
  Sources/VaultPlatform{Darwin,Linux,Windows}/  narrow per-OS seams
  Sources/CSQLite/       system-library shim for libsqlite3
macos/                 vault.app (SwiftUI, links VaultCommands)
windows/hello-helper/  the C# Windows Hello KeyCredential signer
worker/                Cloudflare Worker (TypeScript): src/ (worker, shared handler, Access
                         verification, core/ auth log + sync protocol + rotation), test/, scripts/
deploy/                relay deploy runbooks (systemd units, cloudflared config)
protocol/vectors/      frozen golden vectors and a TypeScript-written SQLite fixture
```

### 15.3 Package boundaries

`VaultCore` is portable Swift with no UI imports. It owns the cryptographic protocol, key derivation, sealed boxes, the CRDT and HLC, the signed auth DAG and membership replay, rotation, grants, recovery, version vectors, sync message types, the SQLite store, item encryption, TOTP, enrollment, sharing, revocation, session state and the secure-buffer type. It depends on explicit seams for the key store and process hardening; platform code lives behind `PlatformKeyStore` and `PlatformProcessSecurity` and never leaks into the protocol or CRDT layers. `VaultNet` holds everything that needs a network server or TLS so `VaultCore` stays dependency-light (swift-crypto only, plus SQLite).

### 15.4 The TypeScript boundary

The Worker owns routing, Durable Object persistence, Access JWT verification, request validation, opaque storage of ops, auth log, rotations and grants, size limits and error handling. It **must not**: decrypt item content, derive account keys, receive passphrases, receive private signing keys, or become authoritative for CRDT resolution or membership validity. Both relays do check pushes against the team’s auth log (op authorship, rotations only from active owner/admin devices, grant principal/role rules) purely to refuse junk; that is filtering, not authority. The client remains responsible for all cryptographic validation. The relay is assumed malicious for confidentiality purposes.

### 15.5 Wire protocol

The protocol is language-independent and versioned. Canonical serialization is `JSON.stringify`-equivalent with **member order preserved** (the Swift `JSONValue` keeps insertion order and JS string escaping) because auth entries, rotation records and grants are hashed and signed over their JSON bytes. Base64 is standard with padding on output and lenient on input. HLCs are fixed-width strings so lexicographic order equals logical order. Sort orders that feed hashes or tie-breaks compare by UTF-16 code unit. Op envelopes hash `deviceId|seq|payload` and sign the hash. Sealed boxes, grants, version vectors and sync requests/responses keep the shapes in §3.2, §7.4 and §8. HTTP surface (both relays): `GET /health` → `{"ok":true}`; `POST /sync` and `POST /push` with JSON bodies that require `teamId`; auth headers `cf-access-token` (app-layer token), `CF-Access-Client-Id`/`CF-Access-Client-Secret` (to the Access edge) and `Cf-Access-Jwt-Assertion` (edge → relay); errors 400/403/404/405/500, plus 413 on the Worker (16 MiB body cap).

### 15.6 Cryptographic primitives and key hierarchy

Primitives: SHA-256, X25519, Ed25519, AES-256-GCM, HKDF-SHA256, HMAC (TOTP), a CSPRNG, and constant-time comparison. The key hierarchy is §3.1: password → KDF → master key → HKDF into `accountKey` and `authVerifier` with fixed domain-separation labels (`credvault/kdf/account-key/v1`, `credvault/kdf/auth-verifier/v1`).

- **scrypt** (swift-crypto `_CryptoExtras`) for new vaults: N=2^17, r=8, p=1, 32-byte output, ≥16-byte salt. Algorithm, salt, N, r, p and length are stored as vault metadata (`kdfParams`) and can be raised later.
- **Argon2id** (v1.3, RFC 9106) is implemented in-tree for reading existing vaults, so no destructive KDF migration is needed. A vault's logical encryption key never changes because the KDF does.
- Ed25519 signing in swift-crypto is hedged/randomized: signatures verify but are not byte-identical between implementations. Everything that is hashed or signed (canonical entry bytes, envelope hashes, rotation and grant bytes) _is_ byte-identical.

### 15.7 Sensitive memory

`SecureBytes` holds long-lived keys in manually allocated, `mlock`ed storage zeroed before release (`memset_s` / `explicit_bzero` / `SecureZeroMemory`). Passphrases and derived keys are wiped after use; secrets are not interpolated into errors, logged, or copied into UI state; core dumps are disabled at process start on macOS and Linux (`RLIMIT_CORE`; a no-op on Windows), and `mlock` is skipped on Windows. Decrypted item values (including passwords) are Swift `String`s in the CRDT, resolve and proxy paths, so they are not zeroed. swift-crypto takes `Data`, so a short-lived copy exists whenever a key is used (`withData` scrubs it); Swift value semantics can still introduce compiler copies, so this narrows the exposure window rather than eliminating it.

### 15.8 Platform layers

- **macOS.** The app links the engine directly: no subprocess, no passphrase IPC, typed errors, direct cancellation. The **Secure Enclave** keystore runs in-process (CryptoKit `dataRepresentation` blob, user-presence gated, no entitlement); where an enclave key cannot be minted (an unsigned host) the engine falls back to the **Keychain** tier. Keychain layout is service `dev.vault.unlock-key`, account = key id.
- **Windows.** Engine, storage, sync, CLI, crypto and secret lifecycle are Swift. **DPAPI** goes through PowerShell `ProtectedData`. **Windows Hello** keeps the small C# `KeyCredential` helper as a narrow shim (`available`, `sign [--create] <name>`, base64 over stdin/stdout, returning only a signature, never receiving the DUK or vault data), with the wrap construction of §3.5. It may later be replaced by a Swift WinRT projection or a small C++/WinRT bridge; manual WinRT/COM in Swift is to be avoided.
- **Linux.** `systemd-creds` and the opt-in `tpm2-tools` tier (§3.5), plus POSIX resource limits and file-permission hardening.

Every blob-backed tier is a `BlobCipher` behind `BlobKeyStore` (0700 directory, 0600 blobs, id-validated filenames).

### 15.9 SQLite

SQLite remains the local store with the logical schema `ops`, `authlog`, `grants`, `rotations`, `meta`. Preserved: transactional mutations, WAL, owner-only file permissions, deterministic op ordering, dedupe by hash, version-vector queries, and tolerance of corrupt rows. The sequence read and write of a new op happen in one `BEGIN IMMEDIATE` transaction, and a busy timeout lets several processes (CLI, app, peer server) share one database.

### 15.10 CRDT, auth DAG, rotation

Semantics are exactly §7.1, §9 and §10.2 and are verified by golden vectors, including shuffled replay: field-level LWW, HLC ordering, tombstones, idempotent replay, deterministic convergence, and the multi-value password register (equal-HLC equivocation resolved deterministically). The auth log is a signed Merkle DAG with hash-ordered topological replay, deterministic tie-breaking, authority evaluated against the state before each entry, invalid entries skipped rather than fatal, and removals/additions of users and devices as specified. Rotation preserves epochs, deterministic winner selection, signing requirements, concurrent-admin handling and security catch-up. **Hardening beyond the original:** only entries that replay actually applies are persisted by the Swift relay, the peer server and the Worker (plus correctly signed entries of unknown future types), so an open or hostile peer cannot grow the append-only log; a device with an unusable encryption key is skipped when sealing a rotation, so it cannot block rotation and revocation; and pre-enrollment private material is deleted when enrollment completes, so it cannot bypass the keystore second factor.

### 15.11 Enrollment and sharing

`auth`, `device-add`, `device-confirm`, `invite`, `share`, `join` and `device-remove` keep the §9 token formats (base64 of JSON; field order is part of the format). The SAS is derived locally on the receiving side from the enroller's key as recorded in the signed log, never echoed from a token. Relay bearer secrets carried in a token are never written to the plaintext meta table. QR rendering is a UI concern and does not define serialization.

### 15.12 Sync

Relay sync, push, pull and anti-entropy reconciliation cover the op log, auth log, rotations and grants. The client re-verifies everything pulled (an op is stored only if the key of the device it names signed it; membership is imported first), keeps each device's run gap-free, pushes in ordered bounded batches (the first carrying the metadata), caps response size as bytes arrive, and treats the relay as untrusted. **Direct tailnet sync** (`vault serve`, `vault sync --tailnet` / `--tailnet-only`) runs the same anti-entropy handler over a keyless peer server bound to the Tailscale address; the tailnet is a transport and access gate, never a confidentiality boundary.

### 15.13 `vault run` and `vault proxy`

`vault run` reads `.env` as a manifest, resolves values from the local vault, injects them only at child launch, never writes them to disk, fails before spawning if a value cannot be resolved, audits without values, and can mask the child's output. `vault proxy` implements §13: loopback only, per-upstream host binding, egress allowlist, no redirect-following, per-injection audit, and a streaming scrubber over every relayed header and textual body. Query credentials are encoded strictly (RFC 3986) so reserved characters survive. `--connect` adds forward-proxy mode with an **ephemeral in-memory P-256 CA** (swift-certificates); a leaf is minted only for allowlisted hosts, and only the public CA certificate is written to disk.

### 15.14 Self-hosted relay

`vault relay` is the supported self-hosted relay (a Swift replacement for the earlier Node relay): the same HTTP protocol and SQLite schema, service-token and Cloudflare Access gates (RS256 pinned; `iss` and `exp` required; audience and `nbf` checked; JWKS cached with bounded staleness), `REQUIRE_ACCESS` to fail closed, systemd `Type=notify` and watchdog support, and a fixed generic 500 body so a credential can never be echoed. It authenticates ops, rotations and grants against each team's own auth log and refuses to persist unauthenticated metadata. The Cloudflare Worker remains TypeScript by design.

### 15.15 Errors, logging, concurrency

Local components use typed internal errors that map to stable machine-readable CLI responses (`{"ok":false,"error":"…"}`); descriptions never contain secrets, keys, passphrases or injected credentials. Logging is allowlist-based: vault name, operation type, device id, upstream host, timestamps, protocol version and non-secret rule names only. Swift 6 strict concurrency is on: the engine is an actor, shared state is value types or actors, and blocking I/O runs on dispatch threads rather than the cooperative pool. Commands carry their I/O context in a task-local, so the same command layer runs both as a process and in-process inside the app.

### 15.16 Build, CI and compatibility evidence

Outputs: `vault` (all platforms), `vault.app` (macOS), `vault-hello-helper.exe` (Windows), and the Worker bundle. CI builds and tests on macOS arm64, Linux x64/arm64 and Windows x64 (advisory until sqlite3 is provisioned there), runs the Worker-side TypeScript checks, compiles the Hello helper, and runs the TPM cipher against `swtpm`. The golden vectors cover crypto (X25519, Ed25519 verification, AES-GCM, HKDF, both KDFs, sealed boxes, TOTP), HLC and CRDT, the auth DAG (forks, forged and unknown entries, rival genesis, transitive device revocation), rotation winners and catch-up, envelopes, grants, gap-free ingest, and a TypeScript-written SQLite replica. They are frozen fixtures: the generator that produced them was removed with the TypeScript client, so they no longer regenerate and drift from them is not otherwise detected.

### 15.17 Security boundary and status

```text
TRUSTED LOCAL SIDE                        UNTRUSTED INFRASTRUCTURE
Swift VaultCore, CLI, macOS app           Cloudflare Worker / Durable Objects
OS keystore / TPM / Secure Enclave        `vault relay` operator, network
the Windows Hello helper (signature only) Receives ciphertext and metadata only.
local SQLite
```

Client signatures and encryption remain the source of integrity and confidentiality.

Status: every Swift phase is implemented (deterministic core, crypto, SQLite, CLI, key stores, macOS app linking the engine, relay and tailnet sync, proxy, self-hosted relay) and the Node SEA distribution is removed. **Not verified in this environment:** the Linux and Windows builds and their CI cells, the Secure Enclave path and its Touch ID prompt, the `swtpm` CI job, the Windows Hello (including its Authenticode caller check) and DPAPI paths on real hardware, and the systemd notify path under the shipped unit. These, together with the open items in §14, are the remaining verification work.
