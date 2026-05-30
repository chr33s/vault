# Credential Vault — Design Specification

**Status:** Draft · **Scope:** End-to-end encrypted credential vault with multi-vault sharing, evaluated under three deployment architectures (centralized, decentralized, and hybrid); **Architecture C (hybrid) is the selected direction.**

This document consolidates the design decisions for a native Swift (macOS) credential vault that synchronizes encrypted credentials across devices and between people. It covers the cryptographic core, data model, three candidate sync architectures, device enrollment, and a coordinator-free key-rotation scheme.

-----

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
1. [Decisions and Verification Notes](#13-decisions-and-verification-notes)

-----

## 1. Goals and Non-Goals

### Goals

- A native Swift macOS app storing credentials (logins, notes, cards, TOTP secrets, custom fields).
- **Zero-knowledge**: no sync intermediary ever holds plaintext or keys.
- **Whole-vault sharing** with **multi-vault** support: each team is a vault; a user may belong to many vaults; a personal vault is a team-of-one.
- Sync across a user’s own devices and between different people.
- Offline-capable, with deterministic conflict resolution.

### Non-Goals

- Per-item (sub-vault) sharing. Whole-vault grants only; per-item multiplies key-management surface for little benefit.
- Hiding the existence/among-membership graph from infrastructure operators (see §2).
- Rolling custom cryptographic primitives. Use audited libraries only.

-----

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

**Read confidentiality is enforced by cryptography; write/role/invite policy is enforced by an authority layer** (a server in Architecture A, a signed replicated auth log in Architectures B and C). Anyone holding a vault key can technically craft valid ciphertext, so write permissions are *policy*, not a cryptographic guarantee — except in the decentralized models, where signed ops + auth-log validation make write authority cryptographically checkable.

-----

## 3. Cryptographic Design

### 3.1 Key hierarchy (three tiers)

1. **Account key** — derived from the master password via **Argon2id** (memory-hard; not in CryptoKit, so via libsodium/swift-sodium; PBKDF2 via CommonCrypto is the weaker fallback). Wraps only the user’s private identity keys.
1. **User private keys** — an **X25519** key (key agreement / sealing) and an **Ed25519** key (signing). Stored as ciphertext under the account key; synced to the user’s devices in that wrapped form.
1. **Vault keys** — one symmetric key per vault, delivered to each member as a *grant*: the vault key sealed to the member’s X25519 public key.

This indirection lets a user change their master password by re-wrapping their private keys, without re-encrypting any vault.

### 3.2 Primitives

- **Symmetric:** AES-GCM or ChaCha20-Poly1305 (both in CryptoKit), authenticated.
- **Key agreement:** X25519 (`Curve25519.KeyAgreement`).
- **Signing:** Ed25519 (`Curve25519.Signing`).
- **KDF:** Argon2id.
- **Sealing a key to a public key** (envelope / sealed-box, ECIES pattern): generate an ephemeral keypair, X25519-ECDH against the recipient’s static public key, HKDF the shared secret into a wrapping key, AES-GCM the payload, and store `{ephemeralPublicKey, nonce, ciphertext}`. libsodium offers this directly as `crypto_box_seal`.

### 3.3 Master password: auth vs encryption split

The master password is stretched into a **master key**, then split into two branches that **cannot derive each other**:

- **Account key** (encryption branch) — never leaves the device; wraps the private keys.
- **authVerifier** (auth branch) — sent to the server (Architecture A) to authenticate login.

Storing a single hash that both authenticates and encrypts is a design failure: it would let the server decrypt the vault.

### 3.4 Local storage at rest

- Working store: **SQLite** (indices, transactions, per-row versioning). JSON reserved for export/backup and signed log entries.
- Items stored as ciphertext locally as well.
- Use the macOS **Keychain** + **Secure Enclave** for biometric-gated unlock material; do not place the whole vault in the system Keychain.

-----

## 4. Data Model and Schema

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

-----

## 5. Identity and Access Control

- Each principal holds an X25519 + Ed25519 keypair. In the decentralized models the unit is a **user with subordinate device keys** (see §9).
- **Membership** is whole-vault: each member holds one `KeyGrant` per vault. The personal vault is a self-grant.
- **Public-key trust** is the hard problem without a trusted directory. Mitigations, increasing in strength: trust-on-first-use with change alerts, out-of-band fingerprint verification (achieved by the QR handshake in §9), key-transparency log.
- **Decentralized authority** (Architectures B and C): a **signed, replicated authorization log** rooted at the vault creator. Entries (“O added M as admin”, “A removed B”) are signed and independently validated by every peer. Because each item write is also a signed op validated against this log, **write authority becomes cryptographically enforced**, not merely server-trusted.

### Account recovery / escrow (decision point)

In a team product, “forgot master password = data loss” is usually unacceptable. Admin-assisted recovery requires **escrow**: an org keypair, with each member’s recovery key sealed to `orgPublicKey` (the `RecoveryGrant` record). The tradeoff is explicit: escrow means the org **can** reconstruct a member’s keys and therefore **can** access their data — which contradicts a naive “zero-knowledge, no one can ever see anything” claim. Offer it as a per-org policy toggle.

-----

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

-----

## 7. Architecture B — Decentralized (Local-First + Tailnet)

No central server. Each device holds a full encrypted replica, with Tailscale providing transport. This is the decentralized baseline; the **selected direction is Architecture C** (§8), which reuses this same local-first core and keeps B’s tailnet as an optional direct-path fallback (§8.6).

### 7.1 Local store and merge

- **SQLite** holds ciphertext + a CRDT op log; JSON for export and signed log entries.
- **CRDTs** replace the single writer: vault = map of items, each item a map of fields, each field a last-writer-wins register keyed by a **hybrid logical clock (HLC)**; tombstones for deletes. Libraries: Automerge / Yjs (verify current APIs).
- **Encryption × CRDT:** sync encrypted op-blobs; each peer decrypts locally, merges in the CRDT on plaintext, re-encrypts for storage. Relaying peers only ever forward opaque blobs. (Whole-item LWW is the simpler fallback if merge must run without decrypting.)

### 7.2 Transport via Tailscale (`tsnet`)

- The CLI embeds a `tsnet` node: a full Tailscale node inside the process (userspace stack, no daemon, no root), with its own tailnet IP/MagicDNS name/HTTPS cert, governed by Tailscale ACLs.
- **The tailnet solves discovery, NAT traversal, and transport encryption** — dropping the DHT, mDNS, STUN/TURN/ICE, and rendezvous server the pure-P2P design needed.
- **Critical invariant: tailnet membership ≠ vault membership.** Being on the tailnet must not grant decryption. All crypto layers (sealed grants, signed ops, auth log) remain. The tailnet is transport + access gate, never the confidentiality boundary.

### 7.3 ACL / tag policy

```hujson
{
  "tagOwners":     { "tag:credvault": ["autogroup:admin"] },
  "acls": [
    { "action": "accept", "src": ["tag:credvault"], "dst": ["tag:credvault:8731"] }
  ],
  "autoApprovers": { "tags": { "tag:credvault": ["autogroup:admin"] } }
}
```

Only tagged vault nodes can reach the sync port. The service additionally re-checks the caller’s tag in-process via `WhoIs` (defense in depth).

### 7.4 Anti-entropy protocol (per pair, both directions, one round)

- Each op is an `OpEnvelope { deviceID, seq, hash, sig, payload(opaque ciphertext) }`.
- A **version vector** (`deviceID → highest seq held`) summarizes local state.
- Caller sends its vector → peer replies with ops past it **plus** the peer’s own vector → caller applies, then pushes whatever the peer lacks. Every node runs this against every reachable peer on a timer: a coordinator-free mesh. Swap the flat vector for a Merkle summary for sublinear diffs on large histories.
- `Apply` is where each op’s signature is verified against the author key and the auth log **before** the CRDT merges it.

### 7.5 Availability

Run any node 24/7 (home server / small VM) as an always-reachable replica. It is just another tailnet node holding ciphertext — no special role, no relay infrastructure to design.

-----

## 8. Architecture C — Hybrid (Local-First + Cloudflare Relay)

**Architecture C is the selected design.** It keeps Architecture B’s entire data, crypto, and trust model **unchanged** — CRDT field-level LWW, conflict-free epochs, the signed auth log, sealed grants, user-with-device-subkeys — and changes only **transport and availability**: an always-on, zero-knowledge Cloudflare relay/replica is the primary sync path, with B’s tailnet/LAN mesh retained as an optional direct fallback (§8.6). The defining distinction from Architecture A: the Cloudflare node here is **a dumb relay, not an authority**. Every device still holds a full replica, and write authority still lives in the signed auth log; Cloudflare only stores and forwards opaque ops while staying awake.

### 8.1 Topology — hub-and-spoke, async store-and-forward

- Each device makes an outbound HTTPS (443) connection to one always-on hub, pushes its ops, and pulls everyone else’s.
- Simpler than B’s mesh: no device-to-device NAT traversal, and outbound 443 works on restrictive networks where WireGuard/Tailscale UDP is often blocked.
- The hub is a persistent inbox, so two devices never need to be online simultaneously — closing B’s availability gap with no self-hosted 24/7 box.

### 8.2 The hub — two placements

- **Serverless (no Tunnel):** a Worker fronting a SQLite-backed Durable Object per vault. It stores the opaque `OpEnvelope` log and version vector, dedups by op hash, and can hold hibernatable WebSockets for live fan-out. This is the §6 DO-per-vault stripped of its authority role — it stores ciphertext and serves “ops since your vector,” enforcing nothing about contents because it cannot read them.
- **Self-hosted behind Cloudflare Tunnel:** run the §7.4 anti-entropy service (the same Go service, minus the `tsnet` wrapper) on an always-on box or a Cloudflare Container, and expose it with `cloudflared` — a public hostname through the edge with no inbound ports. Tunnel is the mechanism for a node you control to be reachable; the serverless option needs no Tunnel.
- The wire protocol is unchanged: the §7.4 version-vector pull + push.

### 8.3 Access control — network gate + crypto authority

- Front the hub with **Cloudflare Access**, using per-device service tokens or mTLS client certs issued at enrollment. This is the network-layer gate, the analog of `tag:credvault` on the tailnet.
- The signed auth log remains the authority for *what a device may do*. Two cleanly separated layers: Cloudflare gates reachability and sees metadata; the crypto gates confidentiality and write authority.

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

Keep B’s direct path (LAN discovery or the tailnet) alive alongside the hub. The hub gives universal reachability and 24/7 availability; the direct path means a down, throttled, or eclipsing hub can never fully isolate two devices that can see each other. Same op-log, two transports, with the hub as one (very reliable) replica among peers. “Cloudflare is down” then degrades to “sync only when devices meet directly,” rather than “no sync.”

-----

## 9. Device Enrollment (CLI + QR)

A two-way out-of-band handshake that doubles as public-key trust establishment.

1. New device: download CLI.
1. `cli auth` generates the device keypair (X25519 + Ed25519) and `deviceId`; emits **Token A** = `deviceId:publicKey`.
1. New device shows Token A as a QR.
1. Authorized device: `cli device-add` scans Token A.
1. It seals the vault key to Token A’s public key and appends a signed auth-log entry (“device added, role R”).
1. It shows **Token B** (the sealed grant bundle) as a QR.
1. New device: `cli device-confirm` scans Token B, unseals the vault key, validates the auth-log entry.
1. New device persists the vault key (Keychain / Secure Enclave), builds its local SQLite replica.
1. It connects to peers and runs anti-entropy to pull the encrypted history.
1. The signed auth-log entry gossips out; honest peers now accept the device.
1. *(Optional)* Both screens show a matching short authentication string (mutual verification).

### Token contents

- **Token A:** `deviceId`, X25519 pub, Ed25519 pub. Small.
- **Token B:** vault key sealed to the new device’s pub, `vaultId`, `currentKeyVersion`, short authentication string. In the tailnet model, **no bootstrap address is needed** (MagicDNS handles reachability). Bulk history flows over normal sync, not the QR (QR ≈ 3 KB cap). (In Architecture C, Token B instead carries the hub hostname and a Cloudflare Access service token issued at enrollment.)

### Security properties

- **The in-person QR is the trust anchor** that replaces the missing key-distribution authority — it’s the fingerprint-verification step baked into the UX, defeating MITM on public keys.
- **Implicit proof-of-possession:** only the holder of the matching private key can unseal Token B.
- In the tailnet model, Tailscale device authorization can act as a **second enrollment factor** (admit to tailnet *and* complete pairing). In Architecture C, issuing the Cloudflare Access token/cert plays the same second-factor role.

### Identity layering (DECIDED: user-with-device-subkeys)

A **user identity key signs subordinate device subkeys**; the auth log lists *people*, each carrying a device set. The vault key is sealed to a device subkey during enrollment, while membership and grants are tracked per user. Revocation granularity follows directly: losing a laptop revokes a single device subkey, whereas removing a person revokes their whole device set in one signed entry. (The alternative — device-as-identity, where the log lists devices directly — is simpler but loses the person-level grouping; rejected for team use.)

-----

## 10. Key Rotation and Revocation

Revocation always carries a non-cryptographic obligation: a removed party keeps whatever it already cached, so **if a device/member was compromised, rotate the actual credentials**, not just the vault key.

### 10.1 Centralized (Architecture A)

The DO serializes rotation atomically (see §6.4).

### 10.2 Decentralized conflict-free epoch scheme (Architectures B and C)

Avoids leader election by **decoupling membership (CRDT) from key material (single-valued epoch)**.

- **Membership** is a CRDT (OR-Set / per-member LWW keyed by HLC). Concurrent removals commute — both take effect. No coordinator, no lost intent.
- **Key material**: each rotation appends a signed record:

```
RotationRecord {
  epoch, baseEpoch, hlc, deviceID,
  keyCommit = hash(K_epoch),         // commitment, not the key
  grants    = { pubkey: sealed(K_epoch) },
  observed  = log position seen by initiator,  // for the security rule
  sig
}
```

`epoch`, `hlc`, `deviceID`, `keyCommit` are cleartext metadata, so every node evaluates the winner without holding the key.

**Total-order tiebreak.** Higher `epoch` always supersedes. Among records at the same epoch:

```
winner = argmax over candidates of (hlc, deviceID)   // hlc first; greater fingerprint breaks ties
```

Deterministic and computable from the records themselves → every honest node elects the same winner with no communication.

**Loser detects and re-applies** (idempotent):

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

Membership intent is never lost — it lives in the CRDT log, separate from the abandoned key bundle.

**Security catch-up.** Convergence guarantees consistency, but a removal’s *security* requires a rotation that **causally follows** it. If the winning rotation `W` did not observe some removal (the removed member may have unsealed the new key during the race), any admin issues one more rotation that observes it. That catch-up is conflict-free by the same scheme, sits at a higher epoch (supersedes unconditionally), and necessarily observes the removal — as would any concurrent competitor. It terminates: finitely many removals → finitely many catch-ups. In the common case (one admin removes + rotates atomically), there is nothing to catch up; the path only covers concurrent admins.

### 10.3 Fast network revocation (B and C)

Stripping `tag:credvault` / removing the device from the tailnet (B), or revoking its Cloudflare Access token/cert (C), cuts network reachability near-instantly via the control plane — closing the *new-data* exposure window before crypto rotation finishes propagating. The network gate handles “can’t reach”; rotation handles “couldn’t read even if it did.”

-----

## 11. Coordination Model

“Coordinator” is several roles, most of which need none:

- **Writes:** leaderless by construction (CRDT).
- **Membership:** authority-by-signature (auth log), not authority-by-node.
- **Rendezvous/availability:** any online node; mesh anti-entropy. The always-on node is a convenience, not a designated leader.
- **Rotation:** conflict-free epochs (§10.2) avoid election entirely; a self-expiring **lease** is the lighter alternative if explicit serialization is wanted. Full Raft/Paxos is feasible but a poor fit — consensus needs a quorum online, which intermittently-connected personal devices rarely have. Architecture C’s always-on hub gives that optional lease a naturally reachable home, but correctness still rests on the conflict-free epochs.
- **The one genuinely central piece:** in B, Tailscale’s control plane (device auth + ACL push); in C, the Cloudflare edge / Access gate. Each gates access and sees metadata but never vault-content confidentiality. The tailnet piece can be **self-hosted (Headscale)**; the Cloudflare piece is Cloudflare-operated. Full elimination means returning to DHT/mDNS discovery — reopening the complexity these models removed — so keep a direct fallback path (§8.6) to avoid a single point of failure for sync.

-----

## 12. Architecture Comparison

|Dimension           |A: Cloudflare (centralized)             |B: Local-first + Tailnet                        |C: Local-first + Cloudflare relay                   |
|--------------------|----------------------------------------|------------------------------------------------|----------------------------------------------------|
|Confidentiality     |Ciphertext-only at server               |Ciphertext-only at every relay                  |Ciphertext-only at the relay                        |
|Write authority     |Server-enforced policy                  |Cryptographically enforced (signed ops)         |Cryptographically enforced (signed ops)             |
|Consistency         |Strong per vault (DO serializes)        |Eventual (CRDT)                                 |Eventual (CRDT)                                     |
|Conflict handling   |Optimistic concurrency + atomic rotation|CRDT merge + conflict-free epochs               |CRDT merge + conflict-free epochs                   |
|Revocation speed    |Immediate server-side                   |Fast network cutoff (tailnet) + rotation gossip |Fast network cutoff (Access token) + rotation gossip|
|Availability        |High (managed)                          |Depends on peers; mitigate with always-on node  |High (always-on hub)                                |
|Offline             |Limited                                 |First-class                                     |First-class                                         |
|Restrictive networks|Works (HTTPS)                           |Often blocked (WireGuard UDP)                   |Works (outbound 443)                                |
|Metadata exposure   |Cloudflare sees `plain` fields          |Tailscale control plane sees device graph       |Cloudflare edge sees identity, op sizes, timing     |
|Operational burden  |Low (serverless)                        |Higher (CRDT, enrollment), simplified by tailnet|Higher (CRDT, enrollment) + relay to run/pay        |
|Trust               |Trust server for policy/availability    |Trustless data; control plane for access only   |Trustless data; relay for availability/access only  |

-----

## 13. Decisions and Verification Notes

### Resolved

- **Identity unit — DECIDED: user-with-device-subkeys** (§9). A user identity key signs subordinate device keys; the auth log lists *people*, each carrying a device set. Revocation is granular: losing a laptop revokes one device subkey; removing a person revokes their whole device set in a single signed entry. Implication: enrollment seals the vault key to a *device* subkey, but membership and grants are tracked per *user*, and the QR handshake additionally binds the new device subkey under the user’s signing key.
- **Recovery escrow — DECIDED: offer admin-assisted recovery** (§5). Each member’s recovery key is sealed to `orgPublicKey` (`RecoveryGrant`); owners holding the org private key can reconstruct a locked-out member. The tradeoff is accepted and must be stated to users explicitly: the org *can* therefore access member data, so this is zero-knowledge **against the infrastructure**, not against an org-level recovery authority. Gate it behind a visible per-org policy flag and emit an audit-logged event on every reset.

### Recommended

- **CRDT granularity — RECOMMEND: field-level LWW** (merge after decrypt) (§7.1). The architecture already merges on-device after decryption — the sync layer only moves opaque blobs and never merges — so the “needs keys to merge” cost of field-level is *already paid*, and the key-free-merge advantage of whole-item LWW is therefore moot. Field-level prevents silent loss when two devices edit *different* fields of one item concurrently; for credentials, silently dropping a freshly-rotated password would be severe, and the extra op/metadata cost is negligible at vault edit volumes. **Refinement:** keep ordinary fields as single-value LWW registers, but model the **password field as a multi-value register** so concurrent *divergent* edits surface for the user to resolve rather than being silently overwritten.
- **Rotation serialization — RECOMMEND: conflict-free epochs as the correctness mechanism** (§10.2). The system is eventually-consistent and partition-tolerant, and a lease cannot provide true mutual exclusion across partitions — two admins offline from each other can each believe they hold the lease — so conflict-free resolution is required as a fallback regardless, making the lease redundant *as a correctness device*. A self-expiring lease may be layered purely as a **best-effort optimization** to avoid duplicate re-encryption when connectivity is good (e.g., all nodes currently on the tailnet, or reachable via the Architecture C hub), but it must never be relied on for correctness; the conflict-free epoch resolution always governs.

### Still open / verification

- **Transport choice — SELECTED: Architecture C** (Cloudflare relay for universal reach + 24/7 availability) as the primary path, with B’s tailnet/LAN mesh as an optional direct fallback (§8.6). Whether to ship the fallback in v1 or defer it is the remaining sub-decision.
- **Control plane ownership:** Tailscale-hosted vs self-hosted Headscale (B); Cloudflare-operated edge (C).
- **Verify against current docs** (these evolve): CryptoKit/CloudKit APIs; Cloudflare D1/DO limits and billing, Tunnel/Access; `tsnet` API surface and `ipnstate` peer-tag accessors; Automerge/Yjs sync APIs.
- **Never roll your own crypto.** Use audited primitives (libsodium, CryptoKit) throughout.