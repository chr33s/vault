# vault — remaining gaps (TODO)

Compiled from a review of [`vault.spec.md`](./vault.spec.md) and
[`vault.plan.md`](./vault.plan.md) against the current tree. Last updated
2026-09-27.

**Baseline:** typecheck clean; the `node:test` suite is green on Node **26.10.0**
(284 tests, 263 pass, 21 platform-skipped). `npm run check` (oxlint + oxfmt) and
`npm run check:deps` (zero runtime deps) pass. CI runs test+typecheck+zero-dep, a
`strong-tier` swtpm/TPM2 job, an SEA matrix, a native Windows Hello helper build
(`win-x64`), and a native macOS build — all pinned to an exact Node via
`engines.node` read by `node-version-file`. Milestones M1–M8 are implemented per
the README status table, and every plan checkbox is `[x]`.

---

## Remaining

### 1. Not built (functional gaps)

- [ ] **Pure-LAN / mDNS direct-fallback variant** — spec §8.6/§11, README "Known
      limitations". The §8.6 direct path ships **tailnet-only** (the
      `vault serve` + `vault sync --tailnet` pair). Without a working tailnet
      there is no direct peer discovery. Decide whether LAN/mDNS discovery is in
      scope for v1 or a documented permanent limitation.

### 2. Verify externally (ongoing, not a code change)

- [ ] **Windows TPM2 over TBS (`tbs.dll`)** — plan §12b. The TPM2 codec, salted
      HMAC + parameter-encrypted sessions, and the persistent-process line framing
      are all validated against the **swtpm** emulator (in CI), but the literal
      `tbs.dll` PowerShell call (`cli/tpm2/transport.ts`) is untested off-Windows.
      Run the TPM2 suite on a real Windows host with a TPM. _(Needs Windows
      hardware.)_

- [ ] **Windows Hello gesture paths** — plan §12b. The `windows-hello` tier
      (`cli/hello.ts` + `native/hello-helper`) is unit-tested against a fake-sign
      oracle and stub helper, and CI compiles the helper and probes `available`
      on a Windows runner, but enrollment (`sign --create` + the determinism
      self-test), per-unlock gestures, and Authenticode caller-auth
      (`WinVerifyTrust` + thumbprint pinning, `VAULT_HELLO_STRICT`) still need a
      real Hello-enrolled host. _(Needs Windows hardware.)_

- [ ] **Re-verify against current external docs** — spec §14. Cloudflare D1/DO
      limits & billing, Tunnel/Access, `tsnet`/`ipnstate` peer-tag accessors;
      CryptoKit/CloudKit for the native side; `KeyCredentialManager` signing
      scheme (must stay RSA PKCS#1 v1.5). These evolve; re-confirm before each
      release.

### 3. Confirm, then close (likely non-goals)

- [ ] **File attachments / R2** — spec §6.1 is an **Architecture A** feature (R2
      for blobs over the 2 MB row cap). Architecture C is the selected design and
      the `Item` model has no attachment field. Confirm "no attachments in v1" as
      an explicit non-goal so it stops reading as a gap.

- [ ] **CLI-native biometric unlock** — plan §5 deferred per-access biometric
      unlock to the native wrapper; v1 CLI = passphrase. The `secure-enclave`
      (macOS Touch ID) and `windows-hello` keystore tiers now deliver
      gesture-gated unlock from the CLI on both desktop platforms; Linux has the
      TPM2+PIN tier only. Confirm no Linux biometric unlock is expected, then
      close.
