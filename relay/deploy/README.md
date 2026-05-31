# Relay deployment & runbook (Architecture C)

The relay is the always-on, **zero-knowledge** sync hub from spec §8 / plan §6.
It stores opaque `OpEnvelope`s and answers "ops since your version vector". It
also gossips the **signed auth log**, **rotation records**, and **recovery-escrow
grants** as cleartext metadata — it can read but never forge them (every entry
is signed and clients re-validate). It holds no keys, reads no vault plaintext,
and enforces no content policy — a malicious or buggy relay can cost
_availability and metadata privacy_, never integrity or confidentiality
(spec §8.4).

## Topology

```
Path A (self-hosted Node):
  device ─outbound 443→ Cloudflare edge ─Tunnel→ cloudflared → node relay (127.0.0.1:8731)
            (Access gate)                (no inbound ports)     (systemd)

Path B (serverless):
  device ─outbound 443→ Cloudflare edge → Worker → Durable Object (SQLite) per vault
            (Access gate)
```

Outbound 443 works on restrictive networks where WireGuard/Tailscale UDP is
blocked (spec §8.1). Devices never connect to each other through the hub; the
hub is a persistent inbox so two devices need never be online simultaneously.

## Two cleanly separated layers (spec §8.3)

1. **Network gate — Cloudflare Access.** Front the hostname with an Access
   policy that issues **per-device service tokens** (or mTLS client certs) at
   enrollment. Revoking a token is the §8.5 fast network cutoff — it severs a
   device's reachability instantly, before crypto rotation finishes propagating.
2. **Crypto authority — the signed auth log.** What a device may _do_ is decided
   by the replicated, signed auth log that every replica validates. The relay
   gates reachability and sees metadata; it never gates confidentiality.

The relay additionally verifies the `Cf-Access-Jwt-Assertion` header against
Cloudflare's JWKS (`relay/access.ts`) as defense in depth, and a static
`VAULT_RELAY_TOKENS` allowlist supports the self-hosted path.

## Two placements (spec §8.2)

Both speak the **identical wire protocol** (`/sync`, `/push`, `/health`) and the
same SQL schema, so a client (`vault sync --relay <url>`) can't tell them apart.
Pick one:

- **Path A — self-hosted Node behind Cloudflare Tunnel.** A box you run hosting
  `node relay/main.ts`, exposed via `cloudflared`. Code: `relay/main.ts`.
- **Path B — serverless Worker + Durable Object.** No box; runs on Cloudflare's
  edge, one Durable Object (SQLite) per vault. Code: `relay/worker/`.

## Tunnel-only / lock-down (is the relay publicly reachable?)

The relay is **zero-knowledge** either way — it only ever holds opaque,
client-encrypted ops, so being public costs _availability and metadata_, never
confidentiality (spec §8.4). But if you want the endpoint itself not publicly
reachable, the two placements differ fundamentally:

- **Path A can be genuinely non-public.** The relay binds `127.0.0.1:8731` and
  `cloudflared` makes only an **outbound** connection to the edge — **no inbound
  ports are opened** on the host, and there is no public IP/port to hit. The
  _only_ ingress is through the Tunnel. Put **Cloudflare Access** in front and
  the edge rejects unauthenticated requests before they ever enter the tunnel.
  Result: not directly reachable **and** edge-gated.

  ```bash
  # Bind localhost only (default PORT=8731); do NOT open a firewall port.
  # cloudflared has NO public ingress of its own — it only dials out:
  #   relay/deploy/cloudflared-config.yml -> ingress: http://127.0.0.1:8731
  # Then gate the hostname with Access (per-device service tokens), so the
  # edge blocks anon traffic up front:
  REQUIRE_ACCESS=1 VAULT_RELAY_TOKENS=tok1,tok2 \
    CF_ACCESS_TEAM_DOMAIN=myteam.cloudflareaccess.com CF_ACCESS_AUD=<aud> \
    node relay/main.ts
  ```

  `REQUIRE_ACCESS=1` is belt-and-suspenders: even if the Access app is
  misconfigured, the relay itself refuses traffic with no valid token.

- **Path B (Worker) is inherently a public edge endpoint.** A Worker _runs on_
  Cloudflare's edge; you cannot put it "behind" a tunnel. You can only **gate**
  it: Cloudflare Access over the route + our `REQUIRE_ACCESS=1` token check make
  it return **403** to everyone unauthenticated, and dropping `workers_dev` +
  binding a custom hostname avoids the `*.workers.dev` URL — but a locked public
  endpoint still exists. **Workers VPC does _not_ help here:** it is
  _egress-only_ (it lets a Worker reach _into_ your private network), not a way
  to make the Worker itself private; inbound-private flows are future work.

**Choose by requirement:** _“no directly reachable endpoint exists”_ → **Path A**
(Tunnel + Access). _“only authenticated callers get through”_ → **either** path
(Access + the token gate); Path B just keeps a public-facing, locked door.

---

## Path A — self-hosted Node behind Cloudflare Tunnel

1. **Host.** Small always-on box (or Cloudflare Container). Create a `vault`
   user and `/opt/vault` (clone) + `/var/lib/vault` (db). Install Node ≥ 26.
2. **Run the relay.** Install `relay/deploy/vault-relay.service`, set
   `VAULT_RELAY_TOKENS` (and optionally the `CF_ACCESS_*` vars), then
   `systemctl enable --now vault-relay`. (Quick check: `curl localhost:8731/health`.)
3. **Tunnel.** Install `cloudflared`; create + route the tunnel:

   ```bash
   cloudflared tunnel login
   cloudflared tunnel create vault-relay
   cloudflared tunnel route dns vault-relay vault.example.com
   # uses relay/deploy/cloudflared-config.yml (ingress -> http://127.0.0.1:8731)
   cloudflared tunnel run vault-relay     # or install as a service
   ```

   No inbound ports are opened on the host.

4. **Access policy.** In the Cloudflare dashboard, protect `vault.example.com`
   with an Access application and a per-device **service token** (full steps in
   "Authenticating clients" below). Or skip Access and gate purely with the
   app-layer `VAULT_RELAY_TOKENS` allowlist.
5. **Verify end-to-end:**

   ```bash
   # With a Cloudflare Access service token:
   VAULT_PASSPHRASE=… vault sync --relay https://vault.example.com \
     --access-id <uuid>.access --access-secret <secret>
   # Or with an app-layer token (no Access app):
   VAULT_PASSPHRASE=… vault sync --relay https://vault.example.com --relay-token <tok>
   ```

---

## Path B — serverless Worker + Durable Object

Runs the relay on Cloudflare's edge — no box to run or pay for, native 24/7,
one SQLite-backed Durable Object per `teamId`. Source: `relay/worker/`
(`worker.ts` = fetch handler + `RelayDO`; `wrangler.toml` = config). It shares
the transport-agnostic `relay/handler.ts` with Path A **and** reuses the same
crypto/auth code (`core/protocol`, `core/authlog`, `relay/access`) via the
`nodejs_compat` `node:crypto` polyfill — so the logic is genuinely identical to
the Node relay, with no duplicated implementation.

### One-click: Deploy to Cloudflare

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/chr33s/vault/tree/main/relay/worker)

The button clones the repo to your Git account and provisions the Worker + the
SQLite Durable Object (from `wrangler.toml`'s migration) automatically. Because
`relay/worker/` sits in a monorepo, the URL targets that **subdirectory**
(`/tree/main/relay/worker`); the build resolves the `../../core/*` and
`../access` imports from the cloned tree.

> **Fail-closed by default.** `wrangler.toml` sets `REQUIRE_ACCESS = "1"`, so a
> freshly button-deployed relay **denies all traffic** (403) until you configure
> Access — it is never silently public. Complete the checklist below to bring it
> online. (Set `REQUIRE_ACCESS = "0"` only for a deliberately public/dev relay.)

**Post-deploy checklist (required):**

1. **Service tokens** — `wrangler secret put VAULT_RELAY_TOKENS` (or in the
   dashboard: Worker → Settings → Variables) with a comma-separated list of
   per-device tokens. _This alone_ lifts fail-closed and gates the relay.
2. _(Recommended)_ **Cloudflare Access app** over the Worker route/hostname, then
   `wrangler secret put CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` for in-Worker
   JWT verification (defense in depth).
3. **Verify:** `curl https://<your-worker>.workers.dev/health` → `{"ok":true}`;
   a `/sync` without a valid token must return **403** until step 1 is done.
4. Hand the Worker URL + each device's credential to clients, then
   `vault sync --relay <url> --relay-token <tok>` (app-layer) — or, if you front
   the Worker with an Access app, `--access-id <id> --access-secret <s>`. See
   "Authenticating clients" below for the full table and dashboard steps.

### Manual deploy (Wrangler CLI)

**Prereqs:** a Cloudflare account and `wrangler` (build-time only, like esbuild
for the binary): `npm i -g wrangler` or `npx wrangler`.

```bash
cd relay/worker

# 1. Auth + (optional) local run with an ephemeral DO SQLite:
wrangler login
wrangler dev                      # http://localhost:8787 ; try /health

# 2. Configure the Access gate as SECRETS (never in wrangler.toml):
wrangler secret put VAULT_RELAY_TOKENS       # comma-separated per-device tokens
wrangler secret put CF_ACCESS_TEAM_DOMAIN    # e.g. myteam.cloudflareaccess.com
wrangler secret put CF_ACCESS_AUD            # Access application audience tag

# 3. Deploy (creates the DO migration on first deploy):
wrangler deploy                   # -> https://vault-relay.<subdomain>.workers.dev

# 4. (optional) Bind a custom hostname via a route in wrangler.toml or the dash.
```

Then point clients at the Worker URL exactly as in Path A:

```bash
vault sync --relay https://vault-relay.<subdomain>.workers.dev --token <service-token>
```

**Notes specific to Path B**

- **Per-vault sharding.** The Worker reads `teamId` from each request body and
  routes to `RELAY_DO.idFromName(teamId)` — so each vault gets its own isolated
  DO + SQLite, matching the §6 "DO-per-vault stripped of authority" model.
- **Crypto via `nodejs_compat`.** The worker reuses the Node relay's exact crypto
  paths — `relay/access.verifyAccessJwt` (`createPublicKey` + `verify` for the
  Access JWT) and `core/protocol.verifyEnvelope` / `core/authlog.entryHash` (the
  cheap op/entry hashing) — through Wrangler's `node:crypto` polyfill. The worker
  needs **only** `node:crypto` (not `node:http`/`node:sqlite`, which are absent);
  storage is the Durable Object's built-in SQLite. Signatures are still **only**
  verified by clients against the auth log — the relay never does, on either path.
  > Workers' `node:crypto` public-key coverage tracks `compatibility_date`, so
  > **smoke-test the JWT check on `wrangler dev`** before relying on it; if a date
  > bump ever regresses `createPublicKey`, swap `relay/access` for a small
  > `crypto.subtle` shim in the worker (the interface is unchanged).
- **Front with Cloudflare Access** the same way (an Access app over the Worker
  route/hostname); the `CF_ACCESS_*` secrets enable in-Worker JWT verification as
  defense in depth.
- **Still zero runtime deps.** The worker imports only project source + the
  `nodejs_compat` polyfill + the DO's built-in SQLite; Wrangler is build-time.
  `npm run check:deps` stays green (the worker ships no `package.json`).

> Switching paths later needs **no client change** — same protocol. Histories do
> not auto-migrate between a Node DB and DO storage, so cut over when convenient
> (devices simply re-converge through whichever relay they're pointed at).

## Authenticating clients — two independent token mechanisms

The relay accepts **two** credential types; they compose and serve different
layers. Pick whichever fits, or use both (defense in depth):

|                  | App-layer token                           | Cloudflare Access service token                                                           |
| ---------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------- |
| Config (relay)   | `VAULT_RELAY_TOKENS=tok1,tok2`            | `CF_ACCESS_TEAM_DOMAIN` + `CF_ACCESS_AUD`                                                 |
| CLI sends header | `cf-access-token`                         | `CF-Access-Client-Id` + `CF-Access-Client-Secret`                                         |
| Enforced         | inside the relay (`authorizeHeaders`)     | at the **edge** by Cloudflare, then re-verified in-relay (JWT)                            |
| CLI flags        | `--relay-token` (env `VAULT_RELAY_TOKEN`) | `--access-id` / `--access-secret` (env `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`) |

> If you put a Cloudflare **Access application** in front of the relay, you MUST
> use a service token (`--access-id/--access-secret`) — the edge blocks anything
> without it _before_ your relay's app-layer token is ever seen. Use the
> app-layer token alone only when there is no Access app (e.g. Path A behind a
> Tunnel with just `VAULT_RELAY_TOKENS`, or local/dev).

### Cloudflare dashboard: configure Access (service tokens)

All under **Zero Trust** (`one.dash.cloudflare.com` → your account → Zero Trust):

1. **Team domain** → _Settings → Custom Pages_ (or _Settings → General_): note
   `https://<team>.cloudflareaccess.com`. The host part is your
   `CF_ACCESS_TEAM_DOMAIN` (e.g. `myteam.cloudflareaccess.com`).
2. **Access application** → _Access → Applications → Add an application →
   Self-hosted_.
   - **Application domain:** the relay's public hostname — your Worker route /
     custom hostname (Path B) or your `cloudflared` hostname (Path A).
   - Save, open the app, and copy its **Application Audience (AUD) Tag**
     (Overview tab) → this is `CF_ACCESS_AUD`.
3. **Service token (per device)** → _Access → Service Auth → Service Tokens →
   Create Service Token_. Name it (e.g. `vault-laptop`). Copy the **Client ID**
   (`<uuid>.access`) and **Client Secret** — shown **once**.
4. **Policy that allows the token** → in the application, _Policies → Add a
   policy_ → **Action: Service Auth**, **Include → Service Token →** your
   token(s). Without an allowing policy a valid token is still denied.
5. **Tell the relay the AUD/team** (so it re-verifies the injected JWT):
   - Path B: `wrangler secret put CF_ACCESS_TEAM_DOMAIN` and
     `wrangler secret put CF_ACCESS_AUD`.
   - Path A: set `CF_ACCESS_TEAM_DOMAIN` / `CF_ACCESS_AUD` in the systemd unit.

### CLI: authenticate with the relay

```bash
# Cloudflare Access service token (when an Access app fronts the relay):
vault sync --relay https://<relay-host> \
  --access-id <uuid>.access --access-secret <client-secret>

# Or via env (e.g. in scripts / the systemd-managed device):
export CF_ACCESS_CLIENT_ID=<uuid>.access
export CF_ACCESS_CLIENT_SECRET=<client-secret>
vault sync --relay https://<relay-host>

# App-layer token (no Access app), or BOTH together:
vault sync --relay https://<relay-host> --relay-token <tok>
vault sync --relay https://<relay-host> \
  --relay-token <tok> --access-id <uuid>.access --access-secret <secret>
```

How it authenticates end-to-end with Access: the CLI sends
`CF-Access-Client-Id`/`CF-Access-Client-Secret`; Cloudflare validates them at the
edge and injects a signed `Cf-Access-Jwt-Assertion`; the relay's
`verifyAccessJwt` checks that JWT's signature (Cloudflare JWKS), audience
(`CF_ACCESS_AUD`), issuer, and expiry before serving the request.

## Enrollment ↔ relay

`device-add` / `share` embed the relay **hostname** (and the non-secret Access
`accessId`) in Token B / the Join Token (spec §9). On confirm, the new device
persists those for convenience — but **bearer secrets are never persisted**: the
local `meta` table is plaintext, so the app-layer `token` and the Access
`accessSecret` must be supplied at sync time and are not written to disk. The new
device runs:

```bash
vault sync --relay <url> --access-id <id> --access-secret <secret>   # Access
vault sync --relay <url> --relay-token <token>                       # app-layer
```

with the URL (and accessId) defaulting from enrollment, so only the secret need
be provided (flag or `CF_ACCESS_CLIENT_SECRET` / `VAULT_RELAY_TOKEN` env).

## Revocation (spec §8.5, §10.3)

- **Network:** revoke the device's Access service token / client cert → instant
  reachability cutoff.
- **Crypto:** `vault device-remove --user <id>` appends a signed removal and
  issues a conflict-free epoch rotation so the removed party cannot read _new_
  data. Remember the non-cryptographic obligation: **rotate the actual
  credentials** of anything a compromised device held (spec §10).

## Process supervision & health (Path A)

`vault-relay.service` keeps the Node relay alive with three layers:

- **Crashes** → `Restart=on-failure` + `RestartSec=2` restart on non-zero exit;
  `StartLimitIntervalSec=300` / `StartLimitBurst=5` stop a crash-loop after 5
  failures in 5 min (clear with `systemctl reset-failed vault-relay`).
- **Hangs** → `Type=notify` + `WatchdogSec=30`. The relay calls
  `systemd-notify READY=1` once listening and pings `WATCHDOG=1` from the event
  loop every ~½·WatchdogSec. If the loop **stalls** (a hang, which the crash-only
  restart can't catch), the pings stop and systemd kills + restarts it. This
  needs the `systemd-notify` helper (ships with systemd) on `PATH`. Everything is
  gated on `NOTIFY_SOCKET`, so off-systemd (dev, tests, the CLI's bundled relay)
  it is a complete no-op — no extra dependency.
- **Leaks** → `MemoryHigh=192M` / `MemoryMax=256M` recycle the process instead of
  degrading the host (tune to your box; credential volume is tiny).

**Dependency-free alternative to the watchdog.** If you'd rather not rely on
`systemd-notify`, install `vault-relay-health.{service,timer}` instead: a timer
curls `/health` every 30s and `systemctl restart vault-relay` on failure. It
catches the same hangs without `Type=notify` (keep the unit `Type=simple` if you
go this route).

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now vault-relay-health.timer
```

The relay is store-and-forward and idempotent, so a restart only delays
propagation — clients re-converge on the next `sync`; no data is lost.

## Compaction (low priority)

Credential write volume is tiny; periodic CRDT op-log snapshotting keeps storage
bounded if ever needed. Not implemented in v1.
