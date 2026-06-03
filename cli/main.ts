// Vault CLI entrypoint (plan §5). Arg parsing via node:util parseArgs — no
// commander/yargs. Runs directly under Node's type stripping
// (`node cli/main.ts <cmd>`); shipped as a single SEA binary (plan §7).

import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { Store } from "../core/store.ts";
import {
	init,
	unlock,
	isInitialized,
	addItem,
	editItem,
	removeItem,
	getItem,
	listItems,
	rotate,
	removeUser,
	removeDevice,
	maybeCatchUp,
	savedRelay,
	authNewDevice,
	deviceAdd,
	deviceConfirm,
	inviteInit,
	shareVault,
	joinConfirm,
	recoveryEnable,
	recoverUser,
	setKeystore,
	keystoreStatus,
	type Session,
	type TokenA,
	type TokenB,
	type InviteToken,
	type JoinToken,
	type RelayInfo,
} from "./engine.ts";
import { defaultKeyStore, keyStoreByName, systemdCredsKeyMode, type KeyStore } from "./keystore.ts";
import { setJsonOutput, emit, emitError } from "./output.ts";
import { dbPath, listVaultNames, DEFAULT_VAULT } from "./paths.ts";
import { createPeerServer } from "./peerserver.ts";
import { readPassphrase, setPassphraseSource, closePassphraseSource } from "./prompt.ts";
import { proxy as proxyCmd, DEFAULT_PROXY_PORT } from "./proxy.ts";
import { syncWithRelay, type RelayAuth } from "./relayclient.ts";
import { run as runCmd } from "./run.ts";
import { syncTailnet, tailscaleStatus, DEFAULT_PEER_PORT } from "./tailnet.ts";

const VERSION = "0.1.0";

const HELP = `vault ${VERSION} — end-to-end encrypted, local-first credential vault

Usage: vault <command> [options]

Vault & items
  init [--keychain] [--with-key host|tpm2|auto]
                               Create a vault + personal keys; bootstrap the auth log
                               (--keychain folds in an OS keystore; --with-key picks
                               the Linux systemd-creds binding)
  add <title> [--field k=v ...] [--password]   Add an item (password read from prompt)
  get <title> [--field name]   Show an item (or one field)
  list                         List item titles
  edit <title> --field k=v...  Update fields
  rm <title>                   Delete (tombstone) an item

Sync
  sync --relay <url> [--relay-token <t>] [--access-id <id> --access-secret <s>]
       [--tailnet] [--tailnet-only] [--port <n>] [--peer-token <t>]
                               Anti-entropy round with the relay. --relay-token is
                               the app-layer token; --access-id/--access-secret is
                               a Cloudflare Access service token (needed when an
                               Access app fronts the relay). Env fallbacks:
                               VAULT_RELAY_TOKEN, CF_ACCESS_CLIENT_ID,
                               CF_ACCESS_CLIENT_SECRET.
                               --tailnet also reconciles directly with online
                               Tailscale peers running 'vault serve' (§8.6 direct
                               fallback); --tailnet-only skips the hub (e.g. it's
                               down). --peer-token gates the peer servers (env:
                               VAULT_PEER_TOKEN); --port sets the peer port (env:
                               VAULT_PEER_PORT, default ${DEFAULT_PEER_PORT}).
                               Env: VAULT_TAILNET=1 enables the tailnet leg.
  serve [--host <ip>] [--port <n>] [--peer-token <t>]
                               Run an always-on replica peer for the direct tailnet
                               path (§8.6): serve this device's op-log to tailnet
                               peers so they can sync when the hub is unreachable.
                               No passphrase — holds no keys, runs while locked.
                               Binds to this device's Tailscale IP by default
                               (--host overrides). Without --peer-token it is open
                               to the whole tailnet.

Devices (token handshake)
  auth                         New device: generate keys, print Token A
  device-add --token <A> [--role member|admin] [--relay <url>] [--relay-token <t>]
                               Authorized device: seal grants, print Token B
  device-confirm --token <B>   New device: unseal vault key, build replica
  device-remove (--device <id> | --user <id>)   Revoke a device or a person, then rotate

Sharing with other people
  invite                       Joiner: generate a user identity, print Invite Token
  share --token <invite> [--role member|admin] [--relay <url>] [--relay-token <t>]
                               Admin: add the user, seal grants, print Join Token
  join --token <join>          Joiner: validate, add own device, build replica

Vaults & keys
  vaults                       List local vaults
  rotate                       Issue a new key epoch (conflict-free)
  keystore (status|enable|disable) [--with-key host|tpm2|auto]
                               OS-keychain second factor for at-rest keys.
                               --with-key picks the Linux systemd-creds binding
                               (host = machine-bound; tpm2/auto = TPM-bound); it
                               also applies to 'init --keychain'. Sugar over
                               $VAULT_SYSTEMD_CREDS_KEY; ignored off Linux.

Recovery escrow (per-vault policy, spec §5)
  recovery-enable              Owner: create the org escrow key; print the org private key
  recover --user <id> --org-key <k>   Owner: reconstruct a locked-out member's keys

Secrets into a command
  run [--env <file>] [--vault <name>] [--allow-missing] -- <cmd> [args...]
                               Resolve .env vars from the vault, inject, spawn
  proxy --config <file> [--config <file> ...] [--vault <name>] [--port <n>] [-- <cmd> [args...]]
                               Run a loopback credential-injecting proxy so an AI
                               agent USES a secret without SEEING it (spec §13).
                               The .env-format policy uses a reserved UPSTREAM=
                               line + header/?query lines (same vault:// refs as
                               run). With -- <cmd>, spawns the agent pointed at
                               the proxy (secret absent from its env); else runs
                               in the foreground. Port default ${DEFAULT_PROXY_PORT}.

Global: --vault <name> selects a vault (default "${DEFAULT_VAULT}"); --db <path> overrides the file.
  --json                       Emit one JSON object per command (machine contract for wrappers).
  --passphrase-stdin           Read each passphrase as a line from stdin (one secret per line)
                               instead of a TTY prompt — for GUI/native wrappers and automation.
Passphrase: prompted, or read from $VAULT_PASSPHRASE for non-interactive use.
`;

const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o), "utf8").toString("base64");
const unb64 = <T>(s: string): T => JSON.parse(Buffer.from(s, "base64").toString("utf8")) as T;

// Read a token from --token (inline base64) or --token-file.
const readToken = async <T>(values: Record<string, unknown>): Promise<T> => {
	if (typeof values.token === "string") return unb64<T>(values.token);
	if (typeof values["token-file"] === "string")
		return unb64<T>((await readFile(values["token-file"] as string, "utf8")).trim());
	throw new Error("provide --token <base64> or --token-file <path>");
};

const openStore = async (values: Record<string, unknown>): Promise<Store> =>
	new Store(
		typeof values.db === "string"
			? (values.db as string)
			: await dbPath(typeof values.vault === "string" ? (values.vault as string) : DEFAULT_VAULT),
	);

// Pick the keystore for UNLOCKING an existing vault: the exact provider it was
// sealed under (so the right DUK is fetched), not merely the strongest available.
// Passphrase-only vaults record no provider and unlock without a keystore.
const unlockKeyStore = async (store: Store): Promise<KeyStore | undefined> => {
	const provider = store.getMeta("keystoreProvider");
	// Pass the persisted binding (systemd-creds --with-key mode) so the keystore is
	// resolved in the same mode the DUK was sealed under, not the ambient default.
	return provider
		? await keyStoreByName(provider, store.getMeta("keystoreKeyMode") || undefined)
		: undefined;
};

const withSession = async (
	values: Record<string, unknown>,
	fn: (s: Session) => Promise<void> | void,
): Promise<void> => {
	const store = await openStore(values);
	try {
		if (!isInitialized(store)) throw new Error("vault not initialized; run `vault init`");
		const pass = await readPassphrase();
		const session = await unlock(store, pass, await unlockKeyStore(store));
		await fn(session);
	} finally {
		store.close();
	}
};

// Parse repeated --field k=v into a record.
const collectFields = (raw: string[] | undefined): Record<string, string> => {
	const out: Record<string, string> = {};
	for (const f of raw ?? []) {
		const eq = f.indexOf("=");
		if (eq < 0) throw new Error(`bad --field "${f}" (expected key=value)`);
		out[f.slice(0, eq)] = f.slice(eq + 1);
	}
	return out;
};

// Build relay credentials from flags, falling back to env. The app-layer token
// (--relay-token / VAULT_RELAY_TOKEN) and the Cloudflare Access service token
// (--access-id/--access-secret / CF_ACCESS_CLIENT_ID/CF_ACCESS_CLIENT_SECRET)
// are independent and may be combined.
const relayAuth = (values: Record<string, unknown>): RelayAuth => ({
	token: (values["relay-token"] as string | undefined) ?? process.env.VAULT_RELAY_TOKEN,
	accessId: (values["access-id"] as string | undefined) ?? process.env.CF_ACCESS_CLIENT_ID,
	accessSecret:
		(values["access-secret"] as string | undefined) ?? process.env.CF_ACCESS_CLIENT_SECRET,
});

// Build the RelayInfo embedded in Token B / the Join Token: the relay URL plus
// whatever credentials are supplied (app-layer token and/or Access service
// token). Returns undefined when no --relay is given. Reuses relayAuth's flag/
// env resolution so an enroller can pass creds once and ship them to the joiner.
const relayInfo = (values: Record<string, unknown>): RelayInfo | undefined => {
	const url = values.relay as string | undefined;
	if (!url) return undefined;
	const a = relayAuth(values);
	return { url, token: a.token, accessId: a.accessId, accessSecret: a.accessSecret };
};

const main = async (): Promise<number> => {
	const argv = process.argv.slice(2);

	// Bare help/version are handled before parsing — strict parseArgs would reject
	// `--help`/`-v` as unknown options. (Per-command help isn't offered.)
	const first = argv[0];
	if (!first || first === "help" || first === "--help" || first === "-h") {
		process.stdout.write(HELP);
		return 0;
	}
	if (first === "version" || first === "--version" || first === "-v") {
		process.stdout.write(`${VERSION}\n`);
		return 0;
	}

	// ONE strict parse for everything. parseArgs puts the command (and any
	// post-`--` child argv for `run`) into `positionals` regardless of where the
	// global flags appear, so `vault --json init` and `vault get gh --json` both
	// resolve correctly — no manual argv filtering, and `run`'s `--` boundary is
	// handled natively (tokens after `--` are positionals, never parsed as flags).
	const { values, positionals } = parseArgs({
		args: argv,
		allowPositionals: true,
		options: {
			// global
			json: { type: "boolean" },
			"passphrase-stdin": { type: "boolean" },
			db: { type: "string" },
			vault: { type: "string" },
			// per-command
			field: { type: "string", multiple: true },
			password: { type: "boolean" },
			name: { type: "string" },
			relay: { type: "string" },
			tailnet: { type: "boolean" }, // sync: also reconcile with direct tailnet peers
			"tailnet-only": { type: "boolean" }, // sync: skip the hub (e.g. hub is down)
			host: { type: "string" }, // serve: bind address (default: this device's tailnet IP)
			port: { type: "string" }, // serve/sync: peer-server port
			"peer-token": { type: "string" }, // serve/sync: shared token gating the peer server
			token: { type: "string" },
			"token-file": { type: "string" },
			"relay-token": { type: "string" },
			role: { type: "string" },
			user: { type: "string" },
			device: { type: "string" },
			"org-key": { type: "string" },
			keychain: { type: "boolean" },
			"with-key": { type: "string" }, // keystore/init: systemd-creds binding (host|tpm2|auto)
			"access-id": { type: "string" },
			"access-secret": { type: "string" },
			env: { type: "string" }, // run
			"allow-missing": { type: "boolean" }, // run
			config: { type: "string", multiple: true }, // proxy: policy file(s)
		},
	});

	if (values.json) setJsonOutput(true);
	if (values["passphrase-stdin"]) setPassphraseSource("stdin");
	// `--with-key <mode>` is sugar over $VAULT_SYSTEMD_CREDS_KEY: it selects the
	// systemd-creds binding used when a DUK is minted (`init --keychain`,
	// `keystore enable`). The systemd provider reads the env at seal time, and
	// systemd-creds decrypt auto-detects the mode, so it never needs persisting.
	if (typeof values["with-key"] === "string")
		process.env.VAULT_SYSTEMD_CREDS_KEY = values["with-key"];

	// positionals[0] is the command; `rest` are its sub-arguments (item title,
	// keystore subcommand, or — for `run` — the child command + its argv).
	const command = positionals[0]!;
	const rest = positionals.slice(1);

	switch (command) {
		case "init": {
			const store = await openStore(values);
			try {
				if (isInitialized(store)) throw new Error("vault already initialized");
				const pass = await readPassphrase("New passphrase: ");
				const ks = values.keychain ? await defaultKeyStore() : undefined;
				if (values.keychain && !ks)
					process.stderr.write("warning: no OS keystore available here; created passphrase-only\n");
				const r = await init(store, pass, ks);
				emit(`Initialized vault ${r.vaultId}\n  user:   ${r.userId}\n  device: ${r.deviceId}\n`, {
					vaultId: r.vaultId,
					userId: r.userId,
					deviceId: r.deviceId,
				});
			} finally {
				store.close();
			}
			return 0;
		}

		case "add":
			await withSession(values, (s) => {
				const title = rest[0];
				if (!title) throw new Error("usage: vault add <title> [--field k=v ...] [--password]");
				const fields = collectFields(values.field as string[] | undefined);
				return (async () => {
					if (values.password) fields.password = await readPassphrase("Item password: ");
					const id = addItem(s, title, fields);
					emit(`Added "${title}" (${id})\n`, { title, itemId: id });
				})();
			});
			return 0;

		case "get":
			await withSession(values, (s) => {
				const title = rest[0];
				if (!title) throw new Error("usage: vault get <title> [--field name]");
				const item = getItem(s, title);
				if (!item) throw new Error(`no item titled "${title}"`);
				const field = values.name as string | undefined;
				if (field) {
					const v = field === "password" ? item.passwords.join("\n") : item.fields[field];
					if (v === undefined) throw new Error(`no field "${field}"`);
					emit(`${v}\n`, { title, field, value: v });
				} else {
					let text = "";
					for (const [k, v] of Object.entries(item.fields)) text += `${k}: ${v}\n`;
					if (item.passwords.length === 1) text += `password: ${item.passwords[0]}\n`;
					else if (item.passwords.length > 1)
						text += `password: <${item.passwords.length} conflicting values: ${item.passwords.join(" | ")}>\n`;
					// JSON exposes the structured item (fields + the multi-value passwords).
					emit(text, {
						title,
						itemId: item.itemId,
						fields: item.fields,
						passwords: item.passwords,
					});
				}
			});
			return 0;

		case "list":
			await withSession(values, (s) => {
				const items = listItems(s);
				emit(items.map((i) => `${i.fields.title ?? i.itemId}\n`).join(""), {
					items: items.map((i) => ({ itemId: i.itemId, title: i.fields.title ?? null })),
				});
			});
			return 0;

		case "edit":
			await withSession(values, (s) => {
				const title = rest[0];
				if (!title) throw new Error("usage: vault edit <title> --field k=v ...");
				editItem(s, title, collectFields(values.field as string[] | undefined));
				emit(`Updated "${title}"\n`, { title });
			});
			return 0;

		case "rm":
			await withSession(values, (s) => {
				const title = rest[0];
				if (!title) throw new Error("usage: vault rm <title>");
				removeItem(s, title);
				emit(`Removed "${title}"\n`, { title });
			});
			return 0;

		case "sync":
			await withSession(values, async (s) => {
				// Two transports for the one op-log (spec §8.6): the always-on Cloudflare
				// hub (primary) and the direct tailnet path (fallback). --tailnet adds the
				// peers alongside the hub; --tailnet-only skips the hub (e.g. it's down).
				const tailnetOnly = !!values["tailnet-only"];
				const useTailnet = tailnetOnly || !!values.tailnet || process.env.VAULT_TAILNET === "1";

				// Fall back to the relay coordinates saved at enrollment (Token B / Join
				// Token). Explicit flags/env override the saved URL and each credential.
				const saved = savedRelay(s.store);
				const relay = (values.relay as string | undefined) ?? saved?.url;
				if (!relay && !useTailnet)
					throw new Error(
						"usage: vault sync --relay <url> [--relay-token <t>] [--access-id <id> --access-secret <s>] [--tailnet]\n" +
							"(no relay saved from enrollment; pass --relay or --tailnet)",
					);
				const flags = relayAuth(values);
				const auth = {
					token: flags.token ?? saved?.token,
					accessId: flags.accessId ?? saved?.accessId,
					accessSecret: flags.accessSecret ?? saved?.accessSecret,
				};

				let pulled = 0;
				let pushed = 0;
				const notes: string[] = [];

				// Hub leg (unless tailnet-only). A hub failure is fatal only when the
				// tailnet fallback isn't also running — otherwise it's the very outage
				// §8.6 exists to ride out, so we note it and continue to the peers.
				if (!tailnetOnly && relay) {
					try {
						const stats = await syncWithRelay(s, relay, auth);
						pulled += stats.pulled;
						pushed += stats.pushed;
						notes.push(`relay: pulled ${stats.pulled}, pushed ${stats.pushed}`);
					} catch (err) {
						if (!useTailnet) throw err;
						notes.push(`relay: failed (${err instanceof Error ? err.message : String(err)})`);
					}
				}

				// Tailnet leg. Discovery (shelling to `tailscale`) failing is fatal only
				// for a tailnet-only sync; otherwise the hub already carried the round.
				if (useTailnet) {
					const port = Number(values.port ?? process.env.VAULT_PEER_PORT ?? DEFAULT_PEER_PORT);
					const peerToken =
						(values["peer-token"] as string | undefined) ?? process.env.VAULT_PEER_TOKEN;
					try {
						const r = await syncTailnet(s, { port, auth: { token: peerToken } });
						pulled += r.pulled;
						pushed += r.pushed;
						let note = `tailnet: reached ${r.reached.length} peer(s)`;
						if (r.failed.length) note += `, ${r.failed.length} unreachable`;
						notes.push(note);
					} catch (err) {
						if (tailnetOnly) throw err;
						notes.push(`tailnet: failed (${err instanceof Error ? err.message : String(err)})`);
					}
				}

				const epoch = maybeCatchUp(s);
				let text = `Synced: pulled ${pulled}, pushed ${pushed}\n`;
				for (const n of notes) text += `  ${n}\n`;
				if (epoch) text += `Issued security catch-up rotation -> epoch ${epoch}\n`;
				emit(text, { pulled, pushed, catchUpEpoch: epoch ?? null, notes });
			});
			return 0;

		case "serve": {
			// Always-on direct-path replica (spec §8.6): expose this device's op-log
			// over the tailnet so a peer can sync when the hub is unreachable. No
			// passphrase — it's a dumb store-and-forward replica that holds no keys and
			// runs while the vault is locked (ops stay end-to-end encrypted).
			const store = await openStore(values);
			const vaultId = store.getMeta("vaultId");
			if (!vaultId) {
				store.close();
				throw new Error("vault not initialized; run `vault init`");
			}
			// The CLI and a long-lived peer server may open the same WAL db at once;
			// wait briefly for a concurrent writer instead of failing on SQLITE_BUSY.
			store.db.exec("PRAGMA busy_timeout = 5000;");
			const port = Number(values.port ?? process.env.VAULT_PEER_PORT ?? DEFAULT_PEER_PORT);
			const token = (values["peer-token"] as string | undefined) ?? process.env.VAULT_PEER_TOKEN;
			// Bind to this device's tailnet IP by default so the server is reachable
			// over the tailnet (the access gate, §7.3) and not the LAN/public iface.
			let host = values.host as string | undefined;
			if (!host) {
				const { selfIP } = await tailscaleStatus();
				if (!selfIP)
					throw new Error(
						"could not determine this device's Tailscale IP (is Tailscale up? pass --host to override)",
					);
				host = selfIP;
			}
			const server = createPeerServer(store, vaultId, { token });
			await new Promise<void>((resolve, reject) => {
				server.on("error", reject);
				server.listen(port, host, resolve);
			});
			emit(
				`vault peer server listening on ${host}:${port} (vault ${vaultId})\n` +
					(token ? "" : "warning: no --peer-token set; open to the whole tailnet\n"),
				{ host, port, vaultId, gated: !!token },
			);
			// Block until signalled, then close the server and store cleanly.
			await new Promise<void>((resolve) => {
				const shut = (): void => {
					server.close(() => {
						store.close();
						resolve();
					});
				};
				process.on("SIGINT", shut);
				process.on("SIGTERM", shut);
			});
			return 0;
		}

		case "rotate":
			await withSession(values, (s) => {
				const epoch = rotate(s);
				emit(`Rotated to epoch ${epoch}\n`, { epoch });
			});
			return 0;

		case "device-remove":
			await withSession(values, (s) => {
				const user = values.user as string | undefined;
				const device = values.device as string | undefined;
				if (device) {
					const epoch = removeDevice(s, device);
					emit(`Removed device ${device}; rotated to epoch ${epoch}\n`, {
						removedDevice: device,
						epoch,
					});
				} else if (user) {
					const epoch = removeUser(s, user);
					emit(`Removed user ${user}; rotated to epoch ${epoch}\n`, { removedUser: user, epoch });
				} else {
					throw new Error("usage: vault device-remove (--device <id> | --user <id>)");
				}
			});
			return 0;

		case "auth": {
			const store = await openStore(values);
			try {
				const pass = await readPassphrase("New passphrase for this device: ");
				const tokenA: TokenA = await authNewDevice(store, pass);
				emit(`Token A (show as QR / paste into 'device-add --token'):\n\n${b64(tokenA)}\n`, {
					tokenA: b64(tokenA),
					deviceId: tokenA.deviceId,
				});
			} finally {
				store.close();
			}
			return 0;
		}

		case "device-add":
			await withSession(values, async (s) => {
				const tokenA = await readToken<TokenA>(values);
				const tokenB: TokenB = deviceAdd(s, tokenA, {
					role: (values.role as TokenB["role"]) ?? undefined,
					relay: relayInfo(values),
				});
				emit(
					`Verify SAS matches the new device: ${tokenB.sas}\n\nToken B (show as QR / paste into 'device-confirm --token'):\n\n${b64(tokenB)}\n`,
					{ sas: tokenB.sas, tokenB: b64(tokenB) },
				);
			});
			return 0;

		case "device-confirm": {
			const store = await openStore(values);
			try {
				const tokenB = await readToken<TokenB>(values);
				const pass = await readPassphrase();
				const { sas } = await deviceConfirm(
					store,
					pass,
					tokenB,
					values.keychain ? await defaultKeyStore() : undefined,
				);
				emit(
					`Enrolled. Verify SAS matches the other device: ${sas}\nRun 'vault sync --relay <url>' to pull history.\n`,
					{ sas },
				);
			} finally {
				store.close();
			}
			return 0;
		}

		case "invite": {
			const store = await openStore(values);
			try {
				const pass = await readPassphrase("New passphrase for this device: ");
				const invite: InviteToken = await inviteInit(store, pass);
				emit(`Invite Token (give to a vault admin to run 'share --token'):\n\n${b64(invite)}\n`, {
					inviteToken: b64(invite),
					userId: invite.userId,
				});
			} finally {
				store.close();
			}
			return 0;
		}

		case "share":
			await withSession(values, async (s) => {
				const invite = await readToken<InviteToken>(values);
				const join: JoinToken = shareVault(s, invite, {
					role: (values.role as JoinToken["role"]) ?? undefined,
					relay: relayInfo(values),
				});
				emit(
					`Verify SAS matches the joiner: ${join.sas}\n\nJoin Token (give back to the joiner for 'join --token'):\n\n${b64(join)}\n`,
					{ sas: join.sas, joinToken: b64(join) },
				);
			});
			return 0;

		case "join": {
			const store = await openStore(values);
			try {
				const join = await readToken<JoinToken>(values);
				const pass = await readPassphrase();
				const { userId, sas } = await joinConfirm(
					store,
					pass,
					join,
					values.keychain ? await defaultKeyStore() : undefined,
				);
				emit(
					`Joined vault as user ${userId}. Verify SAS matches the admin: ${sas}\nRun 'vault sync --relay <url>' to publish your device and pull history.\n`,
					{ userId, sas },
				);
			} finally {
				store.close();
			}
			return 0;
		}

		case "vaults": {
			const names = await listVaultNames();
			emit(names.map((n) => `${n}\n`).join(""), { vaults: names });
			return 0;
		}

		case "recovery-enable":
			await withSession(values, (s) => {
				const orgPrivKey = recoveryEnable(s);
				emit(
					`Recovery escrow enabled for this vault.\n\n` +
						`ORG PRIVATE KEY (store offline; anyone holding it can recover members' keys):\n\n${orgPrivKey}\n\n` +
						`Members' identity keys are sealed to the org key on their next sync/enrollment.\n`,
					{ orgPrivateKey: orgPrivKey },
				);
			});
			return 0;

		case "recover":
			await withSession(values, (s) => {
				const user = values.user as string | undefined;
				const orgKey = values["org-key"] as string | undefined;
				if (!user || !orgKey)
					throw new Error("usage: vault recover --user <id> --org-key <base64>");
				const recovered = recoverUser(s, user, orgKey);
				emit(
					`Recovered identity keys for user ${user}:\n\n${recovered}\n\n` +
						`Deliver securely to the member so they can re-establish access.\n`,
					{ userId: user, recovered: JSON.parse(recovered) },
				);
			});
			return 0;

		case "keystore": {
			const sub = rest[0] ?? "status";
			const store = await openStore(values);
			try {
				if (sub === "status") {
					const st = keystoreStatus(store);
					const ks = await defaultKeyStore();
					// "this vault": how it's actually sealed (the persisted binding).
					// "platform keystore": the mode a NEW enable would use here (env default).
					const vaultLabel = !st.protected
						? "passphrase-only"
						: st.keyMode
							? `${st.provider} (--with-key=${st.keyMode})`
							: st.provider!;
					const platformMode = ks?.name === "systemd-creds" ? systemdCredsKeyMode() : undefined;
					const platformLabel = ks
						? platformMode
							? `${ks.name} (new enable: --with-key=${platformMode})`
							: ks.name
						: "none available";
					emit(`this vault: ${vaultLabel}\nplatform keystore: ${platformLabel}\n`, {
						protected: st.protected,
						provider: st.provider ?? null,
						keyMode: st.keyMode ?? null,
						platformKeystore: ks ? ks.name : null,
						...(platformMode ? { platformKeyMode: platformMode } : {}),
					});
				} else if (sub === "enable" || sub === "disable") {
					const pass = await readPassphrase();
					// Disable needs the CURRENT provider (to read+remove its DUK); enable on a
					// passphrase-only vault picks the strongest tier available. Resolve the
					// current provider in its persisted binding so the probe/get match it.
					const current = store.getMeta("keystoreProvider");
					const ks = current
						? await keyStoreByName(current, store.getMeta("keystoreKeyMode") || undefined)
						: await defaultKeyStore();
					// A non-host --with-key on Linux that ends up with no usable keystore is
					// almost always "that binding isn't available here" (e.g. tpm2 with no
					// TPM) rather than "no keystore at all" — say so, and suggest host.
					if (
						sub === "enable" &&
						!ks &&
						process.platform === "linux" &&
						typeof values["with-key"] === "string" &&
						values["with-key"] !== "host"
					)
						throw new Error(
							`no keystore available with --with-key=${values["with-key"]} ` +
								`(systemd-creds may lack that binding here, e.g. no TPM); try --with-key=host`,
						);
					const name = await setKeystore(store, pass, sub === "enable", ks);
					emit(`keystore ${sub}d -> ${name}\n`, { action: sub, provider: name });
				} else {
					throw new Error("usage: vault keystore (status | enable | disable)");
				}
			} finally {
				store.close();
			}
			return 0;
		}

		case "run": {
			// `rest` is everything after `run`. parseArgs already separated the child
			// command at the `--` boundary into positionals, so rest = [child, ...args]
			// (the run flags --env/--vault/--allow-missing were parsed into `values`).
			if (rest.length === 0)
				throw new Error(
					"usage: vault run [--env f] [--vault n] [--allow-missing] -- <cmd> [args...]",
				);
			const store = await openStore(values);
			try {
				if (!isInitialized(store)) throw new Error("vault not initialized; run `vault init`");
				const pass = await readPassphrase();
				const session = await unlock(store, pass, await unlockKeyStore(store));
				return await runCmd(
					session,
					{
						envFile: (values.env as string | undefined) ?? "./.env",
						defaultVault: (values.vault as string | undefined) ?? session.vaultId,
						allowMissing: !!values["allow-missing"],
					},
					rest[0]!,
					rest.slice(1),
				);
			} finally {
				store.close();
			}
		}

		case "proxy": {
			// `rest` is the optional child command + argv after `--`. The proxy
			// keeps secrets out of that child entirely (spec §13): it resolves them
			// from the local replica and injects on egress, never into the env.
			const configFiles = (values.config as string[] | undefined) ?? [];
			if (configFiles.length === 0)
				throw new Error(
					"usage: vault proxy --config <file> [--config <file> ...] [--port <n>] [-- <cmd> [args...]]",
				);
			const store = await openStore(values);
			try {
				if (!isInitialized(store)) throw new Error("vault not initialized; run `vault init`");
				const pass = await readPassphrase();
				const session = await unlock(store, pass, await unlockKeyStore(store));
				const port = Number(values.port ?? DEFAULT_PROXY_PORT);
				return await proxyCmd(session, { configFiles, port }, rest[0], rest.slice(1));
			} finally {
				store.close();
			}
		}

		default:
			process.stderr.write(`unknown command: ${command}\n\n${HELP}`);
			return 2;
	}
};

// Set process.exitCode and let the event loop drain rather than forcing
// process.exit(), which can abort on Windows if async handles are still being
// torn down (libuv UV_HANDLE_CLOSING assertion). With no keep-alive sockets
// (see relayclient) the loop drains promptly on its own.
main()
	.then((code) => {
		process.exitCode = code;
	})
	.catch((err) => {
		// In --json mode, errors are emitted as {"ok":false,"error":...} on stdout
		// so callers parse a single stream; otherwise to stderr as "error: ...".
		emitError(err instanceof Error ? err.message : String(err));
		process.exitCode = 1;
	})
	.finally(() => {
		// Release the stdin reader (no-op unless --passphrase-stdin opened it) so the
		// event loop can drain and the process exits cleanly.
		closePassphraseSource();
	});
