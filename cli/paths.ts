// OS config-dir resolution for local state (plan §5). Honors VAULT_HOME for
// tests and explicit overrides, then XDG_CONFIG_HOME, then platform defaults.

import { mkdir, readdir, chmod } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { join } from "node:path";

export const configDir = (): string => {
	const override = process.env.VAULT_HOME;
	if (override) return override;
	const xdg = process.env.XDG_CONFIG_HOME;
	if (xdg) return join(xdg, "vault");
	if (platform() === "darwin") {
		return join(homedir(), "Library", "Application Support", "vault");
	}
	if (platform() === "win32") {
		return join(process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "vault");
	}
	return join(homedir(), ".config", "vault");
};

// A user may belong to many vaults (spec §1); each is an independent local
// replica under <config>/vaults/<name>.db. The personal vault is the default.
export const DEFAULT_VAULT = "personal";

// Restrict our config tree to the owner: it holds the encrypted replica, the
// keystore blobs, and cleartext membership/relay metadata. Default umask leaves
// new dirs world-readable/traversable, so on a multi-user host another user could
// copy the vault db for an offline dictionary attack (passphrase-only vaults have
// no second factor) and read the plaintext meta/authlog tables. chmod after
// mkdir because `mode:` is masked by umask and recursive-created parents are not
// re-moded. Best-effort: chmod is a no-op / may throw on Windows and non-owned
// dirs, which must not break the CLI.
const ensureDir700 = async (dir: string): Promise<void> => {
	await mkdir(dir, { recursive: true, mode: 0o700 });
	await chmod(dir, 0o700).catch(() => {});
};

const vaultsDir = async (): Promise<string> => {
	const cfg = configDir();
	await ensureDir700(cfg);
	const dir = join(cfg, "vaults");
	await ensureDir700(dir);
	return dir;
};

const safeName = (name: string): string => {
	if (!/^[A-Za-z0-9._-]+$/.test(name)) throw new Error(`invalid vault name: ${name}`);
	return name;
};

export const dbPath = async (name: string = DEFAULT_VAULT): Promise<string> =>
	join(await vaultsDir(), `${safeName(name)}.db`);

// Names of vaults that exist locally (db files present).
export const listVaultNames = async (): Promise<string[]> =>
	(await readdir(await vaultsDir()))
		.filter((f) => f.endsWith(".db"))
		.map((f) => f.slice(0, -3))
		.sort();
