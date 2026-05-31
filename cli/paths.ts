// OS config-dir resolution for local state (plan §5). Honors VAULT_HOME for
// tests and explicit overrides, then XDG_CONFIG_HOME, then platform defaults.

import { mkdir, readdir } from "node:fs/promises";
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

const vaultsDir = async (): Promise<string> => {
	const dir = join(configDir(), "vaults");
	await mkdir(dir, { recursive: true });
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
