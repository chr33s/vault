// Minimal dotenv parser (plan §5). ~30 lines, no `dotenv` package. Treats a
// .env file as a *manifest of required variables*: bare/empty keys are markers
// to resolve from the vault; non-empty values pass straight through.

export type EnvDecl = {
	key: string;
	// undefined  -> bare `KEY`            (resolve from vault by name)
	// ""         -> `KEY=`                (resolve from vault by name)
	// "vault://" -> explicit reference    (resolve that entry)
	// other      -> literal value         (pass through verbatim)
	value: string | undefined;
};

const LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(=(.*))?\s*$/;

const unquote = (raw: string): string => {
	const v = raw.trim();
	if (v.length >= 2 && ((v[0] === '"' && v.at(-1) === '"') || (v[0] === "'" && v.at(-1) === "'"))) {
		return v.slice(1, -1);
	}
	return v;
};

export const parseDotenv = (text: string): EnvDecl[] => {
	const decls: EnvDecl[] = [];
	for (const rawLine of text.split(/\r?\n/)) {
		const line = rawLine.replace(/\s+#.*$/, ""); // strip trailing comments
		if (!line.trim() || line.trim().startsWith("#")) continue;
		const m = LINE.exec(line);
		if (!m) continue;
		const key = m[1]!;
		if (m[2] === undefined) {
			decls.push({ key, value: undefined }); // bare KEY
		} else {
			const v = unquote(m[3] ?? "");
			decls.push({ key, value: v === "" ? "" : v });
		}
	}
	return decls;
};

// A vault:// reference: vault://<vault>/<item>[/<field>]
export type VaultRef = { vault: string; item: string; field?: string };

export const parseVaultRef = (value: string): VaultRef | undefined => {
	if (!value.startsWith("vault://")) return undefined;
	const rest = value.slice("vault://".length);
	const parts = rest.split("/").filter((p) => p.length > 0);
	if (parts.length < 2) return undefined;
	return { vault: parts[0]!, item: parts[1]!, field: parts[2] };
};
