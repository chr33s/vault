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

// Keys are env-var names for `run`, but `vault proxy` reuses this same parser
// for its policy manifest (plan §5), where a key may be an HTTP header name
// (hyphens, e.g. `x-api-key`) or a query-param marker (a leading `?`). The
// broader charset is backward-compatible: real env-var names never contain
// `-`/`?`, so `run`'s behavior is unchanged.
const LINE = /^\s*(?:export\s+)?(\??[A-Za-z_][A-Za-z0-9_.-]*)\s*(=(.*))?\s*$/;

// Strip a trailing ` #…` comment, but not a `#` inside a quoted value
// (`"p@ss # w0rd"`) — a naive /\s+#/ would clip the inner `#`. A `#` opens a
// comment only at line start or after whitespace; a quote protects a span only
// when value-leading (line start, or after `=`/whitespace) AND closed (a lone
// `it's` is not a span).
const stripComment = (s: string): string => {
	let i = 0;
	while (i < s.length) {
		const ch = s[i]!;
		const prev = i === 0 ? "" : s[i - 1]!;
		const valueLeading = i === 0 || prev === "=" || /\s/.test(prev);
		if ((ch === "'" || ch === '"') && valueLeading) {
			const close = s.indexOf(ch, i + 1);
			if (close !== -1) {
				i = close + 1; // skip the whole quoted span (any `#` within is literal)
				continue;
			}
			// no closing quote: fall through and treat this char as ordinary text
		}
		if (ch === "#" && (i === 0 || /\s/.test(prev))) return s.slice(0, i);
		i++;
	}
	return s;
};

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
		const line = stripComment(rawLine); // strip trailing comments (quote-aware)
		if (!line.trim()) continue;
		const m = LINE.exec(line);
		// A non-empty, non-comment line that isn't a valid declaration (e.g. an
		// invalid key like `2FA_TOKEN=`) must fail loudly: silently dropping it would
		// bypass `run`'s "unresolved variables" guard and spawn the child missing a
		// var the manifest declared.
		if (!m) throw new Error(`malformed .env line: ${line.trim()}`);
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
