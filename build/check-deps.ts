// CI guard for the hard zero-runtime-dependency rule (plan §2): fail if any
// package.json declares non-empty "dependencies". Build/dev deps are allowed.
// Run via Node's type stripping: `node build/check-deps.ts`.

import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";

type Offender = { path: string; deps: string[] };

const found: Offender[] = [];

const scan = async (dir: string): Promise<void> => {
	for (const name of await readdir(dir)) {
		if (name === "node_modules" || name === ".git" || name === "dist") continue;
		const p = join(dir, name);
		if ((await stat(p)).isDirectory()) await scan(p);
		else if (name === "package.json") {
			const pkg = JSON.parse(await readFile(p, "utf8")) as {
				dependencies?: Record<string, string>;
			};
			const deps = Object.keys(pkg.dependencies ?? {});
			if (deps.length > 0) found.push({ path: p, deps });
		}
	}
};

await scan(".");

if (found.length > 0) {
	console.error("ZERO-DEP RULE VIOLATED — runtime dependencies declared:");
	for (const f of found) console.error(`  ${f.path}: ${f.deps.join(", ")}`);
	process.exit(1);
}
console.log("ok: no runtime dependencies declared");
