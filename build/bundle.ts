// Bundle the CLI + core into a single CJS file for SEA injection (plan §7).
// The SEA-injected main can only load built-ins, so everything else must be
// bundled into one file. esbuild also strips types as a side effect.
//
// Build-time only — esbuild never ships inside the binary. Run via Node's type
// stripping: `node build/bundle.ts`.

import { build } from "esbuild";

await build({
	entryPoints: ["cli/main.ts"],
	bundle: true,
	platform: "node",
	format: "cjs", // simplest SEA target (open item: CJS vs ESM, CJS for v1)
	target: "node26",
	outfile: "dist/cli.cjs",
	external: ["node:*"], // keep built-ins external
	// Use an explicit config rather than reading the project tsconfig, whose
	// ES2025 `target` esbuild 0.24 doesn't recognize. Types are stripped anyway;
	// `useDefineForClassFields` matches Node's type-stripping class semantics.
	tsconfigRaw: { compilerOptions: { useDefineForClassFields: true } },
	banner: {
		// node:sqlite / type-strip flags are irrelevant to the bundled binary, but
		// keep the shebang-free CJS clean.
		js: "/* vault CLI bundle — generated; do not edit */",
	},
});

console.log("bundled -> dist/cli.cjs");
