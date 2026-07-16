// Shared child-process driver for every keystore transport (DPAPI/systemd-creds/
// SE helper/Hello helper). Spawns `bin args`, writes `input` to stdin, collects
// stdout/stderr, and resolves {code, stdout, stderr} on close. It NEVER rejects
// on a non-zero exit (the code is returned for the caller to interpret) — only a
// spawn error rejects. Swallows stdin EPIPE, since a child may exit before
// draining stdin and the exit code is authoritative. Lives in its own module so
// keystore.ts and the provider modules it imports (hello.ts) share one copy.

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";

export type SpawnResult = { code: number; stdout: Buffer; stderr: Buffer };

// The flag list every PowerShell transport shares. Centralized so a hardening or
// correctness change to the invocation (e.g. a different -ExecutionPolicy, or
// switching to -EncodedCommand) lands in one place instead of drifting between
// the DPAPI and Hello tiers — which pick different interpreters (pwsh for
// off-Windows testing vs. powershell.exe for WinRT projection) but share flags.
export const powerShellArgs = (script: string): string[] => [
	"-NoProfile",
	"-NonInteractive",
	"-Command",
	script,
];

// A helper binary shipped as a sibling of the running executable (the SEA binary
// ships vault-helper / vault-hello-helper.exe beside itself). One place for the
// execPath→sibling resolution the secure-enclave and hello tiers both need, so a
// future change (e.g. resolving a symlinked execPath) can't fix only one.
export const siblingOfExecutable = (name: string): string => join(dirname(process.execPath), name);

export const spawnCollect = (
	bin: string,
	args: string[],
	opts: { input?: Buffer; env?: NodeJS.ProcessEnv } = {},
): Promise<SpawnResult> =>
	new Promise<SpawnResult>((resolve, reject) => {
		const child = spawn(bin, args, {
			stdio: ["pipe", "pipe", "pipe"],
			...(opts.env ? { env: opts.env } : {}),
		});
		const out: Buffer[] = [];
		const err: Buffer[] = [];
		child.stdout.on("data", (c: Buffer) => out.push(c));
		child.stderr.on("data", (c: Buffer) => err.push(c));
		child.on("error", reject);
		child.on("close", (code) =>
			// A signal-killed child reports code=null; map it to a NON-ZERO code so
			// every transport treats a kill (OOM, taskkill, session teardown) as a
			// failure. Mapping it to 0 would let a `put` interrupted mid-write report
			// success, persisting a truncated/absent blob and leaving the vault's
			// keystore meta pointing at a DUK that was never sealed (un-unlockable).
			resolve({ code: code ?? 1, stdout: Buffer.concat(out), stderr: Buffer.concat(err) }),
		);
		child.stdin.on("error", () => {}); // EPIPE if the child exited first; code is authoritative
		child.stdin.end(opts.input ?? Buffer.alloc(0));
	});
