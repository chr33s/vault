// Where the TPM2 command bytes go. A connection is STATEFUL: transient object
// handles (the primary, the loaded object) live only while the connection is open
// — the kernel resource manager flushes them on close — so seal()/open() run their
// whole CreatePrimary→…→Flush sequence on one connection.
//
//   - devTpmrm0Transport: production. The Linux kernel resource-managed TPM device
//     (/dev/tpmrm0) via node:fs — write a command, read its response. Pure Node,
//     no extra dependency.
//   - socketTransport: a TCP TPM command channel (the swtpm emulator, or a remote
//     TPM). Used to validate the codec against a real TPM2 implementation in tests,
//     and usable in production against a socket TPM.

import { spawn } from "node:child_process";
import { access, open as fsOpen } from "node:fs/promises";
import { connect, type Socket } from "node:net";
import { platform } from "node:os";

export type TpmConn = {
	submit(cmd: Buffer): Promise<Buffer>;
	close(): Promise<void>;
};

export type Transport = {
	available(): Promise<boolean>;
	open(): Promise<TpmConn>;
};

const DEV = "/dev/tpmrm0";

export const devTpmrm0Transport: Transport = {
	async available(): Promise<boolean> {
		if (platform() !== "linux") return false;
		try {
			await access(DEV);
			return true;
		} catch {
			return false;
		}
	},
	async open(): Promise<TpmConn> {
		const fh = await fsOpen(DEV, "r+");
		return {
			async submit(cmd: Buffer): Promise<Buffer> {
				await fh.write(cmd, 0, cmd.length);
				// The char device returns exactly one response per read.
				const buf = Buffer.alloc(8192);
				const { bytesRead } = await fh.read(buf, 0, buf.length, null);
				return buf.subarray(0, bytesRead);
			},
			async close(): Promise<void> {
				await fh.close();
			},
		};
	},
};

// A TCP TPM command channel. Responses are self-describing (UINT32 size at byte
// offset 2), so we frame by accumulating until a full response is buffered.
export const socketTransport = (port: number, host = "127.0.0.1"): Transport => {
	const dial = (): Promise<Socket> =>
		new Promise<Socket>((resolve, reject) => {
			const s = connect(port, host);
			s.once("connect", () => resolve(s));
			s.once("error", reject);
		});
	return {
		async available(): Promise<boolean> {
			try {
				(await dial()).destroy();
				return true;
			} catch {
				return false;
			}
		},
		async open(): Promise<TpmConn> {
			const sock = await dial();
			let buf = Buffer.alloc(0);
			let waiter: ((r: Buffer) => void) | undefined;
			const feed = (): void => {
				if (!waiter || buf.length < 6) return;
				const size = buf.readUInt32BE(2);
				if (buf.length < size) return;
				const resp = buf.subarray(0, size);
				buf = buf.subarray(size);
				const w = waiter;
				waiter = undefined;
				w(Buffer.from(resp));
			};
			sock.on("data", (d: Buffer) => {
				buf = Buffer.concat([buf, d]);
				feed();
			});
			return {
				submit(cmd: Buffer): Promise<Buffer> {
					return new Promise<Buffer>((resolve, reject) => {
						if (waiter) {
							reject(new Error("tpm socket: a request is already in flight"));
							return;
						}
						waiter = resolve;
						sock.write(cmd);
						feed();
					});
				},
				close(): Promise<void> {
					return new Promise<void>((resolve) => {
						sock.end(() => resolve());
					});
				},
			};
		},
	};
};

// ---- Windows TBS transport ----
//
// Windows has no /dev/tpmrm0; raw TPM2 commands go through the TPM Base Services
// C API (Tbsip_Submit_Command in tbs.dll), reached here via a PERSISTENT PowerShell
// process that holds one TBS context and speaks a base64 line protocol (one command
// per line in, one response per line out). The context must persist for the whole
// connection so transient handles survive the CreatePrimary..Unseal sequence — the
// same reason the dev/socket transports keep one fd/socket open.
//
// VALIDATION BOUNDARY: the persistent-process line framing below is exercised on
// Linux (the test points `command`/`args` at a stub that forwards the same base64
// lines to swtpm), so the transport + the whole TPM2 codec are validated. Only the
// PowerShell script body — the actual tbs.dll P/Invoke — is Windows-only and
// UNTESTED here. The TBS_CONTEXT_PARAMS2 flags / submit signature follow the
// documented API and should be verified on a real Windows host before relying on it.

const PS_TBS = `$ErrorActionPreference='Stop'
Add-Type -Namespace Vlt -Name Tbs -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct P2 { public uint version; public uint flags; }
[DllImport("tbs.dll")] public static extern uint Tbsi_Context_Create(ref P2 p, out System.IntPtr h);
[DllImport("tbs.dll")] public static extern uint Tbsip_Submit_Command(System.IntPtr h, uint loc, uint pri, byte[] cmd, uint cmdLen, byte[] res, ref uint resLen);
'@
$p = New-Object Vlt.Tbs+P2; $p.version = 2; $p.flags = 4  # TBS_CONTEXT_VERSION_TWO, includeTpm20
$h = [System.IntPtr]::Zero
[void][Vlt.Tbs]::Tbsi_Context_Create([ref]$p, [ref]$h)
while (($line = [Console]::In.ReadLine()) -ne $null) {
  if ($line.Length -eq 0) { continue }
  $cmd = [Convert]::FromBase64String($line)
  $res = New-Object byte[] 4096
  $rl = [uint32]$res.Length
  [void][Vlt.Tbs]::Tbsip_Submit_Command($h, 0, 200, $cmd, [uint32]$cmd.Length, $res, [ref]$rl)
  [Console]::Out.WriteLine([Convert]::ToBase64String($res, 0, $rl))
}`;

export type TbsOptions = { command?: string; args?: string[] }; // injectable for tests

export const tbsTransport = (opts: TbsOptions = {}): Transport => {
	const command = opts.command ?? "powershell.exe";
	const args = opts.args ?? ["-NoProfile", "-NonInteractive", "-Command", PS_TBS];
	return {
		async available(): Promise<boolean> {
			return opts.command !== undefined || platform() === "win32";
		},
		async open(): Promise<TpmConn> {
			const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
			const waiters: Array<(line: string) => void> = [];
			let buf = "";
			child.stdout.on("data", (d: Buffer) => {
				buf += d.toString("utf8");
				let i: number;
				while ((i = buf.indexOf("\n")) >= 0) {
					const line = buf.slice(0, i);
					buf = buf.slice(i + 1);
					waiters.shift()?.(line);
				}
			});
			return {
				submit(cmd: Buffer): Promise<Buffer> {
					return new Promise<Buffer>((resolve) => {
						waiters.push((line) => resolve(Buffer.from(line.trim(), "base64")));
						child.stdin.write(`${cmd.toString("base64")}\n`);
					});
				},
				close(): Promise<void> {
					return new Promise<void>((resolve) => {
						child.once("close", () => resolve());
						child.stdin.end();
					});
				},
			};
		},
	};
};
