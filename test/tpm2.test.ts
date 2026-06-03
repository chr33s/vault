import assert from "node:assert/strict";
import { execFile as execFileCb, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { makeBlobKeyStore } from "../cli/keystore.ts";
import { decodeBlob, encodeBlob, isAuthFailure, _internal } from "../cli/tpm2/codec.ts";
import { makeTpm2Cipher } from "../cli/tpm2/provider.ts";
import { socketTransport, tbsTransport, type Transport } from "../cli/tpm2/transport.ts";

const pexec = promisify(execFileCb);

// ---- codec marshaling (deterministic, no TPM required — runs everywhere) ----

test("codec.build frames tag/size/code and appends the body", () => {
	const cmd = _internal.build(_internal.ST_NO_SESSIONS, _internal.CC.SelfTest, Buffer.from([0x01]));
	assert.equal(cmd.readUInt16BE(0), 0x8001, "tag = TPM_ST_NO_SESSIONS");
	assert.equal(cmd.readUInt32BE(2), cmd.length, "commandSize is patched to the real length");
	assert.equal(cmd.readUInt32BE(6), 0x143, "commandCode = TPM2_CC_SelfTest");
	assert.equal(cmd[10], 0x01, "body follows the header");
});

test("codec.pwAuth builds a TPM_RS_PW authorization area carrying the auth value", () => {
	const area = _internal.pwAuth(Buffer.from("pin"));
	assert.equal(area.readUInt32BE(0), area.length - 4, "leading authorizationSize covers the rest");
	assert.equal(area.readUInt32BE(4), 0x40000009, "session handle = TPM_RS_PW");
	assert.equal(area.readUInt16BE(8), 0, "empty nonce");
	assert.equal(area[10], 0x01, "continueSession attribute");
	assert.equal(area.readUInt16BE(11), 3, "auth (TPM2B) length = len('pin')");
	assert.equal(area.subarray(13).toString(), "pin");
});

test("encodeBlob/decodeBlob round-trips the sealed {priv,pub}", () => {
	const priv = Buffer.from("private-blob-bytes");
	const pub = Buffer.from("public-area-bytes-longer");
	const back = decodeBlob(encodeBlob({ priv, pub }));
	assert.ok(back.priv.equals(priv));
	assert.ok(back.pub.equals(pub));
});

test("isAuthFailure recognizes AUTH_FAIL/LOCKOUT but not success or RETRY", () => {
	assert.equal(isAuthFailure(0x98e), true, "TPM_RC_AUTH_FAIL on session 1");
	assert.equal(isAuthFailure(0x08e), true, "TPM_RC_AUTH_FAIL (no session N)");
	assert.equal(isAuthFailure(0x921), true, "TPM_RC_LOCKOUT");
	assert.equal(isAuthFailure(0x000), false, "success");
	assert.equal(isAuthFailure(0x922), false, "TPM_RC_RETRY is not an auth failure");
});

// ---- integration against the swtpm TPM2 emulator (skips if swtpm absent) ----

const haveSwtpm = await pexec("swtpm", ["--version"]).then(
	() => true,
	() => false,
);
const swtpmSkip = haveSwtpm ? false : "swtpm not installed";

// Spawn a throwaway swtpm in socket mode and wait for it to accept connections.
const startSwtpm = async (): Promise<{ port: number; stop: () => Promise<void> }> => {
	const dir = await mkdtemp(join(tmpdir(), "swtpm-"));
	const port = 2400 + Math.floor(Math.random() * 400);
	const child = spawn(
		"swtpm",
		[
			"socket",
			"--tpm2",
			"--server",
			`type=tcp,port=${port}`,
			"--ctrl",
			`type=tcp,port=${port + 1}`,
			"--tpmstate",
			`dir=${dir}`,
			"--flags",
			"not-need-init,startup-clear",
		],
		{ stdio: "ignore" },
	);
	const t = socketTransport(port);
	for (let i = 0; i < 100; i++) {
		if (await t.available()) break;
		await new Promise((r) => setTimeout(r, 25));
	}
	return {
		port,
		stop: async () => {
			child.kill();
			await rm(dir, { recursive: true, force: true });
		},
	};
};

test("tpm2: seal/unseal round-trips through a real TPM2 (swtpm)", { skip: swtpmSkip }, async () => {
	const { port, stop } = await startSwtpm();
	try {
		const cipher = makeTpm2Cipher({
			transport: socketTransport(port),
			pin: () => Buffer.from("1234"),
			optIn: () => true,
		});
		assert.equal(await cipher.available(), true, "available when opted in + TPM reachable");

		const secret = Buffer.alloc(32, 0x07); // a 32-byte DUK
		const blob = await cipher.protect(secret);
		// A fresh connection (and a re-derived deterministic primary) must still open it.
		const back = await cipher.unprotect(blob);
		assert.ok(back.equals(secret), "DUK survives seal -> unseal across connections");
	} finally {
		await stop();
	}
});

test("tpm2: a wrong PIN is rejected (per-access auth)", { skip: swtpmSkip }, async () => {
	const { port, stop } = await startSwtpm();
	try {
		const seal = makeTpm2Cipher({
			transport: socketTransport(port),
			pin: () => Buffer.from("1234"),
			optIn: () => true,
		});
		const blob = await seal.protect(Buffer.alloc(32, 0x09));
		const wrong = makeTpm2Cipher({
			transport: socketTransport(port),
			pin: () => Buffer.from("0000"),
			optIn: () => true,
		});
		await assert.rejects(wrong.unprotect(blob), /TPM2 Unseal failed/);
	} finally {
		await stop();
	}
});

test(
	"tpm2: opt-out (no $VAULT_TPM2) reports unavailable even with a reachable TPM",
	{ skip: swtpmSkip },
	async () => {
		const { port, stop } = await startSwtpm();
		try {
			const cipher = makeTpm2Cipher({
				transport: socketTransport(port),
				pin: () => Buffer.alloc(0),
				optIn: () => false, // models $VAULT_TPM2 unset
			});
			assert.equal(await cipher.available(), false, "inert unless opted in");
		} finally {
			await stop();
		}
	},
);

// Wrap a transport to record every command sent and response received, so a test
// can assert what does (not) appear on the CPU↔TPM link.
const capturing = (inner: Transport): { transport: Transport; sent: Buffer[]; recv: Buffer[] } => {
	const sent: Buffer[] = [];
	const recv: Buffer[] = [];
	return {
		sent,
		recv,
		transport: {
			available: () => inner.available(),
			async open() {
				const c = await inner.open();
				return {
					async submit(cmd: Buffer) {
						sent.push(Buffer.from(cmd));
						const r = await c.submit(cmd);
						recv.push(Buffer.from(r));
						return r;
					},
					close: () => c.close(),
				};
			},
		},
	};
};

test(
	"tpm2: the DUK is parameter-encrypted on the bus (never in cleartext)",
	{ skip: swtpmSkip },
	async () => {
		const { port, stop } = await startSwtpm();
		try {
			const cap = capturing(socketTransport(port));
			const cipher = makeTpm2Cipher({
				transport: cap.transport,
				pin: () => Buffer.from("pin"),
				optIn: () => true,
			});
			const secret = randomBytes(32); // high-entropy: an accidental substring match is ~impossible

			const blob = await cipher.protect(secret);
			assert.ok(
				!cap.sent.some((b) => b.includes(secret)),
				"DUK must not appear in any command sent to the TPM (Create is param-encrypted)",
			);

			cap.sent.length = 0;
			cap.recv.length = 0;
			const back = await cipher.unprotect(blob);
			assert.ok(back.equals(secret), "round-trips");
			assert.ok(
				!cap.recv.some((b) => b.includes(secret)),
				"DUK must not appear in any response from the TPM (Unseal is response-encrypted)",
			);
		} finally {
			await stop();
		}
	},
);

// The Windows TBS transport is a persistent process speaking a base64 line protocol
// (one command per line, one response per line), holding the TPM connection for its
// lifetime. On Windows that process is PowerShell P/Invoking tbs.dll (untested off
// Windows). Here we point it at a stub that speaks the SAME line protocol but
// forwards to swtpm — validating the transport framing + the whole codec over it;
// only the literal tbs.dll call is unexercised.
test(
	"tpm2: TBS-style persistent line transport drives the codec (framing validated vs swtpm)",
	{ skip: swtpmSkip },
	async () => {
		const { port, stop } = await startSwtpm();
		const dir = await mkdtemp(join(tmpdir(), "tbs-stub-"));
		const stub = join(dir, "stub.mjs");
		// Reads base64(command) lines on stdin; forwards raw bytes to swtpm over one
		// persistent socket; writes base64(response) lines on stdout. Mirrors the TBS
		// helper's contract (a persistent context per connection).
		await writeFile(
			stub,
			[
				`import net from "node:net"; import readline from "node:readline";`,
				`const s=net.connect(${port},"127.0.0.1"); let b=Buffer.alloc(0); const w=[];`,
				`s.on("data",d=>{b=Buffer.concat([b,d]);while(b.length>=6){const n=b.readUInt32BE(2);if(b.length<n)break;const r=b.subarray(0,n);b=b.subarray(n);w.shift()?.(r);}});`,
				`const rl=readline.createInterface({input:process.stdin});`,
				`rl.on("line",l=>{if(!l)return;const c=Buffer.from(l,"base64");new Promise(res=>{w.push(res);s.write(c);}).then(r=>process.stdout.write(r.toString("base64")+"\\n"));});`,
				// exit when the transport closes stdin (else the open socket keeps it alive)
				`rl.on("close",()=>{s.destroy();process.exit(0);});`,
			].join("\n"),
		);
		try {
			const cipher = makeTpm2Cipher({
				transport: tbsTransport({ command: process.execPath, args: [stub] }),
				pin: () => Buffer.from("pin-tbs"),
				optIn: () => true,
			});
			assert.equal(await cipher.available(), true, "injected helper -> available");
			const secret = randomBytes(32);
			const blob = await cipher.protect(secret);
			assert.ok(
				(await cipher.unprotect(blob)).equals(secret),
				"round-trips over the line transport",
			);
		} finally {
			await rm(dir, { recursive: true, force: true });
			await stop();
		}
	},
);

test(
	"tpm2: end-to-end through makeBlobKeyStore (disk blob + TPM)",
	{ skip: swtpmSkip },
	async () => {
		const { port, stop } = await startSwtpm();
		const home = await mkdtemp(join(tmpdir(), "vault-tpm2-"));
		const prevHome = process.env.VAULT_HOME;
		process.env.VAULT_HOME = home;
		try {
			const ks = makeBlobKeyStore({
				name: "tpm2",
				subdir: "tpm2",
				ext: "tpm2",
				cipher: makeTpm2Cipher({
					transport: socketTransport(port),
					pin: () => Buffer.from("pin-9"),
					optIn: () => true,
				}),
			});
			const duk = Buffer.alloc(32, 0x5a);
			await ks.put("vault-1", duk);
			assert.ok((await ks.get("vault-1"))!.equals(duk), "DUK reloads from disk + TPM");
			await ks.del("vault-1");
			assert.equal(await ks.get("vault-1"), undefined, "deleted blob is gone");
		} finally {
			if (prevHome === undefined) delete process.env.VAULT_HOME;
			else process.env.VAULT_HOME = prevHome;
			await rm(home, { recursive: true, force: true });
			await stop();
		}
	},
);
