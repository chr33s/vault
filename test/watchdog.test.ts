// The relay's sd_notify watchdog. It shells out to `systemd-notify`, gated on
// NOTIFY_SOCKET, so it's a no-op off systemd. We intercept the helper by putting
// a recording stub first on PATH and pointing the relay at it.

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, readFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { sdNotify, startWatchdog } from "../relay/main.ts";

// Build a temp dir with a `systemd-notify` stub that appends its args to a log,
// and return { dir, log, restore } having prepended it to PATH.
const withStubNotify = async (): Promise<{ log: string; restore: () => Promise<void> }> => {
	const dir = await mkdtemp(join(tmpdir(), "wd-"));
	const log = join(dir, "calls.log");
	const stub = join(dir, "systemd-notify");
	await writeFile(stub, `#!/bin/sh\nprintf '%s\\n' "$*" >> ${JSON.stringify(log)}\n`);
	await chmod(stub, 0o755);
	const prevPath = process.env.PATH;
	process.env.PATH = `${dir}:${prevPath ?? ""}`;
	return {
		log,
		restore: async () => {
			process.env.PATH = prevPath;
			await rm(dir, { recursive: true, force: true });
		},
	};
};

const readCalls = async (log: string): Promise<string[]> => {
	try {
		return (await readFile(log, "utf8")).split("\n").filter(Boolean);
	} catch {
		return [];
	}
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("sdNotify is a no-op when NOTIFY_SOCKET is unset", async () => {
	const { log, restore } = await withStubNotify();
	const prev = process.env.NOTIFY_SOCKET;
	delete process.env.NOTIFY_SOCKET;
	try {
		sdNotify("READY=1");
		await sleep(50);
		assert.deepEqual(await readCalls(log), [], "nothing invoked off systemd");
	} finally {
		if (prev !== undefined) process.env.NOTIFY_SOCKET = prev;
		await restore();
	}
});

test("sdNotify invokes systemd-notify when NOTIFY_SOCKET is set", async () => {
	const { log, restore } = await withStubNotify();
	const prev = process.env.NOTIFY_SOCKET;
	process.env.NOTIFY_SOCKET = "/run/dummy.sock";
	try {
		sdNotify("READY=1");
		await sleep(100);
		assert.deepEqual(await readCalls(log), ["READY=1"]);
	} finally {
		if (prev === undefined) delete process.env.NOTIFY_SOCKET;
		else process.env.NOTIFY_SOCKET = prev;
		await restore();
	}
});

test("startWatchdog pings on a timer, and is a no-op without WATCHDOG_USEC", async () => {
	const { log, restore } = await withStubNotify();
	const prevNotify = process.env.NOTIFY_SOCKET;
	const prevUsec = process.env.WATCHDOG_USEC;
	try {
		// No WATCHDOG_USEC -> no pings.
		process.env.NOTIFY_SOCKET = "/run/dummy.sock";
		delete process.env.WATCHDOG_USEC;
		let stop = startWatchdog();
		await sleep(120);
		stop();
		assert.deepEqual(await readCalls(log), [], "no watchdog interval -> no pings");

		// With a tiny interval (2s usec -> clamped to 1s min), expect at least one ping.
		process.env.WATCHDOG_USEC = String(2_000_000); // 2s; half = 1s (the floor)
		stop = startWatchdog();
		await sleep(1200);
		stop();
		const calls = await readCalls(log);
		assert.ok(
			calls.includes("WATCHDOG=1"),
			`expected a WATCHDOG=1 ping, got ${JSON.stringify(calls)}`,
		);
	} finally {
		if (prevNotify === undefined) delete process.env.NOTIFY_SOCKET;
		else process.env.NOTIFY_SOCKET = prevNotify;
		if (prevUsec === undefined) delete process.env.WATCHDOG_USEC;
		else process.env.WATCHDOG_USEC = prevUsec;
		await restore();
	}
});
