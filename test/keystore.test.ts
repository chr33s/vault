import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { init, unlock, addItem, getItem, setKeystore } from "../cli/engine.ts";
import type { KeyStore } from "../cli/keystore.ts";
import { Store } from "../core/store.ts";

const tmp = (): Promise<string> => mkdtemp(join(tmpdir(), "vault-ks-"));
const PASS = "ks-pass";

// In-memory stand-in for an OS keychain, with the backing map exposed for tests.
const memKeystore = (): KeyStore & { map: Map<string, Buffer> } => {
	const map = new Map<string, Buffer>();
	return {
		name: "memory",
		async available() {
			return true;
		},
		async put(id, secret) {
			map.set(id, Buffer.from(secret));
		},
		async get(id) {
			return map.get(id);
		},
		async del(id) {
			map.delete(id);
		},
		map,
	};
};

test("keystore-protected vault stores a DUK and round-trips with the keystore", async () => {
	const dir = await tmp();
	try {
		const ks = memKeystore();
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS, ks);
		assert.equal(store.getMeta("keystoreProvider"), "memory");
		assert.equal(ks.map.size, 1, "a device unlock key was placed in the keystore");

		const s = await unlock(store, PASS, ks);
		addItem(s, "github", { username: "alice", password: "pw" });
		const fresh = await unlock(store, PASS, ks);
		assert.equal(getItem(fresh, "github")!.fields.username, "alice");
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("a stolen disk (no keystore secret) cannot unlock a protected vault", async () => {
	const dir = await tmp();
	try {
		const ks = memKeystore();
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS, ks);

		// Correct passphrase but the keystore is absent (different machine / cold disk).
		await assert.rejects(unlock(store, PASS, undefined), /protected by keystore "memory"/);

		// Keystore present but the DUK is gone -> still cannot unlock.
		ks.map.clear();
		await assert.rejects(unlock(store, PASS, ks), /did not return this device's unlock key/);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("wrong passphrase still fails on a keystore-protected vault", async () => {
	const dir = await tmp();
	try {
		const ks = memKeystore();
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS, ks);
		await assert.rejects(unlock(store, "wrong", ks), /incorrect passphrase/);
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("keystore enable/disable re-wraps an existing vault", async () => {
	const dir = await tmp();
	try {
		const ks = memKeystore();
		const store = new Store(join(dir, "v.db"));
		await init(store, PASS); // passphrase-only
		await unlock(store, PASS, undefined); // opens fine, not protected

		// Enable: now the keystore is required.
		assert.equal(await setKeystore(store, PASS, true, ks), "memory");
		assert.equal(ks.map.size, 1);
		await assert.rejects(unlock(store, PASS, undefined), /protected by keystore/);
		await unlock(store, PASS, ks); // works with the keystore

		// Disable: back to passphrase-only and the DUK is cleaned up.
		assert.equal(await setKeystore(store, PASS, false, ks), "none");
		assert.equal(ks.map.size, 0, "the device unlock key was removed");
		await unlock(store, PASS, undefined); // works again without a keystore
		store.close();
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

// ---- secure-enclave provider (stub helper; no real Enclave/Touch ID) ----
//
// The real provider seals the DUK to a Secure-Enclave key via the signed
// vault-helper; here a tiny shell stub implements the same wire protocol
// (argv command + base64 over stdin/stdout + VAULT_SE_DIR) so the spawn/encode/
// file-path logic is exercised cross-platform without hardware. `put` stores the
// base64 it receives verbatim and `get` echoes it back, so the provider's own
// base64 round-trip is what's under test.

import { keyStoreByName, makeSecureEnclaveKeyStore } from "../cli/keystore.ts";

const STUB_HELPER = `#!/bin/sh
cmd="$1"; id="$2"; dir="$VAULT_SE_DIR"
mkdir -p "$dir"
case "$cmd" in
  available) echo 1 ;;
  put) cat > "$dir/$id.se" ;;
  get) [ -f "$dir/$id.se" ] && cat "$dir/$id.se" || exit 1 ;;
  del) rm -f "$dir/$id.se" ;;
  *) exit 2 ;;
esac
`;

const FAIL_HELPER = `#!/bin/sh
echo "boom" >&2
exit 1
`;

const writeHelper = async (dir: string, body: string, name = "se-helper.sh"): Promise<string> => {
	const p = join(dir, name);
	await writeFile(p, body);
	await chmod(p, 0o755);
	return p;
};

test("secure-enclave provider seals and unseals a DUK through the helper", async () => {
	const dir = await tmp();
	try {
		const helperPath = await writeHelper(dir, STUB_HELPER);
		const storeDir = join(dir, "se");
		const ks = makeSecureEnclaveKeyStore({ helperPath, storeDir });
		assert.equal(ks.name, "secure-enclave");

		const secret = Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef", "hex");
		await ks.put("vault-abc", secret);
		assert.deepEqual(await ks.get("vault-abc"), secret, "round-trips the exact bytes");

		await ks.del("vault-abc");
		assert.equal(await ks.get("vault-abc"), undefined, "missing blob -> undefined");
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("secure-enclave get returns undefined when the helper exits non-zero", async () => {
	const dir = await tmp();
	try {
		const helperPath = await writeHelper(dir, FAIL_HELPER);
		const ks = makeSecureEnclaveKeyStore({ helperPath, storeDir: join(dir, "se") });
		// A denied biometric / missing key is a non-zero exit -> "no secret", not a throw.
		assert.equal(await ks.get("anything"), undefined);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("secure-enclave put surfaces a helper failure", async () => {
	const dir = await tmp();
	try {
		const helperPath = await writeHelper(dir, FAIL_HELPER);
		const ks = makeSecureEnclaveKeyStore({ helperPath, storeDir: join(dir, "se") });
		await assert.rejects(ks.put("id", Buffer.from("x")), /secure-enclave put failed: boom/);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("secure-enclave available() is false when the helper isn't installed", async () => {
	const dir = await tmp();
	try {
		// Non-existent helper path: access() fails -> false (and off-darwin it's false
		// before the path is even checked). Deterministic on every platform.
		const ks = makeSecureEnclaveKeyStore({
			helperPath: join(dir, "nope"),
			storeDir: join(dir, "se"),
		});
		assert.equal(await ks.available(), false);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("secure-enclave available() reflects the platform when the helper answers", async () => {
	const dir = await tmp();
	try {
		const helperPath = await writeHelper(dir, STUB_HELPER);
		const ks = makeSecureEnclaveKeyStore({ helperPath, storeDir: join(dir, "se") });
		// The provider is macOS-only by design: even a working helper reports
		// unavailable off darwin (the platform guard short-circuits first).
		assert.equal(await ks.available(), platform() === "darwin");
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("keyStoreByName returns undefined for an unknown provider", async () => {
	assert.equal(await keyStoreByName("does-not-exist"), undefined);
});

// ---- platform-provider branch coverage (runs on this non-macOS/Windows host) ----

import { macKeychain, windowsDpapi, defaultKeyStore } from "../cli/keystore.ts";

test("macKeychain.available() tracks the platform", async () => {
	// darwin ships /usr/bin/security -> true; elsewhere the platform guard -> false.
	assert.equal(await macKeychain.available(), platform() === "darwin");
});

test("windowsDpapi.available() is false off Windows", async () => {
	assert.equal(
		await windowsDpapi.available(),
		platform() === "win32" ? await windowsDpapi.available() : false,
	);
});

test("defaultKeyStore() resolves a platform provider, or undefined where none exists", async () => {
	const ks = await defaultKeyStore();
	if (platform() === "darwin") {
		// Always at least the login-keychain tier; secure-enclave when its helper is installed.
		assert.ok(ks && (ks.name === "secure-enclave" || ks.name === "macos-keychain"));
	} else if (platform() !== "win32") {
		assert.equal(ks, undefined);
	}
});

// Premise (no /usr/bin/security) only holds off macOS; on darwin `put` would
// touch the real login keychain, so skip there rather than cause a side effect.
test(
	"macKeychain get/del swallow errors when `security` is unavailable",
	{ skip: platform() === "darwin" },
	async () => {
		assert.equal(await macKeychain.get("anything"), undefined);
		await macKeychain.del("anything"); // must not throw
		await assert.rejects(macKeychain.put("id", Buffer.from("x")));
	},
);
