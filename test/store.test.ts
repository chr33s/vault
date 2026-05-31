// Store.transaction atomicity — the property the enrollment flows rely on so a
// crash mid-write can't leave the replica half-initialized.

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Store } from "../core/store.ts";

const withStore = async (fn: (s: Store) => void): Promise<void> => {
	const dir = await mkdtemp(join(tmpdir(), "store-"));
	const store = new Store(join(dir, "v.db"));
	try {
		fn(store);
	} finally {
		store.close();
		await rm(dir, { recursive: true, force: true });
	}
};

test("transaction commits all writes on success", async () => {
	await withStore((s) => {
		s.transaction(() => {
			s.setMeta("a", "1");
			s.setMeta("b", "2");
		});
		assert.equal(s.getMeta("a"), "1");
		assert.equal(s.getMeta("b"), "2");
	});
});

test("transaction rolls back ALL writes when the body throws", async () => {
	await withStore((s) => {
		s.setMeta("pre", "kept"); // committed before the tx
		assert.throws(() =>
			s.transaction(() => {
				s.setMeta("a", "1");
				s.setMeta("b", "2");
				throw new Error("boom"); // simulate a crash mid-enrollment
			}),
		);
		// Nothing from the failed transaction persisted...
		assert.equal(s.getMeta("a"), undefined);
		assert.equal(s.getMeta("b"), undefined);
		// ...and pre-existing state is intact.
		assert.equal(s.getMeta("pre"), "kept");
	});
});

test("transaction returns the body's value", async () => {
	await withStore((s) => {
		const n = s.transaction(() => {
			s.setMeta("k", "v");
			return 42;
		});
		assert.equal(n, 42);
	});
});
