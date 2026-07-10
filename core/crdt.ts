// Field-level CRDT (spec §7.1, §13 decision; plan §4).
// A vault is a map of items; each item is a map of fields; each ordinary field
// is a last-writer-wins register keyed by HLC. The `password` field is a
// multi-value register so divergent concurrent edits surface instead of being
// silently overwritten. Deletes are tombstones (LWW on a reserved field).
//
// Apply is idempotent and order-independent: merging the same set of ops in any
// order converges to the same materialized state.

import { compareEncoded } from "./hlc.ts";

export const PASSWORD_FIELD = "password";
export const DELETED_FIELD = "__deleted__";
// Item type (spec §4): a reserved single-value LWW field, so the type travels
// inside the *encrypted* item content (never plaintext metadata to the relay).
// Absent => the default, so items written before typing existed read as `login`.
export const ITEM_TYPE_FIELD = "__type__";
export type ItemType = "login" | "note" | "card" | "identity";
export const ITEM_TYPES: readonly ItemType[] = ["login", "note", "card", "identity"];
export const DEFAULT_ITEM_TYPE: ItemType = "login";
export const isItemType = (v: string): v is ItemType =>
	(ITEM_TYPES as readonly string[]).includes(v);

// A single field mutation. `value === null` clears the field.
export type FieldOp = {
	itemId: string;
	field: string;
	value: string | null;
	hlc: string; // encoded HLC (see hlc.ts)
	// For the multi-value password register: the HLCs this write supersedes
	// (everything the author had observed at edit time). Ignored for LWW fields.
	replaces?: string[];
};

export type ItemView = {
	itemId: string;
	itemType: ItemType;
	fields: Record<string, string>;
	// Live password values. More than one => unresolved concurrent edits.
	passwords: string[];
	deleted: boolean;
	lastHlc: string;
};

type LwwReg = { value: string | null; hlc: string };

type ItemAcc = {
	// ordinary single-value fields (includes DELETED_FIELD)
	lww: Map<string, LwwReg>;
	// password multi-value register: hlc -> value, plus the set of superseded hlcs
	pwValues: Map<string, string | null>;
	pwSuperseded: Set<string>;
	lastHlc: string;
};

export class VaultState {
	private items = new Map<string, ItemAcc>();

	private acc(itemId: string): ItemAcc {
		let a = this.items.get(itemId);
		if (!a) {
			a = {
				lww: new Map(),
				pwValues: new Map(),
				pwSuperseded: new Set(),
				lastHlc: "",
			};
			this.items.set(itemId, a);
		}
		return a;
	}

	apply(op: FieldOp): void {
		const a = this.acc(op.itemId);
		if (op.hlc > a.lastHlc) a.lastHlc = op.hlc;

		if (op.field === PASSWORD_FIELD) {
			// Keyed by encoded HLC. Honest per-device clocks never repeat an HLC, but
			// a misbehaving author could equivocate two values at the same HLC; resolve
			// such a collision deterministically (keep the larger value) so the merge
			// stays order-independent instead of depending on apply() sequence.
			const prev = a.pwValues.get(op.hlc);
			if (prev === undefined || op.value === null || (prev !== null && op.value! > prev)) {
				a.pwValues.set(op.hlc, op.value);
			}
			for (const r of op.replaces ?? []) a.pwSuperseded.add(r);
			return;
		}

		// LWW: highest HLC wins (deterministic across all replicas).
		const cur = a.lww.get(op.field);
		if (!cur || compareEncoded(op.hlc, cur.hlc) > 0) {
			a.lww.set(op.field, { value: op.value, hlc: op.hlc });
		}
	}

	applyAll(ops: Iterable<FieldOp>): void {
		for (const op of ops) this.apply(op);
	}

	// Currently-live password writes (not superseded by a later observed write,
	// not cleared), in canonical HLC order. The single source of truth behind both
	// the materialized values and the `replaces` set.
	private liveEntries(a: ItemAcc): { hlc: string; value: string }[] {
		const live: { hlc: string; value: string }[] = [];
		for (const [hlc, value] of a.pwValues) {
			if (a.pwSuperseded.has(hlc) || value === null) continue;
			live.push({ hlc, value });
		}
		live.sort((x, y) => compareEncoded(x.hlc, y.hlc));
		return live;
	}

	// Live password values: those not superseded by a later (observed) write.
	private livePasswords(a: ItemAcc): string[] {
		return this.liveEntries(a).map((x) => x.value);
	}

	// The HLCs of the currently-live password writes — an editor passes these as
	// `replaces` on its next password op to converge the multi-value register.
	livePasswordHlcs(itemId: string): string[] {
		const a = this.items.get(itemId);
		if (!a) return [];
		return this.liveEntries(a).map((x) => x.hlc);
	}

	materialize(itemId: string): ItemView | undefined {
		const a = this.items.get(itemId);
		if (!a) return undefined;
		const fields: Record<string, string> = {};
		let deleted = false;
		let itemType: ItemType = DEFAULT_ITEM_TYPE;
		// Emit fields in sorted key order so the materialized view is canonical
		// regardless of the order ops were applied in.
		const names = [...a.lww.keys()].sort();
		for (const name of names) {
			const reg = a.lww.get(name)!;
			if (name === DELETED_FIELD) {
				deleted = reg.value !== null;
				continue;
			}
			if (name === ITEM_TYPE_FIELD) {
				// Reserved: kept off `fields` and surfaced as the typed `itemType`.
				// An unrecognized value (forward-compat / tamper) falls back to default.
				if (reg.value !== null && isItemType(reg.value)) itemType = reg.value;
				continue;
			}
			if (reg.value !== null) fields[name] = reg.value;
		}
		return {
			itemId,
			itemType,
			fields,
			passwords: this.livePasswords(a),
			deleted,
			lastHlc: a.lastHlc,
		};
	}

	list(): ItemView[] {
		const out: ItemView[] = [];
		for (const id of this.items.keys()) {
			const v = this.materialize(id);
			if (v && !v.deleted) out.push(v);
		}
		out.sort((x, y) => (x.itemId < y.itemId ? -1 : 1));
		return out;
	}
}

// Build the set of FieldOps that represent creating/updating an item's fields
// at a given HLC sequence. The caller supplies a function to mint HLCs.
export const buildItemOps = (
	itemId: string,
	fields: Record<string, string | null>,
	nextHlc: () => string,
	livePasswordHlcs: string[] = [],
): FieldOp[] => {
	const ops: FieldOp[] = [];
	for (const [field, value] of Object.entries(fields)) {
		if (field === PASSWORD_FIELD) {
			ops.push({
				itemId,
				field,
				value,
				hlc: nextHlc(),
				replaces: livePasswordHlcs,
			});
		} else {
			ops.push({ itemId, field, value, hlc: nextHlc() });
		}
	}
	return ops;
};

export const buildDeleteOp = (itemId: string, hlc: string): FieldOp => ({
	itemId,
	field: DELETED_FIELD,
	value: "1",
	hlc,
});
