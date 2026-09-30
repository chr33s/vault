// Pure wire-format helpers shared by the client, the relays, and the Worker
// handler. No imports beyond types, so handler.ts can use them without
// pulling node:crypto into the Workers bundle.

import type { EntryBody, LogEntry } from "./authlog.ts";
import type { OpEnvelope } from "./protocol.ts";

// The key a rotation record is stored and advertised under.
export const rotationId = (epoch: number, deviceId: string): string => `${epoch}:${deviceId}`;

const isStr = (v: unknown): v is string => typeof v === "string";

const wellFormedBody = (b: unknown): b is EntryBody => {
	if (!b || typeof b !== "object") return false;
	const o = b as Record<string, unknown>;
	switch (o.type) {
		case "genesis":
			return (
				isStr(o.vaultId) &&
				isStr(o.userId) &&
				isStr(o.userSignPub) &&
				isStr(o.userEncPub) &&
				o.role === "owner"
			);
		case "add-user":
			return isStr(o.userId) && isStr(o.userSignPub) && isStr(o.userEncPub) && isStr(o.role);
		case "add-device":
			return (
				isStr(o.userId) && isStr(o.deviceId) && isStr(o.deviceSignPub) && isStr(o.deviceEncPub)
			);
		case "prove-device":
		case "remove-device":
			return isStr(o.userId) && isStr(o.deviceId);
		case "remove-user":
			return isStr(o.userId);
		default:
			// An entry type from a newer version: relayed and stored opaquely so
			// upgraded clients can exchange it through older relays; replay skips it.
			return isStr(o.type);
	}
};

// Structural check (not a validity check) for an auth-log entry received from anywhere untrusted (a
// relay, a peer, a push, or a corrupt row). replay(), heads() and linearize()
// assume this shape, so one malformed entry (e.g. `parents` as a string) that
// slipped into a store would otherwise throw on every replay and lock the vault
// on every replica. Signatures and authority are checked later, at replay.
export const wellFormedEntry = (e: unknown): e is LogEntry => {
	if (!e || typeof e !== "object") return false;
	const o = e as Record<string, unknown>;
	return (
		Array.isArray(o.parents) &&
		o.parents.every(isStr) &&
		wellFormedBody(o.body) &&
		isStr(o.signerId) &&
		(o.signerKind === "user" || o.signerKind === "device") &&
		isStr(o.sig)
	);
};

// Keep an op log gap-free: of `ops`, return those that extend each device's
// run contiguously from `maxSeq(deviceId)` (the highest seq already held), in
// order. An op past a gap is dropped, not stored: stored, it would make the
// vector (a plain MAX) claim the missing seq, so it would never be requested
// again (a withheld op lost for good); and a writer that skipped seq 1 could
// otherwise make every holder re-download its whole history each round. A
// dropped op is simply requested again once the gap is filled.
export const acceptContiguous = <T extends Pick<OpEnvelope, "deviceId" | "seq">>(
	ops: T[],
	maxSeq: (deviceId: string) => number,
): T[] => {
	const next = new Map<string, number>();
	const out: T[] = [];
	const sorted = [...ops].sort((a, b) =>
		a.deviceId === b.deviceId ? a.seq - b.seq : a.deviceId < b.deviceId ? -1 : 1,
	);
	for (const op of sorted) {
		if (!Number.isInteger(op.seq) || op.seq < 1) continue;
		const have = next.get(op.deviceId) ?? maxSeq(op.deviceId);
		if (op.seq > have + 1) continue; // gap
		out.push(op);
		next.set(op.deviceId, Math.max(have, op.seq));
	}
	return out;
};
