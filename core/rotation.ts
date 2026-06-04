// Conflict-free key rotation (spec §10.2; plan §4). Membership lives in the
// CRDT/auth log; key material is a single-valued epoch chosen by a deterministic
// total order, so concurrent admin rotations converge with no coordinator.

import { sha256, verify, encodeBox, decodeBox } from "./crypto.ts";
import { compareEncoded } from "./hlc.ts";
import type { SealedBox } from "./sealedbox.ts";

// A sealed grant of an epoch key, serialized for transport (base64 fields).
export type SealedGrant = {
	ephPub: string;
	iv: string;
	ct: string;
	tag: string;
};

// A SealedBox is an AeadBox plus an ephemeral pubkey, so its base64 form is the
// shared encodeBox shape with ephPub alongside.
export const encodeGrant = (b: SealedBox): SealedGrant => ({
	ephPub: b.ephPub.toString("base64"),
	...encodeBox(b),
});

export const decodeGrant = (g: SealedGrant): SealedBox => ({
	ephPub: Buffer.from(g.ephPub, "base64"),
	...decodeBox(g),
});

export type RotationRecord = {
	epoch: number;
	baseEpoch: number;
	hlc: string; // encoded HLC
	deviceId: string;
	keyCommit: string; // hex sha256(K_epoch) — commitment, not the key
	grants: Record<string, SealedGrant>; // recipient X25519 pub (base64) -> sealed K_epoch
	observed: string[]; // auth-entry hashes the initiator had seen (catch-up rule)
	signerId: string; // device id that signed
	sig: string; // base64 Ed25519 over canonical bytes
};

export const keyCommit = (key: Buffer): string => sha256(key).toString("hex");

export const rotationBytes = (r: Omit<RotationRecord, "sig">): Buffer =>
	Buffer.from(
		JSON.stringify({
			epoch: r.epoch,
			baseEpoch: r.baseEpoch,
			hlc: r.hlc,
			deviceId: r.deviceId,
			keyCommit: r.keyCommit,
			grants: r.grants,
			observed: r.observed,
			signerId: r.signerId,
		}),
		"utf8",
	);

export const verifyRotation = (r: RotationRecord, signerPub: Buffer): boolean => {
	const { sig, ...rest } = r;
	return verify(rotationBytes(rest), signerPub, Buffer.from(sig, "base64"));
};

// Structural sanity check, independent of the signature. rotate()/init always
// mint epoch >= 1 with baseEpoch === epoch - 1, so this rejects only malformed
// records — a cheap guard against a buggy/hostile authorized device emitting a
// nonsensical epoch chain.
export const wellFormedRotation = (r: RotationRecord): boolean =>
	Number.isInteger(r.epoch) &&
	Number.isInteger(r.baseEpoch) &&
	r.epoch >= 1 &&
	r.baseEpoch === r.epoch - 1;

// Deterministic winner among records: higher epoch always supersedes; within an
// epoch, argmax over (hlc, deviceId). Every honest node computes the same winner
// with no communication.
export const winner = (records: RotationRecord[]): RotationRecord | undefined => {
	let best: RotationRecord | undefined;
	for (const r of records) {
		if (!best) {
			best = r;
			continue;
		}
		if (r.epoch > best.epoch) {
			best = r;
		} else if (r.epoch === best.epoch) {
			const c = compareEncoded(r.hlc, best.hlc);
			if (c > 0 || (c === 0 && r.deviceId > best.deviceId)) best = r;
		}
	}
	return best;
};

export const winnerAtEpoch = (
	records: RotationRecord[],
	epoch: number,
): RotationRecord | undefined => winner(records.filter((r) => r.epoch === epoch));

// Whether a security catch-up rotation is required: the winning rotation did not
// observe a removal that has since landed in the auth log (spec §10.2). With the
// auth-log DAG, "observed" is precise — a removal is observed iff its entry hash
// was in the initiator's set when it rotated. No rotation yet (win===undefined)
// means there's nothing to catch up against, so this returns false.
export const needsCatchUp = (win: RotationRecord | undefined, removalHashes: string[]): boolean => {
	if (!win) return false;
	const observed = new Set(win.observed);
	return removalHashes.some((h) => !observed.has(h));
};
