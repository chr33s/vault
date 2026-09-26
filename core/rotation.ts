// Conflict-free key rotation (spec §10.2; plan §4). Membership lives in the
// CRDT/auth log; key material is a single-valued epoch chosen by a deterministic
// total order, so concurrent admin rotations converge with no coordinator.

import { activeDeviceMember, type Membership } from "./authlog.ts";
import { sha256, verify, encodeBox, decodeBox } from "./crypto.ts";
import { compareEncoded } from "./hlc.ts";
import type { SealedBox } from "./sealedbox.ts";
import { rotationId } from "./wire.ts";

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

// Ed25519 results memoized by (key, sig, signed-bytes digest): every sync
// re-checks the same growing set of records several times (import, recovery,
// winner selection), and hashing is far cheaper than verifying. Bounded.
const verifyCache = new Map<string, boolean>();
const VERIFY_CACHE_MAX = 8192;

export const verifyRotation = (r: RotationRecord, signerPub: Buffer): boolean => {
	const { sig, ...rest } = r;
	const bytes = rotationBytes(rest);
	const key = `${signerPub.toString("base64")}|${sig}|${sha256(bytes).toString("hex")}`;
	const hit = verifyCache.get(key);
	if (hit !== undefined) return hit;
	const ok = verify(bytes, signerPub, Buffer.from(sig, "base64"));
	if (verifyCache.size >= VERIFY_CACHE_MAX) verifyCache.clear();
	verifyCache.set(key, ok);
	return ok;
};

// Structural sanity check, independent of the signature. rotate()/init always
// mint epoch >= 1 with baseEpoch === epoch - 1, so this rejects only malformed
// records — a cheap guard against a buggy/hostile authorized device emitting a
// nonsensical epoch chain.
//
// Also checks every field's type: records arrive from relays and peers, and a
// validly signed record with e.g. `grants: null` would otherwise throw deep in
// key recovery and fail unlock() on every replica.
const isStr = (v: unknown): v is string => typeof v === "string";
const wellFormedGrant = (g: unknown): boolean =>
	!!g &&
	typeof g === "object" &&
	isStr((g as SealedGrant).ephPub) &&
	isStr((g as SealedGrant).iv) &&
	isStr((g as SealedGrant).ct) &&
	isStr((g as SealedGrant).tag);

export const wellFormedRotation = (r: RotationRecord): boolean =>
	!!r &&
	typeof r === "object" &&
	Number.isInteger(r.epoch) &&
	Number.isInteger(r.baseEpoch) &&
	r.epoch >= 1 &&
	r.baseEpoch === r.epoch - 1 &&
	isStr(r.hlc) &&
	isStr(r.deviceId) &&
	isStr(r.keyCommit) &&
	isStr(r.signerId) &&
	isStr(r.sig) &&
	!!r.grants &&
	typeof r.grants === "object" &&
	!Array.isArray(r.grants) &&
	Object.values(r.grants).every(wellFormedGrant) &&
	Array.isArray(r.observed) &&
	r.observed.every(isStr);

// Signed by the (possibly since-removed) device it names, against the retained
// historical key. Enough to keep a record for key recovery and to count it as
// held; whether it may advance the current epoch is rotationAuthentic's call.
export const rotationVerifiable = (r: RotationRecord, membership: Membership): boolean => {
	try {
		if (!wellFormedRotation(r) || r.signerId !== r.deviceId) return false;
		const pub = membership.deviceKeys.get(r.signerId);
		return pub !== undefined && verifyRotation(r, pub);
	} catch {
		return false;
	}
};

// Whether a rotation may advance the *current* epoch: it must name itself as its
// own signer (signerId === deviceId) and be signed by an active owner/admin
// device. Historical device keys are deliberately insufficient here — a removed
// device must not win a later epoch — though they remain usable for decrypting
// old data (see the engine's signature-verified recovery path). This is the
// single source of truth shared by the client, peer server, relay, and worker so
// they cannot drift on which rotations are accepted.
export const rotationAuthentic = (rec: RotationRecord, membership: Membership): boolean => {
	if (rec.signerId !== rec.deviceId) return false;
	if (!wellFormedRotation(rec)) return false;
	const signer = activeDeviceMember(membership, rec.signerId);
	if (!signer || (signer.role !== "owner" && signer.role !== "admin")) return false;
	return verifyRotation(rec, Buffer.from(signer.devices.get(rec.signerId)!.signPub, "base64"));
};

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

// Parse a stored/transported rotation record, tolerating garbage.
export const parseRotation = (raw: unknown): RotationRecord | undefined => {
	if (typeof raw !== "string") return undefined;
	try {
		const r = JSON.parse(raw) as unknown;
		return r && typeof r === "object" ? (r as RotationRecord) : undefined;
	} catch {
		return undefined;
	}
};

// Of serialized records, those that verify (rotationVerifiable), with their ids.
// What a holder may serve and count as held: an unverifiable record in a slot
// must not stop the genuine one from being requested and stored in its place.
export const verifiableRotations = (
	records: string[],
	membership: Membership | undefined,
): Array<{ id: string; record: string }> => {
	if (!membership) return [];
	return records.flatMap((record) => {
		const r = parseRotation(record);
		return r && rotationVerifiable(r, membership)
			? [{ id: rotationId(r.epoch, r.deviceId), record }]
			: [];
	});
};
