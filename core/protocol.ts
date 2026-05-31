// Wire protocol for anti-entropy sync (spec §7.4; plan §4, §6).
// Every CRDT operation travels as an OpEnvelope: opaque ciphertext payload plus
// the metadata needed to dedupe, order, and verify authorship. The relay only
// ever sees these envelopes — never plaintext.

import type { LogEntry } from "./authlog.ts";
import { sha256, sign, verify } from "./crypto.ts";

// Base64 of the AEAD-sealed CRDT op (see store/vault for payload contents).
export type OpEnvelope = {
	deviceId: string; // author device subkey id
	seq: number; // monotonic per-device sequence number
	hash: string; // hex sha256 over (deviceId|seq|payload)
	sig: string; // base64 Ed25519 signature over the hash by the device key
	payload: string; // base64 opaque ciphertext
};

// deviceId -> highest contiguous seq the holder has. Summarizes local state so
// a peer can compute "everything you're missing".
export type VersionVector = Record<string, number>;

// Sync carries three replicated logs (spec §7.4, §5, §10.2): the opaque op log,
// the signed auth log (membership — gossips as cleartext metadata), and the
// rotation records (cleartext epoch metadata + sealed grants). The auth log and
// rotations are NOT opaque to the relay, but neither reveals vault contents.
export type SyncRequest = {
	teamId: string;
	vector: VersionVector;
	authHashes: string[]; // hashes of auth-log (DAG) entries the caller holds
	rotationIds: string[]; // "epoch:deviceId" keys the caller already holds
};
export type SyncResponse = {
	ops: OpEnvelope[];
	vector: VersionVector;
	authLog: LogEntry[]; // DAG entries whose hash the caller did not list
	rotations: string[]; // serialized RotationRecords the caller lacks
	grants: GrantRow[]; // recovery-escrow grants + org-key announcement
};
export type PushRequest = {
	teamId: string;
	ops: OpEnvelope[];
	authLog?: LogEntry[];
	rotations?: string[];
	grants?: GrantRow[];
};

// A row of the grants channel: the org-public-key announcement and each
// member's RecoveryGrant (spec §5 escrow). `wrapped` is cleartext for the org
// key, or a sealed-to-org-key blob for a member's recovery material.
export type GrantRow = {
	principal: string; // "orgPublicKey" | "recovery:<userId>"
	keyVersion: number;
	wrapped: string;
};

export const rotationId = (epoch: number, deviceId: string): string => `${epoch}:${deviceId}`;

const envelopeBytes = (deviceId: string, seq: number, payload: string): Buffer =>
	Buffer.from(`${deviceId}|${seq}|${payload}`, "utf8");

export const makeEnvelope = (
	deviceId: string,
	seq: number,
	payload: Buffer,
	signPriv: Buffer,
): OpEnvelope => {
	const payloadB64 = payload.toString("base64");
	const hash = sha256(envelopeBytes(deviceId, seq, payloadB64)).toString("hex");
	const sig = sign(Buffer.from(hash, "hex"), signPriv).toString("base64");
	return { deviceId, seq, hash, sig, payload: payloadB64 };
};

// Verify hash integrity and (if a key is known) the signature.
export const verifyEnvelope = (env: OpEnvelope, signPub?: Buffer): boolean => {
	const expected = sha256(envelopeBytes(env.deviceId, env.seq, env.payload)).toString("hex");
	if (expected !== env.hash) return false;
	if (!signPub) return true; // hash-only check (relay path)
	return verify(Buffer.from(env.hash, "hex"), signPub, Buffer.from(env.sig, "base64"));
};

// Ops in `have` that the peer (described by `theirVector`) is missing.
export const opsSince = (have: OpEnvelope[], theirVector: VersionVector): OpEnvelope[] =>
	have.filter((op) => op.seq > (theirVector[op.deviceId] ?? 0));

export const vectorFromOps = (ops: OpEnvelope[]): VersionVector => {
	const v: VersionVector = {};
	for (const op of ops) {
		v[op.deviceId] = Math.max(v[op.deviceId] ?? 0, op.seq);
	}
	return v;
};
