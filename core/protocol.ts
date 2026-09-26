// Wire protocol for anti-entropy sync (spec §7.4; plan §4, §6).
// Every CRDT operation travels as an OpEnvelope: opaque ciphertext payload plus
// the metadata needed to dedupe, order, and verify authorship. The relay only
// ever sees these envelopes — never plaintext.

import { activeDeviceMember, type LogEntry, type Membership, type Role } from "./authlog.ts";
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
	// Which of the caller's listed auth hashes / rotation ids the responder lacks,
	// so the caller pushes only those.
	lacksAuth: string[];
	lacksRotations: string[];
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
	// The signer is an active device subkey.  The signature binds the team so a
	// grant copied from another vault cannot be replayed here.
	signerId: string;
	sig: string; // base64 Ed25519 over grantBytes(teamId, grant without sig)
};

export const grantBytes = (teamId: string, g: Omit<GrantRow, "sig">): Buffer =>
	Buffer.from(
		JSON.stringify({
			teamId,
			principal: g.principal,
			keyVersion: g.keyVersion,
			wrapped: g.wrapped,
			signerId: g.signerId,
		}),
		"utf8",
	);

export const verifyGrant = (teamId: string, g: GrantRow, signerPub: Buffer): boolean => {
	const { sig, ...unsigned } = g;
	return verify(grantBytes(teamId, unsigned), signerPub, Buffer.from(sig, "base64"));
};

const wellFormedGrant = (g: GrantRow): boolean =>
	Number.isInteger(g.keyVersion) &&
	g.keyVersion >= 0 &&
	typeof g.principal === "string" &&
	typeof g.wrapped === "string" &&
	typeof g.signerId === "string" &&
	typeof g.sig === "string";

// Recovery escrow has two authorities: only an owner may announce the org key,
// and a member may publish only that member's own sealed recovery material.
const grantPrincipalOk = (g: GrantRow, signerRole: Role, signerUserId: string): boolean => {
	if (g.principal === "orgPublicKey") return g.keyVersion === 0 && signerRole === "owner";
	if (!g.principal.startsWith("recovery:")) return false;
	const userId = g.principal.slice("recovery:".length);
	return g.keyVersion === 0 && userId.length > 0 && signerUserId === userId;
};

// Acceptance check, enforced on both sides of the relay boundary: a grant is
// stored only if signed by a currently *active* device with the right authority.
// Requiring active-ness at ingest is what stops a removed device from injecting
// (or racing in) a malicious org key or recovery blob.
export const grantAuthentic = (teamId: string, g: GrantRow, membership: Membership): boolean => {
	if (!wellFormedGrant(g)) return false;
	const signer = activeDeviceMember(membership, g.signerId);
	if (!signer) return false;
	const pub = signer.devices.get(g.signerId)!.signPub;
	if (!verifyGrant(teamId, g, Buffer.from(pub, "base64"))) return false;
	return grantPrincipalOk(g, signer.role, signer.userId);
};

// Retention check, for reading back a grant we already accepted (recoverUser,
// contributeRecovery, the "already enabled" guard). Unlike grantAuthentic the
// signing device need NOT still be active: escrow must keep working precisely
// when the device that published a grant has since been removed. The signature
// is checked against the retained historical key, and the principal against the
// signer's retained identity/role.
export const grantVerifiable = (teamId: string, g: GrantRow, membership: Membership): boolean => {
	if (!wellFormedGrant(g)) return false;
	const signPub = membership.deviceKeys.get(g.signerId);
	const ownerUserId = membership.deviceOwners.get(g.signerId);
	if (!signPub || ownerUserId === undefined) return false;
	if (!verifyGrant(teamId, g, signPub)) return false;
	const signer = membership.members.get(ownerUserId);
	return !!signer && grantPrincipalOk(g, signer.role, ownerUserId);
};

export { rotationId } from "./wire.ts";

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

// Verify hash integrity and the author's signature.
export const verifyEnvelope = (env: OpEnvelope, signPub: Buffer): boolean => {
	const expected = sha256(envelopeBytes(env.deviceId, env.seq, env.payload)).toString("hex");
	if (expected !== env.hash) return false;
	return verify(Buffer.from(env.hash, "hex"), signPub, Buffer.from(env.sig, "base64"));
};

export { acceptContiguous } from "./wire.ts";

// ---- op-log SQL shared by the client Store and both relay storages ----
// `table` has (device_id, seq, hash, sig, payload) columns, plus team_id when
// team-scoped (the relays); team-scoped queries bind the teamId last.

export const rowToOp = (r: Record<string, unknown>): OpEnvelope => ({
	deviceId: r.device_id as string,
	seq: r.seq as number,
	hash: r.hash as string,
	sig: r.sig as string,
	payload: r.payload as string,
});

// Highest seq per device. Op logs are kept gap-free at ingest (see
// acceptContiguous), so the maximum is also the highest contiguous seq.
export const vectorSql = (table: string, teamScoped: boolean): string =>
	`SELECT device_id, MAX(seq) AS m FROM ${table}${teamScoped ? " WHERE team_id = ?" : ""} GROUP BY device_id`;

export const vectorFromRows = (rows: Array<Record<string, unknown>>): VersionVector => {
	const v: VersionVector = {};
	for (const r of rows) if ((r.m as number) > 0) v[r.device_id as string] = r.m as number;
	return v;
};

// Ops past a vector in one query: the vector is bound as JSON and joined by key.
// Binds JSON.stringify(vector) first, then the teamId when team-scoped.
export const opsSinceSql = (table: string, teamScoped: boolean): string =>
	`SELECT o.device_id, o.seq, o.hash, o.sig, o.payload FROM ${table} o
  LEFT JOIN json_each(?) v ON v.key = o.device_id
  WHERE ${teamScoped ? "o.team_id = ? AND " : ""}o.seq > COALESCE(v.value, 0)
  ORDER BY o.device_id, o.seq`;
