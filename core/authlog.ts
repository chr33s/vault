// Signed membership log (spec §5, §9, §10.2; plan §4).
//
// Identity model: user-with-device-subkeys. A user identity (Ed25519) signs
// subordinate device subkeys; the log lists people, each carrying a device set.
//
// Structure: a **signed Merkle DAG**, not a single linear chain. Each entry
// references the heads it observed as `parents` (by content hash) and is signed
// over its content + parents — but NOT over any global index. This makes entries
// position-independent so concurrent membership edits (forks) reconcile
// deterministically instead of becoming an unresolvable conflict:
//
//   - tamper-evidence: an entry's hash covers its body + parents, so editing any
//     ancestor orphans its descendants (they reference a hash that no longer
//     exists) — exactly the Merkle property the linear chain gave.
//   - deterministic merge: every replica linearizes the DAG identically via a
//     hash-ordered topological sort, so all replicas derive the same membership.
//   - causal authority: entries are folded in that canonical order and each is
//     judged against the state of the entries before it; an entry whose signer
//     was not authorized at that point is skipped (not fatal — a bad entry in a
//     merged branch must not poison the rest of the log).
//
// Concurrent removals of *different* members therefore both take effect (they are
// independently authorized against their causal past), matching spec §10.2.

import { sha256, verify, sign } from "./crypto.ts";

export type Role = "owner" | "admin" | "member";

// Genesis: establishes the vault creator (a user) and roots the DAG.
export type GenesisEntry = {
	type: "genesis";
	vaultId: string;
	userId: string;
	userSignPub: string; // base64 Ed25519 user identity public key
	userEncPub: string; // base64 X25519 user public key
	role: "owner";
};

export type AddUserEntry = {
	type: "add-user";
	userId: string;
	userSignPub: string;
	userEncPub: string;
	role: Role;
};

export type AddDeviceEntry = {
	type: "add-device";
	userId: string;
	deviceId: string;
	deviceSignPub: string; // base64 Ed25519 device public key
	deviceEncPub: string; // base64 X25519 device public key
};

export type RemoveDeviceEntry = { type: "remove-device"; userId: string; deviceId: string };
export type RemoveUserEntry = { type: "remove-user"; userId: string };

export type EntryBody =
	| GenesisEntry
	| AddUserEntry
	| AddDeviceEntry
	| RemoveDeviceEntry
	| RemoveUserEntry;

// A signed DAG node. `parents` are the hashes of the heads observed at creation
// (sorted); `hash` is derived (cached for storage/transport keying).
export type LogEntry = {
	parents: string[];
	body: EntryBody;
	signerId: string;
	signerKind: "user" | "device";
	sig: string; // base64 Ed25519 over canonicalBytes
	hash: string; // hex sha256 of canonicalBytes (NOT part of the signed bytes)
};

// The bytes that are signed and hashed. Parents are sorted so the encoding is
// canonical regardless of insertion order.
export const canonicalBytes = (
	parents: string[],
	body: EntryBody,
	signerId: string,
	signerKind: "user" | "device",
): Buffer =>
	Buffer.from(JSON.stringify({ parents: [...parents].sort(), body, signerId, signerKind }), "utf8");

export const entryHash = (
	e: Pick<LogEntry, "parents" | "body" | "signerId" | "signerKind">,
): string => sha256(canonicalBytes(e.parents, e.body, e.signerId, e.signerKind)).toString("hex");

// Build a signed entry referencing the given parent heads.
export const makeEntry = (
	parents: string[],
	body: EntryBody,
	signerId: string,
	signerKind: "user" | "device",
	signerPriv: Buffer,
): LogEntry => {
	const p = [...parents].sort();
	const bytes = canonicalBytes(p, body, signerId, signerKind);
	return {
		parents: p,
		body,
		signerId,
		signerKind,
		sig: sign(bytes, signerPriv).toString("base64"),
		hash: sha256(bytes).toString("hex"),
	};
};

// The current heads: entries not referenced as a parent by any other entry.
// New entries reference all heads, which heals a fork at the next write.
export const heads = (entries: LogEntry[]): string[] => {
	const referenced = new Set<string>();
	for (const e of entries) for (const p of e.parents) referenced.add(p);
	return entries
		.map(entryHash)
		.filter((h) => !referenced.has(h))
		.sort();
};

// Deterministic topological sort: among entries whose parents are all already
// placed, emit the one with the smallest hash. An entry whose parent isn't in
// this set (not yet synced) is skipped this pass and simply omitted from the
// result; it linearizes on a later call once its ancestors have arrived.
export const linearize = (entries: LogEntry[]): LogEntry[] => {
	const byHash = new Map<string, LogEntry>();
	for (const e of entries) byHash.set(entryHash(e), e);

	const placed = new Set<string>();
	const order: LogEntry[] = [];
	// Repeatedly pick the smallest-hash entry whose parents are all placed.
	// (n is tiny for membership logs, so the simple O(n^2) scan is fine.)
	for (;;) {
		let pick: { hash: string; entry: LogEntry } | undefined;
		for (const [h, e] of byHash) {
			if (placed.has(h)) continue;
			if (!e.parents.every((p) => placed.has(p))) continue; // parent missing/unplaced
			if (!pick || h < pick.hash) pick = { hash: h, entry: e };
		}
		if (!pick) break;
		placed.add(pick.hash);
		order.push(pick.entry);
	}
	return order;
};

// Derived membership.
export type Device = { deviceId: string; signPub: string; encPub: string };
export type Member = {
	userId: string;
	signPub: string;
	encPub: string;
	role: Role;
	active: boolean;
	devices: Map<string, Device>;
};
export type Membership = {
	vaultId: string;
	members: Map<string, Member>;
	// Every device signing key ever validly added (by deviceId), retained even
	// after the device/user is removed. Used to verify the signature on rotation
	// records that may have been authored before the signer was removed — a
	// forgery by a non-key-holder (e.g. the relay) is still rejected, while a
	// historically-valid rotation remains decryptable.
	deviceKeys: Map<string, Buffer>;
};

const isAdmin = (m: Member | undefined): boolean =>
	!!m && m.active && (m.role === "owner" || m.role === "admin");

// Resolve the public key that must have signed an entry, enforcing authority
// against the membership state accumulated so far. Throws if unauthorized; the
// caller catches and skips the entry.
const resolveSigner = (state: Membership, e: LogEntry): string => {
	const b = e.body;
	switch (b.type) {
		case "genesis":
			if (e.signerKind !== "user" || e.signerId !== b.userId)
				throw new Error("genesis must be self-signed by creator");
			return b.userSignPub;
		case "add-user":
		case "remove-user": {
			const signer = state.members.get(e.signerId);
			if (e.signerKind !== "user" || !isAdmin(signer))
				throw new Error(`${b.type} requires an admin signer`);
			return signer!.signPub;
		}
		case "add-device": {
			const signer = state.members.get(b.userId);
			if (e.signerKind !== "user" || e.signerId !== b.userId || !signer || !signer.active)
				throw new Error("add-device must be signed by the owning user");
			return signer.signPub;
		}
		case "remove-device": {
			if (e.signerKind !== "user") throw new Error("remove-device requires a user signer");
			const signer = state.members.get(e.signerId);
			if (!signer || !signer.active) throw new Error("unknown signer");
			if (e.signerId !== b.userId && !isAdmin(signer))
				throw new Error("remove-device requires owner-of-device or admin");
			return signer.signPub;
		}
	}
};

const applyEntry = (state: Membership, e: LogEntry): void => {
	const b = e.body;
	switch (b.type) {
		case "genesis":
			state.members.set(b.userId, {
				userId: b.userId,
				signPub: b.userSignPub,
				encPub: b.userEncPub,
				role: "owner",
				active: true,
				devices: new Map(),
			});
			break;
		case "add-user":
			state.members.set(b.userId, {
				userId: b.userId,
				signPub: b.userSignPub,
				encPub: b.userEncPub,
				role: b.role,
				active: true,
				devices: new Map(),
			});
			break;
		case "remove-user": {
			const m = state.members.get(b.userId);
			if (m) {
				m.active = false;
				m.devices.clear();
			}
			break;
		}
		case "add-device": {
			const m = state.members.get(b.userId);
			if (!m) throw new Error("add-device for unknown user");
			m.devices.set(b.deviceId, {
				deviceId: b.deviceId,
				signPub: b.deviceSignPub,
				encPub: b.deviceEncPub,
			});
			// Retain the key for historical rotation-signature checks (not cleared on removal).
			state.deviceKeys.set(b.deviceId, Buffer.from(b.deviceSignPub, "base64"));
			break;
		}
		case "remove-device": {
			state.members.get(b.userId)?.devices.delete(b.deviceId);
			break;
		}
	}
};

// Validate and fold the DAG into a membership state. Every honest replica
// computes the same result regardless of the order entries arrived in. Invalid
// or unauthorized entries are skipped; only a missing genesis is fatal.
export const replay = (entries: LogEntry[]): Membership => {
	const order = linearize(entries);
	const genesis = order.find((e) => e.body.type === "genesis" && e.parents.length === 0);
	if (!genesis || genesis.body.type !== "genesis") throw new Error("auth log has no genesis");

	const state: Membership = {
		vaultId: genesis.body.vaultId,
		members: new Map(),
		deviceKeys: new Map(),
	};
	for (const e of order) {
		// Exactly one genesis roots the DAG; ignore any others (different vault).
		if (e.body.type === "genesis" && e !== genesis) continue;
		try {
			const signerPub = resolveSigner(state, e);
			const ok = verify(
				canonicalBytes(e.parents, e.body, e.signerId, e.signerKind),
				Buffer.from(signerPub, "base64"),
				Buffer.from(e.sig, "base64"),
			);
			if (!ok) continue; // bad signature — skip
			applyEntry(state, e);
		} catch {
			// unauthorized signer / inapplicable entry — skip, keep folding the rest
		}
	}
	return state;
};

// Resolve a device's signing public key (for op verification), if authorized.
export const deviceSignKey = (state: Membership, deviceId: string): Buffer | undefined => {
	for (const m of state.members.values()) {
		if (!m.active) continue;
		const d = m.devices.get(deviceId);
		if (d) return Buffer.from(d.signPub, "base64");
	}
	return undefined;
};
