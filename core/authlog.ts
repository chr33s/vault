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
export type Device = {
	deviceId: string;
	signPub: string;
	encPub: string;
	// A device key delegates enrollment authority only to descendants it signed.
	// Removing it revokes a *concurrent* delegation too (see remove-device), so a
	// racing/replayed enrollment cannot turn a removed device into a fresh
	// replacement identity.
	enrolledByDeviceId?: string;
	// Hash of the add-device entry that created this device. Used by remove-device
	// to tell a legitimate prior enrollment (causally before the removal) from a
	// concurrent one the removed device raced in.
	enrolledAtHash: string;
};
export type Member = {
	userId: string;
	signPub: string;
	encPub: string;
	role: Role;
	active: boolean;
	devices: Map<string, Device>;
	// A user identity is shared with every enrolled device, so it cannot be the
	// continuing authority to add devices: a removed device retains it.  It may
	// bootstrap exactly the user's first device; every later enrollment must be
	// signed by an already-active device subkey, which is individually revocable.
	hasEverHadDevice: boolean;
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
	// deviceId -> owning userId for every device ever added, retained after
	// removal. Lets a recovery-escrow grant signed by a since-removed device still
	// be attributed to its author (protocol.grantVerifiable) — escrow must survive
	// the removal of the very device that lost access.
	deviceOwners: Map<string, string>;
};

const isAdmin = (m: Member | undefined): boolean =>
	!!m && m.active && (m.role === "owner" || m.role === "admin");

// Resolve an *active* device to its owning member.  In contrast to deviceKeys,
// this deliberately excludes removed devices; use deviceKeys only where a
// historical signature still needs to be checked.
export const activeDeviceMember = (state: Membership, deviceId: string): Member | undefined => {
	for (const m of state.members.values()) {
		if (m.active && m.devices.has(deviceId)) return m;
	}
	return undefined;
};

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
		case "add-user": {
			let signer: Member | undefined;
			let signerPub: string;
			if (e.signerKind === "device") {
				signer = activeDeviceMember(state, e.signerId);
				if (!isAdmin(signer)) throw new Error("add-user requires an active admin device");
				signerPub = signer!.devices.get(e.signerId)!.signPub;
			} else {
				signer = state.members.get(e.signerId);
				// Compatibility/bootstrap only: before an identity has ever enrolled a
				// device, no revocable device key exists yet.  Once it does, user keys
				// distributed in Token B are never sufficient for administration.
				if (e.signerKind !== "user" || !isAdmin(signer) || signer?.hasEverHadDevice)
					throw new Error("add-user requires an active admin device");
				signerPub = signer!.signPub;
			}
			// An add-user must not overwrite a live member: without this, an
			// admin-signed entry reusing an existing userId (e.g. the owner's, which
			// is public in every enrollment token) replaces that member's keys and
			// role on every replica — an owner-lockout / impersonation. A userId that
			// exists only as an inactive (removed) member may be re-added (rejoin).
			const existing = state.members.get(b.userId);
			if (existing?.active) throw new Error("add-user cannot overwrite an existing member");
			// Only the genesis mints an owner; add-user is member|admin (spec §9).
			if (b.role === "owner") throw new Error("add-user cannot grant the owner role");
			return signerPub;
		}
		case "remove-user": {
			let signer: Member | undefined;
			let signerPub: string;
			if (e.signerKind === "device") {
				signer = activeDeviceMember(state, e.signerId);
				if (!isAdmin(signer)) throw new Error("remove-user requires an active admin device");
				signerPub = signer!.devices.get(e.signerId)!.signPub;
			} else {
				signer = state.members.get(e.signerId);
				if (e.signerKind !== "user" || !isAdmin(signer) || signer?.hasEverHadDevice)
					throw new Error("remove-user requires an active admin device");
				signerPub = signer!.signPub;
			}
			// The owner is the root of authority and cannot be removed by an admin
			// (ownership transfer is not a supported operation); otherwise an admin
			// could deactivate the owner and seize sole control.
			const target = state.members.get(b.userId);
			if (target?.role === "owner" && signer!.userId !== b.userId)
				throw new Error("the owner cannot be removed");
			return signerPub;
		}
		case "add-device": {
			const target = state.members.get(b.userId);
			if (!target?.active) throw new Error("add-device requires an active member");
			// A newly-created identity has no device key yet, so its first device is
			// signed by the user identity.  Once a device has ever existed, the user
			// identity is no longer sufficient: Token B copies it to every device and
			// a removed device would otherwise be able to enroll itself again.
			if (e.signerKind === "user") {
				if (e.signerId !== b.userId || target.hasEverHadDevice)
					throw new Error("add-device bootstrap must be the user's first device");
				return target.signPub;
			}
			if (e.signerKind !== "device") throw new Error("add-device requires a device signer");
			const signer = activeDeviceMember(state, e.signerId);
			if (!signer || signer.userId !== b.userId)
				throw new Error("add-device requires an active device of the owning user");
			return signer.devices.get(e.signerId)!.signPub;
		}
		case "remove-device": {
			if (e.signerKind !== "device") throw new Error("remove-device requires a device signer");
			const signer = activeDeviceMember(state, e.signerId);
			if (!signer) throw new Error("unknown signer");
			if (signer.userId !== b.userId && !isAdmin(signer))
				throw new Error("remove-device requires owner-of-device or admin");
			// An admin cannot strip the owner's devices (would let an admin lock the
			// owner out of their own vault); only the owner's device may remove one.
			const target = state.members.get(b.userId);
			if (target?.role === "owner" && signer.userId !== b.userId)
				throw new Error("only the owner may remove the owner's device");
			return signer.devices.get(e.signerId)!.signPub;
		}
	}
};

// `hash` is this entry's own hash; `ancestorHashes` is the set of entries
// causally before it (transitive parents). Only remove-device consults them.
const applyEntry = (
	state: Membership,
	e: LogEntry,
	hash: string,
	ancestorHashes: Set<string>,
): void => {
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
				hasEverHadDevice: false,
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
				hasEverHadDevice: false,
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
				enrolledByDeviceId: e.signerKind === "device" ? e.signerId : undefined,
				enrolledAtHash: hash,
			});
			m.hasEverHadDevice = true;
			// Retain the key and owner for historical rotation-signature / grant checks
			// (not cleared on removal).
			state.deviceKeys.set(b.deviceId, Buffer.from(b.deviceSignPub, "base64"));
			state.deviceOwners.set(b.deviceId, b.userId);
			break;
		}
		case "remove-device": {
			const devices = state.members.get(b.userId)?.devices;
			if (!devices) break;
			// Revocation is transitive over the enrollment delegation tree, but only
			// for enrollments that are NOT causally before this removal. A device the
			// removed device enrolled earlier (e.g. the owner's phone, enrolled from a
			// laptop later decommissioned) is legitimate prior delegation and must
			// survive. A concurrent/later enrollment — a removed device racing in a
			// replacement — is discarded even if canonical DAG ordering happened to
			// fold that add before this removal.
			const revoked = [b.deviceId];
			for (const deviceId of revoked) {
				devices.delete(deviceId);
				for (const d of devices.values()) {
					if (d.enrolledByDeviceId === deviceId && !ancestorHashes.has(d.enrolledAtHash))
						revoked.push(d.deviceId);
				}
			}
			break;
		}
	}
};

// Validate and fold the DAG into a membership state. Every honest replica
// computes the same result regardless of the order entries arrived in. Invalid
// or unauthorized entries are skipped; only a missing genesis is fatal.
//
// `expectedVaultId` pins the root: a genesis is self-signed by whoever authored
// it, so a hostile relay/peer can gossip a rival genesis whose content hash
// sorts below the real one and — since the root was previously chosen purely by
// hash order — hijack the log (every honest membership entry then fails
// authority and the vault goes unusable). When the caller knows which vault it
// is replaying (the common case: an established replica, or a token whose
// vaultId is authenticated by the enrollment ceremony), only a genesis for that
// vault is accepted. The store-level import guard (engine.importAuthAndRotations)
// additionally refuses any second genesis, so a same-vaultId forgery can never
// enter a replica in the first place.
export const replay = (entries: LogEntry[], expectedVaultId?: string): Membership => {
	const order = linearize(entries);
	// Causal ancestry per entry, computed in topological order (parents precede
	// their children in `order`), so remove-device can distinguish a prior
	// enrollment from a concurrent one.
	const hashes = order.map(entryHash);
	const ancestors = new Map<string, Set<string>>();
	order.forEach((e, i) => {
		const set = new Set<string>();
		for (const p of e.parents) {
			set.add(p);
			for (const a of ancestors.get(p) ?? []) set.add(a);
		}
		ancestors.set(hashes[i]!, set);
	});
	const isRootGenesis = (e: LogEntry): boolean =>
		e.body.type === "genesis" &&
		e.parents.length === 0 &&
		(expectedVaultId === undefined || e.body.vaultId === expectedVaultId);
	const genesis = order.find(isRootGenesis);
	if (!genesis || genesis.body.type !== "genesis") throw new Error("auth log has no genesis");

	const state: Membership = {
		vaultId: genesis.body.vaultId,
		members: new Map(),
		deviceKeys: new Map(),
		deviceOwners: new Map(),
	};
	order.forEach((e, i) => {
		// Exactly one genesis roots the DAG; ignore any others (different vault).
		if (e.body.type === "genesis" && e !== genesis) return;
		try {
			const signerPub = resolveSigner(state, e);
			const ok = verify(
				canonicalBytes(e.parents, e.body, e.signerId, e.signerKind),
				Buffer.from(signerPub, "base64"),
				Buffer.from(e.sig, "base64"),
			);
			if (!ok) return; // bad signature — skip
			applyEntry(state, e, hashes[i]!, ancestors.get(hashes[i]!) ?? new Set());
		} catch {
			// unauthorized signer / inapplicable entry — skip, keep folding the rest
		}
	});
	return state;
};

// A root is trusted for relay pinning only when its self-signature actually
// materializes the claimed creator. replay() intentionally skips bad signatures
// rather than throwing, so merely returning a Membership is not sufficient.
export const validRootGenesis = (entry: LogEntry, expectedVaultId: string): boolean => {
	try {
		if (
			entry.body.type !== "genesis" ||
			entry.body.vaultId !== expectedVaultId ||
			entry.parents.length !== 0
		)
			return false;
		const membership = replay([entry], expectedVaultId);
		const creator = membership.members.get(entry.body.userId);
		return (
			creator?.active === true &&
			creator.role === "owner" &&
			creator.signPub === entry.body.userSignPub &&
			creator.encPub === entry.body.userEncPub
		);
	} catch {
		return false;
	}
};

// Resolve a device's signing public key (for op verification), if authorized.
export const deviceSignKey = (state: Membership, deviceId: string): Buffer | undefined => {
	const m = activeDeviceMember(state, deviceId);
	const d = m?.devices.get(deviceId);
	return d ? Buffer.from(d.signPub, "base64") : undefined;
};
