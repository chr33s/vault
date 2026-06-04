// The vault engine (plan §5): ties core crypto/CRDT/auth-log/store into the
// operations the CLI commands invoke. Holds the local encrypted replica and
// performs all crypto on-device. Zero runtime dependencies.

import {
	replay,
	makeEntry,
	heads,
	deviceSignKey,
	type LogEntry,
	type EntryBody,
	type Role,
	type Membership,
} from "../core/authlog.ts";
import {
	VaultState,
	buildItemOps,
	buildDeleteOp,
	type FieldOp,
	type ItemView,
} from "../core/crdt.ts";
import * as cr from "../core/crypto.ts";
import { Clock, encodeHLC, decodeHLC } from "../core/hlc.ts";
import { deriveKeys, DEFAULT_KDF_PARAMS, type KdfParams } from "../core/kdf.ts";
import { makeEnvelope, rotationId, verifyEnvelope, type OpEnvelope } from "../core/protocol.ts";
import {
	winner,
	keyCommit,
	encodeGrant,
	decodeGrant,
	rotationBytes,
	verifyRotation,
	wellFormedRotation,
	needsCatchUp,
	type RotationRecord,
	type SealedGrant,
} from "../core/rotation.ts";
import { seal, unseal } from "../core/sealedbox.ts";
import { Store } from "../core/store.ts";
import type { KeyStore } from "./keystore.ts";

export type PrivKeys = {
	userSign: Buffer;
	userEnc: Buffer;
	deviceSign: Buffer;
	deviceEnc: Buffer;
};

export type PubKeys = {
	userSign: Buffer;
	userEnc: Buffer;
	deviceSign: Buffer;
	deviceEnc: Buffer;
};

export type Session = {
	store: Store;
	vaultId: string;
	userId: string;
	deviceId: string;
	role: Role;
	priv: PrivKeys;
	pub: PubKeys;
	// Vault keys are keyed by their commitment (hash), not by epoch number, so
	// two concurrent rotations at the same epoch coexist and every op stays
	// decryptable. New writes use `currentKeyCommit` — the deterministic winner.
	keys: Map<string, Buffer>;
	currentEpoch: number;
	currentKeyCommit: string;
	clock: Clock;
	state: VaultState;
};

const idFromPub = (pub: Buffer): string => cr.sha256(pub).toString("hex").slice(0, 16);

// ---- at-rest private-key sealing under the account key ----

type SealedBlob = cr.EncodedBox;

const sealPrivUnderAccountKey = (priv: PrivKeys, accountKey: Buffer): SealedBlob => {
	const json = JSON.stringify({
		userSign: priv.userSign.toString("base64"),
		userEnc: priv.userEnc.toString("base64"),
		deviceSign: priv.deviceSign.toString("base64"),
		deviceEnc: priv.deviceEnc.toString("base64"),
	});
	return cr.encodeBox(cr.aeadEncrypt(accountKey, Buffer.from(json, "utf8")));
};

const openPrivWithAccountKey = (blob: SealedBlob, accountKey: Buffer): PrivKeys => {
	const pt = cr.aeadDecrypt(accountKey, cr.decodeBox(blob));
	const o = JSON.parse(pt.toString("utf8"));
	return {
		userSign: Buffer.from(o.userSign, "base64"),
		userEnc: Buffer.from(o.userEnc, "base64"),
		deviceSign: Buffer.from(o.deviceSign, "base64"),
		deviceEnc: Buffer.from(o.deviceEnc, "base64"),
	};
};

// ---- keystore second factor: fold an OS-protected secret into the wrap key ----

const KEYSTORE_INFO = "credvault/keystore/v1";

// Compute the key that wraps the at-rest private keys. With no keystore it is
// just the account key. With a keystore, it is HKDF(accountKey, DUK) where the
// device unlock key (DUK) lives in the OS keychain — so a stolen disk cannot
// decrypt at any passphrase strength. `create` mints+stores a new DUK (init /
// enrollment); otherwise the DUK is fetched per the vault's recorded provider.
// Mint a NEW wrap key for a vault being initialized/enrolled/re-keyed. When a
// keystore is available it generates a DUK, stores it, and returns the wrap key
// plus the meta the CALLER must persist (provider/id) — atomically with
// encPrivKeys — so a crash can't leave meta pointing at a DUK that encPrivKeys
// isn't yet sealed under. With no keystore the wrap key is just the account key.
// keystoreKeyMode records a provider-specific binding (systemd-creds --with-key
// mode) so unlock can resolve the keystore in the SAME binding the DUK was sealed
// under; "" for providers/vaults with no such knob.
type WrapMeta = { keystoreProvider: string; keystoreId: string; keystoreKeyMode: string };
const createWrapKey = async (
	accountKey: Buffer,
	keystore: KeyStore | undefined,
): Promise<{ wrap: Buffer; meta: WrapMeta }> => {
	if (keystore && (await keystore.available())) {
		const id = `vault-${cr.randomBytes(8).toString("hex")}`;
		const duk = cr.randomBytes(32);
		await keystore.put(id, duk);
		return {
			wrap: cr.hkdf(accountKey, duk, KEYSTORE_INFO, 32),
			meta: {
				keystoreProvider: keystore.name,
				keystoreId: id,
				keystoreKeyMode: keystore.bindingMode?.() ?? "",
			},
		};
	}
	return { wrap: accountKey, meta: { keystoreProvider: "", keystoreId: "", keystoreKeyMode: "" } };
};

// Persist the wrap meta (call inside the same transaction as encPrivKeys).
const persistWrapMeta = (store: Store, meta: WrapMeta): void => {
	store.setMeta("keystoreProvider", meta.keystoreProvider);
	store.setMeta("keystoreId", meta.keystoreId);
	store.setMeta("keystoreKeyMode", meta.keystoreKeyMode);
};

// Recompute the EXISTING wrap key to open a vault (no state change).
const openWrapKey = async (
	store: Store,
	accountKey: Buffer,
	keystore: KeyStore | undefined,
): Promise<Buffer> => {
	const provider = store.getMeta("keystoreProvider");
	if (!provider) return accountKey; // passphrase-only vault
	if (!keystore || keystore.name !== provider)
		throw new Error(`vault is protected by keystore "${provider}", which is unavailable here`);
	const id = store.getMeta("keystoreId");
	if (!id) throw new Error("keystore metadata is corrupt");
	const duk = await keystore.get(id);
	if (!duk)
		throw new Error(
			`cannot unlock: the "${provider}" keystore did not return this device's unlock key ` +
				`(item ${id}). Either access was denied/cancelled (retry), or the key was lost ` +
				`(e.g. the secure-enclave blob or keychain entry was deleted) — if so, re-enroll ` +
				`this device (vault auth → device-add → device-confirm), or restore it from a ` +
				`device that can still unlock.`,
		);
	return cr.hkdf(accountKey, duk, KEYSTORE_INFO, 32);
};

// ---- op payload (keyCommit-tagged AEAD ciphertext of a FieldOp) ----
// `keyCommit` identifies which vault key encrypted this op, so an op survives
// even when concurrent rotations leave several keys live at the same epoch.

type OpPayload = cr.EncodedBox & { keyCommit: string };

const encryptOp = (op: FieldOp, keyCommitHex: string, key: Buffer): Buffer => {
	const box = cr.aeadEncrypt(key, Buffer.from(JSON.stringify(op), "utf8"));
	const p: OpPayload = { keyCommit: keyCommitHex, ...cr.encodeBox(box) };
	return Buffer.from(JSON.stringify(p), "utf8");
};

const decryptOp = (payloadB64: string, keys: Map<string, Buffer>): FieldOp | undefined => {
	const p = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8")) as OpPayload;
	const key = keys.get(p.keyCommit);
	if (!key) return undefined; // encrypted under a key we don't hold
	const pt = cr.aeadDecrypt(key, cr.decodeBox(p));
	return JSON.parse(pt.toString("utf8")) as FieldOp;
};

// ---- meta accessors ----

const requireMeta = (store: Store, k: string): string => {
	const v = store.getMeta(k);
	if (v === undefined) throw new Error(`vault not initialized (missing ${k})`);
	return v;
};

export const isInitialized = (store: Store): boolean =>
	store.getMeta("vaultId") !== undefined && store.getMeta("encPrivKeys") !== undefined;

// Persist the relay coordinates carried in an enrollment token so the new device
// can `vault sync` without re-supplying them. IMPORTANT: the store's `meta` table
// is PLAINTEXT (only item contents and private keys are encrypted), so we never
// persist the bearer secrets here — the app-layer `token` and the Cloudflare
// Access `accessSecret`. Those must be supplied at sync time (flag/env); a stolen
// disk must not yield a working relay credential without the passphrase. We do
// persist the non-secret url + accessId for convenience.
const persistRelay = (store: Store, relay: RelayInfo | undefined): void => {
	if (!relay) return;
	const safe: RelayInfo = { url: relay.url, accessId: relay.accessId };
	store.setMeta("relayInfo", JSON.stringify(safe));
};

// Read back the saved relay coordinates (url + accessId only; secrets are never
// stored — see persistRelay). Used as non-secret defaults by `sync`.
export const savedRelay = (store: Store): RelayInfo | undefined => {
	const raw = store.getMeta("relayInfo");
	return raw ? (JSON.parse(raw) as RelayInfo) : undefined;
};

// ---- auth-log helpers ----

// Build a signed DAG entry that references the current heads of `chain` as its
// parents (heads([]) === [] for genesis). Referencing all heads merges any fork.
const signedEntry = (
	chain: LogEntry[],
	body: EntryBody,
	signerId: string,
	signerKind: "user" | "device",
	signerPriv: Buffer,
): LogEntry => makeEntry(heads(chain), body, signerId, signerKind, signerPriv);

// ---- rotation helpers ----

const loadRotations = (store: Store): RotationRecord[] =>
	store.rotations().map((r) => JSON.parse(r) as RotationRecord);

// Only rotation records whose signature verifies against the signing key of an
// authorized device (ever added — see Membership.deviceKeys) are trusted. This
// rejects forged rotations injected by a non-key-holder such as the relay
// (spec §8.4, §10.2); winner selection and key recovery use only these.
const validRotations = (
	store: Store,
	membership: Membership = replay(store.authLog()),
): RotationRecord[] =>
	loadRotations(store).filter((r) => {
		if (!wellFormedRotation(r)) return false; // reject a nonsensical epoch chain
		const pub = membership.deviceKeys.get(r.signerId);
		return pub !== undefined && verifyRotation(r, pub);
	});

// Recover vault keys from rotation grants sealed to this device, keyed by their
// commitment. Both the winner's and any loser's key at an epoch are recovered.
const recoverEpochKeys = (
	rotations: RotationRecord[],
	deviceEncPub: Buffer,
	deviceEncPriv: Buffer,
): Map<string, Buffer> => {
	const keys = new Map<string, Buffer>();
	const pubB64 = deviceEncPub.toString("base64");
	for (const r of rotations) {
		const g = r.grants[pubB64];
		if (!g) continue;
		try {
			const key = unseal(decodeGrant(g), deviceEncPriv, deviceEncPub);
			if (keyCommit(key) === r.keyCommit) keys.set(r.keyCommit, key);
		} catch {
			/* not for us / corrupt */
		}
	}
	return keys;
};

const signRotation = (
	rec: Omit<RotationRecord, "sig">,
	deviceSignPriv: Buffer,
): RotationRecord => ({
	...rec,
	sig: cr.sign(rotationBytes(rec), deviceSignPriv).toString("base64"),
});

// Vault keys captured at enrollment, sealed to this device (see deviceAdd).
// Stored keyed by commitment; verify the commitment on recovery.
const recoverSelfGrants = (
	store: Store,
	deviceEncPub: Buffer,
	deviceEncPriv: Buffer,
	into: Map<string, Buffer>,
): void => {
	const raw = store.getMeta("selfEpochGrants");
	if (!raw) return;
	const grants = JSON.parse(raw) as Record<string, SealedGrant>;
	for (const [commit, g] of Object.entries(grants)) {
		if (into.has(commit)) continue;
		try {
			const key = unseal(decodeGrant(g), deviceEncPriv, deviceEncPub);
			if (keyCommit(key) === commit) into.set(commit, key);
		} catch {
			/* not for us */
		}
	}
};

// ============================================================================
// init — create a vault + personal keys; bootstrap the auth log (spec §5, §8)
// ============================================================================

export type InitResult = { vaultId: string; userId: string; deviceId: string };

export const init = async (
	store: Store,
	password: string,
	keystore?: KeyStore,
): Promise<InitResult> => {
	if (isInitialized(store)) throw new Error("vault already initialized");

	const kdfParams: KdfParams = DEFAULT_KDF_PARAMS();
	const { accountKey } = await deriveKeys(password, kdfParams);

	const userSign = cr.generateEd25519();
	const userEnc = cr.generateX25519();
	const deviceSign = cr.generateEd25519();
	const deviceEnc = cr.generateX25519();

	const userId = idFromPub(userSign.publicKey);
	const deviceId = idFromPub(deviceSign.publicKey);
	const vaultId = cr.randomBytes(16).toString("hex");

	// Bootstrap auth log: genesis (owner) + this device subkey.
	let chain: LogEntry[] = [];
	chain = [
		signedEntry(
			chain,
			{
				type: "genesis",
				vaultId,
				userId,
				userSignPub: userSign.publicKey.toString("base64"),
				userEncPub: userEnc.publicKey.toString("base64"),
				role: "owner",
			},
			userId,
			"user",
			userSign.privateKey,
		),
	];
	chain = [
		...chain,
		signedEntry(
			chain,
			{
				type: "add-device",
				userId,
				deviceId,
				deviceSignPub: deviceSign.publicKey.toString("base64"),
				deviceEncPub: deviceEnc.publicKey.toString("base64"),
			},
			userId,
			"user",
			userSign.privateKey,
		),
	];

	// Epoch 1 key, sealed to this device (the bootstrap self-grant).
	const k1 = cr.randomBytes(32);
	const rec = signRotation(
		{
			epoch: 1,
			baseEpoch: 0,
			hlc: encodeHLC(new Clock(deviceId).tick()),
			deviceId,
			keyCommit: keyCommit(k1),
			grants: {
				[deviceEnc.publicKey.toString("base64")]: encodeGrant(seal(k1, deviceEnc.publicKey)),
			},
			observed: chain.map((e) => e.hash),
			signerId: deviceId,
		},
		deviceSign.privateKey,
	);

	// Mint the wrap key + its meta BEFORE the transaction (async; may mint a DUK
	// in the OS keystore — a side effect we don't roll back). The wrap meta is
	// then persisted atomically with encPrivKeys, so meta can never point at a DUK
	// that encPrivKeys isn't sealed under.
	const { wrap, meta: wrapMeta } = await createWrapKey(accountKey, keystore);
	const encPrivKeys = JSON.stringify(
		sealPrivUnderAccountKey(
			{
				userSign: userSign.privateKey,
				userEnc: userEnc.privateKey,
				deviceSign: deviceSign.privateKey,
				deviceEnc: deviceEnc.privateKey,
			},
			wrap,
		),
	);

	// Persist atomically: a crash mid-write leaves the vault uninitialized (no
	// partial state), not half-initialized.
	store.transaction(() => {
		store.setMeta("vaultId", vaultId);
		store.setMeta("userId", userId);
		store.setMeta("deviceId", deviceId);
		store.setMeta("role", "owner");
		store.setMeta("kdfParams", JSON.stringify(kdfParams));
		store.setMeta("userSignPub", userSign.publicKey.toString("base64"));
		store.setMeta("userEncPub", userEnc.publicKey.toString("base64"));
		store.setMeta("deviceSignPub", deviceSign.publicKey.toString("base64"));
		store.setMeta("deviceEncPub", deviceEnc.publicKey.toString("base64"));
		persistWrapMeta(store, wrapMeta);
		store.setMeta("encPrivKeys", encPrivKeys);
		for (const e of chain) store.appendAuthEntry(e);
		store.putRotation(rec.epoch, rec.deviceId, JSON.stringify(rec));
	});

	return { vaultId, userId, deviceId };
};

// ============================================================================
// unlock — derive keys, recover epoch keys, validate chain, build replica
// ============================================================================

export const unlock = async (
	store: Store,
	password: string,
	keystore?: KeyStore,
): Promise<Session> => {
	if (!isInitialized(store)) throw new Error("vault not initialized; run `vault init`");
	const kdfParams = JSON.parse(requireMeta(store, "kdfParams")) as KdfParams;
	const { accountKey } = await deriveKeys(password, kdfParams);

	// Fold in the keystore second factor (if this vault is keystore-protected);
	// a missing keystore/DUK raises a distinct error before the passphrase check.
	const wrapKey = await openWrapKey(store, accountKey, keystore);
	let priv: PrivKeys;
	try {
		priv = openPrivWithAccountKey(JSON.parse(requireMeta(store, "encPrivKeys")), wrapKey);
	} catch {
		throw new Error("incorrect passphrase");
	}

	const pub: PubKeys = {
		userSign: Buffer.from(requireMeta(store, "userSignPub"), "base64"),
		userEnc: Buffer.from(requireMeta(store, "userEncPub"), "base64"),
		deviceSign: Buffer.from(requireMeta(store, "deviceSignPub"), "base64"),
		deviceEnc: Buffer.from(requireMeta(store, "deviceEncPub"), "base64"),
	};

	const vaultId = requireMeta(store, "vaultId");
	const userId = requireMeta(store, "userId");
	const deviceId = requireMeta(store, "deviceId");
	const role = (store.getMeta("role") as Role) ?? "member";

	// Validate the membership chain.
	const membership = replay(store.authLog());

	// Recover vault keys (by commitment): from signature-verified rotation grants
	// sealed to this device, plus any self-grants captured at enrollment.
	const rotations = validRotations(store, membership);
	const keys = recoverEpochKeys(rotations, pub.deviceEnc, priv.deviceEnc);
	recoverSelfGrants(store, pub.deviceEnc, priv.deviceEnc, keys);
	const win = winner(rotations); // top epoch, deterministic (hlc,deviceId) winner

	const session: Session = {
		store,
		vaultId,
		userId,
		deviceId,
		role,
		priv,
		pub,
		keys,
		currentEpoch: win?.epoch ?? 1,
		currentKeyCommit: win?.keyCommit ?? "",
		clock: new Clock(deviceId),
		state: new VaultState(),
	};

	// Build the materialized replica by decrypting + verifying ops.
	rebuildState(session, membership);
	// If recovery escrow is enabled, ensure this user has contributed a grant.
	contributeRecovery(session);
	return session;
};

// Re-validate the auth log and rebuild the materialized replica from the op
// log (used after a sync round pulls in new ops). Also refreshes the current
// epoch and winning key.
export const rebuildSession = (s: Session): void => {
	const membership = replay(s.store.authLog());
	const rotations = validRotations(s.store, membership);
	// Recompute the key set from scratch (like unlock) rather than accumulating
	// into the existing map, so a key whose rotation is no longer valid is dropped.
	s.keys = recoverEpochKeys(rotations, s.pub.deviceEnc, s.priv.deviceEnc);
	recoverSelfGrants(s.store, s.pub.deviceEnc, s.priv.deviceEnc, s.keys);
	const win = winner(rotations);
	if (win) {
		s.currentEpoch = win.epoch;
		s.currentKeyCommit = win.keyCommit;
	}
	rebuildState(s, membership);
};

// Merge auth-log entries and rotation records pulled during sync. The auth log
// is a signed Merkle DAG: simply add entries we don't already hold (by hash).
// Order, fork reconciliation, and authority are all resolved at replay time, so
// a divergent branch is absorbed and linearized deterministically rather than
// rejected — no fork is "lost".
export const importAuthAndRotations = (
	s: Session,
	incomingAuth: LogEntry[],
	incomingRotations: string[],
): { authImported: number; rotationsImported: number } => {
	let authImported = 0;
	const have = new Set(s.store.authHashes());
	for (const e of incomingAuth) {
		if (!have.has(e.hash)) {
			s.store.appendAuthEntry(e);
			have.add(e.hash);
			authImported++;
		}
	}

	let rotationsImported = 0;
	const haveRot = new Set(
		s.store.rotations().map((r) => {
			const o = JSON.parse(r) as RotationRecord;
			return rotationId(o.epoch, o.deviceId);
		}),
	);
	for (const rec of incomingRotations) {
		const r = JSON.parse(rec) as RotationRecord;
		if (!haveRot.has(rotationId(r.epoch, r.deviceId))) {
			s.store.putRotation(r.epoch, r.deviceId, rec);
			rotationsImported++;
		}
	}
	return { authImported, rotationsImported };
};

// Verify every op's signature against the auth log, decrypt, and merge.
const rebuildState = (s: Session, membership = replay(s.store.authLog())): void => {
	s.state = new VaultState();
	let maxHlc = "";
	for (const op of s.store.allOps()) {
		const signPub = deviceSignKey(membership, op.deviceId);
		if (!signPub) continue; // op from an unknown/revoked device — reject
		if (!verifyEnvelope(op, signPub)) continue;
		const field = decryptOp(op.payload, s.keys);
		if (field) {
			s.state.apply(field);
			if (field.hlc > maxHlc) maxHlc = field.hlc; // encodeHLC is fixed-width: string max == logical max
		}
	}
	// Advance the local clock past everything observed so the next local edit
	// always outranks prior writes it has seen (the "logical" half of the HLC).
	if (maxHlc) s.clock.observe(decodeHLC(maxHlc));
};

// ---- emit ops for a set of field changes ----

const emitOps = (s: Session, ops: FieldOp[]): void => {
	const key = s.keys.get(s.currentKeyCommit);
	if (!key) throw new Error("no key for the current epoch (locked out?)");
	let seq = s.store.maxSeqFor(s.deviceId);
	const envelopes: OpEnvelope[] = [];
	for (const op of ops) {
		seq += 1;
		const payload = encryptOp(op, s.currentKeyCommit, key);
		envelopes.push(makeEnvelope(s.deviceId, seq, payload, s.priv.deviceSign));
		s.state.apply(op);
	}
	s.store.putOps(envelopes);
};

// ============================================================================
// item CRUD (spec §4, §7.1)
// ============================================================================

export type ItemFields = Record<string, string | null>;

const findByTitle = (s: Session, title: string): ItemView | undefined =>
	s.state.list().find((i) => i.fields.title === title);

export const addItem = (s: Session, title: string, fields: ItemFields): string => {
	const itemId = cr.randomBytes(16).toString("hex");
	const ops = buildItemOps(itemId, { title, ...fields }, () => encodeHLC(s.clock.tick()));
	emitOps(s, ops);
	return itemId;
};

export const editItem = (s: Session, title: string, fields: ItemFields): void => {
	const item = findByTitle(s, title);
	if (!item) throw new Error(`no item titled "${title}"`);
	const livePw = s.state.livePasswordHlcs(item.itemId);
	const ops = buildItemOps(item.itemId, fields, () => encodeHLC(s.clock.tick()), livePw);
	emitOps(s, ops);
};

export const removeItem = (s: Session, title: string): void => {
	const item = findByTitle(s, title);
	if (!item) throw new Error(`no item titled "${title}"`);
	emitOps(s, [buildDeleteOp(item.itemId, encodeHLC(s.clock.tick()))]);
};

export const getItem = (s: Session, title: string): ItemView | undefined => findByTitle(s, title);

export const listItems = (s: Session): ItemView[] => s.state.list();

// ============================================================================
// rotation / revocation (spec §10.2)
// ============================================================================

// Issue a new epoch, sealing the fresh key to every active device of the
// remaining members. Re-encrypt local items lazily under the new epoch by
// re-emitting their fields (small credential volumes).
export const rotate = (s: Session, membership = replay(s.store.authLog())): number => {
	const rotations = validRotations(s.store, membership);
	const win = winner(rotations);
	const baseEpoch = win?.epoch ?? 0;
	const epoch = baseEpoch + 1;
	const newKey = cr.randomBytes(32);

	const grants: Record<string, SealedGrant> = {};
	for (const m of membership.members.values()) {
		if (!m.active) continue;
		for (const d of m.devices.values()) {
			const encPub = Buffer.from(d.encPub, "base64");
			grants[d.encPub] = encodeGrant(seal(newKey, encPub));
		}
	}

	const rec = signRotation(
		{
			epoch,
			baseEpoch,
			hlc: encodeHLC(s.clock.tick()),
			deviceId: s.deviceId,
			keyCommit: keyCommit(newKey),
			grants,
			observed: s.store.authHashes(),
			signerId: s.deviceId,
		},
		s.priv.deviceSign,
	);
	s.store.putRotation(rec.epoch, rec.deviceId, JSON.stringify(rec));
	s.keys.set(rec.keyCommit, newKey);
	s.currentEpoch = epoch;
	s.currentKeyCommit = rec.keyCommit;

	// Re-encrypt existing items under the new epoch. If a concurrent rotation
	// later wins this epoch, the next sync adopts its key and re-emits again.
	for (const item of s.state.list()) {
		const fields: ItemFields = { ...item.fields };
		if (item.passwords.length > 0) fields.password = item.passwords[item.passwords.length - 1]!;
		const livePw = s.state.livePasswordHlcs(item.itemId);
		emitOps(
			s,
			buildItemOps(item.itemId, fields, () => encodeHLC(s.clock.tick()), livePw),
		);
	}
	return epoch;
};

// Remove a person (revokes their whole device set) and rotate so they cannot
// read new data (spec §9, §10.2).
export const removeUser = (s: Session, userId: string): number => {
	const chain = s.store.authLog();
	const membership = replay(chain);
	if (s.role !== "owner" && s.role !== "admin") throw new Error("only admins may remove users");
	if (!membership.members.has(userId)) throw new Error(`no such member ${userId}`);

	const entry = signedEntry(
		chain,
		{ type: "remove-user", userId },
		s.userId,
		"user",
		s.priv.userSign,
	);
	s.store.appendAuthEntry(entry);
	return rotate(s, replay(s.store.authLog()));
};

// Remove a single device subkey (e.g. a lost laptop) and rotate, leaving the
// owning user and their other devices intact (spec §9). Signed by the owning
// user or an admin (authority enforced in authlog.replay).
export const removeDevice = (s: Session, deviceId: string): number => {
	const chain = s.store.authLog();
	const membership = replay(chain);
	let ownerId: string | undefined;
	for (const m of membership.members.values()) {
		if (m.active && m.devices.has(deviceId)) ownerId = m.userId;
	}
	if (!ownerId) throw new Error(`no such active device ${deviceId}`);
	if (s.userId !== ownerId && s.role !== "owner" && s.role !== "admin")
		throw new Error("only the owning user or an admin may remove a device");

	const entry = signedEntry(
		chain,
		{ type: "remove-device", userId: ownerId, deviceId },
		s.userId,
		"user",
		s.priv.userSign,
	);
	s.store.appendAuthEntry(entry);
	return rotate(s, replay(s.store.authLog()));
};

// After sync, check whether a security catch-up rotation is required and, if so,
// issue one (spec §10.2). Returns the new epoch, or undefined if none needed.
export const maybeCatchUp = (s: Session): number | undefined => {
	const chain = s.store.authLog();
	const win = winner(validRotations(s.store, replay(chain)));
	const removalHashes = chain
		.filter((e) => e.body.type === "remove-user" || e.body.type === "remove-device")
		.map((e) => e.hash);
	if (needsCatchUp(win, removalHashes)) {
		return rotate(s, replay(chain));
	}
	return undefined;
};

// ============================================================================
// device enrollment (spec §9)
// ============================================================================

export type TokenA = { deviceId: string; signPub: string; encPub: string };

// Relay coordinates handed to a newly-enrolled device in Token B / the Join
// Token (spec §9). Carries the hostname plus whichever credential the relay is
// gated by: the app-layer token and/or a Cloudflare Access service token. The
// new device feeds these straight into `vault sync` (see relayAuthFromInfo).
export type RelayInfo = {
	url: string;
	token?: string; // app-layer (VAULT_RELAY_TOKENS / cf-access-token)
	accessId?: string; // Cloudflare Access service-token client id
	accessSecret?: string; // Cloudflare Access service-token client secret
};

export type TokenB = {
	vaultId: string;
	userId: string;
	role: Role;
	currentEpoch: number;
	authLog: LogEntry[];
	rotations: RotationRecord[];
	epochGrants: Record<string, SealedGrant>; // keyCommit -> vault key sealed to new device
	userPriv: SealedGrant; // {userSign,userEnc} sealed to new device
	relay?: RelayInfo;
	sas: string; // short authentication string for mutual verification
};

// `auth` on the new device: create local device keys, persist them sealed under
// the (new device's) account key, and emit Token A. The user identity keys are
// not known yet — they arrive in Token B at confirm.
export const authNewDevice = async (store: Store, password: string): Promise<TokenA> => {
	if (isInitialized(store)) throw new Error("vault already initialized on this device");
	const kdfParams = DEFAULT_KDF_PARAMS();
	const { accountKey } = await deriveKeys(password, kdfParams);
	const deviceSign = cr.generateEd25519();
	const deviceEnc = cr.generateX25519();
	const deviceId = idFromPub(deviceSign.publicKey);

	// Seal device privs under the account key (verifies the password at confirm).
	const blob = cr.aeadEncrypt(
		accountKey,
		Buffer.from(
			JSON.stringify({
				deviceSign: deviceSign.privateKey.toString("base64"),
				deviceEnc: deviceEnc.privateKey.toString("base64"),
			}),
			"utf8",
		),
	);

	store.setMeta("pending", "1");
	store.setMeta("deviceId", deviceId);
	store.setMeta("kdfParams", JSON.stringify(kdfParams));
	store.setMeta("deviceSignPub", deviceSign.publicKey.toString("base64"));
	store.setMeta("deviceEncPub", deviceEnc.publicKey.toString("base64"));
	store.setMeta("pendingPriv", JSON.stringify(cr.encodeBox(blob)));

	return {
		deviceId,
		signPub: deviceSign.publicKey.toString("base64"),
		encPub: deviceEnc.publicKey.toString("base64"),
	};
};

const sasOf = (a: Buffer, b: Buffer): string => {
	const h = cr.sha256(Buffer.concat([a, b]));
	const n = h.readUInt32BE(0) % 1_000_000;
	return String(n).padStart(6, "0");
};

// `device-add` on an authorized device: seal grants, sign add-device, build Token B.
export const deviceAdd = (
	s: Session,
	tokenA: TokenA,
	opts: { role?: Role; relay?: RelayInfo } = {},
): TokenB => {
	const newEncPub = Buffer.from(tokenA.encPub, "base64");
	const newSignPub = Buffer.from(tokenA.signPub, "base64");

	// Append the signed add-device entry under this user's identity.
	const chain = s.store.authLog();
	const entry = signedEntry(
		chain,
		{
			type: "add-device",
			userId: s.userId,
			deviceId: tokenA.deviceId,
			deviceSignPub: tokenA.signPub,
			deviceEncPub: tokenA.encPub,
		},
		s.userId,
		"user",
		s.priv.userSign,
	);
	s.store.appendAuthEntry(entry);

	// Re-seal every vault key we hold (by commitment) to the new device.
	const epochGrants: Record<string, SealedGrant> = {};
	for (const [commit, key] of s.keys) {
		epochGrants[commit] = encodeGrant(seal(key, newEncPub));
	}

	// Seal the user private identity keys to the new device (full member).
	const userPrivJson = JSON.stringify({
		userSign: s.priv.userSign.toString("base64"),
		userEnc: s.priv.userEnc.toString("base64"),
	});
	const userPriv = encodeGrant(seal(Buffer.from(userPrivJson, "utf8"), newEncPub));

	return {
		vaultId: s.vaultId,
		userId: s.userId,
		role: opts.role ?? s.role,
		currentEpoch: s.currentEpoch,
		authLog: s.store.authLog(),
		rotations: loadRotations(s.store),
		epochGrants,
		userPriv,
		relay: opts.relay,
		sas: sasOf(s.pub.deviceEnc, newSignPub),
	};
};

// `device-confirm` on the new device: validate Token B, unseal the vault and
// user keys, build the local replica. Returns the SAS for mutual verification.
export const deviceConfirm = async (
	store: Store,
	password: string,
	tokenB: TokenB,
	keystore?: KeyStore,
): Promise<{ sas: string }> => {
	if (store.getMeta("pending") !== "1") throw new Error("run `vault auth` first on this device");
	const kdfParams = JSON.parse(requireMeta(store, "kdfParams")) as KdfParams;
	const { accountKey } = await deriveKeys(password, kdfParams);
	const deviceId = requireMeta(store, "deviceId");
	const deviceEncPub = Buffer.from(requireMeta(store, "deviceEncPub"), "base64");

	// Recover this device's private keys (also verifies the passphrase).
	let deviceSign: Buffer;
	let deviceEnc: Buffer;
	try {
		const blob = JSON.parse(requireMeta(store, "pendingPriv")) as SealedBlob;
		const pt = cr.aeadDecrypt(accountKey, cr.decodeBox(blob));
		const o = JSON.parse(pt.toString("utf8"));
		deviceSign = Buffer.from(o.deviceSign, "base64");
		deviceEnc = Buffer.from(o.deviceEnc, "base64");
	} catch {
		throw new Error("incorrect passphrase");
	}

	// Validate the membership chain and confirm this device is authorized in it.
	const membership = replay(tokenB.authLog);
	if (!deviceSignKey(membership, deviceId))
		throw new Error("auth log does not authorize this device");
	const ownerMember = membership.members.get(tokenB.userId);
	if (!ownerMember) throw new Error("auth log missing the enrolling user");

	// Unseal the user private identity keys (sealed to this device in Token B).
	const up = JSON.parse(
		unseal(decodeGrant(tokenB.userPriv), deviceEnc, deviceEncPub).toString("utf8"),
	);
	const userSign = Buffer.from(up.userSign, "base64");
	const userEnc = Buffer.from(up.userEnc, "base64");

	// Mint the wrap key + meta BEFORE the transaction (async; may mint a DUK).
	const { wrap, meta: wrapMeta } = await createWrapKey(accountKey, keystore);
	const encPrivKeys = JSON.stringify(
		sealPrivUnderAccountKey({ userSign, userEnc, deviceSign, deviceEnc }, wrap),
	);

	// Persist atomically: vault identity, auth log, rotations, self-grants, relay.
	store.transaction(() => {
		store.setMeta("vaultId", tokenB.vaultId);
		store.setMeta("userId", tokenB.userId);
		store.setMeta("role", tokenB.role);
		store.setMeta("userSignPub", ownerMember.signPub);
		store.setMeta("userEncPub", ownerMember.encPub);
		persistWrapMeta(store, wrapMeta);
		store.setMeta("encPrivKeys", encPrivKeys);
		for (const e of tokenB.authLog) store.appendAuthEntry(e);
		for (const r of tokenB.rotations) store.putRotation(r.epoch, r.deviceId, JSON.stringify(r));
		store.setMeta("selfEpochGrants", JSON.stringify(tokenB.epochGrants));
		persistRelay(store, tokenB.relay);
		store.setMeta("pending", "0");
	});

	return { sas: tokenB.sas };
};

// ============================================================================
// cross-user sharing (spec §4 KeyGrant, §5 membership, §9). A different person
// joins a vault: they hold their OWN user identity (not a device subkey of an
// existing user). An admin appends a signed `add-user` and seals the epoch
// key(s) to the joiner's device; the joiner appends their own `add-device`.
// ============================================================================

// Generated by the joining person; carried out-of-band to an admin.
export type InviteToken = {
	userId: string;
	userSignPub: string;
	userEncPub: string;
	deviceId: string;
	deviceSignPub: string;
	deviceEncPub: string;
};

// Returned by the admin's `share`; carried back to the joiner.
export type JoinToken = {
	vaultId: string;
	userId: string;
	role: Role;
	currentEpoch: number;
	authLog: LogEntry[];
	rotations: RotationRecord[];
	epochGrants: Record<string, SealedGrant>; // keyCommit -> vault key sealed to joiner device
	relay?: RelayInfo;
	sas: string;
};

// `invite` on the joining person's device: create a fresh user identity + first
// device subkey, persist sealed under the account key, emit the Invite Token.
export const inviteInit = async (store: Store, password: string): Promise<InviteToken> => {
	if (isInitialized(store)) throw new Error("vault already initialized on this device");
	const kdfParams = DEFAULT_KDF_PARAMS();
	const { accountKey } = await deriveKeys(password, kdfParams);

	const userSign = cr.generateEd25519();
	const userEnc = cr.generateX25519();
	const deviceSign = cr.generateEd25519();
	const deviceEnc = cr.generateX25519();
	const userId = idFromPub(userSign.publicKey);
	const deviceId = idFromPub(deviceSign.publicKey);

	store.setMeta("pending", "invite");
	store.setMeta("kdfParams", JSON.stringify(kdfParams));
	store.setMeta("userId", userId);
	store.setMeta("deviceId", deviceId);
	store.setMeta("userSignPub", userSign.publicKey.toString("base64"));
	store.setMeta("userEncPub", userEnc.publicKey.toString("base64"));
	store.setMeta("deviceSignPub", deviceSign.publicKey.toString("base64"));
	store.setMeta("deviceEncPub", deviceEnc.publicKey.toString("base64"));
	store.setMeta(
		"pendingInvitePriv",
		JSON.stringify(
			sealPrivUnderAccountKey(
				{
					userSign: userSign.privateKey,
					userEnc: userEnc.privateKey,
					deviceSign: deviceSign.privateKey,
					deviceEnc: deviceEnc.privateKey,
				},
				accountKey,
			),
		),
	);

	return {
		userId,
		userSignPub: userSign.publicKey.toString("base64"),
		userEncPub: userEnc.publicKey.toString("base64"),
		deviceId,
		deviceSignPub: deviceSign.publicKey.toString("base64"),
		deviceEncPub: deviceEnc.publicKey.toString("base64"),
	};
};

// `share` on an admin device: append a signed `add-user`, seal every epoch key
// to the joiner's device, and build the Join Token.
export const shareVault = (
	s: Session,
	invite: InviteToken,
	opts: { role?: Role; relay?: RelayInfo } = {},
): JoinToken => {
	if (s.role !== "owner" && s.role !== "admin") throw new Error("only admins may share a vault");
	const role: Role = opts.role ?? "member";

	const chain = s.store.authLog();
	const entry = signedEntry(
		chain,
		{
			type: "add-user",
			userId: invite.userId,
			userSignPub: invite.userSignPub,
			userEncPub: invite.userEncPub,
			role,
		},
		s.userId,
		"user",
		s.priv.userSign,
	);
	s.store.appendAuthEntry(entry);

	const joinerEncPub = Buffer.from(invite.deviceEncPub, "base64");
	const epochGrants: Record<string, SealedGrant> = {};
	for (const [commit, key] of s.keys) {
		epochGrants[commit] = encodeGrant(seal(key, joinerEncPub));
	}

	return {
		vaultId: s.vaultId,
		userId: invite.userId,
		role,
		currentEpoch: s.currentEpoch,
		authLog: s.store.authLog(),
		rotations: loadRotations(s.store),
		epochGrants,
		relay: opts.relay,
		sas: sasOf(s.pub.deviceEnc, Buffer.from(invite.deviceSignPub, "base64")),
	};
};

// `join` on the joining person's device: validate the Join Token, append the
// joiner's own signed `add-device`, persist identity, build the local replica.
export const joinConfirm = async (
	store: Store,
	password: string,
	join: JoinToken,
	keystore?: KeyStore,
): Promise<{ userId: string; sas: string }> => {
	if (store.getMeta("pending") !== "invite")
		throw new Error("run `vault invite` first on this device");
	const kdfParams = JSON.parse(requireMeta(store, "kdfParams")) as KdfParams;
	const { accountKey } = await deriveKeys(password, kdfParams);
	const userId = requireMeta(store, "userId");
	const deviceId = requireMeta(store, "deviceId");
	const deviceSignPub = requireMeta(store, "deviceSignPub");
	const deviceEncPubB64 = requireMeta(store, "deviceEncPub");

	// Recover our private keys (also verifies the passphrase).
	let priv: PrivKeys;
	try {
		priv = openPrivWithAccountKey(JSON.parse(requireMeta(store, "pendingInvitePriv")), accountKey);
	} catch {
		throw new Error("incorrect passphrase");
	}

	// Validate the chain and confirm an admin actually added us.
	const membership = replay(join.authLog);
	const me = membership.members.get(userId);
	if (!me || !me.active) throw new Error("join token does not grant this user membership");

	// Build our own device subkey entry against the imported chain (signed by our
	// user identity key — authorized because we are now a member), and verify the
	// extended chain in-memory BEFORE persisting anything.
	const addDevice = signedEntry(
		join.authLog,
		{
			type: "add-device",
			userId,
			deviceId,
			deviceSignPub,
			deviceEncPub: deviceEncPubB64,
		},
		userId,
		"user",
		priv.userSign,
	);
	replay([...join.authLog, addDevice]); // throws if the extended chain is invalid

	// Mint the wrap key + meta BEFORE the transaction (async; may mint a DUK).
	const { wrap, meta: wrapMeta } = await createWrapKey(accountKey, keystore);
	const encPrivKeys = JSON.stringify(sealPrivUnderAccountKey(priv, wrap));

	// Persist atomically.
	store.transaction(() => {
		for (const e of join.authLog) store.appendAuthEntry(e);
		store.appendAuthEntry(addDevice);
		for (const r of join.rotations) store.putRotation(r.epoch, r.deviceId, JSON.stringify(r));
		store.setMeta("vaultId", join.vaultId);
		store.setMeta("role", join.role);
		persistWrapMeta(store, wrapMeta);
		store.setMeta("encPrivKeys", encPrivKeys);
		store.setMeta("selfEpochGrants", JSON.stringify(join.epochGrants));
		persistRelay(store, join.relay);
		store.setMeta("pending", "0");
	});

	return { userId, sas: join.sas };
};

// ============================================================================
// recovery escrow (spec §5, §13 — DECIDED: offer admin-assisted recovery).
// An org keypair lets owners reconstruct a locked-out member. Each member seals
// their identity keys to the org PUBLIC key (a RecoveryGrant); the org PRIVATE
// key is held offline by the owner. Tradeoff is explicit: the org *can* access
// member data — zero-knowledge against infrastructure, not against the org.
// Grants (and the org-key announcement) propagate over the grants sync channel.
// ============================================================================

const ORG_PRINCIPAL = "orgPublicKey";
const recoveryPrincipal = (userId: string): string => `recovery:${userId}`;

// Enable escrow: mint the org keypair, announce the org public key, contribute
// the caller's own RecoveryGrant. Returns the org PRIVATE key (base64) for the
// owner to store offline — it is never persisted in the vault.
export const recoveryEnable = (s: Session): string => {
	if (s.role !== "owner") throw new Error("only the owner may enable recovery escrow");
	if (s.store.getGrant(s.vaultId, ORG_PRINCIPAL, 0))
		throw new Error("recovery escrow already enabled");
	const org = cr.generateX25519();
	s.store.putGrant(s.vaultId, ORG_PRINCIPAL, 0, org.publicKey.toString("base64"));
	contributeRecovery(s);
	return org.privateKey.toString("base64");
};

// If escrow is enabled and we haven't yet sealed our identity to the org key,
// do so now. Idempotent; safe to call on every unlock/sync.
export const contributeRecovery = (s: Session): void => {
	const orgPubB64 = s.store.getGrant(s.vaultId, ORG_PRINCIPAL, 0);
	if (!orgPubB64) return;
	if (s.store.getGrant(s.vaultId, recoveryPrincipal(s.userId), 0)) return;
	const orgPub = Buffer.from(orgPubB64, "base64");
	const material = Buffer.from(
		JSON.stringify({
			userSign: s.priv.userSign.toString("base64"),
			userEnc: s.priv.userEnc.toString("base64"),
		}),
		"utf8",
	);
	const sealed = encodeGrant(seal(material, orgPub));
	s.store.putGrant(s.vaultId, recoveryPrincipal(s.userId), 0, JSON.stringify(sealed));
};

// Reconstruct a member's identity keys using the org private key (held offline).
// Returns the recovered keys as a JSON string for secure out-of-band delivery.
export const recoverUser = (s: Session, userId: string, orgPrivB64: string): string => {
	if (s.role !== "owner") throw new Error("only the owner may run recovery");
	const orgPubB64 = s.store.getGrant(s.vaultId, ORG_PRINCIPAL, 0);
	if (!orgPubB64) throw new Error("recovery escrow is not enabled");
	const g = s.store.getGrant(s.vaultId, recoveryPrincipal(userId), 0);
	if (!g)
		throw new Error(`no recovery grant for ${userId} (have they synced since escrow was enabled?)`);
	const sealed = decodeGrant(JSON.parse(g) as SealedGrant);
	try {
		const pt = unseal(sealed, Buffer.from(orgPrivB64, "base64"), Buffer.from(orgPubB64, "base64"));
		return pt.toString("utf8");
	} catch {
		throw new Error("recovery failed: org key does not match, or the grant is corrupt");
	}
};

// ============================================================================
// keystore second factor — enable/disable/status on an existing vault
// ============================================================================

export type KeystoreStatus = {
	provider: string | undefined;
	protected: boolean;
	keyMode: string | undefined; // provider-specific binding the vault is sealed under
};

export const keystoreStatus = (store: Store): KeystoreStatus => {
	const provider = store.getMeta("keystoreProvider");
	return {
		provider: provider || undefined,
		protected: !!provider,
		keyMode: store.getMeta("keystoreKeyMode") || undefined,
	};
};

// Re-wrap the at-rest private keys with (enable=true) or without (enable=false)
// the OS-keychain second factor. `keystore` is the platform keystore, used both
// to read the current DUK (if already protected) and to mint a new one. Returns
// the resulting provider name or "none".
export const setKeystore = async (
	store: Store,
	password: string,
	enable: boolean,
	keystore: KeyStore | undefined,
): Promise<string> => {
	if (!isInitialized(store)) throw new Error("vault not initialized");
	if (enable && !(keystore && (await keystore.available())))
		throw new Error("no OS keystore is available on this platform");

	const kdfParams = JSON.parse(requireMeta(store, "kdfParams")) as KdfParams;
	const { accountKey } = await deriveKeys(password, kdfParams);

	// Open with the current wrap key (needs the keystore if already protected).
	const currentWrap = await openWrapKey(store, accountKey, keystore);
	let priv: PrivKeys;
	try {
		priv = openPrivWithAccountKey(JSON.parse(requireMeta(store, "encPrivKeys")), currentWrap);
	} catch {
		throw new Error("incorrect passphrase");
	}

	const oldProvider = store.getMeta("keystoreProvider");
	const oldId = store.getMeta("keystoreId");

	// Mint the new wrap (account key for disable; fresh DUK for enable) and re-seal
	// BEFORE persisting, then commit provider/id + encPrivKeys atomically so the
	// stored state is always self-consistent. Delete the old DUK only AFTER commit,
	// when nothing references it (a crash before commit leaves the old setup intact).
	const { wrap, meta } = enable
		? await createWrapKey(accountKey, keystore)
		: { wrap: accountKey, meta: { keystoreProvider: "", keystoreId: "", keystoreKeyMode: "" } };
	const reSealed = JSON.stringify(sealPrivUnderAccountKey(priv, wrap));
	store.transaction(() => {
		persistWrapMeta(store, meta);
		store.setMeta("encPrivKeys", reSealed);
	});
	if (
		oldProvider &&
		oldId &&
		keystore &&
		keystore.name === oldProvider &&
		oldId !== meta.keystoreId
	)
		await keystore.del(oldId);
	return store.getMeta("keystoreProvider") || "none";
};
