// Minimal, dependency-free TPM2 command codec (TCG "Part 1/2/3" wire format) — just
// enough to SEAL a small secret (the DUK) to the TPM under a deterministic primary
// and UNSEAL it, gated by a PIN (authValue) so unseal is per-access and the TPM
// enforces dictionary-attack lockout. Talks raw command/response buffers through a
// `submit` function (see transport.ts); no /dev or sockets here.
//
// HARDENED SESSIONS: authorization uses a SALTED HMAC session (ECDH to a TPM NULL-
// hierarchy primary -> KDFe -> KDFa session key), and the secret-bearing parameters
// are encrypted on the bus — the sealed data on Create (decrypt session) and the
// unsealed data on Unseal (encrypt session) never cross the CPU↔TPM link in the
// clear, and the PIN is folded into the HMAC key rather than sent. This defeats
// passive TPM bus sniffing on discrete TPMs. (Salting via the NULL primary follows
// the Linux kernel's approach; it stops a passive sniffer but not an active on-bus
// MITM that substitutes its own salt key — full defense needs a cert-verified EK.)
//
// Validated end-to-end against the swtpm TPM2 emulator: seal -> (fresh connection,
// re-derived deterministic primary) -> unseal round-trips the secret with the DUK
// encrypted in both directions, and a wrong PIN is rejected with TPM_RC_AUTH_FAIL.

import {
	createCipheriv,
	createDecipheriv,
	createECDH,
	createHash,
	createHmac,
	randomBytes,
} from "node:crypto";

export type Submit = (cmd: Buffer) => Promise<Buffer>;

const u8 = (n: number): Buffer => Buffer.from([n & 0xff]);
const u16 = (n: number): Buffer => {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(n);
	return b;
};
const u32 = (n: number): Buffer => {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(n);
	return b;
};
// TPM2B: a length-prefixed (UINT16) byte block.
const t2b = (b: Buffer): Buffer => Buffer.concat([u16(b.length), b]);

const ST_SESSIONS = 0x8002;
const ST_NO_SESSIONS = 0x8001;
const RH_OWNER = 0x40000001;
const RH_NULL = 0x40000007;
const RS_PW = 0x40000009; // the password (cleartext) "session", used for no-secret commands
const SHA256 = 0x000b;
const CC = {
	SelfTest: 0x143,
	StartAuthSession: 0x176,
	CreatePrimary: 0x131,
	Create: 0x153,
	Load: 0x157,
	Unseal: 0x15e,
	FlushContext: 0x165,
} as const;
// sessionAttributes bits
const ATTR_CONTINUE = 0x01;
const ATTR_DECRYPT = 0x20; // encrypt the first command parameter
const ATTR_ENCRYPT = 0x40; // the first response parameter is encrypted

const sha = (b: Buffer): Buffer => createHash("sha256").update(b).digest();
const hmac = (key: Buffer, b: Buffer): Buffer => createHmac("sha256", key).update(b).digest();

// KDFa (TPM SP800-108 counter mode, HMAC-SHA256) and KDFe (SP800-56A concat KDF) —
// the TPM's two key-derivation functions, used for the session key, the ECDH salt,
// and the CFB parameter-encryption key/IV. Labels are null-terminated per spec.
const kdf =
	(prf: (key: Buffer, data: Buffer) => Buffer, withCounterKey: boolean) =>
	(key: Buffer, label: string, ctxU: Buffer, ctxV: Buffer, bits: number): Buffer => {
		const need = bits / 8;
		const lbl = Buffer.concat([Buffer.from(label, "ascii"), u8(0)]);
		const out: Buffer[] = [];
		for (let i = 1; Buffer.concat(out).length < need; i++) {
			const block = withCounterKey
				? Buffer.concat([u32(i), lbl, ctxU, ctxV, u32(bits)]) // KDFa: HMAC(key, i‖label‖u‖v‖bits)
				: Buffer.concat([u32(i), key, lbl, ctxU, ctxV]); // KDFe: H(i‖Z‖label‖u‖v)
			out.push(withCounterKey ? prf(key, block) : prf(Buffer.alloc(0), block));
		}
		return Buffer.concat(out).subarray(0, need);
	};
const kdfa = kdf((key, data) => hmac(key, data), true);
const kdfe = kdf((_key, data) => sha(data), false);

export class Tpm2Error extends Error {
	readonly command: string;
	readonly rc: number;
	constructor(command: string, rc: number) {
		super(`TPM2 ${command} failed: rc=0x${rc.toString(16)}`);
		this.name = "Tpm2Error";
		this.command = command;
		this.rc = rc;
	}
}

// TPM_RC_AUTH_FAIL (0x9e, format-1 so 0x08e + session N) and TPM_RC_*_LOCKOUT
// (0x921) mean "wrong/blocked PIN" rather than a malformed request — the provider
// maps these to "no secret" (undefined) instead of a hard error.
export const isAuthFailure = (rc: number): boolean => (rc & 0xbf) === 0x8e || rc === 0x921;

const rcOf = (resp: Buffer): number => resp.readUInt32BE(6);

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// Submit, transparently resending while the TPM answers TPM_RC_RETRY (0x922) or
// TPM_RC_TESTING (0x90a) — the deferred-self-test window after startup. These mean
// the command did NOT execute, so resending the same bytes is safe.
const submitReady = async (submit: Submit, cmd: Buffer): Promise<Buffer> => {
	for (let i = 0; i < 50; i++) {
		const r = await submit(cmd);
		const rc = rcOf(r);
		if (rc !== 0x922 && rc !== 0x90a) return r;
		await sleep(20);
	}
	return submit(cmd);
};

// tag · size(patched) · code · body
const build = (tag: number, code: number, body: Buffer): Buffer => {
	const cmd = Buffer.concat([u16(tag), u32(0), u32(code), body]);
	cmd.writeUInt32BE(cmd.length, 2);
	return cmd;
};

// A password-authorization area (empty/clear auth) — used only for commands that
// carry no secret: CreatePrimary and Load.
const pwAuth = (auth: Buffer = Buffer.alloc(0)): Buffer => {
	const area = Buffer.concat([u32(RS_PW), t2b(Buffer.alloc(0)), u8(ATTR_CONTINUE), t2b(auth)]);
	return Buffer.concat([u32(area.length), area]);
};

// An object's Name = nameAlg ‖ H(publicArea); needed inside the HMAC cpHash for any
// handle the session authorizes. Cheaper and more robust than parsing the TPM's
// returned name out of variable-length creation data.
const nameOf = (publicArea: Buffer): Buffer => Buffer.concat([u16(SHA256), sha(publicArea)]);

// Standard ECC P-256 storage-key (SRK) template — restricted decrypt parent. With
// empty unique + a stable hierarchy seed, CreatePrimary is DETERMINISTIC, so the
// same parent (hence the same child encryption) is reproduced on every unlock.
const SRK_PUBLIC = Buffer.concat([
	u16(0x0023),
	u16(SHA256),
	u32(0x00030072),
	t2b(Buffer.alloc(0)),
	u16(0x0006),
	u16(128),
	u16(0x0043),
	u16(0x0010),
	u16(0x0003),
	u16(0x0010),
	t2b(Buffer.alloc(0)),
	t2b(Buffer.alloc(0)),
]);
// Ephemeral ECC salt key (unrestricted decrypt) under the NULL hierarchy — the
// session salt is ECDH'd against its public; the private never leaves the TPM.
const SALT_PUBLIC = Buffer.concat([
	u16(0x0023),
	u16(SHA256),
	u32(0x00020072),
	t2b(Buffer.alloc(0)),
	u16(0x0010),
	u16(0x0010),
	u16(0x0003),
	u16(0x0010),
	t2b(Buffer.alloc(0)),
	t2b(Buffer.alloc(0)),
]);
// keyedhash "sealed data" template: opaque data, no scheme; userWithAuth so the PIN
// authorizes unseal; fixedTPM|fixedParent so the blob is bound to this TPM.
const SEAL_PUBLIC = Buffer.concat([
	u16(0x0008),
	u16(SHA256),
	u32(0x00000052),
	t2b(Buffer.alloc(0)),
	u16(0x0010),
	t2b(Buffer.alloc(0)),
]);

const selfTest = async (submit: Submit): Promise<void> => {
	const r = await submitReady(submit, build(ST_NO_SESSIONS, CC.SelfTest, u8(0x01)));
	const rc = rcOf(r);
	if (rc !== 0 && rc !== 0x90a) throw new Tpm2Error("SelfTest", rc);
};

type Primary = { handle: number; publicArea: Buffer };

const createPrimary = async (
	submit: Submit,
	hierarchy: number,
	template: Buffer,
): Promise<Primary> => {
	const inSensitive = t2b(Buffer.concat([t2b(Buffer.alloc(0)), t2b(Buffer.alloc(0))]));
	const body = Buffer.concat([
		u32(hierarchy),
		pwAuth(),
		inSensitive,
		t2b(template),
		t2b(Buffer.alloc(0)),
		u32(0),
	]);
	const r = await submitReady(submit, build(ST_SESSIONS, CC.CreatePrimary, body));
	const rc = rcOf(r);
	if (rc !== 0) throw new Tpm2Error("CreatePrimary", rc);
	const handle = r.readUInt32BE(10);
	const pubLen = r.readUInt16BE(18); // skip objectHandle(4) + parameterSize(4)
	return { handle, publicArea: Buffer.from(r.subarray(20, 20 + pubLen)) };
};

// Extract the (x,y) point from an ECC TPMT_PUBLIC whose sym/scheme/kdf are all NULL.
const eccPoint = (publicArea: Buffer): { x: Buffer; y: Buffer } => {
	let o = 2 + 2 + 4; // type, nameAlg, objectAttributes
	o += 2 + publicArea.readUInt16BE(o); // skip authPolicy (TPM2B)
	o += 8; // sym(NULL) · scheme(NULL) · curveID · kdf(NULL) — four UINT16s
	const xl = publicArea.readUInt16BE(o);
	const x = publicArea.subarray(o + 2, o + 2 + xl);
	o += 2 + xl;
	const yl = publicArea.readUInt16BE(o);
	return { x: Buffer.from(x), y: Buffer.from(publicArea.subarray(o + 2, o + 2 + yl)) };
};

const flush = async (submit: Submit, handle: number): Promise<void> => {
	await submit(build(ST_NO_SESSIONS, CC.FlushContext, u32(handle))); // best-effort
};

type Session = { handle: number; key: Buffer; nonceCaller: Buffer; nonceTPM: Buffer };

// Start a salted HMAC session with AES-128-CFB parameter encryption. Creates an
// ephemeral NULL-hierarchy salt key, does ECDH to it, derives the session key, then
// flushes the salt key (the session is self-contained once established).
const startSession = async (submit: Submit): Promise<Session> => {
	const salt = await createPrimary(submit, RH_NULL, SALT_PUBLIC);
	try {
		const pt = eccPoint(salt.publicArea);
		const ecdh = createECDH("prime256v1");
		ecdh.generateKeys();
		const ephPub = ecdh.getPublicKey();
		const ephX = ephPub.subarray(1, 33);
		const ephY = ephPub.subarray(33, 65);
		const z = ecdh.computeSecret(Buffer.concat([u8(4), pt.x, pt.y])); // shared X
		const saltSecret = kdfe(z, "SECRET", ephX, pt.x, 256);
		const nonceCaller = randomBytes(16);
		const encryptedSalt = t2b(Buffer.concat([t2b(ephX), t2b(ephY)]));
		const symmetric = Buffer.concat([u16(0x0006), u16(128), u16(0x0043)]); // AES-128-CFB
		const body = Buffer.concat([
			u32(salt.handle),
			u32(RH_NULL), // bind = none
			t2b(nonceCaller),
			encryptedSalt,
			u8(0x00), // sessionType = TPM_SE_HMAC
			symmetric,
			u16(SHA256), // authHash
		]);
		const r = await submitReady(submit, build(ST_NO_SESSIONS, CC.StartAuthSession, body));
		const rc = rcOf(r);
		if (rc !== 0) throw new Tpm2Error("StartAuthSession", rc);
		const handle = r.readUInt32BE(10);
		const nonceTPM = Buffer.from(r.subarray(16, 16 + r.readUInt16BE(14)));
		const key = kdfa(saltSecret, "ATH", nonceTPM, nonceCaller, 256);
		return { handle, key, nonceCaller, nonceTPM };
	} finally {
		await flush(submit, salt.handle);
	}
};

// CFB key+IV for parameter (de/en)cryption: KDFa(sessionKey‖authValue, "CFB", newer,
// older) -> first 16 bytes key, next 16 IV. For a command the newer nonce is the
// caller's; for a response it's the TPM's (from that response's auth area).
const cfbKeyIv = (
	sessionKey: Buffer,
	authValue: Buffer,
	nonceNewer: Buffer,
	nonceOlder: Buffer,
): { key: Buffer; iv: Buffer } => {
	const k = kdfa(Buffer.concat([sessionKey, authValue]), "CFB", nonceNewer, nonceOlder, 256);
	return { key: k.subarray(0, 16), iv: k.subarray(16, 32) };
};

// HMAC authorization area for a session-authorized command.
const authArea = (s: Session, authValue: Buffer, attrs: number, cpHash: Buffer): Buffer => {
	const a = hmac(
		Buffer.concat([s.key, authValue]),
		Buffer.concat([cpHash, s.nonceCaller, s.nonceTPM, u8(attrs)]),
	);
	const inner = Buffer.concat([u32(s.handle), t2b(s.nonceCaller), u8(attrs), t2b(a)]);
	return Buffer.concat([u32(inner.length), inner]);
};

const cpHashOf = (cc: number, names: Buffer, cpParams: Buffer): Buffer =>
	sha(Buffer.concat([u32(cc), names, cpParams]));

// Seal `data` under `parent` with `pin` as the object's authValue. The inSensitive
// parameter (carrying the PIN and the data) is encrypted with the session key, so
// the DUK never crosses the bus in the clear.
const create = async (
	submit: Submit,
	parent: Primary,
	session: Session,
	pin: Buffer,
	data: Buffer,
): Promise<{ priv: Buffer; pub: Buffer }> => {
	const sensitive = Buffer.concat([t2b(pin), t2b(data)]);
	const sensitiveEnc = encParam(sensitive, session, Buffer.alloc(0));
	const cpParams = Buffer.concat([
		t2b(sensitiveEnc),
		t2b(SEAL_PUBLIC),
		t2b(Buffer.alloc(0)),
		u32(0),
	]);
	const attrs = ATTR_CONTINUE | ATTR_DECRYPT;
	const auth = authArea(
		session,
		Buffer.alloc(0),
		attrs,
		cpHashOf(CC.Create, nameOf(parent.publicArea), cpParams),
	);
	const r = await submitReady(
		submit,
		build(ST_SESSIONS, CC.Create, Buffer.concat([u32(parent.handle), auth, cpParams])),
	);
	const rc = rcOf(r);
	if (rc !== 0) throw new Tpm2Error("Create", rc);
	let o = 14; // skip responseCode + parameterSize
	const privLen = r.readUInt16BE(o);
	const priv = r.subarray(o, o + 2 + privLen);
	o += 2 + privLen;
	const pubLen = r.readUInt16BE(o);
	return { priv: Buffer.from(priv), pub: Buffer.from(r.subarray(o, o + 2 + pubLen)) };
};

const load = async (
	submit: Submit,
	parent: Primary,
	priv: Buffer,
	pub: Buffer,
): Promise<number> => {
	const r = await submitReady(
		submit,
		build(ST_SESSIONS, CC.Load, Buffer.concat([u32(parent.handle), pwAuth(), priv, pub])),
	);
	const rc = rcOf(r);
	if (rc !== 0) throw new Tpm2Error("Load", rc);
	return r.readUInt32BE(10);
};

// Unseal the object with the PIN folded into the session HMAC; the response outData
// is parameter-encrypted by the TPM and decrypted here with the response's nonceTPM.
const unsealCmd = async (
	submit: Submit,
	itemHandle: number,
	itemPublic: Buffer,
	session: Session,
	pin: Buffer,
): Promise<Buffer> => {
	const attrs = ATTR_CONTINUE | ATTR_ENCRYPT;
	const auth = authArea(
		session,
		pin,
		attrs,
		cpHashOf(CC.Unseal, nameOf(itemPublic), Buffer.alloc(0)),
	);
	const r = await submitReady(
		submit,
		build(ST_SESSIONS, CC.Unseal, Buffer.concat([u32(itemHandle), auth])),
	);
	const rc = rcOf(r);
	if (rc !== 0) throw new Tpm2Error("Unseal", rc);
	const dataLen = r.readUInt16BE(14);
	const dataEnc = r.subarray(16, 16 + dataLen);
	const respNonceTPM = r.subarray(
		16 + dataLen + 2,
		16 + dataLen + 2 + r.readUInt16BE(16 + dataLen),
	);
	return decParam(Buffer.from(dataEnc), session, pin, Buffer.from(respNonceTPM));
};

// Encrypt the first command parameter (newer=caller, older=tpm).
const encParam = (buf: Buffer, s: Session, authValue: Buffer): Buffer => {
	const { key, iv } = cfbKeyIv(s.key, authValue, s.nonceCaller, s.nonceTPM);
	const c = createCipheriv("aes-128-cfb", key, iv);
	return Buffer.concat([c.update(buf), c.final()]);
};
// Decrypt the first response parameter (newer=response tpm nonce, older=caller).
const decParam = (buf: Buffer, s: Session, authValue: Buffer, respNonceTPM: Buffer): Buffer => {
	const { key, iv } = cfbKeyIv(s.key, authValue, respNonceTPM, s.nonceCaller);
	const d = createDecipheriv("aes-128-cfb", key, iv);
	return Buffer.concat([d.update(buf), d.final()]);
};

// ---- high-level: seal/unseal a small secret over a hardened session ----

export const seal = async (
	submit: Submit,
	secret: Buffer,
	pin: Buffer,
): Promise<{ priv: Buffer; pub: Buffer }> => {
	await selfTest(submit);
	const parent = await createPrimary(submit, RH_OWNER, SRK_PUBLIC);
	const session = await startSession(submit);
	try {
		return await create(submit, parent, session, pin, secret);
	} finally {
		await flush(submit, session.handle);
		await flush(submit, parent.handle);
	}
};

export const open = async (
	submit: Submit,
	blob: { priv: Buffer; pub: Buffer },
	pin: Buffer,
): Promise<Buffer> => {
	await selfTest(submit);
	const parent = await createPrimary(submit, RH_OWNER, SRK_PUBLIC);
	let item: number | undefined;
	let session: Session | undefined;
	try {
		// Start the session first so its transient salt key is flushed before the
		// sealed item loads — keeps at most two objects resident at once.
		session = await startSession(submit);
		item = await load(submit, parent, blob.priv, blob.pub);
		return await unsealCmd(submit, item, blob.pub.subarray(2), session, pin);
	} finally {
		if (session) await flush(submit, session.handle);
		if (item !== undefined) await flush(submit, item);
		await flush(submit, parent.handle);
	}
};

// Serialize/parse the sealed blob for on-disk storage: u16(privLen) · priv · pub.
export const encodeBlob = ({ priv, pub }: { priv: Buffer; pub: Buffer }): Buffer =>
	Buffer.concat([u16(priv.length), priv, pub]);

export const decodeBlob = (buf: Buffer): { priv: Buffer; pub: Buffer } => {
	const privLen = buf.readUInt16BE(0);
	return { priv: buf.subarray(2, 2 + privLen), pub: buf.subarray(2 + privLen) };
};

// Exposed for marshaling unit tests (deterministic, no TPM required).
export const _internal = { build, pwAuth, kdfa, kdfe, nameOf, CC, ST_SESSIONS, ST_NO_SESSIONS };
