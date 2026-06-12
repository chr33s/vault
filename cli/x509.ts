// Minimal X.509 certificate issuance over node:crypto, for `vault proxy
// --connect` (spec §13.1 forward-proxy / CONNECT mode). Node can parse X.509
// (crypto.X509Certificate) but cannot *issue* one, so we hand-roll just enough
// DER + the certificate fields to mint an ephemeral CA and per-host leaf certs.
// In character with the rest of the repo (sealed boxes, HLC, CRDT are all
// hand-rolled on node:crypto) and keeps the zero-runtime-dependency rule.
//
// Scope: RSA-2048 keys, sha256WithRSAEncryption, v3 certs with the extensions a
// modern TLS client actually checks (basicConstraints, keyUsage, extKeyUsage,
// subjectAltName, SKI/AKI). Not a general-purpose CA: no CRL/OCSP, no EC, no
// IPv6 SANs. The CA lives only in memory for one `vault proxy` invocation.

import { createHash, generateKeyPair, type KeyObject, sign } from "node:crypto";
import { promisify } from "node:util";

// Async RSA keygen so minting a CA/leaf never blocks the event loop (sync
// generateKeyPairSync stalls all in-flight tunnels/streams for ~tens of ms).
const genRsa = promisify(generateKeyPair) as (
	type: "rsa",
	opts: { modulusLength: number },
) => Promise<{ publicKey: KeyObject; privateKey: KeyObject }>;

// ---- DER (ASN.1 Distinguished Encoding Rules) primitives ----

const len = (n: number): Buffer => {
	if (n < 0x80) return Buffer.from([n]);
	const out: number[] = [];
	let x = n;
	while (x > 0) {
		out.unshift(x & 0xff);
		x = Math.floor(x / 256);
	}
	return Buffer.from([0x80 | out.length, ...out]);
};

// tag-length-value
const tlv = (tag: number, content: Buffer): Buffer =>
	Buffer.concat([Buffer.from([tag]), len(content.length), content]);

const seq = (...items: Buffer[]): Buffer => tlv(0x30, Buffer.concat(items));
const set = (...items: Buffer[]): Buffer => tlv(0x31, Buffer.concat(items));
const nullv = (): Buffer => Buffer.from([0x05, 0x00]);
const boolv = (b: boolean): Buffer => tlv(0x01, Buffer.from([b ? 0xff : 0x00]));
const octet = (b: Buffer): Buffer => tlv(0x04, b);

// INTEGER from a positive big-endian byte buffer, minimally encoded: strip
// redundant leading 0x00 bytes (a 0x00 whose successor's high bit is clear is
// non-minimal and rejected by strict DER parsers, e.g. Go/BoringSSL), then
// re-add a single 0x00 only if the high bit is set (so it stays positive).
const intFromBytes = (b: Buffer): Buffer => {
	let i = 0;
	while (i < b.length - 1 && b[i] === 0x00 && ((b[i + 1] ?? 0) & 0x80) === 0) i++;
	const t = b.subarray(i);
	return tlv(0x02, (t[0] ?? 0) & 0x80 ? Buffer.concat([Buffer.from([0]), t]) : t);
};

// BIT STRING with an explicit unused-bits count (named-bit extensions need it).
const bitstring = (unused: number, b: Buffer): Buffer =>
	tlv(0x03, Buffer.concat([Buffer.from([unused]), b]));

// Context-specific tag. EXPLICIT wraps a full TLV; primitive carries raw bytes.
const explicit = (n: number, content: Buffer): Buffer => tlv(0xa0 | n, content);
const ctxPrimitive = (n: number, content: Buffer): Buffer => tlv(0x80 | n, content);

const base128 = (v: number): number[] => {
	const out = [v & 0x7f];
	let x = Math.floor(v / 128);
	while (x > 0) {
		out.unshift((x & 0x7f) | 0x80);
		x = Math.floor(x / 128);
	}
	return out;
};

const oid = (dotted: string): Buffer => {
	const p = dotted.split(".").map(Number);
	const bytes: number[] = [40 * (p[0] ?? 0) + (p[1] ?? 0)];
	for (const arc of p.slice(2)) bytes.push(...base128(arc));
	return tlv(0x06, Buffer.from(bytes));
};

// UTCTime (YYMMDDHHMMSSZ) — valid for years < 2050, which covers our short-
// lived ephemeral certs.
const utcTime = (d: Date): Buffer => {
	const p = (n: number): string => String(n).padStart(2, "0");
	const s =
		p(d.getUTCFullYear() % 100) +
		p(d.getUTCMonth() + 1) +
		p(d.getUTCDate()) +
		p(d.getUTCHours()) +
		p(d.getUTCMinutes()) +
		p(d.getUTCSeconds()) +
		"Z";
	return tlv(0x17, Buffer.from(s, "ascii"));
};

// ---- object identifiers ----

const OID = {
	sha256WithRSA: "1.2.840.113549.1.1.11",
	commonName: "2.5.4.3",
	basicConstraints: "2.5.29.19",
	keyUsage: "2.5.29.15",
	extKeyUsage: "2.5.29.37",
	serverAuth: "1.3.6.1.5.5.7.3.1",
	subjectAltName: "2.5.29.17",
	subjectKeyIdentifier: "2.5.29.14",
	authorityKeyIdentifier: "2.5.29.35",
};

const sigAlg = seq(oid(OID.sha256WithRSA), nullv());

// Name ::= SEQUENCE OF RDN; one RDN here, a single CN.
const nameCN = (cn: string): Buffer =>
	seq(set(seq(oid(OID.commonName), tlv(0x0c, Buffer.from(cn)))));

// X.509 v3 Extension { extnID, critical, extnValue OCTET STRING(DER of value) }.
const extension = (id: string, critical: boolean, value: Buffer): Buffer =>
	critical ? seq(oid(id), boolv(true), octet(value)) : seq(oid(id), octet(value));

// KeyUsage named bits: digitalSignature(0) keyEncipherment(2) keyCertSign(5)
// cRLSign(6). Encoded MSB-first with the trailing unused-bit count.
const keyUsage = (positions: number[]): Buffer => {
	const max = Math.max(...positions);
	const bytes = Buffer.alloc((max >> 3) + 1);
	for (const p of positions) {
		const i = p >> 3;
		bytes[i] = (bytes[i] ?? 0) | (0x80 >> (p & 7));
	}
	return bitstring(7 - (max & 7), bytes);
};

const isIPv4 = (h: string): boolean => {
	const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	// Require each octet to be canonical (<= 255 AND no leading zeros): the regex
	// alone accepts 999.* and 010.* etc., which would emit a truncated/garbage
	// iPAddress SAN that won't match the host instead of falling back to a DNS SAN.
	return m !== null && m.slice(1).every((o) => Number(o) <= 255 && String(Number(o)) === o);
};

// SubjectAltName: dNSName [2] IA5String, or iPAddress [7] OCTET STRING (4 bytes).
const subjectAltName = (host: string): Buffer =>
	tlv(
		0x30,
		isIPv4(host)
			? ctxPrimitive(7, Buffer.from(host.split(".").map(Number)))
			: ctxPrimitive(2, Buffer.from(host, "ascii")),
	);

const spkiOf = (key: KeyObject): Buffer => key.export({ type: "spki", format: "der" }) as Buffer;
// Subject Key Identifier: SHA-1 over the SubjectPublicKeyInfo (RFC 5280 method 2
// is permitted; validators only need AKI->SKI to match, not a specific digest).
const keyId = (spki: Buffer): Buffer => createHash("sha1").update(spki).digest();

const toPem = (der: Buffer, label: string): string => {
	const b64 = der.toString("base64").replace(/(.{64})/g, "$1\n");
	return `-----BEGIN ${label}-----\n${b64}${b64.endsWith("\n") ? "" : "\n"}-----END ${label}-----\n`;
};

// Build + sign one certificate. The TBSCertificate carries `subjectKey`'s SPKI
// but is signed by `issuerKey`; `signature` inside TBS must equal the outer
// algorithm (both sha256WithRSA here).
const makeCert = (opts: {
	issuerDN: Buffer;
	issuerKey: KeyObject;
	subjectDN: Buffer;
	subjectKey: KeyObject;
	extensions: Buffer[];
}): Buffer => {
	const serial = createHash("sha256")
		.update(opts.subjectDN)
		.update(String(Math.random()))
		.digest()
		.subarray(0, 16);
	const now = Date.now();
	const tbs = seq(
		explicit(0, intFromBytes(Buffer.from([2]))), // version v3 (2)
		intFromBytes(serial),
		sigAlg,
		opts.issuerDN,
		seq(utcTime(new Date(now - 5 * 60_000)), utcTime(new Date(now + 36 * 3_600_000))),
		opts.subjectDN,
		spkiOf(opts.subjectKey),
		explicit(3, seq(...opts.extensions)),
	);
	const signature = sign("sha256", tbs, opts.issuerKey);
	return seq(tbs, sigAlg, bitstring(0, signature));
};

export type Ca = {
	key: KeyObject;
	dn: Buffer;
	ski: Buffer;
	certPem: string;
};

// Mint a fresh self-signed CA. The private key stays in memory (a KeyObject) and
// is never serialized — only the public cert is ever written out (to be trusted
// by the spawned agent for this session).
export const createCa = async (): Promise<Ca> => {
	const { privateKey, publicKey } = await genRsa("rsa", { modulusLength: 2048 });
	const dn = nameCN("vault proxy ephemeral CA");
	const ski = keyId(spkiOf(publicKey));
	const der = makeCert({
		issuerDN: dn,
		issuerKey: privateKey,
		subjectDN: dn,
		subjectKey: publicKey,
		extensions: [
			extension(OID.basicConstraints, true, seq(boolv(true))), // cA:TRUE
			extension(OID.keyUsage, true, keyUsage([5, 6])), // keyCertSign, cRLSign
			extension(OID.subjectKeyIdentifier, false, octet(ski)),
		],
	});
	return { key: privateKey, dn, ski, certPem: toPem(der, "CERTIFICATE") };
};

// Issue a leaf cert + key for one host, signed by the CA. Returned as PEM ready
// for tls.createSecureContext({ key, cert }).
export const issueLeaf = async (
	ca: Ca,
	host: string,
): Promise<{ keyPem: string; certPem: string }> => {
	const { privateKey, publicKey } = await genRsa("rsa", { modulusLength: 2048 });
	const der = makeCert({
		issuerDN: ca.dn,
		issuerKey: ca.key,
		subjectDN: nameCN(host),
		subjectKey: publicKey,
		extensions: [
			extension(OID.basicConstraints, false, seq()), // cA defaults FALSE
			extension(OID.keyUsage, true, keyUsage([0, 2])), // digitalSignature, keyEncipherment
			extension(OID.extKeyUsage, false, seq(oid(OID.serverAuth))),
			extension(OID.subjectAltName, false, subjectAltName(host)),
			extension(OID.authorityKeyIdentifier, false, seq(ctxPrimitive(0, ca.ski))),
		],
	});
	return {
		keyPem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
		certPem: toPem(der, "CERTIFICATE"),
	};
};
