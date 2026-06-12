// cli/x509.ts: the hand-rolled certificate issuance behind `vault proxy
// --connect`. The proof that the DER/X.509 is correct is operational — Node's
// own X509Certificate must parse it, the chain must verify, and a real TLS
// client trusting only the ephemeral CA must authorize a leaf it signed.

import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import { connect as tlsConnect, createServer as tlsServer } from "node:tls";
import { createCa, issueLeaf } from "../cli/x509.ts";

// Stand up a TLS server presenting `leaf`, connect trusting only `caPem`, and
// resolve whether the client authorized the chain (+ any name to check).
const handshake = (
	leaf: { keyPem: string; certPem: string },
	caPem: string,
	opts: { host: string; servername?: string },
): Promise<{ authorized: boolean; error?: string }> =>
	new Promise((resolve, reject) => {
		const server = tlsServer({ key: leaf.keyPem, cert: leaf.certPem }, (s) => s.end("hi"));
		server.on("error", reject);
		server.listen(0, "127.0.0.1", () => {
			const port = (server.address() as { port: number }).port;
			const sock = tlsConnect(
				{ host: "127.0.0.1", port, ca: [caPem], servername: opts.servername },
				() => {
					const authorized = sock.authorized;
					const error = sock.authorizationError ? String(sock.authorizationError) : undefined;
					sock.end();
					server.close(() => resolve({ authorized, error }));
				},
			);
			sock.on("error", (e) => server.close(() => resolve({ authorized: false, error: e.message })));
		});
	});

test("CA and leaf parse as valid X.509 and the leaf chains to the CA", async () => {
	const ca = await createCa();
	const caCert = new X509Certificate(ca.certPem);
	assert.equal(caCert.ca, true, "CA cert asserts basicConstraints cA:TRUE");

	const leaf = await issueLeaf(ca, "api.example.test");
	const leafCert = new X509Certificate(leaf.certPem);
	assert.match(leafCert.subjectAltName ?? "", /api\.example\.test/, "DNS SAN present");
	assert.equal(leafCert.verify(caCert.publicKey), true, "leaf signature verifies under the CA key");
	assert.equal(leafCert.ca, false, "leaf is not a CA");
});

test("a DNS-SAN leaf is authorized by a client trusting only the CA", async () => {
	const ca = await createCa();
	const leaf = await issueLeaf(ca, "api.example.test");
	const r = await handshake(leaf, ca.certPem, {
		host: "127.0.0.1",
		servername: "api.example.test",
	});
	assert.equal(r.authorized, true, r.error ?? "should authorize");
});

test("an IP-SAN leaf is authorized for an IP connection (no SNI)", async () => {
	const ca = await createCa();
	const leaf = await issueLeaf(ca, "127.0.0.1");
	// No servername: an IP literal sends no SNI; the cert's iPAddress SAN must match.
	const r = await handshake(leaf, ca.certPem, { host: "127.0.0.1" });
	assert.equal(r.authorized, true, r.error ?? "should authorize via IP SAN");
});

test("a host with out-of-range octets is treated as a DNS name, not an IP SAN", async () => {
	const ca = await createCa();
	// 999.1.1.1 passes a naive \d{1,3} regex but isn't a valid IPv4; it must get a
	// dNSName SAN (else Buffer.from([999,…]) truncates to a garbage iPAddress SAN).
	const leaf = await issueLeaf(ca, "999.1.1.1");
	const cert = new X509Certificate(leaf.certPem);
	assert.match(cert.subjectAltName ?? "", /DNS:999\.1\.1\.1/, "DNS SAN, not IP Address");
	assert.doesNotMatch(cert.subjectAltName ?? "", /IP Address/, "no truncated IP SAN emitted");
});

test("a host with zero-padded octets is treated as a DNS name, not a normalized IP SAN", async () => {
	const ca = await createCa();
	// "010.0.0.1" is non-canonical (Number('010')=10): if we emitted an IP SAN it
	// would be 10.0.0.1, silently not matching the requested host. Must be a DNS SAN.
	const leaf = await issueLeaf(ca, "010.0.0.1");
	const cert = new X509Certificate(leaf.certPem);
	assert.match(cert.subjectAltName ?? "", /DNS:010\.0\.0\.1/, "DNS SAN, not a normalized IP");
	assert.doesNotMatch(
		cert.subjectAltName ?? "",
		/IP Address/,
		"no IP SAN for a non-canonical host",
	);
});

test("a leaf from a different CA is rejected (chain actually enforced)", async () => {
	const ca = await createCa();
	const otherCa = await createCa();
	const leaf = await issueLeaf(ca, "api.example.test");
	// Client trusts otherCa, server presents a leaf signed by ca → must fail.
	const r = await handshake(leaf, otherCa.certPem, {
		host: "127.0.0.1",
		servername: "api.example.test",
	});
	assert.equal(r.authorized, false, "an untrusted issuer must not validate");
});
