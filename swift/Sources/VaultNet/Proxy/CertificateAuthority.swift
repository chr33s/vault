#if !os(Windows)  // VaultNet is empty on Windows (see Package.swift)
import Crypto
import Foundation
import NIOSSL
import SwiftASN1
import X509

// Ephemeral in-memory CA for `vault proxy --connect` (spec §13.1). It
// mints a per-host leaf for each allowlisted CONNECT target so the proxy can
// terminate TLS and run the decrypted request through the same injection and
// scrubbing path. The CA private key never leaves memory and ceases to exist when
// the proxy exits; only the public certificate is written to disk (for the child
// to trust). Not a general-purpose CA: P-256 keys, no CRL/OCSP.

public struct LeafCertificate: Sendable {
	public var certPEM: String
	public var keyPEM: String
}

public final class CertificateAuthority: Sendable {
	private let key: Certificate.PrivateKey
	private let name: DistinguishedName
	public let certificate: Certificate
	public var certPEM: String { (try? certificate.serializeAsPEM().pemString) ?? "" }

	public init(validFor seconds: TimeInterval = 24 * 3600) throws {
		let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
		let name = try DistinguishedName { CommonName("vault proxy ephemeral CA \(UUID().uuidString.prefix(8))") }
		let now = Date()
		self.certificate = try Certificate(
			version: .v3, serialNumber: Certificate.SerialNumber(), publicKey: key.publicKey,
			notValidBefore: now.addingTimeInterval(-300), notValidAfter: now.addingTimeInterval(seconds), issuer: name, subject: name,
			signatureAlgorithm: .ecdsaWithSHA256,
			extensions: try Certificate.Extensions {
				Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
				Critical(KeyUsage(keyCertSign: true, cRLSign: true))
				SubjectKeyIdentifier(hash: key.publicKey)
			},
			issuerPrivateKey: key)
		self.key = key
		self.name = name
	}

	// A server leaf for `hostname`: a DNS SAN, or an IPv4 SAN when it is an address.
	public func issueLeaf(hostname: String) throws -> LeafCertificate {
		let leafKey = P256.Signing.PrivateKey()
		let now = Date()
		let san: GeneralName
		if let ip = Self.ipv4Bytes(hostname) {
			san = .ipAddress(ASN1OctetString(contentBytes: ip[...]))
		} else {
			san = .dnsName(hostname)
		}
		let leaf = try Certificate(
			version: .v3, serialNumber: Certificate.SerialNumber(), publicKey: .init(leafKey.publicKey),
			notValidBefore: now.addingTimeInterval(-300), notValidAfter: now.addingTimeInterval(24 * 3600), issuer: name,
			subject: try DistinguishedName { CommonName(hostname) }, signatureAlgorithm: .ecdsaWithSHA256,
			extensions: try Certificate.Extensions {
				Critical(BasicConstraints.notCertificateAuthority)
				Critical(KeyUsage(digitalSignature: true))
				try ExtendedKeyUsage([.serverAuth])
				SubjectAlternativeNames([san])
				SubjectKeyIdentifier(hash: Certificate.PublicKey(leafKey.publicKey))
				AuthorityKeyIdentifier(keyIdentifier: SubjectKeyIdentifier(hash: key.publicKey).keyIdentifier)
			},
			issuerPrivateKey: key)
		return LeafCertificate(certPEM: try leaf.serializeAsPEM().pemString, keyPEM: try Certificate.PrivateKey(leafKey).serializeAsPEM().pemString)
	}

	static func ipv4Bytes(_ s: String) -> [UInt8]? {
		let parts = s.split(separator: ".", omittingEmptySubsequences: false)
		guard parts.count == 4 else { return nil }
		let b = parts.compactMap { UInt8($0) }
		return b.count == 4 ? b : nil
	}

	func serverContext(hostname: String) throws -> NIOSSLContext {
		let leaf = try issueLeaf(hostname: hostname)
		var cfg = TLSConfiguration.makeServerConfiguration(
			certificateChain: [.certificate(try NIOSSLCertificate(bytes: Array(leaf.certPEM.utf8), format: .pem))],
			privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(leaf.keyPEM.utf8), format: .pem)))
		cfg.applicationProtocols = ["http/1.1"]  // the inner parser is HTTP/1.1 only
		return try NIOSSLContext(configuration: cfg)
	}
}

// One TLS context per host. Keyed on the task so two concurrent first-connects to
// the same host do not mint two leaves; a failure is not memoized, so a transient
// error cannot blackhole the host for the proxy's lifetime.
actor LeafContextCache {
	private let ca: CertificateAuthority
	private var contexts: [String: Task<NIOSSLContext, Error>] = [:]
	init(ca: CertificateAuthority) { self.ca = ca }

	func context(for hostname: String) async throws -> NIOSSLContext {
		if let t = contexts[hostname] { return try await t.value }
		let ca = self.ca
		let t = Task { try ca.serverContext(hostname: hostname) }
		contexts[hostname] = t
		do { return try await t.value } catch {
			contexts[hostname] = nil
			throw error
		}
	}
}
#endif
