import Foundation

// DPAPI, systemd-creds and Windows Hello share one shape: an OS
// facility that seals bytes bound to this machine/user and returns a blob we
// persist under the config dir. `BlobCipher` is the facility, `BlobKeyStore` the
// on-disk plumbing.

public protocol BlobCipher: Sendable {
	func available() async -> Bool
	func protect(_ plaintext: Data, name: String) async throws -> Data
	func unprotect(_ blob: Data, name: String) async throws -> Data
	// Provider-specific binding persisted in vault meta so unlock rebuilds the same mode.
	var bindingMode: String { get }
}

extension BlobCipher { public var bindingMode: String { "" } }

public struct BlobKeyStore: PlatformKeyStore {
	public let name: String
	public let subdir: String
	public let ext: String
	public let cipher: BlobCipher
	public let root: String

	public init(name: String, subdir: String, ext: String, cipher: BlobCipher, root: String = VaultPaths.configDir()) {
		self.name = name
		self.subdir = subdir
		self.ext = ext
		self.cipher = cipher
		self.root = root
	}

	public var bindingMode: String { cipher.bindingMode }
	public func available() async -> Bool { await cipher.available() }

	private func path(_ id: String) throws -> String {
		guard !id.isEmpty, id.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) || ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "." || $0 == "_" || $0 == "-" }) else {
			throw VaultError.invalidArgument("invalid keystore id: \(id)")
		}
		let dir = (root as NSString).appendingPathComponent(subdir)
		try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
		try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir)
		return (dir as NSString).appendingPathComponent("\(id).\(ext)")
	}

	public func put(id: String, secret: Data) async throws {
		let blob = try await cipher.protect(secret, name: id)
		// 0600: the blob is the at-rest-wrapped DUK; never leave it world-readable.
		guard FileManager.default.createFile(atPath: try path(id), contents: blob, attributes: [.posixPermissions: 0o600]) else {
			throw VaultError.corrupt("cannot write keystore blob")
		}
	}

	public func get(id: String) async throws -> Data? {
		guard let blob = FileManager.default.contents(atPath: try path(id)) else { return nil }
		do {
			return try await cipher.unprotect(blob, name: id)
		} catch let e as VaultError {
			// A configuration problem the user can fix (e.g. a missing PIN) must not be flattened
			// into "denied, re-enroll"; everything else (wrong machine/user/key) reads as no secret.
			if case .invalidArgument = e { throw e }
			return nil
		} catch {
			return nil
		}
	}

	public func delete(id: String) async throws { try? FileManager.default.removeItem(atPath: try path(id)) }
}
