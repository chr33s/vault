import Foundation

// Narrow platform seams (spec §15.3): the key store and process hardening. Portable code
// depends only on these; each VaultPlatform* module supplies the OS implementation.

// OS-protected storage for the device unlock key (DUK): Keychain / Secure Enclave,
// systemd-creds / TPM, DPAPI / Windows Hello.
public protocol PlatformKeyStore: Sendable {
	var name: String { get }
	// Binding mode recorded in vault meta so unlock resolves the same binding.
	var bindingMode: String { get }
	func available() async -> Bool
	func put(id: String, secret: Data) async throws
	func get(id: String) async throws -> Data?
	func delete(id: String) async throws
}

public protocol PlatformProcessSecurity: Sendable {
	func disableCoreDumps()
}
