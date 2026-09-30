import Foundation

// Typed internal errors (spec §15.15). `description` is the stable machine-facing
// message and never carries secrets, keys, or passphrases.
public enum VaultError: Error, Sendable, Equatable, CustomStringConvertible {
	case notInitialized
	case alreadyInitialized
	case incorrectPassphrase
	case corrupt(String)
	case noSuchItem(String)
	case noSuchField(String)
	case notAuthorized(String)
	case notFound(String)
	case keystoreUnavailable(String)
	case keystoreDenied(provider: String, id: String)
	case noCurrentKey
	case invalidArgument(String)

	public var description: String {
		switch self {
		case .notInitialized: return "vault not initialized; run `vault init`"
		case .alreadyInitialized: return "vault already initialized"
		case .incorrectPassphrase: return "incorrect passphrase"
		case .corrupt(let what): return "vault data is corrupt: \(what)"
		case .noSuchItem(let t): return "no item titled \"\(t)\""
		case .noSuchField(let f): return "no field \"\(f)\""
		case .notAuthorized(let what): return what
		case .notFound(let what): return what
		case .keystoreUnavailable(let name):
			return
				"the \"\(name)\" keystore was requested but is unavailable on this device; re-run without --keychain for a passphrase-only vault"
		case .keystoreDenied(let provider, let id):
			return
				"cannot unlock: the \"\(provider)\" keystore did not return this device's unlock key (item \(id)). Either access was denied/cancelled (retry), or the key was lost — if so, re-enroll this device, or restore it from a device that can still unlock."
		case .noCurrentKey: return "no key for the current epoch (locked out?)"
		case .invalidArgument(let m): return m
		}
	}
}
