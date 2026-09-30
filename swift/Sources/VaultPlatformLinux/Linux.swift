#if os(Linux)
	import Foundation
	import Glibc
	import VaultCore

	// Linux platform layer (spec §15.8): process hardening, the systemd-creds key store
	// (machine-bound; --with-key=auto|tpm2 binds it to the TPM at rest) and, opt-in, the
	// tpm2-tools tier (TPM-sealed key, optional PIN with TPM lockout).

	public struct LinuxProcessSecurity: PlatformProcessSecurity {
		public init() {}

		public func disableCoreDumps() {
			var lim = rlimit(rlim_cur: 0, rlim_max: 0)
			setrlimit(__rlimit_resource_t(RLIMIT_CORE.rawValue), &lim)
		}

	}

	public enum Platform {
		public static let processSecurity: PlatformProcessSecurity = LinuxProcessSecurity()
		// Strongest first, but the TPM tier is OPT-IN (`$VAULT_TPM2=1`) so it never silently
		// displaces systemd-creds. `name` pins the provider a vault was sealed under; `mode` is
		// its persisted binding (systemd-creds --with-key, or "pin" for tpm2).
		public static func keyStore(named name: String?, mode: String? = nil) async -> PlatformKeyStore? {
			let optIn = ProcessInfo.processInfo.environment["VAULT_TPM2"] == "1"
			if name == Tpm2ToolsCipher.providerName || (name == nil && optIn) {
				let ks = BlobKeyStore(name: Tpm2ToolsCipher.providerName, subdir: "tpm2", ext: "tpm2", cipher: Tpm2ToolsCipher(requirePin: mode == "pin"))
				if await ks.available() { return ks }
				if name != nil { return nil }
			}
			guard name == nil || name == SystemdCredsCipher.providerName else { return nil }
			// Unlock pins the persisted seal mode so the probe matches how the DUK was sealed.
			let ks = BlobKeyStore(name: SystemdCredsCipher.providerName, subdir: "systemd-creds", ext: "cred", cipher: SystemdCredsCipher(keyMode: mode))
			return await ks.available() ? ks : nil
		}
	}
#endif
