#if os(Windows)
	import Foundation
	import VaultCore

	// Windows platform layer (spec §15.8): DPAPI, and Windows Hello through the
	// retained C# helper (base64 stdin/stdout protocol to vault-hello-helper.exe).

	public struct WindowsProcessSecurity: PlatformProcessSecurity {
		public init() {}
		public func disableCoreDumps() {}
	}

	public enum Platform {
		public static let processSecurity: PlatformProcessSecurity = WindowsProcessSecurity()
		// The helper is $VAULT_HELLO_HELPER or vault-hello-helper.exe beside this executable.
		static func helloHelper() -> String? {
			if let e = ProcessInfo.processInfo.environment["VAULT_HELLO_HELPER"], !e.isEmpty { return e }
			let sibling = (CommandLine.arguments[0] as NSString).deletingLastPathComponent
			let p = (sibling as NSString).appendingPathComponent("vault-hello-helper.exe")
			return FileManager.default.isExecutableFile(atPath: p) ? p : nil
		}

		// `name` pins the provider a vault was sealed under; nil picks the strongest
		// available (Hello with per-access verification, then DPAPI).
		public static func keyStore(named name: String?, mode: String? = nil) async -> PlatformKeyStore? {
			if name == nil || name == HelloCipher.providerName, let h = helloHelper() {
				let ks = BlobKeyStore(name: HelloCipher.providerName, subdir: "hello", ext: "hello", cipher: HelloCipher(signer: HelperHelloSigner(helperPath: h)))
				if await ks.available() { return ks }
			}
			if name == nil || name == DpapiCipher.providerName {
				let ks = BlobKeyStore(name: DpapiCipher.providerName, subdir: "dpapi", ext: "dpapi", cipher: DpapiCipher())
				if await ks.available() { return ks }
			}
			return nil
		}
	}
#endif
