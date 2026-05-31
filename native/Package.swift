// swift-tools-version:5.9
//
// vault-helper — the Secure-Enclave KeyStore shim (plan §12a Step 2), spawned by
// the `vault` CLI for the "secure-enclave" tier. It is a standalone, separately
// signed arm64 binary, not an npm dep (preserves §0's zero-runtime-dependency
// rule and keeps check:deps green).
//
// NOTE: Vault.app itself is now built by vault.xcodeproj (see build.sh). This
// package exists ONLY to produce the standalone helper for the CLI:
//
//   swift build -c release --arch arm64 --product vault-helper
//
// arm64-only, matching the SEA target (plan §1/§7).

import PackageDescription

let package = Package(
	name: "vault-helper",
	platforms: [.macOS(.v14)],
	targets: [
		.executableTarget(
			name: "vault-helper",
			path: "vault-helper"
		),
	]
)
