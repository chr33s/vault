// swift-tools-version:6.4
//
// Swift local stack (vault.spec.md §15.2–§15.3): portable VaultCore + CLI +
// thin per-OS platform modules. The Cloudflare relay stays TypeScript.

import PackageDescription

let unixOnly = TargetDependencyCondition.when(platforms: [.macOS, .linux])

let package = Package(
	name: "vault",
	platforms: [.macOS(.v14)],
	products: [
		.library(name: "VaultCore", targets: ["VaultCore"]),
		.library(name: "VaultCommands", targets: ["VaultCommands"]),
		.executable(name: "vault", targets: ["VaultCLI"]),
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
		.package(url: "https://github.com/apple/swift-nio.git", from: "2.70.0"),
		.package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
		.package(url: "https://github.com/swift-server/async-http-client.git", from: "1.21.0"),
		.package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
		.package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),
	],
	targets: [
		.systemLibrary(
			name: "CSQLite",
			path: "Sources/CSQLite",
			pkgConfig: "sqlite3",
			providers: [.apt(["libsqlite3-dev"]), .brew(["sqlite3"])]
		),
		// Windows has no system sqlite3: build the vendored amalgamation (3.53.4, sqlite.org
		// sqlite-amalgamation-3530400.zip, SHA3-256 628a44cf…7934e) into the binary instead.
		.target(
			name: "CSQLiteBundled",
			path: "Sources/CSQLiteBundled",
			cSettings: [
				.define("SQLITE_DQS", to: "0"),
				.define("SQLITE_OMIT_LOAD_EXTENSION"),
				.define("SQLITE_THREADSAFE", to: "1"),
			]
		),
		.target(
			name: "VaultCore",
			dependencies: [
				.target(name: "CSQLite", condition: .when(platforms: [.macOS, .linux])),
				.target(name: "CSQLiteBundled", condition: .when(platforms: [.windows])),
				.product(name: "Crypto", package: "swift-crypto"),
				.product(name: "_CryptoExtras", package: "swift-crypto"),
			]
		),
		// Networking: direct-peer server, tailnet sync, credential-injecting proxy.
		// Kept out of VaultCore so the portable engine stays dependency-light. Empty on
		// Windows: swift-nio-extras (via AsyncHTTPClient) doesn't build there, so relay /
		// serve / proxy / sync --tailnet are macOS + Linux only (sources are `#if !os(Windows)`).
		.target(
			name: "VaultNet",
			dependencies: [
				"VaultCore",
				.product(name: "NIOCore", package: "swift-nio", condition: unixOnly),
				.product(name: "NIOPosix", package: "swift-nio", condition: unixOnly),
				.product(name: "NIOHTTP1", package: "swift-nio", condition: unixOnly),
				.product(name: "NIOTLS", package: "swift-nio", condition: unixOnly),
				.product(name: "NIOSSL", package: "swift-nio-ssl", condition: unixOnly),
				.product(name: "AsyncHTTPClient", package: "async-http-client", condition: unixOnly),
				.product(name: "X509", package: "swift-certificates", condition: unixOnly),
				.product(name: "SwiftASN1", package: "swift-asn1", condition: unixOnly),
			]
		),
		.target(
			name: "VaultPlatformDarwin",
			dependencies: ["VaultCore"]
		),
		.target(
			name: "VaultPlatformLinux",
			dependencies: ["VaultCore"]
		),
		.target(
			name: "VaultPlatformWindows",
			dependencies: ["VaultCore"]
		),
		// The command layer (`init add get … sync serve proxy run`), usable both by the
		// `vault` executable and IN-PROCESS by an embedding app such as Vault.app.
		.target(
			name: "VaultCommands",
			dependencies: [
				"VaultCore",
				"VaultNet",
				.target(name: "VaultPlatformDarwin", condition: .when(platforms: [.macOS])),
				.target(name: "VaultPlatformLinux", condition: .when(platforms: [.linux])),
				.target(name: "VaultPlatformWindows", condition: .when(platforms: [.windows])),
			]
		),
		.executableTarget(
			name: "VaultCLI",
			dependencies: ["VaultCommands"]
		),
		.testTarget(
			name: "VaultCoreTests",
			dependencies: [
				"VaultCore", "VaultNet", "VaultCommands",
				.target(name: "VaultPlatformDarwin", condition: .when(platforms: [.macOS])),
			]
		),
	]
)
