#!/usr/bin/env bash
#
# Build, assemble, and code-sign Vault.app (plan §12a Step 3). arm64-only,
# matching the SEA target.
#
# The .app is now built by vault.xcodeproj — xcodebuild compiles the SwiftUI app
# and embeds the Secure-Enclave helper (the "Embed Helper" copy phase + target
# dependency). This script then injects the separately-built SEA CLI (`vault`)
# and signs everything inside-out. The vault-helper can also be built alone via
# `swift build --product vault-helper` (see Package.swift) for the CLI's
# secure-enclave tier.
#
# Usage:
#   CODESIGN_ID="Developer ID Application: You (TEAMID)" ./build.sh
# With no CODESIGN_ID it ad-hoc signs ("-") so you can run locally; ad-hoc builds
# can be launched on the build machine but CANNOT be notarized or distributed.
#
# Prereq built separately: the SEA CLI at <repo>/dist/vault (npm run build:sea).
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd .. && pwd)"
SIGN_ID="${CODESIGN_ID:--}"
DERIVED="build"
APP_NAME="vault.app"
PRODUCT="$DERIVED/Build/Products/Release/$APP_NAME"

echo "==> Building $APP_NAME via xcodebuild (Release, arm64); signing deferred"
# CODE_SIGNING_ALLOWED=NO: let this script sign inside-out below, so the injected
# SEA CLI and the bundle share one consistent signing pass.
xcodebuild \
	-project vault.xcodeproj \
	-scheme vault \
	-configuration Release \
	-derivedDataPath "$DERIVED" \
	ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
	CODE_SIGNING_ALLOWED=NO \
	build

CONTENTS="$PRODUCT/Contents"
SEA_BIN="$REPO_ROOT/dist/vault"

echo "==> Injecting SEA CLI"
if [[ -x "$SEA_BIN" ]]; then
	cp "$SEA_BIN" "$CONTENTS/Resources/vault"
else
	echo "!! WARNING: $SEA_BIN not found — run 'npm run build:sea' first."
	echo "   The app will fall back to \$VAULT_BIN or /usr/local/bin/vault at runtime."
fi

# Sign inside-out: nested executables first, then the app bundle last. Hardened
# runtime (-o runtime) is always applied; a secure --timestamp is added only for
# real identities (ad-hoc "-" has no cert to timestamp and would fail).
sign() {
	local ts=()
	[[ "$SIGN_ID" != "-" ]] && ts=(--timestamp)
	codesign --force --options runtime ${ts[@]+"${ts[@]}"} --sign "$SIGN_ID" "$@"
}

echo "==> Signing (identity: $SIGN_ID)"
[[ -f "$CONTENTS/Resources/vault" ]] && sign "$CONTENTS/Resources/vault"
sign "$CONTENTS/Resources/vault-helper"
sign --entitlements vault/Vault.entitlements "$PRODUCT"

echo "==> Verifying"
codesign --verify --deep --strict --verbose=2 "$PRODUCT"

echo "==> Copying to ./$APP_NAME"
rm -rf "$APP_NAME"
ditto "$PRODUCT" "$APP_NAME"

cat <<EOF

Built ./$APP_NAME (arm64).

To notarize for distribution (needs a Developer ID identity + an App Store
Connect API key or app-specific password):

  ditto -c -k --keepParent "$APP_NAME" vault.zip
  xcrun notarytool submit vault.zip --keychain-profile "VAULT_NOTARY" --wait
  xcrun stapler staple "$APP_NAME"

(Set up the keychain profile once with:
  xcrun notarytool store-credentials VAULT_NOTARY --apple-id you@example.com \\
    --team-id TEAMID --password <app-specific-password>)
EOF
