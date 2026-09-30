#!/usr/bin/env bash
#
# Build, assemble, and code-sign Vault.app. arm64-only.
#
# The .app is built by vault.xcodeproj. It links the Swift engine (VaultCommands ->
# VaultCore, ../swift) DIRECTLY: there is no Node SEA subprocess to inject and no
# passphrase IPC, and the Secure Enclave keystore runs in-process (no helper binary).
# This script signs the bundle.
#
# Usage:
#   CODESIGN_ID="Developer ID Application: You (TEAMID)" ./build.sh
# With no CODESIGN_ID it ad-hoc signs ("-") so you can run locally; ad-hoc builds
# can be launched on the build machine but CANNOT be notarized or distributed.
#
set -euo pipefail

cd "$(dirname "$0")"
SIGN_ID="${CODESIGN_ID:--}"
DERIVED="build"
APP_NAME="vault.app"
PRODUCT="$DERIVED/Build/Products/Release/$APP_NAME"

echo "==> Building $APP_NAME via xcodebuild (Release, arm64); signing deferred"
# CODE_SIGNING_ALLOWED=NO: let this script sign the finished bundle below in one pass.
xcodebuild \
	-project vault.xcodeproj \
	-scheme vault \
	-configuration Release \
	-derivedDataPath "$DERIVED" \
	ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
	CODE_SIGNING_ALLOWED=NO \
	build

# Sign the app bundle (there are no nested executables any more). Hardened
# runtime (-o runtime) is always applied; a secure --timestamp is added only for
# real identities (ad-hoc "-" has no cert to timestamp and would fail).
sign() {
	local ts=()
	[[ "$SIGN_ID" != "-" ]] && ts=(--timestamp)
	codesign --force --options runtime ${ts[@]+"${ts[@]}"} --sign "$SIGN_ID" "$@"
}

echo "==> Signing (identity: $SIGN_ID)"
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
