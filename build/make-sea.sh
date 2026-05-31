#!/usr/bin/env bash
# Build a single-file native executable for the CLI (plan §7).
# Requires Node >= 26 (node --build-sea, built-in since 25.5). The Node binary
# that produces the blob must match the one it is injected into — so build on
# each target OS/arch in CI and pin the exact Node patch version per release.
set -euo pipefail

cd "$(dirname "$0")/.."

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$NODE_MAJOR" -lt 26 ]; then
  echo "warning: node --build-sea needs Node >= 26 (have $(node --version)); the bundle step still runs" >&2
fi

# 1. Bundle TS entry + core into one CJS file.
node build/bundle.ts

# 2 & 3. Generate the SEA binary directly (no postject) and sign it.
if node --help 2>/dev/null | grep -q -- '--build-sea'; then
  node --build-sea build/sea-config.json

  # On Windows the executable must carry the .exe extension to run by name.
  BIN=dist/vault
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      mv -f dist/vault dist/vault.exe
      BIN=dist/vault.exe
      echo "skip codesign on Windows; use signtool / sign in CI"
      ;;
    Darwin)
      # macOS ships arm64 only (plan §1/§7); ad-hoc sign for local use.
      codesign --sign - "$BIN" && echo "codesigned $BIN (ad-hoc)"
      ;;
    *)
      echo "skip codesign on $(uname -s); sign in CI"
      ;;
  esac
  echo "built -> $BIN"

  # Publish a checksum (plan §11: binary integrity).
  if command -v shasum >/dev/null; then
    shasum -a 256 "$BIN" > "$BIN.sha256"
  elif command -v sha256sum >/dev/null; then
    sha256sum "$BIN" > "$BIN.sha256"
  fi
  echo "checksum -> $BIN.sha256"
else
  echo "error: this Node lacks --build-sea; install Node >= 26 to produce the binary" >&2
  exit 1
fi
