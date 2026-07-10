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

# `node --build-sea` injects the blob into a copy of the running Node binary,
# which must contain the NODE_SEA_FUSE sentinel. Homebrew and some distro
# packages strip their binaries, dropping that sentinel — so the build fails
# with "sentinel NODE_SEA_FUSE_... not found". Resolve a Node that still has
# the fuse: prefer the running one (the CI path, where setup-node ships the
# unstripped official binary), else fetch the matching official build.
resolve_sea_node() {
  local exec ver plat arch ext dir cache url tmp sea_node
  exec="$(node -p 'process.execPath')"
  if grep -aq 'NODE_SEA_FUSE' "$exec" 2>/dev/null; then
    printf '%s\n' node
    return 0
  fi

  ver="$(node -p 'process.versions.node')"
  case "$(uname -s)" in
    Darwin) plat=darwin; ext=tar.gz ;;
    Linux) plat=linux; ext=tar.gz ;;
    MINGW*|MSYS*|CYGWIN*) plat=win; ext=zip ;;
    *) echo "error: cannot auto-fetch a SEA-capable Node for $(uname -s); install official Node >= 26 from nodejs.org" >&2; return 1 ;;
  esac
  case "$(uname -m)" in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64) arch=x64 ;;
    *) echo "error: unsupported arch $(uname -m) for SEA auto-fetch; install official Node >= 26 from nodejs.org" >&2; return 1 ;;
  esac

  dir="node-v${ver}-${plat}-${arch}"
  cache="build/.sea-node"
  if [ "$plat" = win ]; then
    sea_node="${cache}/${dir}/node.exe"
  else
    sea_node="${cache}/${dir}/bin/node"
  fi

  if [ ! -x "$sea_node" ]; then
    local archive sums expected actual gpg_required
    mkdir -p "$cache"
    url="https://nodejs.org/dist/v${ver}/${dir}.${ext}"
    archive="${cache}/${dir}.${ext}"
    sums="${cache}/SHASUMS256.txt"
    echo "local node lacks the SEA fuse; fetching official $dir" >&2
    # Download to a FILE first, then verify its checksum BEFORE extracting — the
    # extracted binary is injected into and shipped as the release, so a trojaned
    # mirror/CDN or a TLS-intercepting proxy must not be able to slip in a
    # backdoored Node. (Previously the tarball was piped straight into tar with no
    # integrity check at all.)
    dl() { # dl <url> <out>
      if command -v curl >/dev/null; then curl -fsSL "$1" -o "$2"
      elif command -v wget >/dev/null; then wget -qO "$2" "$1"
      else echo "error: need curl or wget to fetch $1" >&2; return 1; fi
    }
    dl "$url" "$archive"
    dl "https://nodejs.org/dist/v${ver}/SHASUMS256.txt" "$sums"

    # Expected hash: an out-of-band pin (VAULT_SEA_NODE_SHA256) wins — that is the
    # only form that also defends against a MITM who rewrites SHASUMS256.txt.
    # Otherwise use the published checksum file (catches corruption / a bad mirror
    # that didn't also forge the sums file).
    expected="${VAULT_SEA_NODE_SHA256:-$(grep "  ${dir}.${ext}\$" "$sums" | awk '{print $1}')}"
    if [ -z "$expected" ]; then
      echo "error: no SHA-256 for ${dir}.${ext} (not in SHASUMS256.txt, no VAULT_SEA_NODE_SHA256)" >&2
      return 1
    fi
    if command -v sha256sum >/dev/null; then actual="$(sha256sum "$archive" | awk '{print $1}')"
    else actual="$(shasum -a 256 "$archive" | awk '{print $1}')"; fi
    if [ "$expected" != "$actual" ]; then
      echo "error: checksum mismatch for $archive (expected $expected, got $actual) — refusing to build" >&2
      rm -f "$archive"; return 1
    fi

    # Best-effort GPG verification of the checksum file against the Node release
    # keyring. Required mode must fail closed at every prerequisite, not only when
    # `gpg --verify` itself runs and rejects the signature.
    gpg_required="${VAULT_SEA_REQUIRE_GPG:-0}"
    if ! command -v gpg >/dev/null; then
      if [ "$gpg_required" = 1 ]; then
        echo "error: VAULT_SEA_REQUIRE_GPG=1 but gpg is not available" >&2
        return 1
      fi
      echo "warning: gpg is not available; relied on SHA-256 only" >&2
    elif ! dl "https://nodejs.org/dist/v${ver}/SHASUMS256.txt.asc" "${sums}.asc"; then
      if [ "$gpg_required" = 1 ]; then
        echo "error: VAULT_SEA_REQUIRE_GPG=1 but SHASUMS256.txt.asc could not be downloaded" >&2
        return 1
      fi
      echo "warning: could not download SHASUMS256.txt.asc; relied on SHA-256 only" >&2
    elif gpg --verify "${sums}.asc" "$sums" >/dev/null 2>&1; then
      echo "gpg-verified SHASUMS256.txt" >&2
    elif [ "$gpg_required" = 1 ]; then
      echo "error: GPG verification of SHASUMS256.txt failed (import the Node release keys)" >&2
      return 1
    else
      echo "warning: could not GPG-verify SHASUMS256.txt (Node release keys not imported); relied on SHA-256 only" >&2
    fi

    if [ "$ext" = tar.gz ]; then tar -xzf "$archive" -C "$cache"; else unzip -oq "$archive" -d "$cache"; fi
    rm -f "$archive"
  fi

  if [ ! -x "$sea_node" ]; then
    echo "error: failed to obtain a SEA-capable Node at $sea_node" >&2; return 1
  fi
  printf '%s\n' "$sea_node"
}

# 1. Bundle TS entry + core into one CJS file.
node build/bundle.ts

# 2 & 3. Generate the SEA binary directly (no postject) and sign it.
if node --help 2>/dev/null | grep -q -- '--build-sea'; then
  SEA_NODE="$(resolve_sea_node)"
  "$SEA_NODE" --build-sea build/sea-config.json

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
