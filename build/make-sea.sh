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
    mkdir -p "$cache"
    url="https://nodejs.org/dist/v${ver}/${dir}.${ext}"
    echo "local node lacks the SEA fuse; fetching official $dir" >&2
    if [ "$ext" = tar.gz ]; then
      if command -v curl >/dev/null; then
        curl -fsSL "$url" | tar -xz -C "$cache"
      elif command -v wget >/dev/null; then
        wget -qO- "$url" | tar -xz -C "$cache"
      else
        echo "error: need curl or wget to fetch $url" >&2; return 1
      fi
    else
      tmp="${cache}/${dir}.zip"
      if command -v curl >/dev/null; then curl -fsSL "$url" -o "$tmp"; else wget -qO "$tmp" "$url"; fi
      unzip -oq "$tmp" -d "$cache"
      rm -f "$tmp"
    fi
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
