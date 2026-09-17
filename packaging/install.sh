#!/bin/sh
# Installs the AgentSafe runtime from the project's GitHub release assets.
#
#   curl -fsSL https://raw.githubusercontent.com/decionis/agent-safe-pipeline/master/packaging/install.sh | sh
#
# What it does, and all it does: detects the OS and architecture, downloads
# one release archive and the release's SHA256SUMS from
# github.com/decionis/agent-safe-pipeline, refuses to continue unless the
# archive's SHA-256 is the one the release lists, extracts the single
# executable, places it in an install directory, and prints the version it
# now answers. It touches nothing else: no shell profile, no service, no
# configuration. An operator who does not run scripts from the network
# installs the .deb, the .rpm or the archive by hand; docs/install/linux.md
# says how.
#
# Settings, all optional:
#   AGENTSAFE_VERSION      a version such as 0.2.0; the latest release otherwise
#   AGENTSAFE_INSTALL_DIR  where the executable goes; /usr/local/bin if writable, else ~/.local/bin
#   AGENTSAFE_RELEASE_BASE the release download base, for a mirror or a test
#   AGENTSAFE_RELEASE_CA   a CA bundle a mirror's certificate chains to; the system store otherwise
set -eu

REPO="decionis/agent-safe-pipeline"
BASE="${AGENTSAFE_RELEASE_BASE:-https://github.com/$REPO/releases/download}"
API="https://api.github.com/repos/$REPO/releases?per_page=30"

say() { printf '%s\n' "$*"; }
die() { printf 'agentsafe install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need curl
need tar
need uname

case "$(uname -s)" in
  Darwin) os="darwin" ;;
  Linux) os="linux" ;;
  *) die "unsupported operating system: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="x64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

fetch() {
  # HTTPS only, TLS 1.2 or later, no downgrade on redirect, fail on any HTTP error.
  if [ -n "${AGENTSAFE_RELEASE_CA:-}" ]; then
    curl --proto '=https' --tlsv1.2 --cacert "$AGENTSAFE_RELEASE_CA" -fsSL "$@"
  else
    curl --proto '=https' --tlsv1.2 -fsSL "$@"
  fi
}

if [ -n "${AGENTSAFE_VERSION:-}" ]; then
  version="$AGENTSAFE_VERSION"
else
  # The latest release whose tag is a runtime version and which carries an
  # archive for this platform; other releases in the repository are not it.
  version="$(fetch "$API" \
    | tr -d '\r' \
    | grep -E '"(tag_name|name)": "' \
    | sed -E 's/^[[:space:]]*"(tag_name|name)": "([^"]*)".*$/\1 \2/' \
    | awk -v want="agentsafe-.*-$os-$arch\\.tar\\.gz" '
        $1 == "tag_name" { tag = $2; next }
        $1 == "name" && $2 ~ want && tag ~ /^v[0-9]/ { print substr(tag, 2); exit }
      ')"
  [ -n "$version" ] || die "no release with an archive for $os-$arch was found; set AGENTSAFE_VERSION"
fi
case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "not a version: $version" ;;
esac

name="agentsafe-$version-$os-$arch"
archive="$name.tar.gz"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

say "Downloading $archive"
fetch -o "$work/$archive" "$BASE/v$version/$archive"
fetch -o "$work/SHA256SUMS" "$BASE/v$version/SHA256SUMS"

expected="$(grep -E "[[:space:]]$archive\$" "$work/SHA256SUMS" | awk '{ print $1 }' | head -n 1)"
[ -n "$expected" ] || die "the release's SHA256SUMS does not list $archive; refusing to install"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$work/$archive" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$work/$archive" | awk '{ print $1 }')"
else
  die "neither sha256sum nor shasum is available to verify the download"
fi
[ "$actual" = "$expected" ] || die "checksum mismatch for $archive (expected $expected, got $actual); refusing to install"
say "Verified SHA-256 $actual"

tar -xzf "$work/$archive" -C "$work"
[ -x "$work/$name/agentsafe" ] || die "the archive did not contain the executable"

if [ -n "${AGENTSAFE_INSTALL_DIR:-}" ]; then
  target="$AGENTSAFE_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  target="/usr/local/bin"
else
  target="$HOME/.local/bin"
fi
mkdir -p "$target"
[ -w "$target" ] || die "$target is not writable; set AGENTSAFE_INSTALL_DIR to a directory you own"
cp "$work/$name/agentsafe" "$target/agentsafe.tmp.$$"
chmod 0755 "$target/agentsafe.tmp.$$"
mv "$target/agentsafe.tmp.$$" "$target/agentsafe"

installed="$("$target/agentsafe" version)"
say "Installed agentsafe $installed to $target/agentsafe"
case ":$PATH:" in
  *":$target:"*) ;;
  *) say "Add $target to PATH to run it as agentsafe." ;;
esac
say "Next: agentsafe proxy --upstream http://localhost:3000 --port 8080"
