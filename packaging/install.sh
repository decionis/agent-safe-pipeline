#!/bin/sh
# Installs the AgentSafe runtime from the project's GitHub release assets.
#
#   curl -fsSL https://raw.githubusercontent.com/decionis/agent-safe-pipeline/master/packaging/install.sh | sh
#
# What it does, and all it does: detects the OS and architecture, downloads
# one release archive and the release's SHA256SUMS from
# github.com/decionis/agent-safe-pipeline, refuses to continue unless the
# archive's SHA-256 is the one the release lists, places the archive's
# directory under <prefix>/lib/agentsafe/<version>, links
# <prefix>/bin/agentsafe to the executable in it, and prints the version it
# now answers. The prefix is /usr/local when its bin and lib are writable
# and ~/.local otherwise. It touches nothing else: no shell profile, no
# service, no configuration. An operator who does not run scripts from the
# network installs the .deb, the .rpm or the archive by hand;
# docs/install/linux.md says how.
#
# The runtime is versioned on its own, and its archives ride on the
# repository's releases, which are tagged by the library's version: runtime
# 0.1.0 lives under the release v0.2.0, runtime 0.2.0 under v0.3.0. Which
# release carries the archive is read from the release listing, by the
# archive's own name, never guessed from the version.
#
# Settings, all optional:
#   AGENTSAFE_VERSION         a runtime version such as 0.2.0; the latest release's otherwise
#   AGENTSAFE_RELEASE_TAG     the release the archive lives in, for a mirror or a test that has no listing
#   AGENTSAFE_INSTALL_PREFIX  where bin/agentsafe and lib/agentsafe/<version> go
#   AGENTSAFE_RELEASE_BASE    the release download base, for a mirror or a test
#   AGENTSAFE_RELEASE_CA      a CA bundle a mirror's certificate chains to; the system store otherwise
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

# Prints "<tag> <runtime version>" for the newest release whose assets
# include an archive matching the pattern, reading only tag names and asset
# names out of the listing.
resolve() {
  fetch "$API" \
    | tr -d '\r' \
    | grep -E '"(tag_name|name)": "' \
    | sed -E 's/^[[:space:]]*"(tag_name|name)": "([^"]*)".*$/\1 \2/' \
    | awk -v want="$1" -v suffix="-$os-$arch.tar.gz" '
        $1 == "tag_name" { tag = $2; next }
        $1 == "name" && $2 ~ want && tag ~ /^v[0-9]/ {
          v = $2; sub(/^agentsafe-/, "", v); v = substr(v, 1, length(v) - length(suffix))
          print tag " " v; exit
        }
      '
}

if [ -n "${AGENTSAFE_VERSION:-}" ]; then
  version="$AGENTSAFE_VERSION"
  if [ -n "${AGENTSAFE_RELEASE_TAG:-}" ]; then
    tag="$AGENTSAFE_RELEASE_TAG"
  else
    tag="$(resolve "^agentsafe-$version-$os-$arch\\.tar\\.gz\$" | awk '{ print $1 }')"
  fi
  [ -n "$tag" ] || die "no release carries agentsafe-$version-$os-$arch.tar.gz; set AGENTSAFE_RELEASE_TAG for a mirror"
else
  found="$(resolve "^agentsafe-[0-9][^ ]*-$os-$arch\\.tar\\.gz\$")"
  tag="${found%% *}"
  version="${found#* }"
  [ -n "$found" ] || die "no release with an archive for $os-$arch was found; set AGENTSAFE_VERSION"
fi
case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "not a version: $version" ;;
esac
case "$tag" in
  v[0-9]*) ;;
  *) die "not a release tag: $tag" ;;
esac

name="agentsafe-$version-$os-$arch"
archive="$name.tar.gz"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

say "Downloading $archive from release $tag"
fetch -o "$work/$archive" "$BASE/$tag/$archive"
fetch -o "$work/SHA256SUMS" "$BASE/$tag/SHA256SUMS"

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

if [ -n "${AGENTSAFE_INSTALL_PREFIX:-}" ]; then
  prefix="$AGENTSAFE_INSTALL_PREFIX"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ] && { [ -w /usr/local/lib ] || { [ ! -e /usr/local/lib ] && [ -w /usr/local ]; }; }; then
  prefix="/usr/local"
else
  prefix="$HOME/.local"
fi
bin="$prefix/bin"
lib="$prefix/lib/agentsafe/$version"
mkdir -p "$bin" "$prefix/lib/agentsafe"
[ -w "$bin" ] && [ -w "$prefix/lib/agentsafe" ] || die "$prefix is not writable; set AGENTSAFE_INSTALL_PREFIX to a directory you own"
# The whole directory, replaced as one: the launcher layout needs its
# companions beside the executable, and a half-copied install is no install.
rm -rf "$lib.tmp.$$"
cp -R "$work/$name" "$lib.tmp.$$"
rm -rf "$lib"
mv "$lib.tmp.$$" "$lib"
chmod 0755 "$lib/agentsafe"
ln -sf "$lib/agentsafe" "$bin/agentsafe.tmp.$$"
mv "$bin/agentsafe.tmp.$$" "$bin/agentsafe"

installed="$("$bin/agentsafe" version)"
say "Installed agentsafe $installed to $lib, linked from $bin/agentsafe"
case ":$PATH:" in
  *":$bin:"*) ;;
  *) say "Add $bin to PATH to run it as agentsafe." ;;
esac
say "Next: agentsafe proxy --upstream http://localhost:3000 --port 8080"
