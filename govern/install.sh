#!/bin/sh
# Installs govern, the workflow gate, from the project's GitHub release assets.
#
#   curl -fsSL https://raw.githubusercontent.com/decionis/agent-safe-pipeline/master/govern/install.sh | sh
#
# What it does, and all it does: detects the OS and architecture, downloads
# one release archive and the release's SHA256SUMS from
# github.com/decionis/agent-safe-pipeline, refuses to continue unless the
# archive's SHA-256 is the one the release lists, places the archive's
# directory under <prefix>/lib/govern/<version>, links <prefix>/bin/govern
# to the binary in it, and prints the version it now answers. The prefix is
# /usr/local when its bin and lib are writable and ~/.local otherwise. It
# touches nothing else: no shell profile, no workflow file, no configuration.
# A pipeline that does not run scripts from the network downloads the archive
# and SHA256SUMS itself and verifies them the same way; govern/README.md
# says how, and `go install` builds the same version from its signed tag.
# Windows has no installer: its archive is a zip, govern-<version>-windows-x64.zip,
# to download from the release, check against SHA256SUMS, and unpack where
# the path reaches govern.exe; the GitHub action does that itself.
#
# Govern is versioned on its own, and its archives ride on the repository's
# releases, which are tagged by the library's version. Which release carries
# the archive is read from the release listing, by the archive's own name,
# never guessed from the version.
#
# Settings, all optional:
#   GOVERN_VERSION         a govern version such as 2.1.0; the latest release's otherwise
#   GOVERN_RELEASE_TAG     the release the archive lives in, for a mirror or a test that has no listing
#   GOVERN_INSTALL_PREFIX  where bin/govern and lib/govern/<version> go
#   GOVERN_RELEASE_BASE    the release download base, for a mirror or a test
#   GOVERN_RELEASE_CA      a CA bundle a mirror's certificate chains to; the system store otherwise
set -eu

REPO="decionis/agent-safe-pipeline"
BASE="${GOVERN_RELEASE_BASE:-https://github.com/$REPO/releases/download}"
API="https://api.github.com/repos/$REPO/releases?per_page=30"

say() { printf '%s\n' "$*"; }
die() { printf 'govern install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need curl
need tar
need uname

case "$(uname -s)" in
  Darwin) os="darwin" ;;
  Linux) os="linux" ;;
  MINGW* | MSYS* | CYGWIN* | Windows_NT) die "on Windows, download govern-<version>-windows-x64.zip from the release and check it against SHA256SUMS; there is no installer" ;;
  *) die "unsupported operating system: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="x64" ;;
  arm64 | aarch64) arch="arm64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

fetch() {
  # HTTPS only, TLS 1.2 or later, no downgrade on redirect, fail on any HTTP error.
  if [ -n "${GOVERN_RELEASE_CA:-}" ]; then
    curl --proto '=https' --tlsv1.2 --cacert "$GOVERN_RELEASE_CA" -fsSL "$@"
  else
    curl --proto '=https' --tlsv1.2 -fsSL "$@"
  fi
}

# Prints "<tag> <govern version>" for the newest release whose assets include
# an archive matching the pattern, reading only tag names and asset names out
# of the listing.
resolve() {
  fetch "$API" \
    | tr -d '\r' \
    | grep -E '"(tag_name|name)": "' \
    | sed -E 's/^[[:space:]]*"(tag_name|name)": "([^"]*)".*$/\1 \2/' \
    | awk -v want="$1" -v suffix="-$os-$arch.tar.gz" '
        $1 == "tag_name" { tag = $2; next }
        $1 == "name" && $2 ~ want && tag ~ /^v[0-9]/ {
          v = $2; sub(/^govern-/, "", v); v = substr(v, 1, length(v) - length(suffix))
          print tag " " v; exit
        }
      '
}

if [ -n "${GOVERN_VERSION:-}" ]; then
  version="$GOVERN_VERSION"
  if [ -n "${GOVERN_RELEASE_TAG:-}" ]; then
    tag="$GOVERN_RELEASE_TAG"
  else
    tag="$(resolve "^govern-$version-$os-$arch\\.tar\\.gz\$" | awk '{ print $1 }')"
  fi
  [ -n "$tag" ] || die "no release carries govern-$version-$os-$arch.tar.gz; set GOVERN_RELEASE_TAG for a mirror"
else
  found="$(resolve "^govern-[0-9][^ ]*-$os-$arch\\.tar\\.gz\$")"
  tag="${found%% *}"
  version="${found#* }"
  [ -n "$found" ] || die "no release with an archive for $os-$arch was found; set GOVERN_VERSION"
fi
case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "not a version: $version" ;;
esac
case "$tag" in
  v[0-9]*) ;;
  *) die "not a release tag: $tag" ;;
esac

name="govern-$version-$os-$arch"
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
[ -x "$work/$name/govern" ] || die "the archive did not contain the binary"

if [ -n "${GOVERN_INSTALL_PREFIX:-}" ]; then
  prefix="$GOVERN_INSTALL_PREFIX"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ] && { [ -w /usr/local/lib ] || { [ ! -e /usr/local/lib ] && [ -w /usr/local ]; }; }; then
  prefix="/usr/local"
else
  prefix="$HOME/.local"
fi
bin="$prefix/bin"
lib="$prefix/lib/govern/$version"
mkdir -p "$bin" "$prefix/lib/govern"
[ -w "$bin" ] && [ -w "$prefix/lib/govern" ] || die "$prefix is not writable; set GOVERN_INSTALL_PREFIX to a directory you own"
# The whole directory, replaced as one, and the link switched last: a
# half-copied install is no install, and the old version answers until the
# new one is complete.
rm -rf "$lib.tmp.$$"
cp -R "$work/$name" "$lib.tmp.$$"
rm -rf "$lib"
mv "$lib.tmp.$$" "$lib"
chmod 0755 "$lib/govern"
ln -sf "$lib/govern" "$bin/govern.tmp.$$"
mv "$bin/govern.tmp.$$" "$bin/govern"

installed="$("$bin/govern" version)"
say "Installed $installed to $lib, linked from $bin/govern"
case ":$PATH:" in
  *":$bin:"*) ;;
  *) say "Add $bin to PATH to run it as govern." ;;
esac
say "Next: govern run --mode shadow --action production-deploy -- ./deploy.sh"
