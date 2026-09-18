# Install on macOS

The runtime is one self-contained executable, `agentsafe`, built from a pinned Node release and
carrying every dependency; nothing else is installed and no Node needs to be present. On Apple
silicon it is a single file; on Intel, where Node does not support single executables, it is the
same bundle beside the same pinned Node with an `agentsafe` launcher, and the three ship together.
Homebrew is the primary path; the archive and the installer carry the same files.

> Availability: the release assets described here are produced by the release workflow from
> `v0.2.0` on, and the formula reaches master by its own pull request after each release. Before
> that, run from a clone as the [quickstart](../quickstart/README.md) shows; the commands are the same.

## Homebrew

This repository is the tap. Apple silicon and Intel are both built.

```bash
brew tap decionis/agent-safe https://github.com/decionis/agent-safe-pipeline
brew trust decionis/agent-safe
brew install agentsafe
```

Homebrew 5 and later load a formula from a third-party tap only after you trust the tap once;
`brew trust` is the command, and an older Homebrew that does not have it does not need it.

The formula, `Formula/agentsafe.rb` in this repository, pins each platform's archive to
the SHA-256 the release listed; it is rendered by the release workflow from the release's own
`SHA256SUMS` and opened as a pull request, never typed by hand. `brew test agentsafe` runs the
binary and the offline doctor.

## The installer

```bash
curl -fsSL https://raw.githubusercontent.com/decionis/agent-safe-pipeline/master/packaging/install.sh | sh
```

[`packaging/install.sh`](../../packaging/install.sh) detects the OS and architecture, downloads
one archive and the release's `SHA256SUMS` from this repository's GitHub releases over HTTPS only,
refuses to continue unless the checksum matches, places the archive's directory under
`<prefix>/lib/agentsafe/<version>` and links `<prefix>/bin/agentsafe` to the executable in it,
with `/usr/local` as the prefix when its `bin` and `lib` are writable and `~/.local` otherwise. It
never uses `sudo`, never edits a shell profile, and installs nothing else. `AGENTSAFE_VERSION` pins
a runtime version; `AGENTSAFE_INSTALL_PREFIX` chooses the prefix. The archives ride on the
repository's releases, which are tagged by the library's version, so the installer reads which
release carries the archive from the release listing. Read it before you run it; it is short.

## By hand

Download `agentsafe-<version>-darwin-arm64.tar.gz` (or `-darwin-x64`) and `SHA256SUMS` from the
[release](https://github.com/decionis/agent-safe-pipeline/releases), verify, and extract:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf agentsafe-<version>-darwin-arm64.tar.gz
mkdir -p /usr/local/lib/agentsafe
mv agentsafe-<version>-darwin-arm64 /usr/local/lib/agentsafe/<version>
ln -sf /usr/local/lib/agentsafe/<version>/agentsafe /usr/local/bin/agentsafe
```

Keep the directory together: on Intel the launcher runs the `node` and `agentsafe.cjs` beside it.

Every archive is attested by the release workflow; `gh attestation verify <archive> --repo
decionis/agent-safe-pipeline` checks the provenance.

## After installing

```bash
agentsafe version
agentsafe doctor --upstream http://localhost:3000
```

Both work with no account and no configuration file: the doctor reports the binary, the demo
authority, and whether anything answers at the upstream.

## Send your first governed action

```bash
agentsafe proxy --upstream http://localhost:3000 --port 8080
curl -i -X POST http://127.0.0.1:8080/payments -H 'content-type: application/json' -d '{"amount": 500}'
```

The gateway prints `ESCALATE` with `Execution HELD` and the dossier it left; the caller gets
`202`. `{"amount": 50}` is forwarded once as `ALLOW`, `{"amount": 5000}` is refused as `BLOCK`.
From here the [quickstart](../quickstart/README.md#connect-decionis) connects a Decionis key and
the [gateway pages](../gateway/http-interception.md) say what was bound and forwarded.
