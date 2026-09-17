# Install on macOS

The runtime is one self-contained executable, `agentsafe`, built from a pinned Node release and
carrying every dependency; nothing else is installed and no Node is needed. Homebrew is the
primary path; the archive and the installer are the same binary.

> Availability: the release assets described here are produced by the release workflow from the
> first release after `v0.1.4`. Until that release exists, run from a clone as the
> [quickstart](../quickstart/README.md) shows; the commands are the same.

## Homebrew

This repository is the tap. Apple silicon and Intel are both built.

```bash
brew tap decionis/agent-safe https://github.com/decionis/agent-safe-pipeline
brew install agentsafe
```

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
refuses to continue unless the checksum matches, and places the executable in `/usr/local/bin`
when that is writable and `~/.local/bin` otherwise. It never uses `sudo`, never edits a shell
profile, and installs nothing else. `AGENTSAFE_VERSION` pins a version; `AGENTSAFE_INSTALL_DIR`
chooses the directory. Read it before you run it; it is short.

## By hand

Download `agentsafe-<version>-darwin-arm64.tar.gz` (or `-darwin-x64`) and `SHA256SUMS` from the
[release](https://github.com/decionis/agent-safe-pipeline/releases), verify, and extract:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf agentsafe-<version>-darwin-arm64.tar.gz
install -m 0755 agentsafe-<version>-darwin-arm64/agentsafe /usr/local/bin/agentsafe
```

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
