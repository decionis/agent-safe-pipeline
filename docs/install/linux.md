# Install on Linux

The runtime is one self-contained executable, `agentsafe`, for `x86_64` and `arm64`, built from a
pinned Node release and carrying every dependency. It is distributed as a `.deb`, an `.rpm`, an
archive, and an installer script; all four contain the same binary. Homebrew on Linux uses the
same formula as macOS.

> Availability: the release assets described here are produced by the release workflow from
> `v0.2.0` on. Before that, run from a clone as the [quickstart](../quickstart/README.md) shows;
> the commands are the same.

## The installer

```bash
curl -fsSL https://raw.githubusercontent.com/decionis/agent-safe-pipeline/master/packaging/install.sh | sh
```

[`packaging/install.sh`](../../packaging/install.sh) detects the OS and architecture, downloads
one archive and the release's `SHA256SUMS` from this repository's GitHub releases over HTTPS only,
refuses to continue unless the checksum matches, places the archive's directory under
`<prefix>/lib/agentsafe/<version>` and links `<prefix>/bin/agentsafe` to the executable in it,
with `/usr/local` as the prefix when its `bin` and `lib` are writable and `~/.local` otherwise. It
never uses `sudo`, never edits a shell profile, never installs a service, and touches nothing
else. `AGENTSAFE_VERSION` pins a runtime version; `AGENTSAFE_INSTALL_PREFIX` chooses the prefix. The
runtime is versioned on its own and its archives ride on the repository's releases, which are tagged
by the library's version, so the installer reads which release carries the archive from the release
listing; `AGENTSAFE_RELEASE_TAG` names it for a mirror that has no listing.

## Packages, for operators who do not run scripts from the network

Download the package and `SHA256SUMS` from the
[release](https://github.com/decionis/agent-safe-pipeline/releases), verify, and install:

```bash
sha256sum -c SHA256SUMS --ignore-missing
sudo dpkg -i agentsafe_<version>_amd64.deb      # Debian, Ubuntu
sudo rpm -i agentsafe-<version>-1.x86_64.rpm    # RHEL, Fedora, SUSE
```

The package places:

| Path                                        | What                                                    |
| ------------------------------------------- | ------------------------------------------------------- |
| `/usr/bin/agentsafe`                        | the executable                                          |
| `/usr/lib/systemd/system/agentsafe.service` | the gateway as a hardened service, off until configured |
| `/etc/agentsafe/agentsafe.yaml.example`     | the configuration to copy and edit                      |
| `/etc/agentsafe/environment.example`        | the organization id and other variables, to copy        |
| `/usr/share/doc/agentsafe/`                 | LICENSE and NOTICE                                      |

Every package is attested by the release workflow; `gh attestation verify <package> --repo
decionis/agent-safe-pipeline` checks the provenance. Packages are not GPG-signed; the checksum
file and the attestation are the integrity evidence.

What the repository checks before any of this is published, on both Linux architectures: the
`.deb` is installed on the Ubuntu runner and the `.rpm` in a Fedora container pinned by digest, the
installed executable answers its version and runs the boundary test, the unit and the examples land
at the paths above, and each package removes cleanly; the installer runs end to end against the
archive just built, served over HTTPS by a local mirror with a certificate it is told to trust, and
a tampered archive is refused with `checksum mismatch` and nothing installed. The steps are in
[`.github/workflows/deploy.yml`](../../.github/workflows/deploy.yml) under the `distribution`
job; to repeat the installer's check against a mirror of your own, set `AGENTSAFE_RELEASE_BASE`,
`AGENTSAFE_RELEASE_CA` and `AGENTSAFE_RELEASE_TAG` as that step does.

## The service

The unit ([`packaging/linux/agentsafe.service`](../../packaging/linux/agentsafe.service)) runs
`agentsafe run --config /etc/agentsafe/agentsafe.yaml` as a dynamic user with a read-only system,
no new privileges, no capabilities, and `/var/lib/agentsafe` as its only writable directory, where
the chained evidence and the chain heads go. The Decionis key is a systemd credential: root writes
it to `/etc/agentsafe/decionis-api-key`, systemd hands the service a private copy, and the gateway
reads it from `DECIONIS_API_KEY_FILE`. The key is never in the environment, the unit, or the
configuration file.

```bash
sudo cp /etc/agentsafe/agentsafe.yaml.example /etc/agentsafe/agentsafe.yaml
sudo install -m 0600 /etc/agentsafe/environment.example /etc/agentsafe/environment
sudo -e /etc/agentsafe/agentsafe.yaml          # the upstream, the routes, shadow or enforcement
sudo -e /etc/agentsafe/environment             # DECIONIS_TENANT_ID
(umask 077; printf '%s' "$DECIONIS_API_KEY" | sudo tee /etc/agentsafe/decionis-api-key >/dev/null)
sudo systemctl enable --now agentsafe
journalctl -u agentsafe -f
```

`agentsafe.yaml` stays world-readable, because the service reads it as its dynamic user, and it
holds no secret. `environment` and `decionis-api-key` are read by systemd as root before the
service starts, so they are the operator's 0600 files; a metrics token, if one is set, goes in
`environment`, never in the configuration file.

The service refuses to start until `agentsafe.yaml` exists, and refuses the demo authority: a
server runs in production and asks Decionis. Its log is one JSON line per event, the chained
evidence included.

## Homebrew on Linux

```bash
brew tap decionis/agent-safe https://github.com/decionis/agent-safe-pipeline
brew trust decionis/agent-safe
brew install agentsafe
```

Homebrew 5 and later load a formula from a third-party tap only after you trust the tap once;
`brew trust` is the command, and an older Homebrew that does not have it does not need it.

## After installing

```bash
agentsafe version
agentsafe doctor --upstream http://localhost:3000
```

## Send your first governed action

```bash
agentsafe proxy --upstream http://localhost:3000 --port 8080
curl -i -X POST http://127.0.0.1:8080/payments -H 'content-type: application/json' -d '{"amount": 500}'
```

The gateway prints `ESCALATE` with `Execution HELD` and the dossier it left; the caller gets
`202`. `{"amount": 50}` is forwarded once as `ALLOW`, `{"amount": 5000}` is refused as `BLOCK`.
From here the [quickstart](../quickstart/README.md#connect-decionis) connects a Decionis key and
the [gateway pages](../gateway/http-interception.md) say what was bound and forwarded.

## Govern, the workflow gate

The same releases carry `govern`, the gate for CI steps, as one static binary per platform, with
no package of its own: the installer,
`curl -fsSL https://raw.githubusercontent.com/decionis/agent-safe-pipeline/master/govern/install.sh | sh`,
verifies the archive against the release's `SHA256SUMS` the way the runtime's does and installs
under `/usr/local` or `~/.local`; Homebrew on Linux has `brew install govern` from the same tap;
`go install github.com/decionis/agent-safe-pipeline/govern/v2/cmd/govern@v2.1.0` builds the
same bytes from the signed module tag. A pipeline image without a shell profile pins the version
and prefix: `GOVERN_VERSION=2.1.0 GOVERN_INSTALL_PREFIX="$PWD/.govern" sh install.sh`. Govern's
[README](../../govern/README.md#install) has what it does and every way to run it.
