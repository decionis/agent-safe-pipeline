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
else. `AGENTSAFE_VERSION` pins a version; `AGENTSAFE_INSTALL_PREFIX` chooses the prefix.

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
brew install agentsafe
```

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
