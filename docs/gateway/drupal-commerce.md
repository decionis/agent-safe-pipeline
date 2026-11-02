# Drupal Commerce: the gateway holds the Fincra key

A Drupal Commerce store that takes payments through Commerce Fincra sends Fincra's secret key with
every checkout it creates, so the site holds a key that can also refund and pay out. Put the
AgentSafe gateway on the store's own server, between Drupal and Fincra, and the key moves into the
gateway: checkout creation and payment verification pass straight through with the key the gateway
adds, and every refund or payout needs a Decionis verdict and a single-use grant. A site that is
fully compromised still cannot move money without one.

```text
Drupal (Commerce Fincra) ─▶ AgentSafe gateway, 127.0.0.1 (holds the key) ─▶ Fincra
                                     │
                                     └─▶ Decionis: decide, grant, evidence
```

Decionis for Drupal, the module that sets this up, is in private beta and is not on drupal.org
yet. To try it, [contact Decionis](https://decionis.com/contact).

## 1. What the setup writes

`drush decionis:gateway-setup` writes an addressed gateway for Fincra, a key file, and a service
that runs it. `--dry-run` prints every command and file instead, with the keys left out, for the
host's support team. The configuration:

```yaml
version: 1
gateway:
  listen: "127.0.0.1:8787"
  upstream: "https://api.fincra.com" # https://sandboxapi.fincra.com for a test-mode gateway
  upstreamCredential:
    header: api-key
    file: "/run/credentials/agentsafe.service/fincra-api-key"
authority:
  endpoint: "https://api.decionis.com"
  tenantId: "00000000-0000-4000-8000-000000000000" # the store's Decionis organization
  mode: shadow # enforcement once the store turns it on
  failurePolicy: failClosed
  timeoutMs: 4000
interception:
  http: true
  unmatched: passthrough
  routes:
    - path: /collections/refund
      action: fincra.refund
      methods: [POST]
    - path: /disbursements/**
      action: fincra.payout
      methods: [POST]
```

`gateway.upstreamCredential` makes the gateway, not Drupal, hold the key
([configuration](./configuration.md)). Drupal keeps only Fincra's public key and webhook key.

`presence` is written only when the setup is given `--approver=<id>`, the person who approves an
escalated refund or payout:

```yaml
presence:
  managed: true
  approverId: "owner@example.com"
```

A gateway with `presence.managed: true` and no `approverId` refuses to start. Without the block, an
`ESCALATE` is held and reported, and nothing is forwarded.

## 2. Where the key lives

The setup installs the gateway the strongest way the hosting account allows:

| What the account can do                | How the gateway runs                                               | Where the key is                                      |
| -------------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------- |
| Root, or password-less `sudo -n`       | The `.deb` or `.rpm` package for the machine, as a systemd service | A root-only file, handed over as a systemd credential |
| A separate system user for the gateway | A user-level install and systemd user service under that user      | A file only that user can read                        |
| Only the account Drupal runs under     | A user-level install under that account                            | A file Drupal's own account can read; shown in amber  |

On the root tier the package comes from the release that carries the runtime version: runtime
`0.7.0` is on release `v0.5.0`. The download goes to a directory only root can write, and the
package is installed only when it has its own line in the release's `SHA256SUMS`. On the user tiers
the installer comes from the same release tag, with `AGENTSAFE_RELEASE_TAG` set.

The third tier still refuses refund and payout mistakes, but a site that is fully compromised can
read the key. Ask the host for a separate system user.

## 3. Drupal lets go of the key last

The setup moves the key out of Drupal's configuration, and points Commerce Fincra at
`http://127.0.0.1:8787`, only once the gateway answers `GET /_agentsafe/readyz` with `200`.
Probe the gateway only under `/_agentsafe/`: every other path, a bare `/healthz` included, is
forwarded to Fincra with the key.

Commerce Fincra needs two changes for this, a configurable API base URL and a secret key held by a
gateway. Decionis has prepared them for Commerce Fincra's maintainers; until they are merged, the
setup refuses to run against a Commerce Fincra without them.

## 4. What each request gets

| Request                                         | What the gateway does                                                                         |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Checkout creation, payment verification, others | Forwarded with the key (`agentsafe-execution: PASSTHROUGH`)                                   |
| Refund or payout, `ALLOW`                       | Forwarded once, on a claimed single-use grant (`FORWARDED`)                                   |
| Refund or payout, `BLOCK`                       | `403`, not forwarded                                                                          |
| Refund or payout, `ESCALATE`                    | Held: with `presence.managed`, for the named approver; without it, reported and not forwarded |
| Refund or payout, Decionis unreachable          | `503 AUTHORITY_UNAVAILABLE`, not forwarded (`failClosed`)                                     |

The module's integration test runs runtime `0.7.0` on this configuration in front of a Fincra
double: a checkout created without a key reaches the double with the key the gateway holds, and a
refund that cannot get a grant never reaches it.

## 5. Roll out watch-first

Start in `shadow`: refunds and payouts pass and each is decided and logged. Turn `enforcement` on
alongside the module's own refund gate once the shadow log shows what it would hold. Turn on Fincra's
IP allowlisting for the server's address, so a copied key cannot be used anywhere else.

## Boundary

Fincra does not verify Decionis signatures. The protection rests on the key and the network path:
the gateway holds the only copy the store keeps, and the allowlist limits where Fincra accepts it.
A refund made in the Fincra dashboard never passes through the gateway or the store; the module
logs it as made outside Decionis when Fincra reports it back.
