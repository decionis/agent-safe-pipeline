# Accept a deployment

`agentsafe accept` answers four questions for one installed gateway:

- which consequential paths it governs;
- what evidence shows that;
- under what conditions that evidence holds;
- where the claim stops.

It runs from the agent's zone against the deployed gateway. It sends only what a plan you write
names. The gateway signs what it observed into a report, `agent-safe.acceptance/1`, which anyone can
verify offline with a key you pin. The design, and the options it rejected, are in
[ADR 0009](../architecture/decisions/0009-acceptance-run-on-named-targets.md).

A run proves your deployment, under one fingerprint, for the writes and routes you named. It does
not carry over to other adapters, routes or environments. The build's own proofs
(`pnpm examples:prove`) prove the runtime; this proves where you put it.

## What a run does

| Case                  | What is sent                                                                                                                                                       | Who observes it | Passes when                                                                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Permitted write       | Each `permitted` write, once, through the gateway                                                                                                                  | Gateway         | Allowed, forwarded, answered `2xx`, and read back as asked (`CONFIRMED`), or not read (`PENDING`, which the report says)                   |
| Prohibited write      | Each `prohibited` write, decided first in shadow on the gateway, and sent through it only when that decision was `BLOCK` or `ESCALATE`                             | Gateway         | Refused, and the gateway's read of the target after the refusal found it `UNCHANGED`                                                       |
| Authority unreachable | Every plan write, through a second gateway the deployed process builds from its own configuration, with its authority unreachable and its upstream a recording one | Gateway         | `503` `NOT_FORWARDED`, and no write reached the recording upstream. Not run on a gateway that fails open, which governs nothing while down |
| Other routes          | Each origin's read directly and through the gateway; each provider's write unattested and signed by a key it cannot know; MCP servers; the metadata endpoint       | Zone            | An origin is `CONTAINED`; a provider refused both writes; the metadata endpoint, when probed, did not answer                               |
| Stated, not run       | Nothing                                                                                                                                                            | Nobody          | Listed with the reason: grants after issuance, lost outcomes and restarts, downstream consequences, host integrity, node isolation         |

The verdict is `ACCEPTED` only when every case that ran passed. A zone finding is the zone's word:
it is what the containment probe says it is, where `REACHABLE` proves a hole and nothing proves
containment. Credentials found in the zone and reachable MCP servers are listed by name and kind,
never by value, and do not decide the verdict.

## 1. Give the gateway a key and a token

The gateway serves runs only when both files are configured. Without them its acceptance endpoints
answer `404`, and any request carrying the run header is refused.

```yaml
acceptance:
  key:
    file: /etc/agentsafe/acceptance.pem # Ed25519, PKCS#8 PEM; signs acceptance reports and nothing else
  operatorToken:
    file: /etc/agentsafe/acceptance-token # the bearer agentsafe accept presents
  kid: null # the key's id in a report; its RFC 7638 thumbprint when unset
```

Or `AGENTSAFE_ACCEPTANCE_KEY_FILE` and `AGENTSAFE_ACCEPTANCE_TOKEN_FILE`. Make the key with:

```bash
openssl genpkey -algorithm ed25519 -out /etc/agentsafe/acceptance.pem
```

Then pin its public half where the gateway runs. `agentsafe identity --json` prints it as
`acceptance.public_jwk`, beside its `kid`:

```bash
agentsafe identity --json --config agentsafe.yaml > acceptance-key.json
```

The operator token reaches the agent's zone for the run only. It opens runs and asks for shadow
decisions on the writes a run's plan names as prohibited, and nothing else. Every decision made with
it is on the gateway's chain. Remove it from the zone when the run is done.

## 2. Write the plan

```yaml
version: agent-safe.acceptance-plan/1
gateway: https://agentsafe.payments.internal
expires_at: "2026-12-31T00:00:00Z"
permitted:
  - name: unblock-test-customer
    method: PATCH
    path: /companies(…)/customers(…)
    body: { blocked: " " }
prohibited:
  - name: block-canary-customer
    method: PATCH
    path: /companies(…)/customers(…)
    body: { blocked: "All" }
    canary: the canary customer C-90000, created for this run
origins:
  - name: erp
    url: https://erp.internal/api/v2.0/companies # a read with no side effect
providers: [] # verifying providers, each with one write at a canary resource
mcp: [] # MCP server URLs to check for reachability
metadata: false # true probes the cloud metadata endpoint with one GET
```

The gateway refuses a run whose plan names a write it does not decide in enforcement, or a
prohibited write whose profile operation names no read of its target: a refusal there could not be
observed at the target. `expires_at` is required, because the fingerprint does not see network
policy, cloud IAM or the upstream's own configuration. A canary is your statement that the resource
may change, and the report repeats it as yours.

## 3. Run it from the agent's zone

```bash
agentsafe accept --plan acceptance.yaml --token-file /run/secrets/acceptance-token --out acceptance.jws
```

Run it where the agent runs, with the agent's network position: in its pod, its container or its
namespace. The command exits `0` when the gateway signed an `ACCEPTED` report, `1` when it signed
`NOT_ACCEPTED`, and `2` when no report was signed.

## 4. Verify the report

```bash
agentsafe verify acceptance acceptance.jws --key acceptance-key.json
```

This checks the signature and the report offline, against the key you pinned, and its date.
`--current --gateway <url>` also compares the report's fingerprint with the gateway running now:
`CURRENT`, `STALE` with the fields that changed, or `EXPIRED`. `agentsafe status --acceptance
acceptance.jws` shows the same on the gateway's own status, checked with the key the gateway
serves. A stale report is reported, never enforced.

## 5. Rerun it on every change

The plan and the report are yours. Keep the plan beside your deployment and rerun it whenever the
gateway's configuration, image, profile, routes, credentials, network policy or the authority's
policy changes: in CI after a deploy, or as a `helm test` hook. A report goes `STALE` the moment
the fingerprint moves, and it stops being current on its date whatever happens.

## What the report holds

- The fingerprint it was observed under, its document and digest, and the plan's digest.
- The coverage: the governed routes, each saying whether its target is read, and the ungoverned
  ones by kind (shadow, fail-open, passthrough), the refused ones, and how reads are treated.
- Each case, with `observed_by`, the decision and dossier ids, the gateway chain lines it wrote,
  and the target versions it read.
- The fixed list of what no run establishes, each with its reason.
- The verdict and the failing cases.
- The sentence that it does not carry over to other adapters, routes or environments.

The gateway records `ACCEPTANCE_RUN_OPENED`, `ACCEPTANCE_SHADOW_DECIDED` and `ACCEPTANCE_SIGNED` on
its chain ([executor evidence](../executor-evidence.md)). The last one carries the report's digest,
so a report can be matched to the chain that witnessed it.
