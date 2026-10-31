# Deployment fingerprint and action-space drift

A test of a boundary holds for the boundary that was tested. The deployment fingerprint says which
one that was: what the running gateway is, in one small document with one digest, so a later
reader can tell whether the gateway in front of them is still the one a test, an acceptance run or
a review described. Beside it, the gateway compares the action space it loaded with the one the
deciding policy release was checked against, and reports when they differ.

Both are reports. Nothing refuses to start, and no decision is changed, delayed or refused, for a
fingerprint that changed or an action space that drifted (decision D-3 of the buyer-evidence plan).
Neither sends anything anywhere: the fingerprint is computed from the configuration in the process,
and the release's action space arrives on the decision the gateway already asked for.

## `agent-safe.deployment-fingerprint/1`

The gateway computes the document once when it is built: at start, and for each tenant gateway a
host rebuilds on a reload. Nothing it covers changes while a gateway runs, so a gateway has one
fingerprint for its life. Every field comes from the configuration and the build, and none from
anything the gateway observed, so the same configuration under the same build yields the same
document and digest on every start.

| Field                    | What it holds                                                                                                                                                                                                                                                                |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fingerprint`            | `agent-safe.deployment-fingerprint/1`                                                                                                                                                                                                                                        |
| `runtime`                | `version`, and `image_digest`: the image digest the orchestrator declared (`AGENTSAFE_WORKLOAD_DIGEST`, `supplied` and never more, as [workload provenance](./authority/workload-provenance.md) says), or `null`                                                             |
| `configuration_digest`   | `sha256:` over the RFC 8785 form of the effective configuration, without `sources` (where a setting came from does not change what the gateway does) and with every tenant key digest written as `[REDACTED]`                                                                |
| `action_manifest_digest` | the digest of the action space this gateway loaded, exactly as `agentsafe actions manifest --gateway --digest` prints it for the same configuration; `null` when no manifest describes it (the gateway governs nothing, or more actions or targets than one manifest lists)  |
| `routes`                 | the route table in the order the gateway tries it: each row's `methods`, `path` (`/**` for the rest), `action`, `mode` (`SHADOW` or `ENFORCEMENT` for a governed row, `PASSTHROUGH` or `REFUSE` where nothing is asked) and `failure_policy` (`null` where nothing is asked) |
| `principals`             | `actor` (the actor the gateway names on every intent), `header` (the header a caller names itself in, or `null`) and `subject_issuer` (the identity provider a session's subject is pinned to, or `null`)                                                                    |
| `upstream_identity`      | `mode` (`CALLER`, the caller's headers as they are, or `GATEWAY_CREDENTIAL`, a credential the gateway holds), its `header`, and `gateway_token` (whether the gateway sends its own token)                                                                                    |
| `authority`              | `kind` (`DECIONIS` or `LOCAL`), the `endpoint` as configured, and the `tenant`                                                                                                                                                                                               |
| `containment`            | the declared [containment targets](#containment-targets), as `name=host:port`, in the order declared                                                                                                                                                                         |

The digest is `sha256:` over the document's RFC 8785 form. A change to any field is a different
deployment, and the field that changed says why: a new route changes `configuration_digest`,
`action_manifest_digest` and `routes`; a rotated upstream credential file with the same header
changes nothing.

The configuration holds no secret value, only the names of the secrets and the files they are
read from, so no secret can reach the document. The tenant keys' digests are the one value
derived from a secret; each is redacted, so a rotation that keeps their number is the same
deployment.

### Where it appears

- `agentsafe status --json`, and `GET /_agentsafe/status`, as `fingerprint`: `{ digest, document }`.
  `agentsafe status` prints the short digest as `Fingerprint`. The document names the route table,
  including what passes ungoverned, and the declared containment targets: restrict
  `/_agentsafe/status` to operators, as [deployment](./gateway/deployment.md) already says, since
  a non-hosted gateway answers it without the metrics token.
- The gateway's chained stream, `agent-safe.gateway-events/1`, as a `DEPLOYMENT_FINGERPRINT` line
  right after `GATEWAY_STARTED`, carrying `digest` and the whole `document`. A gateway a host built
  to replace another records its own only when its digest differs from the one it replaces, so the
  chain shows each change once.
- The metric `agentsafe_deployment_fingerprint{digest="sha256:..."} 1`.
- `agentsafe doctor` compares the running gateway's fingerprint with the one its own configuration
  describes, the runtime aside, and fails the check, naming the fields that differ, when the
  gateway runs another configuration.

### Containment targets

`containment.targets` (`AGENTSAFE_CONTAINMENT_TARGETS`, comma-separated) declares the systems of
record the agent zone must not reach except through this gateway, as `name=host:port`, at most 64.
The gateway never dials them: they are part of what the deployment says it is, and what
`agentsafe probe-containment` is pointed at from the agent zone ([bypass
resistance](./bypass-resistance.md)).

## Action-space drift

A Decionis policy release is checked against an action manifest: a release that leaves a manifest
action matched by no rule but its default is refused before it can be promoted. If the gateway can
propose an action the release's manifest never named, the coverage check never saw it.

From `agent-safe-pipeline` 0.5.1, the decision on `enforce-and-bind` carries the deciding release's
`actionManifestDigest` as `action_manifest_digest` (`null` when no governed release decided, or its
release attached no manifest). The gateway compares it with its own `action_manifest_digest`:

- `UNCHECKED` until a decision names a release's action space;
- `MATCH` while the last decision that named one named this gateway's;
- `DRIFT` when it named another. Each drifting release is recorded once, as an `ACTION_SPACE_DRIFT`
  line on `agent-safe.gateway-events/1` carrying the gateway's `fingerprint`, its `loaded` digest,
  the `release` digest and the `decision_id` that first named it. The last 64 drifting releases are
  remembered; an older one is recorded again if it returns.

A decision that names no release changes nothing. Both modes compare: an enforced decision, and
what the authority answered a shadow observation. The comparison shows in `agentsafe status`
(`Action space`, and `action_space` in the JSON: `loaded`, `release`, `state`, `drifted`), in
`agentsafe doctor` (the `action space` check fails on `DRIFT`), and as the gauge
`agentsafe_action_space_drift`, `1` while the state is `DRIFT`.

To clear it, attach this gateway's own manifest to the policy revision and release it again:

```bash
agentsafe actions manifest --gateway --config agentsafe.yaml > actions.json
```

A gateway governed by an API profile alone describes the profile's writes exactly as
`agentsafe actions manifest --api <profile>` does, so a release held to that manifest matches it.
Explicit routes, and the derived `http.<method>` actions when the rest is governed, are entries of
the gateway's own family (`gateway`).

## What this does not do

- It does not check the host, the network or the upstream. The fingerprint is what the gateway was
  configured to be; that the configuration is enforced around it is the
  [containment probe](./bypass-resistance.md)'s question and the platform's.
- It does not refuse anything. Refusing to enforce on a stale acceptance or on drift may become an
  opt-in later; today drift is reported and the gateway keeps deciding.
- It sends nothing. There is no telemetry call: the digest leaves the process only in the lines,
  the status and the metric the operator already reads.
