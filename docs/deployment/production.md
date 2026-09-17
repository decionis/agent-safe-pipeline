# Production

What a production deployment of the gateway looks like, on Kubernetes or a Linux host, and the
order in which it gets there. None of it changes the protocol: the same intent, the same
authority, the same claim and finalization as on a laptop.

## The checklist

- **Pin the image by digest.** `image.digest` in the chart, or `ghcr.io/decionis/agentsafe@sha256:...`
  on a host; `latest` never. The release notes carry the digest, and
  `gh attestation verify oci://ghcr.io/decionis/agentsafe@<digest> --repo decionis/agent-safe-pipeline`
  checks who built it. Mirror the image into your own registry first.
- **Enforcement, fail closed.** `gateway.mode: enforcement`, `gateway.failurePolicy: FailClosed`.
  Fail open is a per-service decision written in the values, and every ungoverned forward it
  causes is on the evidence chain.
- **The key is a file.** A Secret mounted at `/var/run/agent-safe/secrets`, a systemd credential
  on a host; never an environment variable, never in a values file. `NODE_ENV=production`, which
  the image and the unit set, refuses the other forms.
- **Name the routes.** Policy is written about actions; `gateway.routes` gives them their names.
  Keep `unmatched: govern` unless the boundary is meant to cover only what the routes name.
- **Keep the evidence.** Standard output is one JSON line per event, chained; the cluster's log
  pipeline retains it. `agentsafe verify chain` checks a retained file offline. On a host,
  `/var/lib/agentsafe/evidence` holds the lines and the chain heads a restart resumes from.
- **Tighten the network.** Ingress to the gateway from the callers only; no route from the callers
  to the upstream except through the gateway; egress from the gateway to DNS, the upstream and the
  authority only ([security](./security.md)).
- **Alert.** `agentsafe_authority_errors_total` rising means the boundary is refusing for lack of
  an answer; `agentsafe_execution_indeterminate_total` means an upstream stopped answering after
  dispatch; `agentsafe_ungoverned_forwards_total` above zero means fail open is doing what it was
  told. The executor's [alert rules](../../deploy/alerts/TrustedExecutor.yaml) are the model.
- **Resources.** The defaults (100m CPU, 128Mi request, 512Mi limit) fit a gateway that holds up
  to 1,000 escalations of 1 MiB each; raise the memory limit if `maxBodyBytes` is raised.

## Three modes, in order

1. **Shadow.** The gateway is in the path, forwarding unchanged, and Decionis records what it
   would have decided. Compare the observations with what happened; write the stopping criteria
   for enforcement in your own words. The executor's [runbook](../../deploy/Runbook.md) says what
   to compare.
2. **Enforcement, one route.** `gateway.mode: enforcement` with `unmatched: passthrough` and one
   route named: the decisions bind for that action and nothing else changes.
3. **Enforcement.** `unmatched: govern`: every consequential action is governed, and the callers
   have no route around the gateway.

Rolling back any step is a `helm upgrade` with the previous values, or `helm rollback`.

## What the gateway does not do

It does not decide. `ALLOW`, `BLOCK` and `ESCALATE` are Decionis's; the gateway asks, enforces
and records, and a demo authority is refused in production. It does not verify a person: an
`ESCALATE` is held until Decionis, having run the Presence ceremony, answers again. It does not
make the cluster enforce a NetworkPolicy, and it cannot tell whether the cluster does. And it does
not stand in for the trusted executor where one is wanted: a bank boundary with principals,
downstream credentials and a verified host posture is [`deploy/`](../../deploy/README.md).
