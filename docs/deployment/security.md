# Security

What the chart and the image establish, and what stays with the cluster. The executor's
[threat model](../../THREAT-MODEL.md) is the fuller account; the gateway is the same runtime under
a different ingress and shares its invariants.

## What the image establishes

Distroless, no shell, no package manager; the process runs as `65532` under Node's permission
model with read access to the application, `/etc/agentsafe` and `/var/run/agent-safe`, write
access to `/var/lib/agent-safe` alone, and no ability to spawn a process, a worker or an addon.
`NODE_ENV=production` refuses the demo authority, a key in the environment, the stored login and a
plain-http authority.

## What the chart establishes

- `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, every capability
  dropped, `RuntimeDefault` seccomp; the pod fails admission under a `restricted` Pod Security
  profile only where the profile is not applied.
- No service-account token mounted and no bindings: the gateway calls no Kubernetes API.
- The key as a file from a Secret referenced by name, mode `0440`, group-readable by the process.
- A NetworkPolicy: ingress on the listener from the named sources; egress to DNS, the upstream
  Service's pods, and the authority on 443 (to the CIDRs named, or to every non-cluster address
  when none are). The kubelet's probes are node-local and need no rule.
- A read-only on-call Role, optional, with no verb on Secrets or ConfigMaps.

## What the runtime establishes

- **Exact-action forwarding.** The bytes the upstream receives are the bytes whose digest the
  authority bound; the handler recomputes and compares before the point of no return, and
  `SafeExecutor` re-checks the intent's conformance before the handler runs.
- **One execution per grant.** The grant is single-use and claimed with Decionis immediately before
  dispatch; a replayed or expired grant claims nothing.
- **No local verdict.** `ALLOW`, `BLOCK` and `ESCALATE` come from Decionis; an `ESCALATE` becomes
  an execution only through a fresh decision after the ceremony; an unreachable authority is
  `AUTHORITY_UNAVAILABLE`, never a `BLOCK` and never an `ALLOW`.
- **Nothing sensitive in evidence or telemetry.** Request headers never enter the intent; the
  evidence lines carry identifiers, digests, verdicts and codes; metric labels are verdicts, codes
  and configured action names; the key is read through a handle and redacted from every line by
  digest.
- **The authority over sealed egress.** Decionis and Presence are reached through the guarded
  fetch: HTTPS, no redirects, bounded bodies, the origin the configuration named and no other.

## What stays with the cluster

- **Enforcing the NetworkPolicy.** A CNI that does not enforce it ignores it silently; the runtime
  cannot tell. Without it, a caller can reach the upstream around the gateway, and the boundary is
  a convention.
- **The callers' own route to the upstream.** Denying it is the cluster's policy, in the upstream's
  namespace, not the gateway's.
- **TLS to the gateway.** The listener is plain HTTP behind the platform's TLS (a mesh, an
  ingress controller); a gateway exposed beyond the namespace needs that in front of it.
- **The Secret's lifecycle.** How the key gets into the Secret, who can read it, and rotation
  (a rolled Secret is read on the next request; a rotated key that no longer works is
  `AUTHORITY_UNAVAILABLE` until the Secret is updated).
- **Who is on call**, and what group `rbac.operatorGroup` binds.

## Reporting

Security reports go to the address in [SECURITY.md](../../SECURITY.md).
