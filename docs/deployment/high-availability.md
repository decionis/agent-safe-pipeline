# High availability

The gateway keeps approval holds, evidence-chain state and admission counters per process. The
chart's defaults account for the routing requirement of held approvals; they do not make that
state shared or durable.

## What the defaults give

- **Two replicas**, preferring different nodes (`podAntiAffinity` on the hostname), so one node's
  loss does not remove the boundary. `topologySpreadConstraints` spreads them across zones where
  the cluster has them.
- **A PodDisruptionBudget** with `minAvailable: 1`, so a drain never removes both.
- **Rolling updates** with `maxUnavailable: 0`, so an upgrade adds a replica before it removes
  one, and the ConfigMap checksum rolls the pods when the configuration changes.
- **Readiness on `/_agentsafe/readyz`**, which answers once the listener is bound; a pod that is
  not ready receives no traffic. **Liveness on `/_agentsafe/healthz`**, which answers while the
  process lives; a hung process is restarted.
- **A clean stop.** `SIGTERM` closes the listener, gives requests in flight ten seconds, and exits
  `0`; `terminationGracePeriodSeconds: 20` leaves room for it.
- **An autoscaler**, when `autoscaling.enabled`, on CPU between `minReplicas` and `maxReplicas`.

## Approval holds and routing

A held escalation lives in the memory of the replica that holds it, until the intent expires
(`intentTtlSeconds`, 120 by default, at most 300) or the resume resolves it. A resume that reaches
another replica is `404 ESCALATION_NOT_HELD`. The Service's `sessionAffinity: ClientIP` keeps one
caller on one replica, which covers a caller that resumes what it held; a replica that restarts
loses its holds, which the caller sees as `404` and answers by sending the request again, for a
fresh decision. Nothing is executed twice: a hold is never a grant, and a grant is claimed once.

With managed Presence the ceremony itself is Decionis's and survives the replica; only the
gateway's memory of which request it belongs to does not. A durable hold shared across replicas is
a feature the runtime does not have yet, and the honest answer until it does is the affinity and
the retry.

## Capacity

A gateway reads a governed body in full under `maxBodyBytes` and holds up to 1,000 escalations.
At the default 1 MiB body limit, 1,000 full-size holds alone need about 1,000 MiB, before request,
intent, response and runtime overhead. The chart's 512Mi memory limit is therefore not a promise
that the maximum backlog fits. Size for the expected concurrent requests and approval backlog,
and coordinate memory, body bounds and admission limits. A per-process rate limit is not a global
cluster limit.

Enforcement includes authority evaluation, grant claim, the upstream call and finalization;
human approval adds another stage. `decionis.timeoutMs` in Helm values (`authority.timeoutMs`
in runtime YAML) defaults to 4,000 ms and permits up to 15,000 ms for an authority call. It is
not the complete action's latency budget. Measure the full lifecycle under the intended workload.
Passthrough skips authority calls but still incurs the upstream request and bounded buffering.

Keep evidence ordered and separated by replica. Persisting evidence does not persist approval
holds. For the trusted executor's card APIs, card holds and authorization retry lookup also
require their own replica-routing and recovery design; the gateway chart does not deploy those
APIs. See [deployment boundaries](../gateway/deployment.md).

## The authority

Decionis unreachable is not a failure of the gateway but of the boundary's purpose, and the
gateway says so: `503 AUTHORITY_UNAVAILABLE` with `Retry-After`, `agentsafe_authority_errors_total`
counting, and nothing forwarded under fail closed. A deployment that must keep forwarding while
Decionis is down writes `failurePolicy: FailOpen` and accepts what the [failure
policy](../gateway/failure-policy.md) page says that costs.
