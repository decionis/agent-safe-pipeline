# High availability

The gateway is stateless but for one thing, and the chart's defaults are shaped around it.

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

## The one piece of state

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

A gateway reads a governed body in full under `maxBodyBytes` and holds up to 1,000 escalations,
so the memory a replica can need is bounded by those two numbers; the default limit (512Mi) covers
the defaults (1 MiB, 1,000). Latency per governed request is one round trip to Decionis
(`decionis.timeoutMs`, 4 seconds at most) plus one to the upstream. Passthrough requests cost
neither.

## The authority

Decionis unreachable is not a failure of the gateway but of the boundary's purpose, and the
gateway says so: `503 AUTHORITY_UNAVAILABLE` with `Retry-After`, `agentsafe_authority_errors_total`
counting, and nothing forwarded under fail closed. A deployment that must keep forwarding while
Decionis is down writes `failurePolicy: FailOpen` and accepts what the [failure
policy](../gateway/failure-policy.md) page says that costs.
