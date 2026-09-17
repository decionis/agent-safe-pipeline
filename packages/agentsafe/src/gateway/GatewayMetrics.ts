import { Metrics, type Counter, type Gauge } from "../incident/Metrics.js";

/**
 * The gateway's families. Label values are verdicts, states, codes and the
 * action names the configuration itself produced, never anything a caller
 * sent, so the cardinality is the configuration's and no value can leak
 * through a label. A latency is a running sum and a count, which is what a
 * scraper needs to compute a rate and a mean between two scrapes.
 */
export interface GatewayMetrics {
  readonly registry: Metrics;
  readonly requests: Counter;
  readonly interceptions: Counter;
  readonly decisions: Counter;
  readonly allows: Counter;
  readonly blocks: Counter;
  readonly escalations: Counter;
  readonly shadowDecisions: Counter;
  readonly authorityErrors: Counter;
  readonly indeterminate: Counter;
  readonly ungoverned: Counter;
  readonly held: Gauge;
  observeAuthorityLatency(ms: number): void;
  observeForwardLatency(ms: number): void;
}

function latency(registry: Metrics, name: string, help: string): (ms: number) => void {
  const sum = registry.gauge(`${name}_sum`, `${help}: sum.`);
  const count = registry.gauge(`${name}_count`, `${help}: count.`);
  return (ms) => {
    sum.set(sum.get() + Math.max(ms, 0));
    count.set(count.get() + 1);
  };
}

export function gatewayMetrics(registry: Metrics = new Metrics()): GatewayMetrics {
  return {
    registry,
    requests: registry.counter("agentsafe_requests", "Requests received, by kind.", ["kind"]),
    interceptions: registry.counter(
      "agentsafe_interceptions",
      "Consequential requests intercepted, by action.",
      ["action"],
    ),
    decisions: registry.counter(
      "agentsafe_decisions",
      "Authority decisions received in enforcement, by verdict.",
      ["verdict"],
    ),
    allows: registry.counter("agentsafe_allows", "ALLOW decisions enforced."),
    blocks: registry.counter("agentsafe_blocks", "BLOCK decisions enforced."),
    escalations: registry.counter("agentsafe_escalations", "ESCALATE decisions held."),
    shadowDecisions: registry.counter(
      "agentsafe_shadow_decisions",
      "What the authority would have decided in shadow, by verdict.",
      ["verdict"],
    ),
    authorityErrors: registry.counter(
      "agentsafe_authority_errors",
      "Fail-closed authority outcomes, by reason code.",
      ["code"],
    ),
    indeterminate: registry.counter(
      "agentsafe_execution_indeterminate",
      "Executions whose upstream outcome is unknown.",
    ),
    ungoverned: registry.counter(
      "agentsafe_ungoverned_forwards",
      "Requests forwarded under an explicit fail-open policy while the authority was unavailable.",
    ),
    held: registry.gauge("agentsafe_escalations_held", "Escalations held for a human answer."),
    observeAuthorityLatency: latency(
      registry,
      "agentsafe_authority_latency_ms",
      "Milliseconds spent waiting for the authority",
    ),
    observeForwardLatency: latency(
      registry,
      "agentsafe_forward_latency_ms",
      "Milliseconds spent waiting for the upstream",
    ),
  };
}
