import { describe, expect, it } from "vitest";
import { Metrics, executorMetrics } from "../../src/incident/Metrics.js";

describe("Metrics", () => {
  it("renders counters and gauges as OpenMetrics text with fixed label names", () => {
    const registry = new Metrics();
    const proposals = registry.counter("agentsafe_proposals", "Proposals, by verdict.", [
      "verdict",
    ]);
    const drift = registry.gauge("agentsafe_posture_degraded", "Whether a drift stands.");
    proposals.inc({ verdict: "ALLOW" });
    proposals.inc({ verdict: "ALLOW" });
    proposals.inc({ verdict: "BLOCK" }, 3);
    proposals.inc({ verdict: 'quo"te\\back\nline' });
    proposals.inc({ unrelated: "x" });
    drift.set(1);
    drift.set(0);
    expect(proposals.get({ verdict: "ALLOW" })).toBe(2);
    expect(proposals.get({ verdict: "NONE" })).toBe(0);
    expect(drift.get()).toBe(0);
    expect(registry.render()).toBe(
      [
        "# HELP agentsafe_proposals Proposals, by verdict.",
        "# TYPE agentsafe_proposals counter",
        'agentsafe_proposals_total{verdict="ALLOW"} 2',
        'agentsafe_proposals_total{verdict="BLOCK"} 3',
        'agentsafe_proposals_total{verdict="quo\\"te\\\\back\\nline"} 1',
        'agentsafe_proposals_total{verdict=""} 1',
        'agentsafe_proposals_total{verdict="NONE"} 0',
        "# HELP agentsafe_posture_degraded Whether a drift stands.",
        "# TYPE agentsafe_posture_degraded gauge",
        "agentsafe_posture_degraded 0",
        "# EOF",
        "",
      ].join("\n"),
    );
    expect(
      registry.counter("agentsafe_proposals", "again", ["other"]).get({ verdict: "ALLOW" }),
    ).toBe(2);
  });

  it("counts the security events that have a family, and leaves the rest alone", () => {
    const metrics = executorMetrics();
    metrics.observe({ event: "AUTH_FAILED", method: "bearer", code: "CALLER_NOT_AUTHENTICATED" });
    metrics.observe({ event: "AUTH_FAILED", method: "mtls", code: "CALLER_NOT_AUTHENTICATED" });
    metrics.observe({ event: "EGRESS_REFUSED", origin: null, code: "EGRESS_ORIGIN_NOT_ALLOWED" });
    metrics.observe({ event: "SECRET_ROTATED", name: "DECIONIS_API_KEY" });
    metrics.observe({ event: "POSTURE_DRIFT", check: "PROXY_ENV" });
    metrics.observe({ event: "LEAK_SUSPECTED", patterns: ["bearer"] });
    metrics.observe({ event: "TLS_CONTEXT_ROTATED" });
    metrics.observe({ event: "POSTURE_VERIFIED", checks: 22, waived: 0 });
    metrics.observe({ event: "CHAIN_CHECKPOINT", chain: "agent-safe.security/1", head: 3 });
    expect(metrics.authFailures.get({ method: "bearer" })).toBe(1);
    expect(metrics.authFailures.get({ method: "mtls" })).toBe(1);
    expect(metrics.egressRefused.get({ code: "EGRESS_ORIGIN_NOT_ALLOWED" })).toBe(1);
    expect(metrics.secretRotations.get({ name: "DECIONIS_API_KEY" })).toBe(1);
    expect(metrics.postureDrift.get({ check: "PROXY_ENV" })).toBe(1);
    expect(metrics.leaksSuspected.get()).toBe(1);
    expect(metrics.tlsRotations.get()).toBe(1);
    metrics.proposals.inc({ verdict: "ALLOW" });
    metrics.executions.inc({ outcome: "COMPLETED" });
    metrics.auditLines.inc({ chain: "agent-safe.executor-evidence/1" });
    const text = metrics.registry.render();
    for (const family of [
      "agentsafe_proposals",
      "agentsafe_executions",
      "agentsafe_auth_failures",
      "agentsafe_egress_refused",
      "agentsafe_secret_rotations",
      "agentsafe_posture_drift",
      "agentsafe_leaks_suspected",
      "agentsafe_tls_rotations",
      "agentsafe_audit_lines",
    ]) {
      expect(text).toContain(`# TYPE ${family} counter`);
    }
    expect(text).toContain('agentsafe_auth_failures_total{method="mtls"} 1');
    expect(text).toContain("agentsafe_leaks_suspected_total 1");
    expect(text.endsWith("# EOF\n")).toBe(true);
  });
});
