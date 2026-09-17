import { describe, expect, it } from "vitest";
import { gatewayMetrics } from "../../src/gateway/GatewayMetrics.js";

describe("the gateway's metric families", () => {
  it("renders the operational families the brief names, with bounded labels", () => {
    const metrics = gatewayMetrics();
    metrics.requests.inc({ kind: "governed" });
    metrics.interceptions.inc({ action: "payment.create" });
    metrics.decisions.inc({ verdict: "ALLOW" });
    metrics.allows.inc();
    metrics.blocks.inc();
    metrics.escalations.inc();
    metrics.shadowDecisions.inc({ verdict: "BLOCK" });
    metrics.authorityErrors.inc({ code: "AUTHORITY_UNAVAILABLE" });
    metrics.indeterminate.inc();
    metrics.ungoverned.inc();
    metrics.held.set(2);
    metrics.observeAuthorityLatency(12);
    metrics.observeAuthorityLatency(-3);
    metrics.observeForwardLatency(40);
    const text = metrics.registry.render();
    expect(text).toContain('agentsafe_requests_total{kind="governed"} 1');
    expect(text).toContain('agentsafe_interceptions_total{action="payment.create"} 1');
    expect(text).toContain('agentsafe_decisions_total{verdict="ALLOW"} 1');
    expect(text).toContain("agentsafe_allows_total 1");
    expect(text).toContain("agentsafe_blocks_total 1");
    expect(text).toContain("agentsafe_escalations_total 1");
    expect(text).toContain('agentsafe_shadow_decisions_total{verdict="BLOCK"} 1');
    expect(text).toContain('agentsafe_authority_errors_total{code="AUTHORITY_UNAVAILABLE"} 1');
    expect(text).toContain("agentsafe_execution_indeterminate_total 1");
    expect(text).toContain("agentsafe_ungoverned_forwards_total 1");
    expect(text).toContain("agentsafe_escalations_held 2");
    expect(text).toContain("agentsafe_authority_latency_ms_sum 12");
    expect(text).toContain("agentsafe_authority_latency_ms_count 2");
    expect(text).toContain("agentsafe_forward_latency_ms_sum 40");
    expect(text).toContain("agentsafe_forward_latency_ms_count 1");
    expect(text.trim().endsWith("# EOF")).toBe(true);
  });
});
