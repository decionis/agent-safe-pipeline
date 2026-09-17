import { describe, expect, it } from "vitest";
import { ACTIVATION_MILESTONES, ActivationFunnel } from "../../src/gateway/Activation.js";
import { renderHuman, renderJson } from "../../src/gateway/GatewayReport.js";

describe("the activation funnel", () => {
  it("reports each milestone once, with when, and nothing else", () => {
    const reported: [string, string][] = [];
    let now = 1_000;
    const funnel = new ActivationFunnel(
      (milestone, at) => reported.push([milestone, at]),
      () => now,
    );
    funnel.started({ mode: "SHADOW", authority: "DECIONIS", production: true });
    now = 2_000;
    funnel.intercepted();
    funnel.intercepted();
    funnel.governed();
    funnel.started({ mode: "ENFORCEMENT", authority: "LOCAL", production: false });
    expect(reported).toEqual([
      ["gateway_started", "1970-01-01T00:00:01.000Z"],
      ["shadow_enabled", "1970-01-01T00:00:01.000Z"],
      ["decionis_connected", "1970-01-01T00:00:01.000Z"],
      ["production_deployment", "1970-01-01T00:00:01.000Z"],
      ["first_interception", "1970-01-01T00:00:02.000Z"],
      ["first_governed_action", "1970-01-01T00:00:02.000Z"],
      ["enforcement_enabled", "1970-01-01T00:00:02.000Z"],
    ]);
    const snapshot = funnel.snapshot();
    expect(Object.keys(snapshot)).toEqual([...ACTIVATION_MILESTONES]);
    expect(snapshot.first_governed_action).toBe("1970-01-01T00:00:02.000Z");
    const fresh = new ActivationFunnel(() => undefined);
    expect(Object.values(fresh.snapshot()).every((value) => value === null)).toBe(true);
    fresh.started({ mode: "ENFORCEMENT", authority: "LOCAL", production: false });
    expect(fresh.snapshot().decionis_connected).toBeNull();
    expect(fresh.snapshot().production_deployment).toBeNull();
    expect(fresh.snapshot().enforcement_enabled).not.toBeNull();
  });

  it("renders as one dim line, or one JSON line, carrying the name and the time only", () => {
    const report = {
      event: "ACTIVATION" as const,
      milestone: "first_governed_action",
      at: "2026-01-01T00:00:00.000Z",
    };
    expect(renderHuman(report, { color: false })).toBe("✓ first governed action\n");
    expect(JSON.parse(renderJson(report))).toEqual(report);
  });
});
