import { describe, expect, it } from "vitest";
import {
  executionLabel,
  renderHuman,
  renderJson,
  stateLabel,
  type InterceptionReport,
} from "../../src/gateway/GatewayReport.js";

const ESC = String.fromCharCode(27);

const base: InterceptionReport = {
  event: "INTERCEPTED",
  at: "2026-01-01T00:00:00.000Z",
  method: "POST",
  path: "/payments",
  action: "payment.create",
  state: "ESCALATE",
  verdict: "ESCALATE",
  reason_codes: ["HUMAN_APPROVAL_REQUIRED"],
  execution: "HELD",
  mode: "ENFORCEMENT",
  authority: "local/demo",
  intent_id: "i",
  intent_hash: "sha256:0",
  decision_id: "d",
  dossier_id: "dss_01",
  upstream_status: null,
  finalization: null,
  latency_ms: 18,
  authority_ms: 12,
};

describe("the gateway's reports", () => {
  it("renders an interception as the brief shows it", () => {
    const text = renderHuman(base, { color: false });
    expect(text).toBe(
      [
        "ESCALATE",
        "",
        "POST /payments",
        "",
        "Action       payment.create",
        "Decision     ESCALATE",
        "Reason       HUMAN_APPROVAL_REQUIRED",
        "Execution    HELD",
        "Dossier      dss_01",
        "Latency      18ms",
        "",
      ].join("\n"),
    );
  });

  it("renders every state distinctly, colored when asked, and never confuses an outage with a block", () => {
    const states = [
      "ALLOW",
      "BLOCK",
      "ESCALATE",
      "SHADOW",
      "AUTHORITY_UNAVAILABLE",
      "EXECUTION_FAILED",
      "EXECUTION_INDETERMINATE",
      "ERROR",
    ] as const;
    const headings = new Set(
      states.map((state) => renderHuman({ ...base, state }, { color: false }).split("\n")[0]),
    );
    expect(headings.size).toBe(states.length);
    const colored = renderHuman({ ...base, state: "BLOCK" }, { color: true });
    expect(colored).toContain(`${ESC}[31m`);
    expect(
      renderHuman(
        {
          ...base,
          state: "AUTHORITY_UNAVAILABLE",
          verdict: null,
          reason_codes: ["AUTHORITY_UNAVAILABLE"],
          execution: "NOT_FORWARDED",
        },
        { color: false },
      ),
    ).toContain("Decision     none (authority unreachable)");
    expect(
      renderHuman(
        {
          ...base,
          state: "ERROR",
          verdict: null,
          reason_codes: [],
          execution: "NOT_FORWARDED",
          dossier_id: null,
        },
        { color: false },
      ),
    ).toContain("Reason       none");
    expect(stateLabel("EXECUTION_INDETERMINATE")).toBe("EXECUTION INDETERMINATE");
    for (const execution of [
      "FORWARDED",
      "NOT_FORWARDED",
      "HELD",
      "PASSTHROUGH",
      "FORWARDED_UNGOVERNED",
      "FAILED",
      "INDETERMINATE",
    ] as const) {
      expect(executionLabel(execution).length).toBeGreaterThan(0);
    }
  });

  it("renders a shadow observation as what would have happened, and that the request went through", () => {
    const text = renderHuman(
      {
        ...base,
        state: "SHADOW",
        verdict: "BLOCK",
        reason_codes: ["POLICY_HARD_LIMIT_EXCEEDED"],
        execution: "PASSTHROUGH",
        upstream_status: 201,
        mode: "SHADOW",
      },
      { color: false },
    );
    expect(text).toContain("SHADOW");
    expect(text).toContain("Would decide      BLOCK");
    expect(text).toContain("Actual execution  PASSTHROUGH (201)");
    expect(
      renderHuman(
        { ...base, state: "SHADOW", verdict: null, execution: "PASSTHROUGH" },
        { color: false },
      ),
    ).toContain("none (authority unavailable)");
  });

  it("renders the forwarded status and the finalization when there is one", () => {
    const text = renderHuman(
      {
        ...base,
        state: "ALLOW",
        verdict: "ALLOW",
        execution: "FORWARDED",
        upstream_status: 201,
        finalization: "RECORDED",
      },
      { color: false },
    );
    expect(text).toContain("Execution    FORWARDED (201)");
    expect(text).toContain("Finalized    RECORDED");
  });

  it("renders the banner, notes and the stop line", () => {
    const banner = renderHuman(
      {
        event: "GATEWAY_STARTED",
        at: base.at,
        gateway: "http://127.0.0.1:8080",
        upstream: "http://localhost:3000",
        mode: "SHADOW",
        authority: "local/demo",
        failure_policy: "FAIL_CLOSED",
        routes: 0,
        evidence: "terminal",
        version: "1.0.0",
      },
      { color: false },
    );
    expect(banner).toContain("Gateway      http://127.0.0.1:8080");
    expect(banner).toContain("Mode         SHADOW");
    expect(banner).toContain("Status       READY");
    expect(banner).toContain("Waiting for consequential actions...");
    expect(banner).toContain("none named; every unsafe method is governed");
    const open = renderHuman(
      {
        event: "GATEWAY_STARTED",
        at: base.at,
        gateway: "g",
        upstream: "u",
        mode: "ENFORCEMENT",
        authority: "a",
        failure_policy: "FAIL_OPEN",
        routes: 3,
        evidence: "e",
        version: "1",
      },
      { color: true },
    );
    expect(open).toContain("fail-open (explicit)");
    expect(open).toContain("Routes       3");
    expect(
      renderHuman({ event: "GATEWAY_STOPPED", at: base.at, signal: "SIGINT" }, { color: false }),
    ).toBe("Stopped on SIGINT.\n");
    expect(
      renderHuman(
        { event: "NOTE", at: base.at, level: "info", code: "X", message: "hello" },
        { color: false },
      ),
    ).toBe("NOTE hello\n");
    expect(
      renderHuman(
        { event: "NOTE", at: base.at, level: "warn", code: "X", message: "careful" },
        { color: false },
      ),
    ).toBe("WARNING careful\n");
    expect(
      renderHuman(
        { event: "NOTE", at: base.at, level: "error", code: "X", message: "bad" },
        { color: true },
      ),
    ).toContain("ERROR");
  });

  it("renders JSON as the same fields on one line", () => {
    expect(JSON.parse(renderJson(base))).toEqual(base);
    expect(renderJson(base)).not.toContain("\n");
  });
});
