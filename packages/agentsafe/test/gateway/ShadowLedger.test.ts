import { describe, expect, it } from "vitest";
import { GatewayConfigLoader, type GatewayConfig } from "../../src/gateway/GatewayConfig.js";
import {
  enforcementSwitch,
  renderShadowReport,
  ShadowLedger,
  type ShadowReport,
} from "../../src/gateway/ShadowLedger.js";

const ESC = String.fromCharCode(27);
const TENANT_ID = "00000000-0000-4000-8000-000000000009";

function config(
  input: Partial<Parameters<typeof GatewayConfigLoader.load>[0]> = {},
): GatewayConfig {
  return GatewayConfigLoader.load({
    env: { AGENTSAFE_UPSTREAM: "http://localhost:3000" },
    version: "0.0.0",
    ...input,
  });
}

const report = (ledger: ShadowLedger, enforce = "switch"): ShadowReport => ({
  event: "SHADOW_REPORT",
  at: "2026-09-19T12:00:00.000Z",
  shadow: ledger.summary(),
  enforce,
});

describe("the shadow ledger", () => {
  it("counts observations by verdict and by action, from the first to the last", () => {
    const ledger = new ShadowLedger();
    expect(ledger.summary()).toEqual({
      since: null,
      until: null,
      observed: 0,
      would: { ALLOW: 0, ESCALATE: 0, BLOCK: 0, NONE: 0 },
      accepted: { ESCALATE: 0, BLOCK: 0 },
      by_action: {},
    });
    expect(ledger.observed).toBe(0);
    ledger.record("payments.refund", "BLOCK", "2026-09-19T10:00:00.000Z");
    ledger.record("http.post", "ALLOW", "2026-09-19T10:00:01.000Z");
    ledger.record("http.post", null, "2026-09-19T10:00:02.000Z");
    ledger.record("http.post", "ESCALATE", "2026-09-19T10:00:03.000Z");
    expect(ledger.summary()).toEqual({
      since: "2026-09-19T10:00:00.000Z",
      until: "2026-09-19T10:00:03.000Z",
      observed: 4,
      would: { ALLOW: 1, ESCALATE: 1, BLOCK: 1, NONE: 1 },
      accepted: { ESCALATE: 0, BLOCK: 0 },
      by_action: {
        "http.post": { ALLOW: 1, ESCALATE: 1, BLOCK: 0, NONE: 1 },
        "payments.refund": { ALLOW: 0, ESCALATE: 0, BLOCK: 1, NONE: 0 },
      },
    });
    expect(ledger.observed).toBe(4);
  });

  it("counts the would-be holds and refusals the upstream accepted as sent, and no others", () => {
    const ledger = new ShadowLedger();
    const at = "2026-09-19T10:00:00.000Z";
    ledger.record("payments.refund", "BLOCK", at, 201);
    ledger.record("payments.refund", "BLOCK", at, 200);
    ledger.record("payments.refund", "BLOCK", at, 299);
    // Refused by the upstream itself, or unanswered: not a credential that passed.
    ledger.record("payments.refund", "BLOCK", at, 403);
    ledger.record("payments.refund", "BLOCK", at, 199);
    ledger.record("payments.refund", "BLOCK", at, 300);
    ledger.record("payments.refund", "BLOCK", at, null);
    ledger.record("payments.refund", "BLOCK", at);
    ledger.record("payments.refund", "ESCALATE", at, 202);
    ledger.record("payments.refund", "ESCALATE", at, 500);
    // What would have been allowed, or had no verdict, is not a refusal accepted.
    ledger.record("payments.refund", "ALLOW", at, 200);
    ledger.record("payments.refund", null, at, 200);
    expect(ledger.summary()).toMatchObject({
      observed: 12,
      would: { ALLOW: 1, ESCALATE: 2, BLOCK: 8, NONE: 1 },
      accepted: { ESCALATE: 1, BLOCK: 3 },
    });
  });

  it("keeps the action names bounded, folding the rest into one bucket", () => {
    const ledger = new ShadowLedger();
    for (let index = 0; index < 1_005; index += 1) {
      ledger.record(`action.${String(index)}`, "ALLOW", "2026-09-19T10:00:00.000Z");
    }
    ledger.record("action.0", "BLOCK", "2026-09-19T10:00:00.000Z");
    const summary = ledger.summary();
    expect(Object.keys(summary.by_action)).toHaveLength(1_001);
    expect(summary.by_action["other"]).toEqual({ ALLOW: 5, ESCALATE: 0, BLOCK: 0, NONE: 0 });
    expect(summary.by_action["action.0"]).toEqual({ ALLOW: 1, ESCALATE: 0, BLOCK: 1, NONE: 0 });
    expect(summary.observed).toBe(1_006);
  });

  it("renders the report: nothing yet, then the counts, the actions and what enforcement would change", () => {
    const ledger = new ShadowLedger();
    const empty = renderShadowReport(report(ledger, "the switch"), { color: false });
    expect(empty).toContain("Shadow report");
    expect(empty).toContain("no consequential action yet");
    expect(empty).toContain("Turn it on   the switch");
    ledger.record("http.post", "ALLOW", "2026-09-19T10:00:00.000Z");
    ledger.record("http.post", "ALLOW", "2026-09-19T10:00:00.000Z");
    const unchanged = renderShadowReport(report(ledger), { color: false });
    expect(unchanged).toContain("Since        2026-09-19T10:00:00.000Z\n");
    expect(unchanged).toContain(
      "Observed     2 consequential actions, every one forwarded unchanged",
    );
    expect(unchanged).toContain(
      "Enforcement would have changed nothing: all 2 would have gone through as they did.",
    );
    ledger.record("payments.refund", "BLOCK", "2026-09-19T11:00:00.000Z");
    ledger.record("payments.refund", "ESCALATE", "2026-09-19T11:00:00.000Z");
    ledger.record("payments.refund", null, "2026-09-19T11:00:00.000Z");
    const text = renderShadowReport(report(ledger), { color: false });
    expect(text).toContain("Since        2026-09-19T10:00:00.000Z until 2026-09-19T11:00:00.000Z");
    expect(text).toContain("Would ALLOW  2");
    expect(text).toContain("Would hold   1   ESCALATE: a person would have been asked first");
    expect(text).toContain("Would BLOCK  1   nothing would have reached the upstream");
    expect(text).toContain("No verdict   1   the authority could not be asked, or not in time");
    expect(text).toContain("By action    http.post            2   allow 2  hold 0  block 0\n");
    expect(text).toContain(
      "             payments.refund      3   allow 0  hold 1  block 1  none 1",
    );
    expect(text).toContain(
      "Enforcement would have held 1 and refused 1 of 5; 2 would have gone through as they did.",
    );
    expect(text).not.toContain("Compromised Principal Test");
    expect(text).not.toContain(ESC);
    expect(renderShadowReport(report(ledger), { color: true })).toContain(`${ESC}[1m`);
    // A would-be refusal the upstream accepted is the test, observed; the
    // line comes before the switch, and counts its own number.
    ledger.record("payments.refund", "BLOCK", "2026-09-19T12:00:00.000Z", 201);
    const one = renderShadowReport(report(ledger, "the switch"), { color: false });
    expect(one).toContain(
      "1 would-be refusal was accepted by the upstream as sent: a valid credential, a permitted API, an intent nobody authorized. That is the Compromised Principal Test, observed (docs/compromised-principal-test.md).\nTurn it on   the switch",
    );
    ledger.record("payments.refund", "BLOCK", "2026-09-19T12:00:00.000Z", 200);
    expect(renderShadowReport(report(ledger), { color: false })).toContain(
      "2 would-be refusals were accepted by the upstream as sent",
    );
  });

  it("names the switch in the terms the mode was configured in", () => {
    // Against the demo authority, the switch says what it enforces and how
    // Decionis comes to decide instead.
    const demo =
      "; that enforces the local demo authority's synthetic policy. For Decionis to decide: `agentsafe login --provision` mints a free workspace (no account; it decides in shadow), and `agentsafe login` with a key from your organization enables enforcement";
    expect(enforcementSwitch(config())).toBe(
      `\`agentsafe proxy --mode enforcement\`, or \`AGENTSAFE_MODE=enforcement\`, or \`authority.mode: enforcement\` in agentsafe.yaml${demo}`,
    );
    expect(
      enforcementSwitch(
        config({ env: { AGENTSAFE_UPSTREAM: "http://localhost:3000", AGENTSAFE_MODE: "shadow" } }),
      ),
    ).toBe(`set \`AGENTSAFE_MODE=enforcement\` and restart${demo}`);
    expect(
      enforcementSwitch(
        config({
          file: {
            version: 1,
            gateway: { upstream: "http://localhost:3000" },
            authority: { mode: "shadow" },
          },
        }),
      ),
    ).toBe(
      `set \`authority.mode: enforcement\` in agentsafe.yaml (\`gateway.mode: enforcement\` in the chart's values) and restart${demo}`,
    );
    // With a Decionis key, the switch is the switch.
    expect(
      enforcementSwitch(
        config({
          env: {
            AGENTSAFE_UPSTREAM: "http://localhost:3000",
            AGENTSAFE_MODE: "shadow",
            DECIONIS_API_KEY: "synthetic-decionis-key-aaaaaaaa",
            DECIONIS_TENANT_ID: TENANT_ID,
          },
        }),
      ),
    ).toBe("set `AGENTSAFE_MODE=enforcement` and restart");
    const provisional = config({
      env: { AGENTSAFE_UPSTREAM: "http://localhost:3000", DECIONIS_TENANT_ID: TENANT_ID },
      credentials: {
        apiKey: "synthetic-provisional-key",
        tenantId: TENANT_ID,
        endpoint: null,
        provisional: true,
      },
    });
    expect(provisional.authority.provisional).toBe(true);
    expect(provisional.authority.mode).toBe("SHADOW");
    expect(enforcementSwitch(provisional)).toContain(
      "a provisional workspace evaluates in shadow only",
    );
  });
});
