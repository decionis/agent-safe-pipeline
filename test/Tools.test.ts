import { describe, expect, it, vi } from "vitest";

import type {
  CommerceGateApi,
  EvaluateActionInput,
  ShadowReportQuery,
} from "../src/CommerceGateClient.js";
import { CommerceGateConfiguration } from "../src/Configuration.js";
import {
  COMMERCEGATE_OUTCOME_MAP,
  COMMERCEGATE_TOOL_NAMES,
  CommerceGateTools,
} from "../src/Tools.js";

const SHADOW_REPORT = {
  service: "decionis",
  generated_at: "2026-09-09T00:00:00.000Z",
  window_days: 30,
  since: "2026-08-10T00:00:00.000Z",
  summary: { shadow_evaluations: 1, would_block: 1 },
  cards: [{ key: "would_block", value: 1 }],
  reason_breakdown: [{ reason_code: "margin_floor", count: 1 }],
  candidate_enforcement_paths: [],
  near_misses: [],
  recent_evaluations: [{ outcome: "REJECT" }],
};

class StubApi implements CommerceGateApi {
  readonly evaluateAction = vi.fn(async (_input: EvaluateActionInput): Promise<unknown> => ({
    outcome: "REVIEW",
    mode: "SHADOW",
    dossier_id: "22222222-2222-4222-8222-222222222222",
  }));
  readonly getDossier = vi.fn(async (_id: string): Promise<unknown> => ({ dossier: true }));
  readonly getProofPacket = vi.fn(async (_id: string): Promise<unknown> => ({ proof: true }));
  readonly listShadowReports = vi.fn(
    async (_query: ShadowReportQuery): Promise<unknown> => SHADOW_REPORT,
  );
  readonly summarizeShadowReports = vi.fn(
    async (_query: ShadowReportQuery): Promise<unknown> => SHADOW_REPORT,
  );
}

const ORDER = {
  action: {
    action_type: "ORDER_ACCEPTANCE",
    actor: { type: "AGENT", id: "order-agent" },
    platform: "shopify",
    idempotency_key: "order:42:accept",
    payload: {
      order_id: "42",
      gross_amount: 100,
      discount_amount: 10,
      estimated_cost: 60,
      currency: "USD",
    },
  },
} as const;

function catalog(api = new StubApi()) {
  const configuration = new CommerceGateConfiguration({});
  return { api, tools: new CommerceGateTools(configuration, api).build() };
}

describe("CommerceGateTools", () => {
  it("exposes exactly the six bounded CommerceGate tools", () => {
    const { tools } = catalog();

    expect(tools.map(({ name }) => name)).toEqual(COMMERCEGATE_TOOL_NAMES);
    expect(tools.every((tool) => tool.annotations.destructiveHint === false)).toBe(true);
    expect(tools.find((tool) => tool.name === "commercegate_evaluate_action")?.annotations).toEqual(
      {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    );
  });

  it("describes safety and setup without credentials or a network call", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_describe_capabilities")!;

    const response = await tool.handler({});

    expect(response.isError).toBeUndefined();
    expect(response.structuredContent).toMatchObject({
      ok: true,
      identity: "com.decionis/commerce-gate",
      evaluation_mode: "SHADOW",
      outcome_mapping: COMMERCEGATE_OUTCOME_MAP,
      connection: { connected: false },
      guarantees: {
        marketplace_writes: false,
        approve_is_not_execution_consent: true,
      },
    });
    expect(api.evaluateAction).not.toHaveBeenCalled();
  });

  it("validates and evaluates a canonical order action", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const response = await tool.handler(ORDER as unknown as Record<string, unknown>);

    expect(response.isError).toBeUndefined();
    expect(api.evaluateAction).toHaveBeenCalledWith(ORDER);
    expect(response.structuredContent).toMatchObject({
      ok: true,
      mode: "SHADOW",
      no_downstream_action_executed: true,
      approve_is_not_execution_consent: true,
      commercegate_disposition: "HOLD",
    });
    expect(String(response.structuredContent.agent_guidance)).toContain("HOLD");
  });

  it("rejects unsupported action types without calling the API", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const response = await tool.handler({
      action: { ...ORDER.action, action_type: "REFUND_REQUEST" },
    });

    expect(response.isError).toBe(true);
    expect(response.structuredContent).toMatchObject({
      ok: false,
      error: { code: "INVALID_INPUT" },
      safety: { fail_closed: true, no_downstream_action_executed: true },
    });
    expect(api.evaluateAction).not.toHaveBeenCalled();
  });

  it("rejects incomplete economics and lowercase currency", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;
    const action = {
      ...ORDER.action,
      payload: { ...ORDER.action.payload, estimated_cost: undefined, currency: "usd" },
    };

    const response = await tool.handler({ action });

    expect(response.isError).toBe(true);
    expect(api.evaluateAction).not.toHaveBeenCalled();
  });

  it("rejects an order discount greater than the gross amount", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const response = await tool.handler({
      action: {
        ...ORDER.action,
        payload: { ...ORDER.action.payload, gross_amount: 10, discount_amount: 11 },
      },
    });

    expect(response.isError).toBe(true);
    expect(response.structuredContent).toMatchObject({ error: { code: "INVALID_INPUT" } });
    expect(api.evaluateAction).not.toHaveBeenCalled();
  });

  it("rejects a three-letter value that is not an ISO-4217 currency", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const response = await tool.handler({
      action: {
        ...ORDER.action,
        payload: { ...ORDER.action.payload, currency: "ZZZ" },
      },
    });

    expect(response.isError).toBe(true);
    expect(api.evaluateAction).not.toHaveBeenCalled();
  });

  it("accepts the discriminated price-change shape", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;
    const input = {
      action: {
        action_type: "PRICE_CHANGE",
        actor: { type: "REPRICER", id: "reprice-agent" },
        platform: "walmart-marketplace",
        idempotency_key: "sku:42:price:v2",
        payload: {
          sku: "SKU-42",
          from_price: null,
          to_price: 19.5,
          estimated_cost: 12,
          currency: "EUR",
        },
      },
      policy_version: "commerce-v2",
    };

    const response = await tool.handler(input);

    expect(response.isError).toBeUndefined();
    expect(api.evaluateAction).toHaveBeenCalledWith(input);
  });

  it.each([
    ["APPROVE", "PROCEED"],
    ["REJECT", "BLOCK"],
    ["REVIEW", "HOLD"],
    ["ESCALATE", "HOLD"],
    ["UNKNOWN", "HOLD"],
  ])("normalizes Protocol outcome %s to %s", async (outcome, disposition) => {
    const api = new StubApi();
    api.evaluateAction.mockResolvedValueOnce({ outcome });
    const { tools } = catalog(api);
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const response = await tool.handler(ORDER as unknown as Record<string, unknown>);

    expect(response.structuredContent.commercegate_disposition).toBe(disposition);
  });

  it("validates dossier UUIDs and report query bounds before tenant reads", async () => {
    const { api, tools } = catalog();
    const dossier = tools.find(({ name }) => name === "commercegate_get_dossier")!;
    const reports = tools.find(({ name }) => name === "commercegate_list_shadow_reports")!;

    const badDossier = await dossier.handler({ dossier_id: "not-a-uuid" });
    const badLimit = await reports.handler({ limit: 101 });
    const goodReports = await reports.handler({ days: 30, limit: 20 });

    expect(badDossier.isError).toBe(true);
    expect(badLimit.isError).toBe(true);
    expect(goodReports.isError).toBeUndefined();
    expect(api.getDossier).not.toHaveBeenCalled();
    expect(api.listShadowReports).toHaveBeenCalledWith({ days: 30, limit: 20 });
    expect(goodReports.structuredContent).toMatchObject({
      reports: { recent_evaluations: [{ outcome: "REJECT" }] },
    });
  });

  it("projects summary fields from the canonical Shadow Report document", async () => {
    const { api, tools } = catalog();
    const summary = tools.find(({ name }) => name === "commercegate_summarize_shadow_reports")!;

    const response = await summary.handler({ days: 7, limit: 10 });

    expect(api.summarizeShadowReports).toHaveBeenCalledWith({ days: 7, limit: 10 });
    expect(response.structuredContent).toMatchObject({
      summary: {
        window_days: 30,
        summary: { shadow_evaluations: 1, would_block: 1 },
        cards: [{ key: "would_block", value: 1 }],
      },
    });
  });

  it("fails closed on a malformed Shadow Report document", async () => {
    const api = new StubApi();
    api.listShadowReports.mockResolvedValueOnce({ summary: {} });
    const { tools } = catalog(api);
    const reports = tools.find(({ name }) => name === "commercegate_list_shadow_reports")!;

    const response = await reports.handler({});

    expect(response.isError).toBe(true);
    expect(response.structuredContent).toMatchObject({
      error: { code: "INVALID_UPSTREAM_RESPONSE" },
      safety: { fail_closed: true },
    });
  });

  it("redacts unknown API failures", async () => {
    const api = new StubApi();
    api.evaluateAction.mockRejectedValueOnce(new Error("top-secret-key and tenant details"));
    const { tools } = catalog(api);
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const response = await tool.handler(ORDER as unknown as Record<string, unknown>);
    const serialized = JSON.stringify(response);

    expect(response.isError).toBe(true);
    expect(serialized).toContain("UNEXPECTED_FAILURE");
    expect(serialized).not.toContain("top-secret-key");
    expect(serialized).not.toContain("tenant details");
  });

  it("does not expose org or mode overrides in tenant tool schemas", () => {
    const { tools } = catalog();
    const serialized = JSON.stringify(tools.map((tool) => tool.inputSchema));

    expect(serialized).not.toContain("org_id");
    expect(serialized).not.toContain('"mode"');
    expect(serialized).not.toContain("REFUND_REQUEST");
    expect(serialized).toContain("ORDER_ACCEPTANCE");
    expect(serialized).toContain("PRICE_CHANGE");
  });
});
