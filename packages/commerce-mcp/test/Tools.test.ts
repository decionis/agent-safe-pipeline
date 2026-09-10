import { describe, expect, it, vi } from "vitest";

import type {
  CommerceGateApi,
  ErpGuardResponse,
  EvaluateActionInput,
  ShadowReportQuery,
} from "../src/CommerceGateClient.js";
import { CommerceGateConfiguration } from "../src/Configuration.js";
import {
  COMMERCEGATE_ACTION_SUPPORT,
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
  readonly validateErpTransaction = vi.fn(async (): Promise<ErpGuardResponse> => ({
    decision: "ALLOW" as const,
    transaction_id: "sales-order:1001",
    execution_time_ms: 8.5,
    reason_code: "AGENT_BUDGET_PASSED",
    message: "Transaction cleared all margin and spend guards.",
  }));
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

const ERP_GUARD = {
  erp_region: "westeurope",
  request: {
    transaction_id: "sales-order:1001",
    erp_type: "D365_BC",
    tenant_id: "44444444-4444-4444-8444-444444444444",
    timestamp: "2026-09-10T08:30:00.000Z",
    agent_id: "copilot:finance",
    currency: "USD",
    lines: [{ line_id: 1, sku: "SKU-1", quantity: 2, unit_price: 50, cost_base: 30 }],
  },
} as const;

const ADDITIONAL_ACTIONS = [
  {
    label: "inventory mutation",
    action: {
      action_type: "INVENTORY_MUTATION",
      actor: { type: "ERP", id: "inventory-sync" },
      platform: "walmart-marketplace",
      idempotency_key: "sku:42:inventory:v2",
      payload: { sku: "SKU-42", from: 18, to: 7, location_id: null },
    },
  },
  {
    label: "fulfillment action",
    action: {
      action_type: "FULFILLMENT_ACTION",
      actor: { type: "WORKFLOW", id: "warehouse-flow" },
      platform: "walmart-marketplace",
      idempotency_key: "order:42:fulfillment:v2",
      payload: { order_id: "42", action: "hold" },
    },
  },
  {
    label: "promotion change",
    action: {
      action_type: "PROMOTION_CHANGE",
      actor: { type: "HUMAN", id: "merchandiser" },
      platform: "shopify",
      idempotency_key: "promotion:42:update:v2",
      payload: {
        promotion_id: null,
        percentage_fraction: 0.2,
        ends_at: null,
        status: "ACTIVE",
        combines_with: {
          order_discounts: true,
          product_discounts: false,
          shipping_discounts: true,
        },
      },
    },
  },
  {
    label: "refund request",
    action: {
      action_type: "REFUND_REQUEST",
      actor: { type: "AGENT", id: "support-agent" },
      platform: "walmart-marketplace",
      idempotency_key: "order:42:refund:v2",
      payload: { order_id: "42", amount: 10, reason_code: null },
    },
  },
  {
    label: "return authorization",
    action: {
      action_type: "RETURN_AUTHORIZATION",
      actor: { type: "HUMAN", id: "returns-operator" },
      platform: "shopify",
      idempotency_key: "order:42:return:v2",
      payload: { order_id: "42", rma_id: null, amount: null },
    },
  },
] as const;

function catalog(api = new StubApi()) {
  const configuration = new CommerceGateConfiguration({});
  return { api, tools: new CommerceGateTools(configuration, api).build() };
}

describe("CommerceGateTools", () => {
  it("exposes exactly the seven bounded CommerceGate tools", () => {
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

  it("performs enforced binary ERP authorization without claiming an ERP write", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_validate_erp_transaction")!;

    const response = await tool.handler(ERP_GUARD as unknown as Record<string, unknown>);

    expect(api.validateErpTransaction).toHaveBeenCalledWith(ERP_GUARD);
    expect(response.isError).toBeUndefined();
    expect(response.structuredContent).toMatchObject({
      ok: true,
      mode: "ENFORCED",
      budget_authorization_status: "AUTHORIZED",
      no_erp_write_executed: true,
      allow_is_not_execution_consent: true,
      commercegate_disposition: "PROCEED",
      validation: { decision: "ALLOW", transaction_id: ERP_GUARD.request.transaction_id },
    });
  });

  it("reports when a margin-policy block stops before agent-budget authorization", async () => {
    const { api, tools } = catalog();
    api.validateErpTransaction.mockResolvedValueOnce({
      decision: "BLOCK",
      transaction_id: ERP_GUARD.request.transaction_id,
      execution_time_ms: 4.2,
      reason_code: "MARGIN_BELOW_FLOOR",
      message: "Transaction blocked by the central CommerceGate policy.",
    });
    const tool = tools.find(({ name }) => name === "commercegate_validate_erp_transaction")!;

    const response = await tool.handler(ERP_GUARD as unknown as Record<string, unknown>);

    expect(response.structuredContent).toMatchObject({
      budget_authorization_status: "NOT_REACHED",
      commercegate_disposition: "BLOCK",
    });
  });

  it.each([
    ["extra request field", { ...ERP_GUARD.request, org_id: "not-accepted" }],
    ["bad tenant", { ...ERP_GUARD.request, tenant_id: "not-a-uuid" }],
    ["invalid date", { ...ERP_GUARD.request, timestamp: "2026-02-30T08:30:00Z" }],
    ["empty lines", { ...ERP_GUARD.request, lines: [] }],
    [
      "non-positive quantity",
      {
        ...ERP_GUARD.request,
        lines: [{ ...ERP_GUARD.request.lines[0], quantity: 0 }],
      },
    ],
  ])("rejects an ERP guard request with %s", async (_label, request) => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_validate_erp_transaction")!;

    const response = await tool.handler({ erp_region: "westeurope", request });

    expect(response.isError).toBe(true);
    expect(response.structuredContent).toMatchObject({ error: { code: "INVALID_INPUT" } });
    expect(api.validateErpTransaction).not.toHaveBeenCalled();
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
      action_support: COMMERCEGATE_ACTION_SUPPORT,
      connection: { connected: false },
      erp_guard: {
        mode: "ENFORCED",
        agent_budget_authorization_after_policy_approval: true,
        configuration_ready: false,
        erp_writes: false,
      },
      guarantees: {
        marketplace_writes: false,
        approve_is_not_execution_consent: true,
      },
    });
    expect(api.evaluateAction).not.toHaveBeenCalled();
  });

  it("makes every canonical action branch independently discoverable", () => {
    const { tools } = catalog();
    const evaluation = tools.find(({ name }) => name === "commercegate_evaluate_action")!;
    const action = (
      evaluation.inputSchema.properties as Record<
        string,
        { oneOf?: Array<Record<string, unknown>> }
      >
    ).action;
    const branches = action.oneOf ?? [];

    expect(branches).toHaveLength(7);
    expect(branches.map((branch) => branch.title)).toEqual([
      "Price change preflight",
      "Stock change or oversell preflight",
      "Order acceptance preflight",
      "Fulfillment action preflight",
      "Promotion change preflight",
      "Refund request preflight",
      "Return authorization preflight",
    ]);
    expect(
      branches.every(
        (branch) =>
          typeof branch.description === "string" &&
          branch.description.length > 0 &&
          Array.isArray(branch.examples) &&
          branch.examples.length > 0,
      ),
    ).toBe(true);
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

  it("rejects unknown action types without calling the API", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const response = await tool.handler({
      action: { ...ORDER.action, action_type: "GIFT_CARD_ISSUE" },
    });

    expect(response.isError).toBe(true);
    expect(response.structuredContent).toMatchObject({
      ok: false,
      error: { code: "INVALID_INPUT" },
      safety: { fail_closed: true, no_downstream_action_executed: true },
    });
    expect(api.evaluateAction).not.toHaveBeenCalled();
  });

  it.each(ADDITIONAL_ACTIONS)("accepts the canonical $label shape", async ({ action }) => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const response = await tool.handler({ action } as unknown as Record<string, unknown>);

    expect(response.isError).toBeUndefined();
    expect(api.evaluateAction).toHaveBeenCalledWith({ action });
    expect(response.structuredContent).toMatchObject({
      ok: true,
      mode: "SHADOW",
      action_type: action.action_type,
      no_downstream_action_executed: true,
    });
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

  it("matches the Protocol API's 180-character idempotency-key limit", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const accepted = await tool.handler({
      action: { ...ORDER.action, idempotency_key: "a".repeat(180) },
    });
    const rejected = await tool.handler({
      action: { ...ORDER.action, idempotency_key: "a".repeat(181) },
    });

    expect(accepted.isError).toBeUndefined();
    expect(rejected.isError).toBe(true);
    expect(api.evaluateAction).toHaveBeenCalledOnce();
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

  it("accepts contract-nullable and optional order and price fields", async () => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;
    const order = {
      action: {
        ...ORDER.action,
        idempotency_key: "order:unknown:accept",
        payload: {
          order_id: null,
          gross_amount: 100,
          discount_amount: 0,
          estimated_cost: 70,
        },
      },
    };
    const price = {
      action: {
        action_type: "PRICE_CHANGE",
        actor: { type: "REPRICER", id: "reprice-agent" },
        platform: "walmart-marketplace",
        idempotency_key: "sku:42:price:unknown-cost",
        payload: { sku: "SKU-42", from_price: null, to_price: 19.5, estimated_cost: null },
      },
    };

    const orderResponse = await tool.handler(order as unknown as Record<string, unknown>);
    const priceResponse = await tool.handler(price);

    expect(orderResponse.isError).toBeUndefined();
    expect(priceResponse.isError).toBeUndefined();
    expect(api.evaluateAction).toHaveBeenNthCalledWith(1, order);
    expect(api.evaluateAction).toHaveBeenNthCalledWith(2, price);
  });

  it.each([
    [
      "negative inventory",
      {
        ...ADDITIONAL_ACTIONS[0].action,
        payload: { ...ADDITIONAL_ACTIONS[0].action.payload, to: -1 },
      },
    ],
    [
      "unsupported fulfillment transition",
      {
        ...ADDITIONAL_ACTIONS[1].action,
        payload: { ...ADDITIONAL_ACTIONS[1].action.payload, action: "refund" },
      },
    ],
    [
      "out-of-range promotion fraction",
      {
        ...ADDITIONAL_ACTIONS[2].action,
        payload: { ...ADDITIONAL_ACTIONS[2].action.payload, percentage_fraction: 1.01 },
      },
    ],
    [
      "incomplete promotion combination",
      {
        ...ADDITIONAL_ACTIONS[2].action,
        payload: {
          ...ADDITIONAL_ACTIONS[2].action.payload,
          combines_with: { order_discounts: true, product_discounts: false },
        },
      },
    ],
    [
      "refund extra field",
      {
        ...ADDITIONAL_ACTIONS[3].action,
        payload: { ...ADDITIONAL_ACTIONS[3].action.payload, approval_limit: 100 },
      },
    ],
    [
      "negative return amount",
      {
        ...ADDITIONAL_ACTIONS[4].action,
        payload: { ...ADDITIONAL_ACTIONS[4].action.payload, amount: -1 },
      },
    ],
  ])("rejects %s before calling the API", async (_label, action) => {
    const { api, tools } = catalog();
    const tool = tools.find(({ name }) => name === "commercegate_evaluate_action")!;

    const response = await tool.handler({ action } as unknown as Record<string, unknown>);

    expect(response.isError).toBe(true);
    expect(response.structuredContent).toMatchObject({ error: { code: "INVALID_INPUT" } });
    expect(api.evaluateAction).not.toHaveBeenCalled();
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
    for (const actionType of [
      "PRICE_CHANGE",
      "INVENTORY_MUTATION",
      "ORDER_ACCEPTANCE",
      "FULFILLMENT_ACTION",
      "PROMOTION_CHANGE",
      "REFUND_REQUEST",
      "RETURN_AUTHORIZATION",
    ]) {
      expect(serialized).toContain(actionType);
    }
  });
});
