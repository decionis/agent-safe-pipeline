import { describe, expect, it, vi } from "vitest";

import {
  CommerceGateClient,
  CommerceGateRequestMapping,
  type CommerceAction,
  type FetchLike,
} from "../src/CommerceGateClient.js";
import { CommerceGateConfiguration } from "../src/Configuration.js";
import { MCP_SERVER_VERSION } from "../src/Version.js";

const ORG_ID = "11111111-1111-4111-8111-111111111111";
const EVALUATION_ID = "22222222-2222-4222-8222-222222222222";
const DOSSIER_ID = "33333333-3333-4333-8333-333333333333";

function evaluationResponse(overrides: Record<string, unknown> = {}) {
  return {
    outcome: "APPROVE",
    confidence: 0.9,
    policy_version: "commerce-default",
    objective_profile: "commerce",
    dossier_id: DOSSIER_ID,
    evaluation_id: EVALUATION_ID,
    mode: "SHADOW",
    fallback_to_legacy: false,
    governance_metrics: {
      override_drift_rate: 0,
      governance_tension_index: 0,
      boundary_volatility_score: 0,
      decision_volume_under_governance: 1,
    },
    idempotent_replay: false,
    ...overrides,
  };
}

function configured(): CommerceGateConfiguration {
  return new CommerceGateConfiguration({
    DECIONIS_API_KEY: "top-secret-key",
    DECIONIS_ORG_ID: ORG_ID,
    DECIONIS_API_BASE: "https://api.example.test",
  });
}

function jsonFetch(body: unknown, status = 200) {
  return vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      }),
  ) as unknown as FetchLike;
}

describe("CommerceGateClient", () => {
  it("maps order acceptance to a tenant-bound, idempotent SHADOW evaluation", async () => {
    const fetchImpl = jsonFetch(
      evaluationResponse({ outcome: "REVIEW", policy_version: "commerce-7" }),
    );
    const client = new CommerceGateClient(configured(), fetchImpl);

    await client.evaluateAction({
      policy_version: "commerce-7",
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
    });

    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(String(url)).toBe("https://api.example.test/v1/protocol/evaluate-decision");
    const headers = new Headers(init?.headers);
    expect(headers.get("authorization")).toBe("Bearer top-secret-key");
    expect(headers.get("idempotency-key")).toBe("order:42:accept");
    expect(headers.get("user-agent")).toBe(`decionis-commercegate-mcp/${MCP_SERVER_VERSION}`);
    expect(init?.redirect).toBe("error");
    const body = JSON.parse(String(init?.body));
    expect(body).toMatchObject({
      org_id: ORG_ID,
      decision_type: "ORDER_ACCEPTANCE",
      transaction_type: "order_acceptance",
      workflow_key: "commerce_order_acceptance",
      amount: 100,
      source: "commercegate-mcp",
      channel: "mcp",
      mode: "SHADOW",
      policy_version: "commerce-7",
      require_exact_policy_version: true,
      idempotency_key: "order:42:accept",
      context: {
        action_type: "ORDER_ACCEPTANCE",
        net_revenue: 90,
        net_margin_amount: 30,
        net_margin_fraction: 0.333333,
        net_margin_percent: 33.333333,
        signals: {
          net_margin_fraction: 0.333333,
          net_margin_percent: 33.333333,
        },
      },
    });
  });

  it("maps a price change and computes the post-change margin signal", async () => {
    const fetchImpl = jsonFetch(evaluationResponse());
    const client = new CommerceGateClient(configured(), fetchImpl);

    await client.evaluateAction({
      action: {
        action_type: "PRICE_CHANGE",
        actor: { type: "REPRICER", id: "repricer-1" },
        platform: "walmart-marketplace",
        idempotency_key: "sku:1:price:19",
        payload: {
          sku: "SKU-1",
          from_price: 25,
          to_price: 20,
          estimated_cost: 12,
          currency: "USD",
        },
      },
    });

    const [, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(String(init?.body));
    expect(body).toMatchObject({
      org_id: ORG_ID,
      decision_type: "PRICE_CHANGE",
      amount: 20,
      mode: "SHADOW",
      context: {
        sku: "SKU-1",
        price_change_amount: -5,
        net_revenue: 20,
        estimated_cost: 12,
        net_margin_amount: 8,
        net_margin_fraction: 0.4,
        net_margin_percent: 40,
        signals: {
          price_change_amount: -5,
          net_margin_fraction: 0.4,
          net_margin_percent: 40,
        },
      },
    });
  });

  it("maps an unknown price cost without inventing margin facts", () => {
    const request = CommerceGateRequestMapping.buildEvaluationRequest({
      action: {
        action_type: "PRICE_CHANGE",
        actor: { type: "REPRICER", id: "repricer-1" },
        platform: "walmart-marketplace",
        idempotency_key: "sku:1:price:unknown-cost",
        payload: { sku: "SKU-1", from_price: null, to_price: 20 },
      },
    });

    expect(request).toMatchObject({
      amount: 20,
      context: {
        estimated_cost: null,
        net_margin_amount: null,
        net_margin_fraction: null,
        net_margin_percent: null,
        signals: {
          estimated_cost: null,
          net_margin_percent: null,
        },
      },
    });
  });

  it("uses the configured API key for a bounded ERP guard call without adding Protocol fields", async () => {
    const guardResponse = {
      decision: "ALLOW",
      transaction_id: "sales-order:1001",
      execution_time_ms: 12.5,
      reason_code: "AGENT_BUDGET_PASSED",
      message: "Transaction cleared all margin and spend guards.",
    } as const;
    const fetchImpl = jsonFetch(guardResponse);
    const client = new CommerceGateClient(
      new CommerceGateConfiguration({
        DECIONIS_API_KEY: "top-secret-key",
        DECIONIS_API_BASE: "https://api.example.test",
      }),
      fetchImpl,
    );
    const request = {
      transaction_id: "sales-order:1001",
      erp_type: "D365_BC" as const,
      tenant_id: "44444444-4444-4444-8444-444444444444",
      timestamp: "2026-09-10T08:30:00.000Z",
      agent_id: "copilot:finance",
      currency: "USD",
      lines: [{ line_id: 1, sku: "SKU-1", quantity: 2, unit_price: 50, cost_base: 30 }],
    };

    await expect(
      client.validateErpTransaction({ erp_region: "westeurope", request }),
    ).resolves.toEqual(guardResponse);

    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(String(url)).toBe("https://api.example.test/v1/guard/validate");
    const headers = new Headers(init?.headers);
    expect(headers.get("x-decionis-api-key")).toBe("top-secret-key");
    expect(headers.get("x-erp-region")).toBe("westeurope");
    expect(headers.get("authorization")).toBeNull();
    expect(JSON.parse(String(init?.body))).toEqual(request);
  });

  it.each([
    {
      label: "inventory mutation",
      action: {
        action_type: "INVENTORY_MUTATION",
        actor: { type: "ERP", id: "inventory-sync" },
        platform: "walmart-marketplace",
        idempotency_key: "sku:1:inventory:7",
        payload: { sku: "SKU-1", from: 12, to: 7, location_id: "node-1" },
      },
      expected: {
        decision_type: "INVENTORY_MUTATION",
        transaction_type: "inventory_mutation",
        workflow_key: "commerce_inventory_mutation",
        context: {
          current_inventory: 12,
          proposed_inventory: 7,
          available_inventory: 7,
          signals: {
            sku: "SKU-1",
            location_id: "node-1",
            current_inventory: 12,
            proposed_inventory: 7,
            available_inventory: 7,
          },
        },
      },
    },
    {
      label: "fulfillment action",
      action: {
        action_type: "FULFILLMENT_ACTION",
        actor: { type: "WORKFLOW", id: "warehouse-flow" },
        platform: "tiktok-shop",
        idempotency_key: "order:2:ship",
        payload: { order_id: "2", action: "ship" },
      },
      expected: {
        decision_type: "FULFILLMENT_ACTION",
        transaction_type: "fulfillment_action",
        workflow_key: "commerce_fulfillment_action",
        context: {
          fulfillment_action: "ship",
          signals: { order_id: "2", action: "ship", fulfillment_action: "ship" },
        },
      },
    },
    {
      label: "promotion change",
      action: {
        action_type: "PROMOTION_CHANGE",
        actor: { type: "HUMAN", id: "merchandiser" },
        platform: "shopify",
        idempotency_key: "promotion:3:update",
        payload: {
          promotion_id: "promo-3",
          percentage_fraction: 0.2,
          ends_at: "2026-09-30T00:00:00.000Z",
          status: "ACTIVE",
          combines_with: {
            order_discounts: true,
            product_discounts: false,
            shipping_discounts: true,
          },
        },
      },
      expected: {
        decision_type: "PROMOTION_CHANGE",
        transaction_type: "promotion_change",
        workflow_key: "commerce_promotion_change",
        context: {
          discount_percent: 20,
          signals: {
            promotion_id: "promo-3",
            percentage_fraction: 0.2,
            ends_at: "2026-09-30T00:00:00.000Z",
            status: "ACTIVE",
            combines_with_order_discounts: true,
            combines_with_product_discounts: false,
            combines_with_shipping_discounts: true,
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
        idempotency_key: "order:4:refund:1",
        payload: { order_id: "4", amount: 90, currency: "USD", reason_code: "CustomerReturn" },
      },
      expected: {
        decision_type: "REFUND_REQUEST",
        transaction_type: "refund_request",
        workflow_key: "commerce_refund_request",
        amount: 90,
        context: {
          refund_amount: 90,
          signals: {
            order_id: "4",
            refund_amount: 90,
            currency: "USD",
            reason_code: "CustomerReturn",
          },
        },
      },
    },
    {
      label: "return authorization",
      action: {
        action_type: "RETURN_AUTHORIZATION",
        actor: { type: "HUMAN", id: "returns-operator" },
        platform: "shopify",
        idempotency_key: "order:5:return:1",
        payload: { order_id: "5", rma_id: null, amount: null },
      },
      expected: {
        decision_type: "RETURN_AUTHORIZATION",
        transaction_type: "return_authorization",
        workflow_key: "commerce_return_authorization",
        context: {
          return_amount: null,
          signals: { order_id: "5", rma_id: null, amount: null, return_amount: null },
        },
      },
    },
  ])("maps $label into canonical Shadow policy signals", ({ action, expected }) => {
    const request = CommerceGateRequestMapping.buildEvaluationRequest({
      action: action as CommerceAction,
    });

    expect(request).toMatchObject({
      ...expected,
      mode: "SHADOW",
      channel: "mcp",
      source: "commercegate-mcp",
      idempotency_key: action.idempotency_key,
      context: {
        ...expected.context,
        action_type: action.action_type,
        actor_type: action.actor.type,
        actor_id: action.actor.id,
        actor: action.actor,
        platform: action.platform,
        payload: action.payload,
        signals: {
          ...expected.context.signals,
          action_type: action.action_type,
          actor_type: action.actor.type,
          actor_id: action.actor.id,
          platform: action.platform,
        },
      },
    });
    if (action.action_type === "PROMOTION_CHANGE") {
      const context = request.context as Record<string, unknown>;
      expect(context.signals).not.toHaveProperty("discount_count");
    }
    if (
      action.action_type === "INVENTORY_MUTATION" ||
      action.action_type === "FULFILLMENT_ACTION" ||
      action.action_type === "PROMOTION_CHANGE" ||
      action.action_type === "RETURN_AUTHORIZATION"
    ) {
      expect(request).not.toHaveProperty("amount");
    }
  });

  it("builds tenant-scoped evidence and shadow-report URLs", async () => {
    const fetchImpl = jsonFetch({ ok: true });
    const client = new CommerceGateClient(configured(), fetchImpl);
    const dossierId = "22222222-2222-4222-8222-222222222222";

    await client.getDossier(dossierId);
    await client.getProofPacket(dossierId);
    await client.listShadowReports({ days: 30, limit: 25 });
    await client.summarizeShadowReports({ limit: 10 });

    const urls = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls.map(([url]) => String(url));
    expect(urls[0]).toBe(
      `https://api.example.test/v1/protocol/dossiers/${dossierId}?org_id=${ORG_ID}`,
    );
    expect(urls[1]).toBe(
      `https://api.example.test/v1/protocol/dossiers/${dossierId}/proof-packet?org_id=${ORG_ID}`,
    );
    expect(urls[2]).toContain("/v1/protocol/shadow-reports?");
    expect(urls[2]).toContain("days=30");
    expect(urls[2]).toContain("limit=25");
    expect(urls[2]).not.toContain("mode=");
    expect(urls[3]).toContain("/v1/protocol/shadow-reports?");
  });

  it("does not call the network when tenant credentials are absent", async () => {
    const fetchImpl = jsonFetch({ ok: true });
    const client = new CommerceGateClient(new CommerceGateConfiguration({}), fetchImpl);

    await expect(client.listShadowReports({})).rejects.toMatchObject({
      code: "CONFIGURATION_REQUIRED",
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("fails closed if the API does not confirm SHADOW mode", async () => {
    const fetchImpl = jsonFetch({ outcome: "APPROVE", mode: "ENFORCEMENT" });
    const client = new CommerceGateClient(configured(), fetchImpl);

    await expect(
      client.evaluateAction({
        action: {
          action_type: "PRICE_CHANGE",
          actor: { type: "REPRICER", id: "repricer-1" },
          platform: "shopify",
          idempotency_key: "sku:1:price:20",
          payload: {
            sku: "SKU-1",
            from_price: 19,
            to_price: 20,
            estimated_cost: 10,
            currency: "USD",
          },
        },
      }),
    ).rejects.toMatchObject({ code: "INVALID_UPSTREAM_RESPONSE" });
  });

  it("fails closed on incomplete evaluation evidence or a non-exact policy response", async () => {
    const action = {
      action_type: "PRICE_CHANGE" as const,
      actor: { type: "REPRICER" as const, id: "repricer-1" },
      platform: "shopify",
      idempotency_key: "sku:1:price:20",
      payload: { sku: "SKU-1", from_price: 19, to_price: 20, estimated_cost: 10 },
    };
    const incomplete = new CommerceGateClient(
      configured(),
      jsonFetch({ outcome: "APPROVE", mode: "SHADOW" }),
    );
    const wrongPolicy = new CommerceGateClient(
      configured(),
      jsonFetch(evaluationResponse({ policy_version: "commerce-other" })),
    );

    await expect(incomplete.evaluateAction({ action })).rejects.toMatchObject({
      code: "INVALID_UPSTREAM_RESPONSE",
    });
    await expect(
      wrongPolicy.evaluateAction({ action, policy_version: "commerce-exact" }),
    ).rejects.toMatchObject({ code: "INVALID_UPSTREAM_RESPONSE" });
  });

  it("fails closed when optional evaluation reason codes violate the response contract", async () => {
    const client = new CommerceGateClient(
      configured(),
      jsonFetch(evaluationResponse({ reason_codes: ["MARGIN_FLOOR", ""] })),
    );

    await expect(
      client.evaluateAction({
        action: {
          action_type: "PRICE_CHANGE",
          actor: { type: "REPRICER", id: "repricer-1" },
          platform: "walmart-marketplace",
          idempotency_key: "sku:1:price:bad-reason",
          payload: { sku: "SKU-1", from_price: 25, to_price: 20, estimated_cost: 12 },
        },
      }),
    ).rejects.toMatchObject({ code: "INVALID_UPSTREAM_RESPONSE" });
  });

  it("fails closed when an ERP guard response is incomplete or bound to another transaction", async () => {
    const request = {
      transaction_id: "sales-order:1001",
      erp_type: "D365_FSCM" as const,
      tenant_id: "44444444-4444-4444-8444-444444444444",
      timestamp: "2026-09-10T08:30:00Z",
      agent_id: "copilot:finance",
      currency: "USD",
      lines: [{ line_id: 1, sku: "SKU-1", quantity: 1, unit_price: 50, cost_base: 30 }],
    };
    const incomplete = new CommerceGateClient(
      configured(),
      jsonFetch({ decision: "ALLOW", transaction_id: request.transaction_id }),
    );
    const mismatched = new CommerceGateClient(
      configured(),
      jsonFetch({
        decision: "ALLOW",
        transaction_id: "sales-order:other",
        execution_time_ms: 1,
        reason_code: "AGENT_BUDGET_PASSED",
        message: "Allowed.",
      }),
    );

    await expect(
      incomplete.validateErpTransaction({ erp_region: "westeurope", request }),
    ).rejects.toMatchObject({ code: "INVALID_UPSTREAM_RESPONSE" });
    await expect(
      mismatched.validateErpTransaction({ erp_region: "westeurope", request }),
    ).rejects.toMatchObject({ code: "INVALID_UPSTREAM_RESPONSE" });
  });

  it("redacts upstream error bodies and credentials", async () => {
    const fetchImpl = jsonFetch({ error: "top-secret-key", debug: ORG_ID }, 401);
    const client = new CommerceGateClient(configured(), fetchImpl);

    let thrown: unknown;
    try {
      await client.getDossier("22222222-2222-4222-8222-222222222222");
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ code: "AUTHENTICATION_FAILED", options: { status: 401 } });
    expect(JSON.stringify(thrown)).not.toContain("top-secret-key");
    expect(JSON.stringify(thrown)).not.toContain(ORG_ID);
  });

  it("fails closed on invalid JSON from an otherwise successful upstream", async () => {
    const fetchImpl = vi.fn(
      async () => new Response("not-json", { status: 200 }),
    ) as unknown as FetchLike;
    const client = new CommerceGateClient(configured(), fetchImpl);

    await expect(client.listShadowReports({})).rejects.toMatchObject({
      code: "INVALID_UPSTREAM_RESPONSE",
    });
  });

  it("aborts and cancels a chunked response as soon as it exceeds 2 MiB", async () => {
    let responseCancelled = false;
    const observed: { requestSignal: AbortSignal | null } = { requestSignal: null };
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(2 * 1024 * 1024));
        controller.enqueue(new Uint8Array([1]));
      },
      cancel() {
        responseCancelled = true;
      },
    });
    const response = new Response(body, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
    const fetchImpl = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      observed.requestSignal = init?.signal ?? null;
      return response;
    }) as unknown as FetchLike;
    const client = new CommerceGateClient(configured(), fetchImpl);

    expect(response.headers.get("content-length")).toBeNull();
    await expect(client.listShadowReports({})).rejects.toMatchObject({
      code: "INVALID_UPSTREAM_RESPONSE",
    });
    expect(observed.requestSignal?.aborted).toBe(true);
    expect(responseCancelled).toBe(true);
  });

  it("fails closed when the upstream cannot be reached", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("network contained top-secret-key");
    }) as unknown as FetchLike;
    const client = new CommerceGateClient(configured(), fetchImpl);

    await expect(client.listShadowReports({})).rejects.toMatchObject({
      code: "UPSTREAM_UNREACHABLE",
      options: { retryable: true },
    });
  });
});

describe("CommerceGate request mapping", () => {
  it("reports a fail-closed total loss when revenue is zero and cost is positive", () => {
    expect(CommerceGateRequestMapping.marginSignal(0, 2)).toEqual({
      net_revenue: 0,
      estimated_cost: 2,
      net_margin_amount: -2,
      net_margin_fraction: -1,
      net_margin_percent: -100,
    });
  });

  it("reports percentage points and preserves negative margin", () => {
    expect(CommerceGateRequestMapping.marginSignal(100, 150)).toMatchObject({
      net_margin_amount: -50,
      net_margin_fraction: -0.5,
      net_margin_percent: -50,
    });
  });
});
