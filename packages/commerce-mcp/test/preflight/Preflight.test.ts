import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  CommerceGateClient,
  type CommerceAction,
  type CommerceGateApi,
  type EvaluateActionInput,
} from "../../src/CommerceGateClient.js";
import { CommerceGateConfiguration } from "../../src/Configuration.js";
import {
  COMMERCEGATE_TOOL_NAMES,
  CommerceGateTools,
  CommerceGateToolParsing,
} from "../../src/Tools.js";
import { canonicalPreflightDigest, CommercePreflightBinding } from "../../src/preflight/Binding.js";
import {
  COMMERCE_CHECK_IDS,
  COMMERCE_PREFLIGHT_CHECKS,
  COMMERCE_PREFLIGHT_VERSION,
  type CommercePreflightInput,
  type CommercePreflightResult,
} from "../../src/preflight/Contracts.js";
import {
  commercePreflightInputSchema,
  matchesPreflightSchema,
} from "../../src/preflight/Schema.js";

const ORG = "11111111-1111-4111-8111-111111111111";
const POLICY = "fixture-commerce-v1";
const NOW = "2026-10-05T08:00:00.000Z";
const ACTION_BASE = {
  actor: { type: "AGENT" as const, id: "fixture-agent" },
  platform: "custom-commerce-platform",
  idempotency_key: "fixture:preflight:v1",
};
const ACTIONS: CommerceAction[] = [
  {
    ...ACTION_BASE,
    action_type: "PRICE_CHANGE",
    payload: {
      sku: "fixture-sku",
      from_price: 100,
      to_price: 80,
      estimated_cost: 60,
      currency: "USD",
    },
  },
  {
    ...ACTION_BASE,
    action_type: "INVENTORY_MUTATION",
    payload: { sku: "fixture-sku", from: 20, to: 18 },
  },
  {
    ...ACTION_BASE,
    action_type: "ORDER_ACCEPTANCE",
    payload: {
      order_id: "fixture-order",
      gross_amount: 100,
      discount_amount: 20,
      estimated_cost: 60,
      currency: "USD",
    },
  },
  {
    ...ACTION_BASE,
    action_type: "FULFILLMENT_ACTION",
    payload: { order_id: "fixture-order", action: "ship" },
  },
  {
    ...ACTION_BASE,
    action_type: "PROMOTION_CHANGE",
    payload: {
      promotion_id: "fixture-promo",
      percentage_fraction: 0.2,
      ends_at: null,
      status: "ACTIVE",
      combines_with: null,
    },
  },
  {
    ...ACTION_BASE,
    action_type: "REFUND_REQUEST",
    payload: { order_id: "fixture-order", amount: 20, currency: "USD" },
  },
  {
    ...ACTION_BASE,
    action_type: "RETURN_AUTHORIZATION",
    payload: { order_id: "fixture-order", rma_id: "fixture-return", amount: 20 },
  },
];

function input(
  action: CommerceAction = ACTIONS[0],
): EvaluateActionInput & { preflight: CommercePreflightInput } {
  return {
    action: structuredClone(action),
    policy_version: POLICY,
    preflight: {
      version: COMMERCE_PREFLIGHT_VERSION,
      facts: { source: "fixture.erp", observed_at: NOW, currency: "USD" },
    },
  };
}

/** Synthetic server response for transport/contract testing; never an operational evaluation. */
function response(
  request = input(),
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const applicable = COMMERCE_PREFLIGHT_CHECKS.find((check) =>
    check.action_types.includes(request.action.action_type),
  )!;
  const preflight: CommercePreflightResult = {
    version: COMMERCE_PREFLIGHT_VERSION,
    action_type: request.action.action_type,
    action_digest: canonicalPreflightDigest(request.action),
    facts_digest: canonicalPreflightDigest(request.preflight.facts),
    policy_version: POLICY,
    idempotency_key: request.action.idempotency_key,
    evaluated_at: NOW,
    disposition: "PROCEED",
    execution_available: false,
    checks: COMMERCE_CHECK_IDS.map((id) => ({
      id,
      status: id === applicable.id ? "evaluated" : "not_applicable",
      verdict: id === applicable.id ? "PROCEED" : null,
      reason_codes: [id === applicable.id ? "FIXTURE_POLICY_PASSED" : "CHECK_NOT_APPLICABLE"],
      missing_facts: [],
    })),
  };
  return {
    outcome: "APPROVE",
    confidence: 1,
    policy_version: POLICY,
    objective_profile: "commerce",
    dossier_id: "22222222-2222-4222-8222-222222222222",
    evaluation_id: "33333333-3333-4333-8333-333333333333",
    mode: "SHADOW",
    fallback_to_legacy: true,
    idempotent_replay: false,
    governance_metrics: {
      override_drift_rate: 0,
      governance_tension_index: 0,
      boundary_volatility_score: 0,
      decision_volume_under_governance: 1,
    },
    commerce_preflight: preflight,
    ...overrides,
  };
}

function network(
  body: unknown,
  config = new CommerceGateConfiguration({
    DECIONIS_API_KEY: "fixture-key",
    DECIONIS_ORG_ID: ORG,
    DECIONIS_API_BASE: "https://api.example.test",
  }),
) {
  const fetch = vi.fn(
    async () =>
      new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } }),
  );
  return { fetch, client: new CommerceGateClient(config, fetch) };
}

function catalog(evaluation: unknown) {
  const api: CommerceGateApi = {
    evaluateAction: vi.fn(async () => evaluation),
    validateErpTransaction: vi.fn(),
    evaluateMarketplaceOfferSubmission: vi.fn(),
    getDossier: vi.fn(),
    getProofPacket: vi.fn(),
    listShadowReports: vi.fn(),
    summarizeShadowReports: vi.fn(),
  };
  return { api, tools: new CommerceGateTools(new CommerceGateConfiguration({}), api).build() };
}

describe("versioned Commerce preflight", () => {
  it("keeps eight tools and discloses eleven opt-in checks without probing a backend", async () => {
    const { api, tools } = catalog(null);
    expect(tools.map((tool) => tool.name)).toEqual(COMMERCEGATE_TOOL_NAMES);
    const described = await tools[0].handler({});
    expect(described.structuredContent?.versioned_preflight).toEqual({
      version: "commerce-preflight-v1",
      release_status: "source_candidate",
      input_option: "preflight",
      opt_in: true,
      requires_matching_backend: true,
      backend_support_probed: false,
      policy_authority: "server",
      execution_available: false,
      checks: COMMERCE_PREFLIGHT_CHECKS,
    });
    expect(COMMERCE_PREFLIGHT_CHECKS.map((check) => check.id)).toEqual([
      "P01",
      "P02",
      "P03",
      "P04",
      "P05",
      "P06",
      "P07",
      "P08",
      "P09",
      "P10",
      "P11",
    ]);
    expect(api.evaluateAction).not.toHaveBeenCalled();
  });

  it("preserves legacy evaluation input and does not add the explicit contract to its HTTP request", async () => {
    const legacy = { action: ACTIONS[0] };
    expect(CommerceGateToolParsing.parseEvaluationInput(legacy)).toEqual(legacy);
    const answer = response();
    delete answer.commerce_preflight;
    const { fetch, client } = network(answer);
    await expect(client.evaluateAction(legacy)).resolves.toEqual(answer);
    const init = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init[1].body)).context).not.toHaveProperty("commerce_preflight");
  });

  it.each(ACTIONS.map((action) => [action.action_type, action] as const))(
    "forwards %s with request-bound strict results and no policy rules in the caller",
    async (_name, action) => {
      const request = input(action);
      const answer = response(request);
      const { fetch, client } = network(answer);
      await expect(client.evaluateAction(request)).resolves.toEqual(answer);
      const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
      expect(url.toString()).toBe("https://api.example.test/v1/protocol/evaluate-decision");
      const wire = JSON.parse(String(init.body));
      expect(wire.org_id).toBe(ORG);
      expect(wire.mode).toBe("SHADOW");
      expect(wire.context.commerce_action).toEqual(action);
      expect(wire.context.commerce_preflight).toEqual(request.preflight);
      expect(wire.context.signals).not.toHaveProperty("observed_at");
      expect(wire).not.toHaveProperty("policy");
      expect(fetch).toHaveBeenCalledOnce();
    },
  );

  it("accepts all bounded fact groups and leaves missing, stale, or contradictory business facts to the server", () => {
    const request = input();
    request.preflight.facts = {
      observed_at: "2000-01-01T00:00:00Z",
      source: "fixture.erp",
      currency: "USD",
      pricing: { gross_amount: 80, discount_amount: 100, estimated_cost: 90 },
      cost_basis: { source_cost: 60, system_of_record_cost: 70 },
      inventory: {
        source_on_hand: 1,
        system_on_hand: 0,
        reserved_quantity: 10,
        requested_quantity: 20,
      },
      region: { country: "SE" },
      discounts: { count: 2, sources: ["fixture-1", "fixture-2"] },
      contract: { account_type: "b2b", offered_price: 80, contract_price: 90 },
      promotion: {
        discount_codes: ["FIXTURE"],
        prior_redemptions: 100,
        account_age_days: 0.5,
        identity_hash: "a".repeat(64),
      },
      refund: { remaining_refundable: 0, prior_refund_count: 20 },
      lifecycle: { current_state: "returned", delivered_at: NOW, return_eligible: false },
    };
    expect(CommerceGateToolParsing.parseEvaluationInput({ ...request })).toEqual(request);
    expect(matchesPreflightSchema(request.preflight, commercePreflightInputSchema)).toBe(true);
    expect(
      CommerceGateToolParsing.parseEvaluationInput({
        ...request,
        preflight: { version: COMMERCE_PREFLIGHT_VERSION, facts: {} },
      }),
    ).toMatchObject({ preflight: { facts: {} } });
  });

  const invalidFacts = [
    { policy: { checks: { P01: { enabled: false } } } },
    { org_id: ORG },
    { execution_available: true },
    { customer_email: "fixture@example.test" },
    { cost_basis: { source_cost: Infinity } },
    { cost_basis: { source_cost: -1 } },
    { pricing: { gross_amount: 1_000_000_000_001 } },
    { inventory: { requested_quantity: 1.5 } },
    { inventory: { system_on_hand: 1_000_000_001 } },
    { region: { country: "se" } },
    { source: "fixture bad source" },
    { currency: "usd" },
    { promotion: { identity_hash: "raw-address" } },
    { promotion: { account_age_days: 100_001 } },
    { discounts: { count: 33 } },
    { discounts: { sources: Array(33).fill("fixture") } },
    { lifecycle: { current_state: "unknown" } },
    { lifecycle: { return_eligible: "true" } },
    { observed_at: "2026-02-30T00:00:00Z" },
    { observed_at: "2026-10-05" },
    { observed_at: "2026-10-05T24:00:00Z" },
    { refund: { remaining_refundable: null } },
  ];
  it.each(invalidFacts.map((facts, index) => [index, facts] as const))(
    "rejects invalid or unscoped facts %s before any API call",
    async (_index, facts) => {
      const { api, tools } = catalog(null);
      const result = await tools[2].handler({
        ...input(),
        preflight: { version: COMMERCE_PREFLIGHT_VERSION, facts },
      });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({ error: { code: "INVALID_INPUT" } });
      expect(api.evaluateAction).not.toHaveBeenCalled();
    },
  );

  it.each([
    null,
    {},
    { version: "commerce-preflight-v2", facts: {} },
    { version: COMMERCE_PREFLIGHT_VERSION, facts: {}, policy: {} },
    { version: COMMERCE_PREFLIGHT_VERSION, facts: {}, mode: "ENFORCED" },
  ])("rejects incomplete or reconfigured opt-in %j", (preflight) =>
    expect(() => CommerceGateToolParsing.parseEvaluationInput({ ...input(), preflight })).toThrow(),
  );

  it("exposes the complete server result and keeps the stronger Protocol disposition", async () => {
    const request = input();
    const answer = response(request, { outcome: "REVIEW" });
    const { tools } = catalog(answer);
    const result = await tools[2].handler({ ...request });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({
      mode: "SHADOW",
      no_downstream_action_executed: true,
      commercegate_disposition: "HOLD",
      preflight: answer.commerce_preflight,
    });
  });

  const mutations: Array<
    [string, (answer: Record<string, unknown>, result: CommercePreflightResult) => void]
  > = [
    [
      "missing result",
      (answer) => {
        delete answer.commerce_preflight;
      },
    ],
    [
      "wrong version",
      (_answer, result) => {
        Object.assign(result, { version: "commerce-preflight-v2" });
      },
    ],
    [
      "other action",
      (_answer, result) => {
        result.action_type = "REFUND_REQUEST";
      },
    ],
    [
      "other idempotency key",
      (_answer, result) => {
        result.idempotency_key = "other:key";
      },
    ],
    [
      "other action digest",
      (_answer, result) => {
        result.action_digest = `sha256:${"a".repeat(64)}`;
      },
    ],
    [
      "other facts digest",
      (_answer, result) => {
        result.facts_digest = `sha256:${"b".repeat(64)}`;
      },
    ],
    [
      "other policy",
      (_answer, result) => {
        result.policy_version = "other-policy";
      },
    ],
    [
      "changed Protocol policy",
      (answer) => {
        answer.policy_version = "other-policy";
      },
    ],
    [
      "unknown check",
      (_answer, result) => {
        Object.assign(result.checks[0], { id: "P12" });
      },
    ],
    [
      "missing check",
      (_answer, result) => {
        result.checks.pop();
      },
    ],
    [
      "duplicate check",
      (_answer, result) => {
        result.checks[10] = result.checks[0];
      },
    ],
    [
      "empty reason codes",
      (_answer, result) => {
        result.checks[0].reason_codes = [];
      },
    ],
    [
      "unbounded reason code",
      (_answer, result) => {
        result.checks[0].reason_codes = ["A".repeat(121)];
      },
    ],
    [
      "empty missing fact",
      (_answer, result) => {
        result.checks[0].missing_facts = [""];
      },
    ],
    [
      "wrong measurement",
      (_answer, result) => {
        Object.assign(result.checks[0], { measurements: { margin: "25" } });
      },
    ],
    [
      "unknown result field",
      (_answer, result) => {
        Object.assign(result, { platform_token: "fixture-invalid" });
      },
    ],
    [
      "invented executor",
      (_answer, result) => {
        Object.assign(result, { execution_available: true });
      },
    ],
    [
      "wrong mode",
      (answer) => {
        answer.mode = "ENFORCED";
      },
    ],
    [
      "invalid timestamp",
      (_answer, result) => {
        result.evaluated_at = "2026-02-30T00:00:00Z";
      },
    ],
    [
      "evaluated without verdict",
      (_answer, result) => {
        result.checks[0].verdict = null;
      },
    ],
    [
      "unsupported permits",
      (_answer, result) => {
        result.checks[0].status = "unsupported";
      },
    ],
    [
      "missing facts permit",
      (_answer, result) => {
        result.checks[0].status = "missing_facts";
      },
    ],
    [
      "not applicable has verdict",
      (_answer, result) => {
        result.checks[1].verdict = "HOLD";
      },
    ],
    [
      "aggregation drops hold",
      (_answer, result) => {
        result.checks[0].verdict = "HOLD";
      },
    ],
    [
      "aggregation drops block",
      (_answer, result) => {
        result.checks[0].verdict = "BLOCK";
      },
    ],
    [
      "Protocol weakens block",
      (answer, result) => {
        result.checks[0].verdict = "BLOCK";
        result.disposition = "BLOCK";
        answer.outcome = "REVIEW";
      },
    ],
    [
      "Protocol weakens hold",
      (_answer, result) => {
        result.checks[0].verdict = "HOLD";
        result.disposition = "HOLD";
      },
    ],
    [
      "entirely unassessed permit",
      (_answer, result) => {
        result.checks[0].status = "disabled";
        result.checks[0].verdict = null;
      },
    ],
  ];

  it.each(mutations)("fails closed on %s without a legacy retry", async (_name, mutate) => {
    const request = input();
    const answer = response(request);
    mutate(answer, answer.commerce_preflight as CommercePreflightResult);
    const { client, fetch } = network(answer);
    await expect(client.evaluateAction(request)).rejects.toMatchObject({
      code: "INVALID_UPSTREAM_RESPONSE",
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("returns HOLD for complete server missing-facts evidence and accepts legacy-flow continuity", async () => {
    const request = input();
    const answer = response(request, { outcome: "REVIEW", fallback_to_legacy: true });
    const preflight = answer.commerce_preflight as CommercePreflightResult;
    Object.assign(preflight.checks[0], {
      status: "missing_facts",
      verdict: "HOLD",
      reason_codes: ["REQUIRED_FACT_MISSING"],
      missing_facts: ["pricing.estimated_cost"],
    });
    preflight.disposition = "HOLD";
    const { client } = network(answer);
    await expect(client.evaluateAction(request)).resolves.toEqual(answer);
  });

  it("captures the sent action and facts before asynchronous access resolution", async () => {
    const request = input();
    const original = structuredClone(request);
    const config = new CommerceGateConfiguration({
      DECIONIS_API_KEY: "fixture-key",
      DECIONIS_ORG_ID: ORG,
      DECIONIS_API_BASE: "https://api.example.test",
    });
    vi.spyOn(config, "resolveAccess").mockImplementationOnce(async () => {
      request.action.platform = "mutated-platform";
      request.preflight.facts.source = "mutated-source";
      request.policy_version = "mutated-policy";
    });
    const { client, fetch } = network(response(original), config);
    await expect(client.evaluateAction(request)).resolves.toMatchObject({
      commerce_preflight: { action_digest: canonicalPreflightDigest(original.action) },
    });
    const [, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    const wire = JSON.parse(String(init.body));
    expect(wire.context.commerce_action).toEqual(original.action);
    expect(wire.context.commerce_preflight).toEqual(original.preflight);
    expect(wire.policy_version).toBe(POLICY);
  });

  it("does not turn a transport failure into a stripped-down evaluation", async () => {
    const request = input();
    const fetch = vi.fn(async () => {
      throw new Error("fixture-offline");
    });
    const config = new CommerceGateConfiguration({
      DECIONIS_API_KEY: "fixture-key",
      DECIONIS_ORG_ID: ORG,
    });
    await expect(
      new CommerceGateClient(config, fetch).evaluateAction(request),
    ).rejects.toMatchObject({ code: "UPSTREAM_UNREACHABLE" });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("uses JCS lexicographic key order, JSON numeric serialization and unescaped Unicode", () => {
    const value = { z: [1e30, -0, 0.002], "2": "two", "10": "ten", a: "€" };
    const canonical = '{"10":"ten","2":"two","a":"€","z":[1e+30,0,0.002]}';
    const expected = `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
    expect(canonicalPreflightDigest(value)).toBe(expected);
    expect(canonicalPreflightDigest({ a: "€", "10": "ten", "2": "two", z: [1e30, 0, 0.002] })).toBe(
      expected,
    );
  });

  it("rejects non-JSON or excessive canonical input rather than normalizing away the mismatch", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    for (const value of [
      NaN,
      Infinity,
      "\ud800",
      { x: undefined },
      new Date(),
      cyclic,
      Array(4097).fill(0),
    ]) {
      expect(() => canonicalPreflightDigest(value)).toThrow();
    }
    const invalid = { ...ACTIONS[0], platform: "\ud800" };
    expect(() => new CommercePreflightBinding(invalid, input().preflight)).toThrow();
  });
});
