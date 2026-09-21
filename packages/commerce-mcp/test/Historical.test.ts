import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";

import { CommerceGateConfiguration } from "../src/Configuration.js";
import { HistoricalClient } from "../src/HistoricalClient.js";
import {
  historicalAssessmentResponse,
  historicalSourcesResponse,
  HISTORICAL_RESPONSE_BYTES,
} from "../src/HistoricalContract.js";
import { HISTORICAL_TOOL_NAMES } from "../src/HistoricalTools.js";
import { createRuntimeHandler } from "../src/Runtime.js";
import { COMMERCEGATE_TOOL_NAMES } from "../src/Tools.js";

const ID = "00000000-0000-4000-8000-000000000001";
const OTHER_ID = "00000000-0000-4000-8000-000000000002";
const BASE = "https://commerce.example.test/aws";
const ENV = {
  DECIONIS_API_BASE: BASE,
  DECIONIS_API_KEY: "synthetic-test-key",
  DECIONIS_ORG_ID: ID,
};
const SOURCES = {
  mode: "historical_only",
  window_days: 90,
  connected_store_required: true,
  sources: [
    {
      kind: "synthetic",
      dataset_version: "commerce-history-v1",
      label: "Synthetic commerce history",
    },
  ],
};
const ASSESSMENT = {
  assessment_id: ID,
  status: "completed",
  mode: "historical_only",
  window: {
    days: 90,
    start: "2026-01-01T00:00:00.000Z",
    end: "2026-04-01T00:00:00.000Z",
    timestamp_field: "transaction_at",
  },
  provenance: SOURCES.sources[0],
  policy: { kind: "sample", version: "sample-v1", floor_percent: 12 },
  summary: {
    transactions_scanned: 1,
    evaluated: 1,
    missing_cost: 0,
    excluded_timestamp: 0,
    evaluation_errors: 0,
    allow: 1,
    hold: 0,
    escalate: 0,
  },
  evidence: [
    {
      record_id: "a".repeat(64),
      transaction_at: "2026-02-01T00:00:00.000Z",
      decision: "PROCEED",
      reason_codes: ["MARGIN_ABOVE_FLOOR"],
      proof_ref: null,
    },
  ],
  coverage: { record_limit: 100, complete: true },
  truncated: false,
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const call = (name: string, args: Record<string, unknown> = {}) => ({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name, arguments: args },
});

describe("additive AgentOps historical delivery", () => {
  it("retains the seven existing tools and instructions; adds three only in managed HTTP", async () => {
    const api = vi.fn<typeof fetch>();
    for (const transport of ["http", "stdio"]) {
      const handler = createRuntimeHandler(ENV, transport, { fetch: api });
      const listed = await handler({ jsonrpc: "2.0", id: 1, method: "tools/list" });
      const tools = (listed?.result as { tools: { name: string }[] }).tools;
      expect(tools.map((tool) => tool.name)).toEqual([
        ...COMMERCEGATE_TOOL_NAMES,
        ...(transport === "http" ? HISTORICAL_TOOL_NAMES : []),
      ]);
      const initialization = await handler({
        jsonrpc: "2.0",
        id: 2,
        method: "initialize",
        params: {},
      });
      const instructions = (initialization?.result as { instructions: string }).instructions;
      expect(instructions).toContain("commercegate_evaluate_action");
      expect(instructions).toContain("commercegate_validate_erp_transaction");
      if (transport === "http") expect(instructions).toContain("previous 90 days");
      const response = await handler(call("commercegate_describe_capabilities"));
      const capabilities = (response?.result as { structuredContent: Record<string, unknown> })
        .structuredContent;
      expect(capabilities.tools).toEqual(tools.map((tool) => tool.name));
      expect(capabilities.historical_assessment !== undefined).toBe(transport === "http");
    }
    expect(api).not.toHaveBeenCalled();
  });

  it("does not create an anonymous HTTP trial or accept an organization override", async () => {
    const api = vi.fn<typeof fetch>();
    const handler = createRuntimeHandler({}, "http", { fetch: api });
    const denied = await handler(
      call(HISTORICAL_TOOL_NAMES[1], { source: { kind: "synthetic" }, idempotency_key: "trial-1" }),
    );
    expect(JSON.stringify(denied)).toContain("CONFIGURATION_REQUIRED");
    const bound = createRuntimeHandler(ENV, "http", { fetch: api });
    for (const args of [
      { source: { kind: "synthetic" }, idempotency_key: "test", org_id: OTHER_ID },
      { source: { kind: "synthetic", transactions: [] }, idempotency_key: "test" },
      { source: { kind: "synthetic" }, idempotency_key: "test", window_days: 91 },
      { source: { kind: "synthetic" }, idempotency_key: "test", policy: {} },
      {
        source: { kind: "connected_store", connection_id: "../../guard" },
        idempotency_key: "test",
      },
      { source: { kind: "synthetic" }, idempotency_key: "x".repeat(201) },
    ]) {
      expect(JSON.stringify(await bound(call(HISTORICAL_TOOL_NAMES[1], args)))).toContain(
        "INVALID_INPUT",
      );
    }
    expect(api).not.toHaveBeenCalled();
  });

  it("uses exact history routes with bearer-only workspace binding and bounded immutable evidence", async () => {
    const api = vi.fn<typeof fetch>(async (url) =>
      String(url).endsWith("/sources") ? json(SOURCES) : json(ASSESSMENT),
    );
    const handler = createRuntimeHandler(ENV, "http", { fetch: api });
    expect(JSON.stringify(await handler(call(HISTORICAL_TOOL_NAMES[0])))).toContain(
      "commerce-history-v1",
    );
    const input = { source: { kind: "synthetic" }, idempotency_key: "history-1" };
    const started = await handler(call(HISTORICAL_TOOL_NAMES[1], input));
    expect((started?.result as { structuredContent: unknown }).structuredContent).toEqual({
      ok: true,
      no_downstream_action_executed: true,
      assessment: ASSESSMENT,
    });
    await handler(call(HISTORICAL_TOOL_NAMES[2], { assessment_id: ID }));
    expect(api.mock.calls.map(([url]) => String(url))).toEqual([
      `${BASE}/commerce/history/sources`,
      `${BASE}/commerce/history/assessments`,
      `${BASE}/commerce/history/assessments/${ID}`,
    ]);
    const init = api.mock.calls[1][1]!;
    expect(JSON.parse(init.body as string)).toEqual(input);
    expect(init.headers).toMatchObject({
      authorization: `Bearer ${ENV.DECIONIS_API_KEY}`,
      "idempotency-key": "history-1",
    });
    for (const [, options] of api.mock.calls) expect(options?.redirect).toBe("error");
    expect(JSON.stringify(started)).not.toContain(ENV.DECIONIS_API_KEY);
  });

  it("loads durable AWS credentials once and keeps grant eligibility on the service", async () => {
    const key = `dcn_aws_${"a".repeat(64)}`;
    const loadSecret = vi.fn(async () => key);
    const api = vi.fn<typeof fetch>(async (url) => {
      if (String(url).endsWith("/commerce/session"))
        return json({ org_id: ID, api_base_url: "https://commerce.decionis.com/aws" });
      return json(SOURCES);
    });
    const handler = createRuntimeHandler(
      {
        AGENTOPS_ACCESS_SECRET_ARN:
          "arn:aws:secretsmanager:us-east-1:123456789012:secret:synthetic-test-abcdef",
      },
      "http",
      { loadSecret, fetch: api },
    );
    for (let count = 0; count < 2; count++) {
      const answer = await handler(call(HISTORICAL_TOOL_NAMES[0]));
      expect(JSON.stringify(answer)).toContain("commerce-history-v1");
      expect(JSON.stringify(answer)).not.toContain(key);
    }
    expect(loadSecret).toHaveBeenCalledTimes(1);
    expect(api.mock.calls.map(([url]) => String(url))).toEqual([
      "https://commerce.decionis.com/aws/commerce/session",
      "https://commerce.decionis.com/aws/commerce/history/sources",
      "https://commerce.decionis.com/aws/commerce/history/sources",
    ]);
  });
});

describe("historical response boundary", () => {
  it("accepts exact DTOs generated by the Commerce historical service without discarding provenance or missing costs", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL("../contract/HistoricalAssessmentExamples.json", import.meta.url),
        "utf8",
      ),
    );
    expect(fixture.fixture_only).toBe(true);
    expect(historicalAssessmentResponse(fixture.completed)).toEqual(fixture.completed);
    expect(historicalAssessmentResponse(fixture.failed)).toEqual(fixture.failed);
    expect(fixture.completed.summary.missing_cost).toBe(9);
    expect(fixture.completed.coverage.complete).toBe(false);
    expect(
      fixture.completed.evidence.every((item: { proof_ref: unknown }) => item.proof_ref === null),
    ).toBe(true);
    expect(fixture.failed.policy).toBeNull();
  });

  it.each([401, 403, 404, 409, 429, 503])(
    "redacts error bodies and preserves failure at HTTP %s",
    async (status) => {
      const api = vi.fn<typeof fetch>(async () => json({ secret: ENV.DECIONIS_API_KEY }, status));
      const handler = createRuntimeHandler(ENV, "http", { fetch: api });
      const answer = await handler(call(HISTORICAL_TOOL_NAMES[0]));
      expect(JSON.stringify(answer)).toContain(`"status":${status}`);
      expect(JSON.stringify(answer)).not.toContain(ENV.DECIONIS_API_KEY);
      expect((answer?.result as { isError: boolean }).isError).toBe(true);
      expect(api).toHaveBeenCalledTimes(1);
    },
  );

  it("refuses non-gateway origins before network access", async () => {
    const api = vi.fn<typeof fetch>();
    const client = new HistoricalClient(
      new CommerceGateConfiguration({ ...ENV, DECIONIS_API_BASE: "https://api.example.test" }),
      api,
    );
    await expect(client.sources()).rejects.toMatchObject({ code: "CONFIGURATION_INVALID" });
    expect(api).not.toHaveBeenCalled();
  });

  it("rejects oversized declared and streamed responses, malformed JSON, redirects and timeouts", async () => {
    for (const response of [
      new Response("{}", { headers: { "content-length": String(HISTORICAL_RESPONSE_BYTES + 1) } }),
      new Response("x".repeat(HISTORICAL_RESPONSE_BYTES + 1)),
      new Response("not json"),
    ]) {
      await expect(
        new HistoricalClient(new CommerceGateConfiguration(ENV), async () => response).sources(),
      ).rejects.toMatchObject({ code: "INVALID_UPSTREAM_RESPONSE" });
    }
    await expect(
      new HistoricalClient(new CommerceGateConfiguration(ENV), async () => {
        throw new Error("redirect with secret");
      }).sources(),
    ).rejects.toMatchObject({ code: "UPSTREAM_UNREACHABLE" });
    const timed = new HistoricalClient(
      new CommerceGateConfiguration(ENV),
      async (_url, init) =>
        new Promise((_resolve, reject) =>
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))),
        ),
      1,
    );
    await expect(timed.sources()).rejects.toMatchObject({ code: "UPSTREAM_TIMEOUT" });
  });

  it("validates the history source, policy, fixed window and assessment identity", () => {
    expect(historicalAssessmentResponse(ASSESSMENT, ID)).toEqual(ASSESSMENT);
    for (const value of [
      { ...ASSESSMENT, mode: "ENFORCED" },
      { ...ASSESSMENT, window: { ...ASSESSMENT.window, days: 91 } },
      { ...ASSESSMENT, window: { ...ASSESSMENT.window, end: "2026-04-02T00:00:00.000Z" } },
      { ...ASSESSMENT, policy: { ...ASSESSMENT.policy, kind: "merchant" } },
      { ...ASSESSMENT, evidence: Array(101).fill(ASSESSMENT.evidence[0]) },
      {
        ...ASSESSMENT,
        evidence: [{ ...ASSESSMENT.evidence[0], transaction_at: "2027-01-01T00:00:00.000Z" }],
      },
      { ...ASSESSMENT, evidence: [{ ...ASSESSMENT.evidence[0], decision: "ALLOW" }] },
      { ...ASSESSMENT, evidence: [{ ...ASSESSMENT.evidence[0], raw_order: {} }] },
      { ...ASSESSMENT, summary: { ...ASSESSMENT.summary, missing_cost: -1 } },
    ])
      expect(() => historicalAssessmentResponse(value)).toThrow();
    expect(() => historicalAssessmentResponse(ASSESSMENT, OTHER_ID)).toThrow();
    expect(() =>
      historicalSourcesResponse({ ...SOURCES, sources: Array(22).fill(SOURCES.sources[0]) }),
    ).toThrow();
    expect(() =>
      historicalSourcesResponse({ ...SOURCES, api_key: ENV.DECIONIS_API_KEY }),
    ).toThrow();
  });

  it("retains failed assessments with no invented policy or proof", () => {
    const failed = {
      ...ASSESSMENT,
      status: "failed",
      policy: null,
      evidence: [],
      coverage: { record_limit: 100, complete: false },
      error_code: "HISTORICAL_POLICY_REQUIRED",
    };
    expect(historicalAssessmentResponse(failed)).toEqual(failed);
    expect(() => historicalAssessmentResponse({ ...failed, status: "completed" })).toThrow();
    expect(() =>
      historicalAssessmentResponse({ ...failed, coverage: { record_limit: 100, complete: true } }),
    ).toThrow();
  });

  it("rejects a response that changes the requested source", async () => {
    const client = new HistoricalClient(new CommerceGateConfiguration(ENV), async () =>
      json(ASSESSMENT),
    );
    await expect(
      client.start({
        source: { kind: "connected_store", connection_id: OTHER_ID },
        idempotency_key: "same-source",
      }),
    ).rejects.toMatchObject({ code: "INVALID_UPSTREAM_RESPONSE" });
  });
});
