import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { Gateway } from "../../src/gateway/Gateway.js";
import type { RouteConfig } from "../../src/gateway/GatewayConfig.js";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import {
  collectedIo,
  LOOPBACK_ORIGIN,
  testConfig,
  UpstreamDouble,
} from "../support/GatewayHarness.js";

const POLICY_ID = "00000000-0000-4000-8000-000000000010";
const POLICY_VERSION = "synthetic-payments-v1";
const OTHER_POLICY_ID = "00000000-0000-4000-8000-000000000011";
const route: RouteConfig = {
  path: "/decide",
  methods: ["POST"],
  action: "payment.decide",
  policyId: POLICY_ID,
  policyVersion: POLICY_VERSION,
};

/** The caller tries all three places; none may choose the authority's policy. */
function request(overrides: Partial<InterceptedRequest> = {}): InterceptedRequest {
  return {
    method: "POST",
    path: "/decide",
    search: `?policy_id=${OTHER_POLICY_ID}&policy_version=caller-query`,
    headers: {
      "content-type": "application/json",
      "x-policy-id": OTHER_POLICY_ID,
      "x-policy-version": "caller-header",
    },
    body: Buffer.from(
      `{ "action": "hold", "amount_minor": 100, "policy_id": "${OTHER_POLICY_ID}", "policy_version": "caller-body" }`,
      "utf8",
    ),
    remoteAddress: "127.0.0.1",
    encrypted: false,
    ...overrides,
  };
}

interface EvaluatedRequest {
  readonly action: { readonly type: string; readonly parameters: Record<string, unknown> };
  readonly intent_hash: string;
}

describe("an HTTP route's policy selection", () => {
  const upstream = new UpstreamDouble();
  // This local policy deliberately refuses an unselected or different policy.
  // LocalAuthority independently checks the canonical intent hash as well.
  const authority = new LocalAuthority({
    policy: (input) =>
      input.action.parameters["policy_id"] === POLICY_ID &&
      input.action.parameters["policy_version"] === POLICY_VERSION
        ? "ALLOW"
        : "BLOCK",
  });
  beforeAll(async () => {
    await upstream.start();
    await authority.start();
  });
  afterAll(async () => {
    await authority.stop();
    await upstream.stop();
  });

  async function gatewayFor(routes: readonly RouteConfig[]): Promise<Gateway> {
    const env = {
      DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
      DECIONIS_TENANT_ID: "00000000-0000-4000-8000-000000000009",
      DECIONIS_API_URL: authority.baseUrl,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      AGENTSAFE_MODE: "enforcement",
    };
    return await Gateway.create(
      testConfig(upstream.baseUrl, { env, file: { version: 1, interception: { routes } } }),
      { env, io: collectedIo(), version: "0.0.0-test" },
    );
  }

  function evaluatedAfter(before: number): EvaluatedRequest {
    const calls = authority.requests
      .slice(before)
      .filter((seen) => seen.path === "/v1/authority/grants");
    expect(calls).toHaveLength(1);
    return calls[0]!.body as EvaluatedRequest;
  }

  it("sends the operator's selector at the authority's top level and forwards the original bytes", async () => {
    const gateway = await gatewayFor([route]);
    const server = new GatewayHttpServer(gateway);
    const { port } = await server.listen(0, "127.0.0.1");
    try {
      const before = authority.requests.length;
      const sentBefore = upstream.seen.length;
      const input = request();
      const response = await fetch(`${LOOPBACK_ORIGIN}:${port}${input.path}${input.search}`, {
        method: input.method,
        headers: input.headers,
        body: input.body.toString("utf8"),
      });
      const responseBody = await response.text();
      expect(response.status, responseBody).toBe(201);
      expect(response.headers.get("agentsafe-execution")).toBe("FORWARDED");
      const evaluated = evaluatedAfter(before);
      expect(evaluated.action).toMatchObject({
        type: "payment.decide",
        parameters: {
          policy_id: POLICY_ID,
          policy_version: POLICY_VERSION,
          method: "POST",
          path: "/decide",
          body: { policy_id: OTHER_POLICY_ID, policy_version: "caller-body" },
          query: { policy_id: OTHER_POLICY_ID, policy_version: "caller-query" },
        },
      });
      expect(response.headers.get("agentsafe-intent-hash")).toBe(evaluated.intent_hash);
      expect(upstream.seen.slice(sentBefore)).toHaveLength(1);
      expect(upstream.seen.at(-1)).toMatchObject({
        method: "POST",
        url: `${input.path}${input.search}`,
        body: input.body.toString("utf8"),
        headers: { "x-policy-id": OTHER_POLICY_ID, "x-policy-version": "caller-header" },
      });
    } finally {
      await server.close(10);
      await gateway.close();
    }
  });

  it("never promotes a caller's policy fields when the route has no selector", async () => {
    const gateway = await gatewayFor([]);
    try {
      const before = authority.requests.length;
      const sentBefore = upstream.seen.length;
      const input = request({
        search: `?policy_id=${POLICY_ID}&policy_version=${POLICY_VERSION}`,
        headers: { "content-type": "application/json", "x-policy-id": POLICY_ID },
        body: Buffer.from(JSON.stringify({ policy_id: POLICY_ID, policy_version: POLICY_VERSION })),
      });
      const response = await gateway.govern(input, "http.post");
      expect(response.status).toBe(403);
      const parameters = evaluatedAfter(before).action.parameters;
      expect(parameters["policy_id"]).toBeUndefined();
      expect(parameters["policy_version"]).toBeUndefined();
      expect(upstream.seen).toHaveLength(sentBefore);
    } finally {
      await gateway.close();
    }
  });

  it.each([
    ["POST", "/different", "http.post"],
    ["PATCH", "/decide", "http.patch"],
  ])("does not apply the route's selector to %s %s", async (method, path, action) => {
    const gateway = await gatewayFor([route]);
    try {
      const before = authority.requests.length;
      const sentBefore = upstream.seen.length;
      const response = await gateway.govern(request({ method, path }), action);
      expect(response.status).toBe(403);
      const evaluated = evaluatedAfter(before);
      expect(evaluated.action.type).toBe(action);
      expect(evaluated.action.parameters["policy_id"]).toBeUndefined();
      expect(evaluated.action.parameters["policy_version"]).toBeUndefined();
      expect(upstream.seen).toHaveLength(sentBefore);
    } finally {
      await gateway.close();
    }
  });

  it("refuses an attempt to change the pinned route's action before asking the authority", async () => {
    const gateway = await gatewayFor([route]);
    try {
      const before = authority.requests.length;
      const sentBefore = upstream.seen.length;
      const response = await gateway.govern(request(), "http.post");
      expect(response.status).toBe(400);
      expect(JSON.parse(response.body.toString("utf8"))).toMatchObject({
        state: "ERROR",
        reason_codes: ["ROUTE_ACTION_MISMATCH"],
        execution: "NOT_FORWARDED",
      });
      expect(authority.requests).toHaveLength(before);
      expect(upstream.seen).toHaveLength(sentBefore);
    } finally {
      await gateway.close();
    }
  });

  it("keeps an authority refusal of the selected policy closed instead of retrying without it", async () => {
    const gateway = await gatewayFor([{ ...route, policyId: OTHER_POLICY_ID }]);
    try {
      const before = authority.requests.length;
      const sentBefore = upstream.seen.length;
      const response = await gateway.govern(request(), route.action);
      expect(response.status).toBe(403);
      expect(evaluatedAfter(before).action.parameters["policy_id"]).toBe(OTHER_POLICY_ID);
      expect(upstream.seen).toHaveLength(sentBefore);
    } finally {
      await gateway.close();
    }
  });
});
