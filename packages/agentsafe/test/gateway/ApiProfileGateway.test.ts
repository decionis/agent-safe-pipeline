import { afterAll, describe, expect, it } from "vitest";
import { ApiProfiles, type JsonObject } from "@decionis/agent-safe-pipeline";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { demoPolicy } from "../../src/gateway/DemoAuthority.js";
import { Gateway } from "../../src/gateway/Gateway.js";
import { GatewayConfigError } from "../../src/gateway/GatewayConfig.js";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import { RouteTable } from "../../src/gateway/RouteTable.js";
import { collectedIo, testConfig, UpstreamDouble } from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const walmart = ApiProfiles.get("walmart/api/v3")!;

function request(
  method: string,
  path: string,
  body: unknown = undefined,
  search = "",
): InterceptedRequest {
  return {
    method,
    path,
    search,
    headers: {
      host: "gateway.example",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), "utf8"),
    remoteAddress: "127.0.0.1",
    encrypted: false,
  };
}

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 30));

describe("the gateway's profile setting", () => {
  it("takes a shipped profile from the file or the environment, the environment first", () => {
    expect(testConfig("http://127.0.0.1:1").interception.profile).toBeNull();
    expect(
      testConfig("http://127.0.0.1:1", {
        file: { version: 1, interception: { profile: "walmart/api/v3" } },
      }).interception.profile,
    ).toBe("walmart/api/v3");
    const both = testConfig("http://127.0.0.1:1", {
      env: { AGENTSAFE_PROFILE: "businesscentral/api/v2" },
      file: { version: 1, interception: { profile: "walmart/api/v3" } },
    });
    expect(both.interception.profile).toBe("businesscentral/api/v2");
    expect(both.sources["interception.profile"]).toBe("environment");
  });

  it("refuses a profile this build does not ship, by name", () => {
    expect(() =>
      testConfig("http://127.0.0.1:1", { env: { AGENTSAFE_PROFILE: "walmart/api/v9" } }),
    ).toThrow(GatewayConfigError);
  });
});

describe("the route table with a profile", () => {
  const table = new RouteTable(
    [{ path: "/v3/orders/*/acknowledge", action: "custom.ack", methods: ["POST"] }],
    "GOVERN",
    true,
    walmart,
  );

  it("names a call by an explicit route first, then by the profile's operation", () => {
    expect(table.plan("POST", "/v3/orders/42/acknowledge")).toMatchObject({
      kind: "GOVERN",
      action: "custom.ack",
    });
    expect(table.plan("POST", "/v3/orders/42/cancel")).toEqual({
      kind: "GOVERN",
      action: "order.cancel",
      route: null,
      operation: "orders.cancel",
    });
  });

  it("tells an overloaded path apart by its query, and leaves the rest to the unmatched policy", () => {
    expect(table.plan("PUT", "/v3/price", { promo: "true" })).toMatchObject({
      action: "promotion.change",
      operation: "prices.promotion",
    });
    expect(table.plan("PUT", "/v3/price")).toMatchObject({ action: "price.change" });
    expect(table.plan("POST", "/v3/orders/42/notes")).toEqual({
      kind: "GOVERN",
      action: "http.post",
      route: null,
    });
    expect(table.plan("GET", "/v3/orders/42")).toMatchObject({ kind: "PASSTHROUGH" });
    expect(new RouteTable([], "PASSTHROUGH", true, walmart).plan("POST", "/v3/x")).toMatchObject({
      kind: "PASSTHROUGH",
      reason: "UNMATCHED",
    });
  });

  it("seals the registry over every action the profile can produce", () => {
    expect(table.actions()).toEqual(expect.arrayContaining([...walmart.actions(), "custom.ack"]));
  });
});

describe("what the gateway states for a profile's call", () => {
  const upstream = new UpstreamDouble();
  const authority = new LocalAuthority({ policy: demoPolicy });
  afterAll(async () => {
    await authority.stop();
    await upstream.stop();
  });

  async function contextOf(
    file: Record<string, unknown>,
    call: InterceptedRequest,
    action: string,
  ): Promise<JsonObject> {
    const env = {
      DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
      DECIONIS_API_URL: authority.baseUrl,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      DECIONIS_TENANT_ID: TENANT_ID,
    };
    const gateway = await Gateway.create(testConfig(upstream.baseUrl, { env, file }), {
      env,
      io: collectedIo(),
      version: "9.9.9",
    });
    const before = authority.requests.length;
    await gateway.govern(call, action);
    await settle();
    await gateway.close();
    const sent = authority.requests
      .slice(before)
      .find((seen) => seen.path === "/v1/authority/grants");
    return (sent?.body as { context: JsonObject }).context;
  }

  it("states the operation's facts at the top of the trusted context, beside the operation", async () => {
    await upstream.start();
    await authority.start();
    const price = {
      sku: "SKU-RED-12",
      pricing: [{ currentPriceType: "BASE", currentPrice: { currency: "USD", amount: 18.49 } }],
    };
    const context = await contextOf(
      { version: 1, interception: { profile: "walmart/api/v3" } },
      request("PUT", "/v3/price", price),
      "price.change",
    );
    expect(context).toMatchObject({
      sku: "SKU-RED-12",
      price_amount: 18.49,
      price_currency: "USD",
      api_profile: { id: "walmart/api/v3", operation: "prices.update" },
      ingress: "http",
    });
  });

  it("reads facts from a body it does not embed, and from the path and query", async () => {
    const context = await contextOf(
      { version: 1, interception: { profile: "walmart/api/v3", maxEmbeddedBodyBytes: 0 } },
      request(
        "PUT",
        "/v3/inventory",
        { quantity: { unit: "EACH", amount: 40 } },
        "?sku=SKU-RED-12",
      ),
      "inventory.update",
    );
    expect(context).toMatchObject({
      sku: "SKU-RED-12",
      quantity: 40,
      quantity_unit: "EACH",
      body_embedded: false,
    });
  });

  it("states nothing of a profile for a call an explicit route named, or without one", async () => {
    const routed = await contextOf(
      {
        version: 1,
        interception: {
          profile: "walmart/api/v3",
          routes: [{ path: "/v3/orders/*/acknowledge", action: "custom.ack" }],
        },
      },
      request("POST", "/v3/orders/42/acknowledge", {}),
      "custom.ack",
    );
    expect(Object.hasOwn(routed, "api_profile")).toBe(false);
    expect(Object.hasOwn(routed, "purchase_order_id")).toBe(false);
    const plain = await contextOf(
      { version: 1 },
      request("POST", "/v3/orders/42/acknowledge", {}),
      "http.post",
    );
    expect(Object.hasOwn(plain, "api_profile")).toBe(false);
  });
});
