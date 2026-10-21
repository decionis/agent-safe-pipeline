import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { Gateway } from "../../src/gateway/Gateway.js";
import { GatewayConfigError } from "../../src/gateway/GatewayConfig.js";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import {
  collectedIo,
  LOOPBACK_ORIGIN,
  testConfig,
  UpstreamDouble,
} from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const COMPANY = "c0ffee00-0000-4000-8000-000000000001";

/**
 * Every part of the request that is not a fact the profile names carries a
 * canary. The authority must see none of them, in any byte of any call.
 */
const CANARIES = {
  path: "PATHCANARY",
  query: "QUERYCANARY",
  authorization: "AUTHCANARY",
  correlation: "CORRELCANARY",
  idempotency: "IDEMCANARY",
  header: "HEADERCANARY",
  body: "BODYCANARY",
} as const;

const salesOrder = {
  customerNumber: "10000",
  currencyCode: "USD",
  externalDocumentNumber: "EXT-1",
  comment: `deliver to ${CANARIES.body}`,
  salesOrderLines: [{ lineType: "Item", lineObjectNumber: "1896-S", quantity: 2 }],
};
const PATH = `/v2.0/tenant-${CANARIES.path}/production/api/v2.0/companies(${COMPANY})/salesOrders`;

function call(path = PATH, body: unknown = salesOrder): InterceptedRequest {
  return {
    method: "POST",
    path,
    search: `?note=${CANARIES.query}`,
    headers: {
      host: "gateway.example",
      "content-type": "application/json",
      authorization: `Bearer ${CANARIES.authorization}`,
      "x-request-id": CANARIES.correlation,
      "idempotency-key": CANARIES.idempotency,
      "x-tenant-note": CANARIES.header,
    },
    body: Buffer.from(JSON.stringify(body), "utf8"),
    remoteAddress: "127.0.0.1",
    encrypted: false,
  };
}

/** Everything a fetch to the authority carried: its address, its headers and its body. */
interface Sent {
  readonly url: string;
  readonly text: string;
}

function spying(sent: Sent[]): typeof fetch {
  return async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    const headers = JSON.stringify([...new Headers(init?.headers ?? {}).entries()]);
    const body =
      init?.body === undefined || init.body === null
        ? ""
        : typeof init.body === "string"
          ? init.body
          : Buffer.from(init.body as Uint8Array).toString("utf8");
    sent.push({ url, text: `${url}\n${headers}\n${body}` });
    return await fetch(input, init);
  };
}

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 50));
const FACTS_FILE = {
  version: 1,
  interception: { profile: "businesscentral/api/v2", privacy: "facts" },
};

describe("the facts-only setting", () => {
  it("is full by default, and facts from the file or the environment", () => {
    expect(testConfig("http://127.0.0.1:1").interception.privacy).toBe("FULL");
    expect(testConfig("http://127.0.0.1:1", { file: FACTS_FILE }).interception.privacy).toBe(
      "FACTS",
    );
    const env = testConfig("http://127.0.0.1:1", {
      env: { AGENTSAFE_PRIVACY: "facts", AGENTSAFE_PROFILE: "walmart/api/v3" },
    });
    expect(env.interception.privacy).toBe("FACTS");
    expect(env.sources["interception.privacy"]).toBe("environment");
  });

  it("refuses, by name, every setting that would send a raw part of the request", () => {
    const refused = (file: Record<string, unknown>, env: Record<string, string> = {}): string => {
      try {
        testConfig("http://127.0.0.1:1", { file: { version: 1, ...file }, env });
      } catch (error) {
        if (error instanceof GatewayConfigError) return `${error.code} ${error.setting}`;
        throw error;
      }
      throw new Error("expected a refusal");
    };
    expect(refused({ interception: { privacy: "facts" } })).toBe(
      "CONFIG_MISSING interception.profile",
    );
    expect(
      refused({
        interception: {
          privacy: "facts",
          profile: "walmart/api/v3",
          routes: [{ path: "/payments", action: "payment.create" }],
        },
      }),
    ).toBe("CONFIG_INVALID interception.routes");
    expect(
      refused({
        interception: { privacy: "facts", profile: "walmart/api/v3", principalHeader: "x-agent" },
      }),
    ).toBe("CONFIG_INVALID interception.principalHeader");
    expect(
      refused({
        interception: { privacy: "facts", profile: "walmart/api/v3", unmatched: "passthrough" },
      }),
    ).toBe("CONFIG_INVALID interception.unmatched");
    expect(refused({ interception: { privacy: "names" } })).toBe(
      "CONFIG_INVALID interception.privacy",
    );
    expect(refused({}, { AGENTSAFE_PRIVACY: "some" })).toBe("CONFIG_INVALID AGENTSAFE_PRIVACY");
  });
});

describe("a facts-only gateway", () => {
  const upstream = new UpstreamDouble();
  const authority = new LocalAuthority({ policy: () => "ALLOW" });
  const env = {
    DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
    DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    DECIONIS_TENANT_ID: TENANT_ID,
  };
  beforeAll(async () => {
    await upstream.start();
    await authority.start();
  });
  afterAll(async () => {
    await authority.stop();
    await upstream.stop();
  });

  async function gatewayFor(mode: "enforcement" | "shadow", sent: Sent[]): Promise<Gateway> {
    const withUrl = { ...env, DECIONIS_API_URL: authority.baseUrl, AGENTSAFE_MODE: mode };
    return await Gateway.create(testConfig(upstream.baseUrl, { env: withUrl, file: FACTS_FILE }), {
      env: withUrl,
      io: collectedIo(),
      version: "9.9.9",
      authorityFetch: spying(sent),
    });
  }

  function expectNoCanary(sent: readonly Sent[]): void {
    expect(sent.length).toBeGreaterThan(0);
    for (const { text } of sent) {
      for (const canary of Object.values(CANARIES)) expect(text).not.toContain(canary);
      // Not even the plain digests, which a guess of a small body or a path could confirm.
      expect(text).not.toMatch(/request_sha256|body_sha256|body_bytes|content_type/);
    }
  }

  it("sends the authority the operation, its template and the named facts, and no raw byte", async () => {
    const sent: Sent[] = [];
    const gateway = await gatewayFor("enforcement", sent);
    const plan = gateway.plan("POST", PATH, `?note=${CANARIES.query}`);
    expect(plan).toMatchObject({ kind: "GOVERN", action: "sales.create" });
    const before = upstream.seen.length;
    const answer = await gateway.govern(call(), "sales.create");
    await settle();
    await gateway.close();
    expect(answer.status).toBe(201);
    expectNoCanary(sent);

    const evaluated = sent.find(({ url }) => url.endsWith("/v1/authority/grants"));
    const binding = JSON.parse(evaluated?.text.split("\n").slice(2).join("\n") ?? "{}") as {
      action: { type: string; resource: string; parameters: Record<string, unknown> };
      context: Record<string, unknown>;
    };
    expect(binding.action).toEqual({
      type: "sales.create",
      resource: "POST /companies({companyId})/salesOrders",
      parameters: {
        method: "POST",
        operation: "salesOrders.create",
        path_template: "/companies({companyId})/salesOrders",
      },
    });
    expect(binding.context).toMatchObject({
      company_id: COMPANY,
      environment: "production",
      customer_number: "10000",
      currency_code: "USD",
      external_document_number: "EXT-1",
      api_profile: { id: "businesscentral/api/v2", operation: "salesOrders.create" },
      ingress: "http",
    });
    expect(binding.context["request_hmac_sha256"]).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(binding.context["idempotency_key"]).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);

    // The upstream still receives the request exactly as the agent sent it.
    const forwarded = upstream.seen.slice(before).at(-1);
    expect(forwarded?.url).toBe(`${PATH}?note=${CANARIES.query}`);
    expect(forwarded?.headers["authorization"]).toBe(`Bearer ${CANARIES.authorization}`);
    expect(JSON.parse(forwarded?.body ?? "{}")).toEqual(salesOrder);
  });

  it("would see the raw request if it were sent: full privacy carries the path, query and body", async () => {
    const sent: Sent[] = [];
    const withUrl = { ...env, DECIONIS_API_URL: authority.baseUrl, AGENTSAFE_MODE: "enforcement" };
    const gateway = await Gateway.create(
      testConfig(upstream.baseUrl, {
        env: withUrl,
        file: { version: 1, interception: { profile: "businesscentral/api/v2" } },
      }),
      { env: withUrl, io: collectedIo(), version: "9.9.9", authorityFetch: spying(sent) },
    );
    await gateway.govern(call(), "sales.create");
    await settle();
    await gateway.close();
    const all = sent.map(({ text }) => text).join("\n");
    for (const canary of [CANARIES.path, CANARIES.query, CANARIES.body, CANARIES.idempotency]) {
      expect(all).toContain(canary);
    }
  });

  it("sends no raw byte in shadow either", async () => {
    const sent: Sent[] = [];
    const gateway = await gatewayFor("shadow", sent);
    const answer = await gateway.govern(call(), "sales.create");
    await settle();
    await gateway.close();
    expect(answer.status).toBe(201);
    expectNoCanary(sent);
  });

  it("refuses a call no profile operation names, and asks the authority nothing", async () => {
    const sent: Sent[] = [];
    const gateway = await gatewayFor("enforcement", sent);
    const server = new GatewayHttpServer(gateway);
    const { port } = await server.listen(0, "127.0.0.1");
    const before = upstream.seen.length;
    const response = await fetch(
      `${LOOPBACK_ORIGIN}:${port}/v2.0/production/api/v2.0/companies(${COMPANY})/notes?q=${CANARIES.query}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: CANARIES.body }),
      },
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ code: "PROFILE_OPERATION_UNMATCHED" });
    expect(response.headers.get("agentsafe-execution")).toBe("NOT_FORWARDED");
    // A read is not governed, so it still passes through.
    const read = await fetch(`${LOOPBACK_ORIGIN}:${port}/v2.0/production/api/v2.0/companies`);
    expect(read.status).toBe(200);
    await server.close(10);
    await gateway.close();
    expect(sent.filter(({ url }) => url.includes("/v1/authority/"))).toEqual([]);
    expect(upstream.seen.slice(before).map((seen) => seen.method)).toEqual(["GET"]);
  });
});
