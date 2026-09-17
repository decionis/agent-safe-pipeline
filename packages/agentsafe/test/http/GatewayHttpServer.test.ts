import { request as httpRequest } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Gateway } from "../../src/gateway/Gateway.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import {
  collectedIo,
  testConfig,
  UpstreamDouble,
  LOOPBACK_ORIGIN,
} from "../support/GatewayHarness.js";

describe("the gateway listener", () => {
  const upstream = new UpstreamDouble();
  let gateway: Gateway;
  let server: GatewayHttpServer;
  let origin = "";

  beforeAll(async () => {
    await upstream.start();
    gateway = await Gateway.create(
      testConfig(upstream.baseUrl, {
        file: {
          version: 1,
          interception: {
            maxBodyBytes: 2048,
            routes: [{ path: "/payments/**", action: "payment.create", methods: ["POST"] }],
          },
        },
      }),
      { env: {}, io: collectedIo() },
    );
    server = new GatewayHttpServer(gateway, { metricsToken: "synthetic-metrics-token" });
    const address = await server.listen(0, "127.0.0.1");
    origin = `${LOOPBACK_ORIGIN}:${address.port}`;
  });
  afterAll(async () => {
    await server.close(100);
    await gateway.close();
    await upstream.stop();
  });

  it("answers its own routes under the reserved prefix and nothing else there", async () => {
    expect(await (await fetch(`${origin}/_agentsafe/healthz`)).json()).toEqual({ status: "ok" });
    expect((await fetch(`${origin}/_agentsafe/readyz`)).status).toBe(200);
    const status = (await (await fetch(`${origin}/_agentsafe/status`)).json()) as {
      status: string;
      mode: string;
    };
    expect(status).toMatchObject({ status: "ready", mode: "ENFORCEMENT" });
    expect((await fetch(`${origin}/_agentsafe/nope`)).status).toBe(404);
    expect((await fetch(`${origin}/_agentsafe`)).status).toBe(404);
    expect((await fetch(`${origin}/_agentsafe/status`, { method: "POST" })).status).toBe(405);
    const health = await fetch(`${origin}/_agentsafe/healthz`);
    expect(health.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  it("guards the metrics route with the token it was given", async () => {
    expect((await fetch(`${origin}/_agentsafe/metrics`)).status).toBe(401);
    const metrics = await fetch(`${origin}/_agentsafe/metrics`, {
      headers: { authorization: "Bearer synthetic-metrics-token" },
    });
    expect(metrics.status).toBe(200);
    expect(metrics.headers.get("content-type")).toContain("openmetrics");
    expect(await metrics.text()).toContain("# TYPE agentsafe_requests counter");
  });

  it("governs a routed request and relays the upstream's answer with the evidence headers", async () => {
    const response = await fetch(`${origin}/payments/p1`, {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": "pay-9" },
      body: '{"amount": 20}',
    });
    expect(response.status).toBe(201);
    expect(response.headers.get("agentsafe-decision")).toBe("ALLOW");
    expect(response.headers.get("agentsafe-execution")).toBe("FORWARDED");
    expect(response.headers.get("x-upstream")).toBe("double");
    expect(response.headers.getSetCookie()).toHaveLength(2);
    expect(((await response.json()) as { body: string }).body).toBe('{"amount": 20}');
    expect(upstream.seen.at(-1)?.headers["idempotency-key"]).toBe("pay-9");
    expect(gateway.metricsText()).toContain(
      'agentsafe_interceptions_total{action="payment.create"} 1',
    );
  });

  it("holds an escalation and exposes it under its intent id, refusing ids it does not hold", async () => {
    const held = await fetch(`${origin}/payments/p2`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"amount": 500}',
    });
    expect(held.status).toBe(202);
    const body = (await held.json()) as { intent_id: string; resume: string };
    expect((await fetch(`${origin}${body.resume}`)).status).toBe(200);
    expect((await fetch(`${origin}${body.resume}/resume`, { method: "POST" })).status).toBe(409);
    expect((await fetch(`${origin}${body.resume}`, { method: "DELETE" })).status).toBe(405);
    expect((await fetch(`${origin}${body.resume}/other`)).status).toBe(404);
    expect((await fetch(`${origin}/_agentsafe/v1/escalations/not-an-id`)).status).toBe(404);
    expect(
      (await fetch(`${origin}/_agentsafe/v1/escalations/00000000-0000-4000-8000-000000000000`))
        .status,
    ).toBe(404);
    expect(
      (
        await fetch(
          `${origin}/_agentsafe/v1/escalations/00000000-0000-4000-8000-000000000000/resume`,
          { method: "POST" },
        )
      ).status,
    ).toBe(404);
  });

  it("passes a safe request through with its query, and bounds a governed body", async () => {
    const read = await fetch(`${origin}/health?x=1`);
    expect(read.status).toBe(200);
    expect(((await read.json()) as { url: string }).url).toBe("/health?x=1");
    const declared = await fetch(`${origin}/payments/big`, {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": "4096" },
      body: "x".repeat(4096),
    });
    expect(declared.status).toBe(413);
    expect(await declared.json()).toEqual({ code: "BODY_TOO_LARGE" });
    const streamed = await fetch(`${origin}/payments/big`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "x".repeat(4096),
      duplex: "half",
    } as RequestInit);
    expect(streamed.status).toBe(413);
  });

  it("answers an internal failure with a code and nothing from the request", async () => {
    const broken = new GatewayHttpServer({
      config: gateway.config,
      plan: () => {
        throw new Error("boom with a secret");
      },
    } as unknown as Gateway);
    const address = await broken.listen(0, "127.0.0.1");
    const response = await fetch(`${LOOPBACK_ORIGIN}:${address.port}/anything`);
    expect(response.status).toBe(500);
    expect(await response.text()).toBe('{"code":"INTERNAL_ERROR"}');
    await broken.close(10);
  });
});

describe("one listener in front of many gateways", () => {
  const upstreamA = new UpstreamDouble();
  const upstreamB = new UpstreamDouble();
  let a: Gateway;
  let b: Gateway;
  let server: GatewayHttpServer;
  let port = 0;

  /** A raw request, because `fetch` will not let a test set the Host header. */
  function raw(
    method: string,
    path: string,
    host: string,
    body: string | null = null,
  ): Promise<{
    status: number;
    headers: Record<string, string | string[] | undefined>;
    body: string;
  }> {
    return new Promise((resolve, reject) => {
      const request = httpRequest(
        {
          host: "127.0.0.1",
          port,
          method,
          path,
          headers: {
            host,
            ...(body === null ? {} : { "content-type": "application/json" }),
          },
        },
        (response) => {
          let text = "";
          response.setEncoding("utf8");
          response.on("data", (chunk: string) => {
            text += chunk;
          });
          response.on("end", () =>
            resolve({ status: response.statusCode ?? 0, headers: response.headers, body: text }),
          );
        },
      );
      request.on("error", reject);
      request.end(body ?? undefined);
    });
  }

  beforeAll(async () => {
    await upstreamA.start();
    await upstreamB.start();
    a = await Gateway.create(testConfig(upstreamA.baseUrl), { env: {}, io: collectedIo() });
    b = await Gateway.create(testConfig(upstreamB.baseUrl, { flags: { mode: "shadow" } }), {
      env: {},
      io: collectedIo(),
    });
    const byHost = new Map([
      ["a.gateway.example", a],
      ["b.gateway.example", b],
    ]);
    server = new GatewayHttpServer((hostname) =>
      hostname === null ? null : (byHost.get(hostname) ?? null),
    );
    port = (await server.listen(0, "127.0.0.1")).port;
  });
  afterAll(async () => {
    await server.close(100);
    await a.close();
    await b.close();
    await upstreamA.stop();
    await upstreamB.stop();
  });

  it("routes each host to its own gateway, own routes included, and refuses a host it does not serve", async () => {
    const blocked = await raw("POST", "/payments", "a.gateway.example:8080", '{"amount": 5000}');
    expect(blocked.status).toBe(403);
    expect(upstreamA.seen).toHaveLength(0);
    const shadowed = await raw("POST", "/payments", "B.GATEWAY.EXAMPLE", '{"amount": 5000}');
    expect(shadowed.status).toBe(201);
    expect(shadowed.headers["agentsafe-mode"]).toBe("SHADOW");
    expect(upstreamB.seen).toHaveLength(1);
    const statusA = JSON.parse(
      (await raw("GET", "/_agentsafe/status", "a.gateway.example")).body,
    ) as { mode: string };
    const statusB = JSON.parse(
      (await raw("GET", "/_agentsafe/status", "b.gateway.example")).body,
    ) as { mode: string };
    expect(statusA.mode).toBe("ENFORCEMENT");
    expect(statusB.mode).toBe("SHADOW");
    const unknown = await raw("GET", "/_agentsafe/healthz", "c.gateway.example");
    expect(unknown.status).toBe(421);
    expect(JSON.parse(unknown.body)).toEqual({ code: "HOST_NOT_SERVED" });
    const bracketed = await raw("GET", "/_agentsafe/healthz", "[::1]:8080");
    expect(bracketed.status).toBe(421);
    const none = await raw("GET", "/_agentsafe/healthz", "");
    expect(none.status).toBe(421);
  });
});
