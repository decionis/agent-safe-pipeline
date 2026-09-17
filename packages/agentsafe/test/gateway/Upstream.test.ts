import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import { Upstream, UpstreamResponseTooLarge } from "../../src/gateway/Upstream.js";
import { closedPort } from "../support/Environment.js";
import { UpstreamDouble, LOOPBACK_ORIGIN } from "../support/GatewayHarness.js";

const request = (overrides: Partial<InterceptedRequest> = {}): InterceptedRequest => ({
  method: "POST",
  path: "/payments",
  search: "?a=1",
  headers: {
    host: "gateway.example",
    "content-type": "application/json",
    authorization: "Bearer synthetic",
    connection: "keep-alive, x-trace",
    "x-trace": "t",
    "transfer-encoding": "chunked",
    "content-length": "9",
    "accept-encoding": "gzip",
    "x-forwarded-for": "10.0.0.9",
    "x-forwarded-proto": "spoofed",
  },
  body: Buffer.from('{"a": 1}', "utf8"),
  remoteAddress: "192.0.2.1",
  encrypted: true,
  ...overrides,
});

describe("the upstream client", () => {
  const double = new UpstreamDouble();
  let upstream: Upstream;
  beforeAll(async () => {
    await double.start();
    upstream = new Upstream({
      url: `${double.baseUrl}/base/`,
      timeoutMs: 2_000,
      maxResponseBytes: 1024 * 1024,
      fetch,
    });
  });
  afterAll(() => double.stop());

  it("builds the target under the configured base path", () => {
    expect(upstream.target("/payments", "?x=1")).toBe(`${double.baseUrl}/base/payments?x=1`);
    expect(upstream.url).toBe(`${double.baseUrl}/base/`);
    expect(upstream.timeoutMs).toBe(2_000);
  });

  it("drops hop-by-hop and gateway-owned headers, appends the forwarding chain, and adds what it is given", () => {
    const headers = upstream.headersFor(request(), { "X-Agent-Safe-Dossier-Id": "dss" });
    expect(headers).toEqual({
      "content-type": "application/json",
      authorization: "Bearer synthetic",
      "x-forwarded-for": "10.0.0.9, 192.0.2.1",
      "x-forwarded-proto": "https",
      "x-forwarded-host": "gateway.example",
      "accept-encoding": "identity",
      "x-agent-safe-dossier-id": "dss",
    });
    const bare = upstream.headersFor(
      request({ headers: {}, remoteAddress: null, encrypted: false }),
    );
    expect(bare).toEqual({ "x-forwarded-proto": "http", "accept-encoding": "identity" });
  });

  it("sends the bytes verbatim and relays status, headers and cookies, never following a redirect", async () => {
    const result = await upstream.send(
      "POST",
      "/payments",
      "?a=1",
      upstream.headersFor(request()),
      Buffer.from('{"a": 1}'),
      upstream.signal(),
    );
    expect(result.status).toBe(201);
    expect(double.seen.at(-1)).toMatchObject({
      method: "POST",
      url: "/base/payments?a=1",
      body: '{"a": 1}',
    });
    const names = result.headers.map(([name]) => name);
    expect(names).toContain("x-upstream");
    expect(names.filter((name) => name === "set-cookie")).toHaveLength(2);
    expect(names).not.toContain("connection");
    expect(names).not.toContain("content-length");
    const redirect = await upstream.send(
      "POST",
      "/redirect",
      "",
      {},
      Buffer.alloc(0),
      upstream.signal(),
    );
    expect(redirect.status).toBe(302);
    expect(Object.fromEntries(redirect.headers)["location"]).toBe("/elsewhere");
    const read = await upstream.send(
      "GET",
      "/health",
      "",
      {},
      Buffer.from("ignored"),
      upstream.signal(),
    );
    expect(read.status).toBe(200);
    expect(double.seen.at(-1)?.body).toBe("");
  });

  it("refuses a response longer than the relay allows, and reports a dead upstream as a transport failure", async () => {
    const small = new Upstream({
      url: double.baseUrl,
      timeoutMs: 2_000,
      maxResponseBytes: 1024,
      fetch,
    });
    await expect(
      small.send("GET", "/big", "", {}, Buffer.alloc(0), small.signal()),
    ).rejects.toBeInstanceOf(UpstreamResponseTooLarge);
    const dead = new Upstream({
      url: `${LOOPBACK_ORIGIN}:${await closedPort()}`,
      timeoutMs: 500,
      maxResponseBytes: 1024,
      fetch,
    });
    await expect(dead.send("POST", "/x", "", {}, Buffer.alloc(0), dead.signal())).rejects.toThrow();
    expect(small.signal(50)).toBeInstanceOf(AbortSignal);
    expect(small.signal(0)).toBeInstanceOf(AbortSignal);
  });
});
