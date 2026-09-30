import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import { hostOnlyCookie, Upstream, UpstreamResponseTooLarge } from "../../src/gateway/Upstream.js";
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
    const spoofed = upstream.headersFor(
      request({
        headers: { "x-agent-safe-dossier-id": "forged", "x-agent-safe-intent-hash": "forged" },
      }),
      { "x-agent-safe-dossier-id": "real" },
    );
    expect(spoofed["x-agent-safe-dossier-id"]).toBe("real");
    expect(spoofed["x-agent-safe-intent-hash"]).toBeUndefined();
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

describe("host-only cookies, for a hosted gateway", () => {
  it("drops the Domain attribute and nothing else", () => {
    expect(hostOnlyCookie("sid=1; Domain=gw.example; Path=/; Secure; HttpOnly")).toBe(
      "sid=1; Path=/; Secure; HttpOnly",
    );
    expect(hostOnlyCookie("sid=1;DOMAIN=.gw.example;Path=/")).toBe("sid=1;Path=/");
    expect(hostOnlyCookie("sid=1; domain = gw.example")).toBe("sid=1");
    expect(hostOnlyCookie("sid=1; Domain")).toBe("sid=1");
    expect(hostOnlyCookie("sid=1; Domainish=1; Path=/")).toBe("sid=1; Domainish=1; Path=/");
    // The name and value are never read as attributes, whatever they contain.
    expect(hostOnlyCookie("Domain=gw.example; Path=/")).toBe("Domain=gw.example; Path=/");
    expect(hostOnlyCookie("note=domain=x; Path=/")).toBe("note=domain=x; Path=/");
    expect(hostOnlyCookie("a=b")).toBe("a=b");
  });

  it("is applied to every relayed cookie only when asked", async () => {
    const answer = (): Response => {
      const headers = new Headers();
      headers.append("set-cookie", "a=1; Domain=gw.example; Path=/");
      headers.append("set-cookie", "b=2; Path=/");
      return new Response("ok", { status: 200, headers });
    };
    const cookies = async (hostOnlyCookies: boolean | undefined): Promise<string[]> => {
      const upstream = new Upstream({
        url: "https://shop.tenant.example",
        timeoutMs: 1_000,
        maxResponseBytes: 1_024,
        fetch: async () => answer(),
        ...(hostOnlyCookies === undefined ? {} : { hostOnlyCookies }),
      });
      const result = await upstream.send("GET", "/", "", {}, Buffer.alloc(0), upstream.signal());
      return result.headers.filter(([name]) => name === "set-cookie").map(([, value]) => value);
    };
    expect(await cookies(true)).toEqual(["a=1; Path=/", "b=2; Path=/"]);
    expect(await cookies(false)).toEqual(["a=1; Domain=gw.example; Path=/", "b=2; Path=/"]);
    expect(await cookies(undefined)).toEqual(["a=1; Domain=gw.example; Path=/", "b=2; Path=/"]);
  });
});
