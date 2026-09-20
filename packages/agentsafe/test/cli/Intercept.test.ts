import { once } from "node:events";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { connect, type AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  describe as describeEvent,
  INTERCEPT_ENVIRONMENT,
  resolveInterceptor,
  runIntercept,
} from "../../src/cli/Intercept.js";
import { INTERCEPT_DEFAULTS } from "../../src/http/InterceptServer.js";
import { closedPort } from "../support/Environment.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 50));
const port = (server: HttpServer): number => (server.address() as AddressInfo).port;

describe("resolveInterceptor", () => {
  it("takes the flags over the environment over the defaults, and names what it refuses", () => {
    expect(resolveInterceptor([], {})).toEqual({
      bind: "127.0.0.1",
      listeners: [
        { port: INTERCEPT_DEFAULTS.httpPort, destinationPort: 80 },
        { port: INTERCEPT_DEFAULTS.httpsPort, destinationPort: 443 },
      ],
      peekTimeoutMs: INTERCEPT_DEFAULTS.peekTimeoutMs,
      connectTimeoutMs: INTERCEPT_DEFAULTS.connectTimeoutMs,
      idleTimeoutMs: INTERCEPT_DEFAULTS.idleTimeoutMs,
      maxConnections: INTERCEPT_DEFAULTS.maxConnections,
    });
    const env = {
      [INTERCEPT_ENVIRONMENT.httpPort]: "16001",
      [INTERCEPT_ENVIRONMENT.httpsPort]: "16002",
      [INTERCEPT_ENVIRONMENT.bind]: "::1",
    };
    expect(resolveInterceptor([], env)).toMatchObject({
      bind: "::1",
      listeners: [
        { port: 16_001, destinationPort: 80 },
        { port: 16_002, destinationPort: 443 },
      ],
    });
    expect(resolveInterceptor(["--http-port", "17001", "--bind=127.0.0.2"], env)).toMatchObject({
      bind: "127.0.0.2",
      listeners: [
        { port: 17_001, destinationPort: 80 },
        { port: 16_002, destinationPort: 443 },
      ],
    });
    expect(() => resolveInterceptor([], { [INTERCEPT_ENVIRONMENT.httpPort]: "eighty" })).toThrow(
      `CONFIG_INVALID: ${INTERCEPT_ENVIRONMENT.httpPort}`,
    );
    expect(() => resolveInterceptor([], { [INTERCEPT_ENVIRONMENT.httpsPort]: "70000" })).toThrow(
      `CONFIG_INVALID: ${INTERCEPT_ENVIRONMENT.httpsPort}`,
    );
    expect(() => resolveInterceptor(["--http-port", "15002"], {})).toThrow(
      "CONFIG_INVALID: https-port",
    );
    expect(() => resolveInterceptor(["--bind", "not an address"], {})).toThrow(
      "CONFIG_INVALID: bind",
    );
    expect(() => resolveInterceptor(["--https-port", "0"], {})).toThrow(
      "VALUE_INVALID: https-port",
    );
    expect(() => resolveInterceptor(["--verbose"], {})).toThrow("UNKNOWN_OPTION: verbose");
  });
});

describe("describe", () => {
  it("says each event in one line, and the report in a few", () => {
    const at = "2026-09-20T12:00:00.000Z";
    expect(
      describeEvent(
        {
          event: "INTERCEPT_STARTED",
          at,
          listeners: [
            { listen: "127.0.0.1:15001", for_port: 80 },
            { listen: "127.0.0.1:15002", for_port: 443 },
          ],
        },
        "0.2.0",
      ),
    ).toBe(
      "AgentSafe intercept 0.2.0 listening on 127.0.0.1:15001 (for :80) and 127.0.0.1:15002 (for :443). Observing; nothing is decrypted or decided.",
    );
    expect(
      describeEvent(
        {
          event: "INTERCEPT_OBSERVED",
          at,
          protocol: "HTTP",
          host: "a.example",
          port: 80,
          method: "POST",
          target: "/x",
        },
        "0.2.0",
      ),
    ).toBe("-> HTTP POST a.example:80 /x");
    expect(
      describeEvent(
        {
          event: "INTERCEPT_OBSERVED",
          at,
          protocol: "TLS",
          host: "b.example",
          port: 443,
          alpn: ["h2", "http/1.1"],
        },
        "0.2.0",
      ),
    ).toBe("-> TLS b.example:443 (h2, http/1.1)");
    expect(
      describeEvent(
        { event: "INTERCEPT_OBSERVED", at, protocol: "TLS", host: "b.example", port: 443 },
        "0.2.0",
      ),
    ).toBe("-> TLS b.example:443");
    expect(
      describeEvent(
        { event: "INTERCEPT_REFUSED", at, reason: "DESTINATION_UNKNOWN", protocol: null },
        "0.2.0",
      ),
    ).toBe("x  refused: DESTINATION_UNKNOWN");
    expect(
      describeEvent(
        {
          event: "INTERCEPT_REFUSED",
          at,
          reason: "UPSTREAM_UNREACHABLE",
          protocol: "HTTP",
          host: "a.example",
          port: 80,
          detail: "ECONNREFUSED",
        },
        "0.2.0",
      ),
    ).toBe("x  refused a.example:80: UPSTREAM_UNREACHABLE (ECONNREFUSED)");
    const report = describeEvent(
      {
        event: "INTERCEPT_REPORT",
        at,
        intercept: {
          since: at,
          until: at,
          connections: 3,
          placed: 2,
          refused: { DESTINATION_UNKNOWN: 1 },
          destinations: {
            "a.example:80": {
              protocol: "HTTP",
              connections: 1,
              bytes_to_destination: 120,
              bytes_from_destination: 300,
              methods: { POST: 1 },
            },
            "b.example:443": {
              protocol: "TLS",
              connections: 1,
              bytes_to_destination: 1_000,
              bytes_from_destination: 5_000,
              methods: {},
            },
          },
        },
        next: "Next.",
      },
      "0.2.0",
    ).split("\n");
    expect(report).toEqual([
      `Intercept report: 3 connection(s), 2 placed, 1 refused, ${at} to ${at}.`,
      "  a.example:80  HTTP  1 connection(s), 120 B out, 300 B in  POST x1",
      "  b.example:443  TLS  1 connection(s), 1000 B out, 5000 B in",
      "  refused DESTINATION_UNKNOWN x1",
      "Next.",
    ]);
    expect(
      describeEvent(
        {
          event: "INTERCEPT_REPORT",
          at,
          intercept: {
            since: null,
            until: null,
            connections: 0,
            placed: 0,
            refused: {},
            destinations: {},
          },
          next: "Next.",
        },
        "0.2.0",
      ),
    ).toBe("Intercept report: 0 connection(s), 0 placed, 0 refused.\nNext.");
    expect(describeEvent({ event: "INTERCEPT_STOPPED", at, signal: "SIGTERM" }, "0.2.0")).toBe(
      "Stopped on SIGTERM.",
    );
  });
});

describe("runIntercept", () => {
  const servers: HttpServer[] = [];
  afterEach(async () => {
    for (const server of servers.splice(0))
      await new Promise((resolve) => server.close(() => resolve(undefined)));
  });

  it("starts, observes a redirected request as JSON lines, and reports on a signal", async () => {
    // A constant answer: what was asked is asserted on the interceptor's own
    // observation, which is the point.
    const upstream = createHttpServer((_request, response) => response.end("seen"));
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    servers.push(upstream);
    const httpPort = await closedPort();
    const httpsPort = await closedPort();
    const io = fakeProcess({ env: { NODE_ENV: "production" } });
    await runIntercept(io, ["--http-port", String(httpPort), "--https-port", String(httpsPort)]);
    expect(io.exits).toEqual([]);
    const started = JSON.parse(io.out[0] ?? "{}") as { event: string; listeners: unknown[] };
    expect(started.event).toBe("INTERCEPT_STARTED");
    expect(started.listeners).toEqual([
      { listen: `127.0.0.1:${httpPort}`, for_port: 80 },
      { listen: `127.0.0.1:${httpsPort}`, for_port: 443 },
    ]);

    const client = connect({ host: "127.0.0.1", port: httpPort });
    await once(client, "connect");
    client.write(
      `POST /orders HTTP/1.1\r\nHost: 127.0.0.1:${port(upstream)}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
    );
    const answer = await new Promise<string>((resolve) => {
      let text = "";
      client.on("data", (chunk: Buffer) => (text += chunk.toString()));
      client.once("close", () => resolve(text));
    });
    expect(answer).toMatch(/^HTTP\/1\.1 200 OK/);
    expect(answer).toContain("seen");
    await settle();
    const observed = io.out
      .map((line) => JSON.parse(line) as { event: string })
      .find((e) => e.event === "INTERCEPT_OBSERVED");
    expect(observed).toMatchObject({
      protocol: "HTTP",
      host: "127.0.0.1",
      port: port(upstream),
      method: "POST",
      target: "/orders",
    });

    expect([...io.signals.keys()]).toEqual(["SIGTERM", "SIGINT"]);
    io.signals.get("SIGTERM")?.();
    io.signals.get("SIGINT")?.();
    for (let attempt = 0; attempt < 40 && io.exits.length === 0; attempt += 1) await settle();
    expect(io.exits).toEqual([0]);
    const events = io.out.map((line) => (JSON.parse(line) as { event: string }).event);
    expect(events.slice(-2)).toEqual(["INTERCEPT_REPORT", "INTERCEPT_STOPPED"]);
    const report = JSON.parse(io.out.at(-2) ?? "{}") as {
      intercept: { placed: number; destinations: Record<string, unknown> };
    };
    expect(report.intercept.placed).toBe(1);
    expect(Object.keys(report.intercept.destinations)).toEqual([`127.0.0.1:${port(upstream)}`]);
    await expect(
      new Promise((resolve, reject) => {
        const late = connect({ host: "127.0.0.1", port: httpPort });
        late.once("connect", () => resolve("connected"));
        late.once("error", reject);
      }),
    ).rejects.toMatchObject({ code: "ECONNREFUSED" });
  });

  it("speaks to a terminal in lines, and refuses bad arguments and a taken port by name", async () => {
    const httpPort = await closedPort();
    const httpsPort = await closedPort();
    const io = fakeProcess();
    await runIntercept(io, ["--http-port", String(httpPort), "--https-port", String(httpsPort)]);
    expect(io.out[0]).toContain(`AgentSafe intercept`);
    expect(io.out[0]).toContain(`127.0.0.1:${httpPort} (for :80)`);
    io.signals.get("SIGTERM")?.();
    for (let attempt = 0; attempt < 40 && io.exits.length === 0; attempt += 1) await settle();
    expect(io.exits).toEqual([0]);
    expect(io.out.at(-2)).toContain("Intercept report: 0 connection(s)");
    expect(io.out.at(-1)).toBe("Stopped on SIGTERM.\n");

    const argument = fakeProcess();
    await runIntercept(argument, ["--http-port", "0"]);
    expect(argument.exits).toEqual([2]);
    expect(argument.err.join("")).toContain("VALUE_INVALID: http-port");
    const production = fakeProcess({
      env: { NODE_ENV: "production", [INTERCEPT_ENVIRONMENT.bind]: "bad host" },
    });
    await runIntercept(production, []);
    expect(production.exits).toEqual([2]);
    expect(JSON.parse(production.err.join(""))).toEqual({
      event: "REFUSED_TO_START",
      reason: "CONFIG_INVALID: bind",
    });
    const unknown = fakeProcess();
    await runIntercept(unknown, ["--json", "--http-port"]);
    expect(unknown.exits).toEqual([2]);
    expect(JSON.parse(unknown.err.join(""))).toEqual({
      event: "REFUSED_TO_START",
      reason: "VALUE_REQUIRED: http-port",
    });

    const holder = createHttpServer();
    holder.listen(0, "127.0.0.1");
    await once(holder, "listening");
    servers.push(holder);
    const taken = fakeProcess();
    await runIntercept(taken, [
      "--http-port",
      String(port(holder)),
      "--https-port",
      String(await closedPort()),
    ]);
    expect(taken.exits).toEqual([1]);
    expect(taken.err.join("")).toContain("EADDRINUSE");
    expect(taken.err.join("")).toContain("--http-port and --https-port");
    const takenJson = fakeProcess({ env: { NODE_ENV: "production" } });
    await runIntercept(takenJson, [
      "--http-port",
      String(port(holder)),
      "--https-port",
      String(await closedPort()),
    ]);
    expect(takenJson.exits).toEqual([1]);
    expect(JSON.parse(takenJson.err.join("")).reason).toMatch(/^EADDRINUSE: 127\.0\.0\.1:/);
  });
});
