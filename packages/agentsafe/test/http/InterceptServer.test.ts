import { once } from "node:events";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { connect, createServer, type AddressInfo, type Socket } from "node:net";
import {
  connect as tlsConnect,
  createServer as createTlsServer,
  type Server as TlsServer,
} from "node:tls";
import { afterEach, describe, expect, it } from "vitest";
import { transparentDial, type Dial } from "../../src/egress/TransparentDial.js";
import {
  INTERCEPT_DEFAULTS,
  INTERCEPT_REPORT_INTERVAL_MS,
  INTERCEPT_REPORT_MILESTONES,
  Interceptor,
  type InterceptEvent,
  type InterceptorOptions,
} from "../../src/http/InterceptServer.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";

const settle = (ms = 30): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const port = (server: { address(): AddressInfo | string | null }): number =>
  (server.address() as AddressInfo).port;

function options(overrides: Partial<InterceptorOptions> = {}): InterceptorOptions {
  return {
    bind: "127.0.0.1",
    listeners: [{ port: 0, destinationPort: 80 }],
    peekTimeoutMs: INTERCEPT_DEFAULTS.peekTimeoutMs,
    connectTimeoutMs: INTERCEPT_DEFAULTS.connectTimeoutMs,
    idleTimeoutMs: INTERCEPT_DEFAULTS.idleTimeoutMs,
    maxConnections: INTERCEPT_DEFAULTS.maxConnections,
    ...overrides,
  };
}

/** A fixed clock, so the events' times are the test's. */
const at = "2026-09-20T12:00:00.000Z";
const now = (): Date => new Date(at);

/** Reads everything a socket sends until it ends. */
function drain(socket: Socket): Promise<string> {
  return new Promise((resolve) => {
    let text = "";
    socket.on("data", (chunk: Buffer) => (text += chunk.toString("latin1")));
    socket.once("close", () => resolve(text));
  });
}

describe("Interceptor", () => {
  const open: { close(): unknown }[] = [];
  afterEach(async () => {
    for (const closable of open.splice(0)) await closable.close();
  });

  async function echoHttp(): Promise<HttpServer> {
    const server = createHttpServer((request, response) => {
      let body = "";
      request.on("data", (chunk: Buffer) => (body += chunk.toString()));
      request.on("end", () => {
        response.setHeader("content-type", "application/json");
        response.end(
          JSON.stringify({
            method: request.method,
            url: request.url,
            host: request.headers.host,
            body,
          }),
        );
      });
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    open.push({ close: () => new Promise((resolve) => server.close(() => resolve(undefined))) });
    return server;
  }

  async function start(
    interceptorOptions: InterceptorOptions,
    dial?: Dial,
  ): Promise<{ interceptor: Interceptor; events: InterceptEvent[]; port: number }> {
    const events: InterceptEvent[] = [];
    const interceptor = new Interceptor(interceptorOptions, {
      emit: (event) => events.push(event),
      now,
      ...(dial === undefined ? {} : { dial }),
    });
    const bound = await interceptor.listen();
    open.push(interceptor);
    return { interceptor, events, port: bound[0]?.port ?? 0 };
  }

  it("places a plaintext request by its host header and splices the answer back", async () => {
    const upstream = await echoHttp();
    const {
      interceptor,
      events,
      port: listen,
    } = await start(options({ listeners: [{ port: 0, destinationPort: port(upstream) }] }));
    expect(events).toEqual([
      {
        event: "INTERCEPT_STARTED",
        at,
        listeners: [{ listen: `127.0.0.1:${listen}`, for_port: port(upstream) }],
      },
    ]);
    const client = connect({ host: "127.0.0.1", port: listen });
    await once(client, "connect");
    const body = '{"amount":500}';
    client.write(
      `POST /payments HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`,
    );
    const answer = await drain(client);
    expect(answer).toMatch(/^HTTP\/1\.1 200 OK/);
    expect(answer).toContain(
      `{"method":"POST","url":"/payments","host":"127.0.0.1","body":${JSON.stringify(body)}}`,
    );
    expect(events[1]).toEqual({
      event: "INTERCEPT_OBSERVED",
      at,
      protocol: "HTTP",
      host: "127.0.0.1",
      port: port(upstream),
      governed: false,
      method: "POST",
      target: "/payments",
    });
    await settle();
    const report = interceptor.report();
    expect(report.intercept.connections).toBe(1);
    expect(report.intercept.placed).toBe(1);
    const counts = report.intercept.destinations[`127.0.0.1:${port(upstream)}`];
    expect(counts?.methods).toEqual({ POST: 1 });
    expect(counts?.governed).toBe(false);
    if (counts?.governed !== false) throw new Error("spliced");
    expect(counts.bytes_to_destination).toBeGreaterThan(100);
    expect(counts.bytes_from_destination).toBeGreaterThan(100);
  });

  it("takes the port the host header names over the listener's", async () => {
    const upstream = await echoHttp();
    const { events, port: listen } = await start(options());
    const client = connect({ host: "127.0.0.1", port: listen });
    await once(client, "connect");
    client.write(
      `GET /x HTTP/1.1\r\nHost: 127.0.0.1:${port(upstream)}\r\nConnection: close\r\n\r\n`,
    );
    const answer = await drain(client);
    expect(answer).toContain(`"host":"127.0.0.1:${port(upstream)}"`);
    expect(events[1]).toMatchObject({
      event: "INTERCEPT_OBSERVED",
      protocol: "HTTP",
      port: port(upstream),
    });
  });

  it("splices TLS by its server name without touching the handshake", async () => {
    const ca = new TestCertificateAuthority();
    const issued = ca.issueServer(["upstream.example"], []);
    const upstream: TlsServer = createTlsServer(
      { cert: issued.cert, key: issued.key },
      (socket) => {
        socket.on("data", (chunk: Buffer) => socket.end(`echo:${chunk.toString()}`));
      },
    );
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    open.push({ close: () => new Promise((resolve) => upstream.close(() => resolve(undefined))) });
    const dialled: string[] = [];
    const dial: Dial = (host, destinationPort, timeoutMs) => {
      dialled.push(`${host}:${destinationPort}`);
      return transparentDial("127.0.0.1", port(upstream), timeoutMs);
    };
    const { events, port: listen } = await start(
      options({ listeners: [{ port: 0, destinationPort: 443 }] }),
      dial,
    );
    const client = tlsConnect({
      host: "127.0.0.1",
      port: listen,
      servername: "upstream.example",
      ca: [ca.certificate],
      ALPNProtocols: ["http/1.1"],
    });
    await once(client, "secureConnect");
    expect(client.authorized).toBe(true);
    client.write("hello");
    const answer = await new Promise<string>((resolve) => {
      let text = "";
      client.on("data", (chunk: Buffer) => (text += chunk.toString()));
      client.once("end", () => resolve(text));
    });
    expect(answer).toBe("echo:hello");
    expect(dialled).toEqual(["upstream.example:443"]);
    expect(events[1]).toEqual({
      event: "INTERCEPT_OBSERVED",
      at,
      protocol: "TLS",
      host: "upstream.example",
      port: 443,
      governed: false,
      alpn: ["http/1.1"],
    });
  });

  it("prints its report on its own cadence: at each milestone of connections, and daily", async () => {
    const upstream = await echoHttp();
    const events: InterceptEvent[] = [];
    let clock = Date.UTC(2026, 8, 20, 9, 0, 0);
    const interceptor = new Interceptor(
      options({ listeners: [{ port: 0, destinationPort: port(upstream) }] }),
      {
        emit: (event) => events.push(event),
        now: () => new Date(clock),
        governedCounts: (host, protocol) =>
          host === "127.0.0.1" && protocol === "HTTP"
            ? { mode: "SHADOW", requests: { governed: 1 } }
            : null,
      },
    );
    const [bound] = await interceptor.listen();
    open.push(interceptor);
    const listen = bound?.port ?? 0;
    const reports = (): InterceptEvent[] =>
      events.filter((event) => event.event === "INTERCEPT_REPORT");
    const connection = async (): Promise<void> => {
      const client = connect({ host: "127.0.0.1", port: listen });
      await once(client, "connect");
      client.write("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
      await drain(client);
    };
    expect(INTERCEPT_REPORT_MILESTONES[0]).toBe(10);
    // Nine connections, no report; the tenth carries one, after its own line.
    for (let index = 0; index < 9; index += 1) await connection();
    await settle();
    expect(reports()).toEqual([]);
    await connection();
    await settle();
    expect(reports()).toHaveLength(1);
    const first = reports()[0];
    expect(first).toMatchObject({
      event: "INTERCEPT_REPORT",
      at: new Date(clock).toISOString(),
      intercept: { connections: 10 },
    });
    const observedBefore = events.findIndex((event) => event.event === "INTERCEPT_REPORT") - 1;
    expect(events[observedBefore]).toMatchObject({ event: "INTERCEPT_OBSERVED" });
    // A refused connection counts toward the cadence too; the eleventh and
    // twelfth are no milestone, and a day has not passed.
    const opaque = connect({ host: "127.0.0.1", port: listen });
    await once(opaque, "connect");
    opaque.write("SSH-2.0-OpenSSH_9.9\r\n\r\n");
    await once(opaque, "close");
    await connection();
    await settle();
    expect(reports()).toHaveLength(1);
    // A day on, the next connection carries a report, and the one after does not.
    clock += INTERCEPT_REPORT_INTERVAL_MS;
    await connection();
    await settle();
    expect(reports()).toHaveLength(2);
    // The report is of the moment the connection was counted: the one that
    // carried it is not yet placed.
    expect(reports()[1]).toMatchObject({
      intercept: { connections: 13, placed: 11, refused: { DESTINATION_UNKNOWN: 1 } },
    });
    await connection();
    await settle();
    expect(reports()).toHaveLength(2);
    // The report an operator asks for is the same one, and it asks the
    // gateways for their account of what they were handed.
    const asked = interceptor.report();
    expect(asked.intercept.connections).toBe(14);
    expect(asked.intercept.destinations[`127.0.0.1:${port(upstream)}`]).toMatchObject({
      governed: false,
    });
  });

  it("refuses what names no destination, and says why", async () => {
    const { interceptor, events, port: listen } = await start(options({ peekTimeoutMs: 200 }));
    const opaque = connect({ host: "127.0.0.1", port: listen });
    await once(opaque, "connect");
    opaque.write("SSH-2.0-OpenSSH_9.9\r\n\r\n");
    await once(opaque, "close");
    const noHost = connect({ host: "127.0.0.1", port: listen });
    await once(noHost, "connect");
    noHost.write("GET / HTTP/1.1\r\n\r\n");
    await once(noHost, "close");
    const silent = connect({ host: "127.0.0.1", port: listen });
    await once(silent, "connect");
    await once(silent, "close");
    const quitter = connect({ host: "127.0.0.1", port: listen });
    await once(quitter, "connect");
    quitter.end();
    await once(quitter, "close");
    // Refused before any handshake, so no certificate is checked; the client
    // still trusts only a test authority.
    const noSni = tlsConnect({
      host: "127.0.0.1",
      port: listen,
      ca: [new TestCertificateAuthority().certificate],
    });
    noSni.on("error", () => undefined);
    await new Promise((resolve) => noSni.once("close", resolve));
    const refusals = events.filter((event) => event.event === "INTERCEPT_REFUSED");
    expect(
      refusals.map((event) =>
        event.event === "INTERCEPT_REFUSED" ? [event.reason, event.protocol, event.detail] : [],
      ),
    ).toEqual([
      ["DESTINATION_UNKNOWN", null, undefined],
      ["MALFORMED", "HTTP", "HOST_MISSING"],
      ["PEEK_TIMEOUT", null, undefined],
      ["DESTINATION_UNKNOWN", null, undefined],
      ["DESTINATION_UNKNOWN", "TLS", undefined],
    ]);
    const summary = interceptor.report().intercept;
    expect(summary.connections).toBe(5);
    expect(summary.placed).toBe(0);
    expect(summary.refused).toEqual({ DESTINATION_UNKNOWN: 3, MALFORMED: 1, PEEK_TIMEOUT: 1 });
  });

  it("refuses an unreachable destination and a loop back into itself", async () => {
    const dial: Dial = () =>
      Promise.reject(Object.assign(new Error("ECONNREFUSED"), { code: "ECONNREFUSED" }));
    const { interceptor, events, port: listen } = await start(options(), dial);
    const client = connect({ host: "127.0.0.1", port: listen });
    await once(client, "connect");
    client.write("GET / HTTP/1.1\r\nHost: nowhere.example\r\n\r\n");
    await once(client, "close");
    const loop = connect({ host: "127.0.0.1", port: listen });
    await once(loop, "connect");
    loop.write(`GET / HTTP/1.1\r\nHost: localhost:${listen}\r\n\r\n`);
    await once(loop, "close");
    expect(events.slice(1)).toEqual([
      {
        event: "INTERCEPT_OBSERVED",
        at,
        protocol: "HTTP",
        host: "nowhere.example",
        port: 80,
        governed: false,
        method: "GET",
        target: "/",
      },
      {
        event: "INTERCEPT_REFUSED",
        at,
        reason: "UPSTREAM_UNREACHABLE",
        protocol: "HTTP",
        host: "nowhere.example",
        port: 80,
        detail: "ECONNREFUSED",
      },
      {
        event: "INTERCEPT_REFUSED",
        at,
        reason: "HOST_IS_INTERCEPTOR",
        protocol: "HTTP",
        host: "localhost",
        port: listen,
      },
    ]);
    const summary = interceptor.report().intercept;
    expect(summary.connections).toBe(2);
    expect(summary.placed).toBe(0);
    expect(summary.refused).toEqual({ HOST_IS_INTERCEPTOR: 1, UPSTREAM_UNREACHABLE: 1 });
    expect(summary.destinations["nowhere.example:80"]?.connections).toBe(1);
  });

  it("holds only as many connections as it will, and drops the rest before reading them", async () => {
    const { events, port: listen } = await start(
      options({ maxConnections: 1, peekTimeoutMs: 400 }),
    );
    const first = connect({ host: "127.0.0.1", port: listen });
    await once(first, "connect");
    await settle();
    const second = connect({ host: "127.0.0.1", port: listen });
    await once(second, "connect");
    await once(second, "close");
    expect(events.at(-1)).toEqual({
      event: "INTERCEPT_REFUSED",
      at,
      reason: "TOO_MANY_CONNECTIONS",
      protocol: null,
    });
    first.destroy();
  });

  it("ends the destination when the client half-closes, and closes both on idle", async () => {
    const seen: string[] = [];
    const sink = createServer((socket) => {
      socket.on("data", (chunk: Buffer) => seen.push(chunk.toString()));
      socket.on("end", () => {
        seen.push("<end>");
        socket.end();
      });
    });
    sink.listen(0, "127.0.0.1");
    await once(sink, "listening");
    open.push({ close: () => new Promise((resolve) => sink.close(() => resolve(undefined))) });
    const { port: listen } = await start(
      options({ listeners: [{ port: 0, destinationPort: port(sink) }], idleTimeoutMs: 150 }),
    );
    const client = connect({ host: "127.0.0.1", port: listen });
    await once(client, "connect");
    client.end("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    await once(client, "close");
    expect(seen).toEqual(["GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "<end>"]);

    const idle = connect({ host: "127.0.0.1", port: listen });
    await once(idle, "connect");
    idle.write("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    const closed = Date.now();
    await once(idle, "close");
    expect(Date.now() - closed).toBeGreaterThanOrEqual(100);
  });

  it("closes what it bound when a later listener cannot bind, and drops connections on close", async () => {
    const taken = createServer();
    taken.listen(0, "127.0.0.1");
    await once(taken, "listening");
    open.push({ close: () => new Promise((resolve) => taken.close(() => resolve(undefined))) });
    const events: InterceptEvent[] = [];
    const interceptor = new Interceptor(
      options({
        listeners: [
          { port: 0, destinationPort: 80 },
          { port: port(taken), destinationPort: 443 },
        ],
      }),
      { emit: (event) => events.push(event), now },
    );
    await expect(interceptor.listen()).rejects.toMatchObject({ code: "EADDRINUSE" });
    expect(interceptor.listeners()).toEqual([]);
    expect(events).toEqual([]);

    const upstream = await echoHttp();
    const { interceptor: running, port: listen } = await start(
      options({ listeners: [{ port: 0, destinationPort: port(upstream) }] }),
    );
    const client = connect({ host: "127.0.0.1", port: listen });
    await once(client, "connect");
    client.resume();
    client.write("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    await settle();
    const dropped = once(client, "close");
    await running.close();
    await dropped;
    await expect(
      new Promise((resolve, reject) => {
        const late = connect({ host: "127.0.0.1", port: listen });
        late.once("connect", () => resolve("connected"));
        late.once("error", reject);
      }),
    ).rejects.toMatchObject({ code: "ECONNREFUSED" });
  });
});
