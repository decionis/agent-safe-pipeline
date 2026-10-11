import { createHash } from "node:crypto";
import { once } from "node:events";
import { connect, createServer as netServer, type AddressInfo, type Socket } from "node:net";
import { createServer as tlsServer, type TLSSocket } from "node:tls";
import { setTimeout as settle } from "node:timers/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  parseTcpTarget,
  TCP_CLIENT_LIMITS,
  TcpConnector,
  TcpTunnel,
  verifiedTls,
  type TcpClientConfig,
  type TcpClientDependencies,
  type TcpClientEvent,
} from "../../src/egress/TcpClient.js";
import { readLine } from "../../src/tcp/TcpWire.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";

const ROUTE = "00000000-0000-4000-8000-000000000123";
const HOST = "tenant.decionisedge.example";
const GATEWAY_URL = "https://tenant.decionisedge.example";
const CREDENTIAL = "synthetic-connector-credential";
const TOKEN = "a".repeat(43);
const authority = new TestCertificateAuthority();
const cert = authority.issueServer([HOST]);
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  await Promise.all(
    cleanups
      .splice(0)
      .reverse()
      .map((close) => close()),
  );
});

async function until(check: () => boolean): Promise<void> {
  const end = Date.now() + 3000;
  while (!check() && Date.now() < end) await settle(5);
  expect(check()).toBe(true);
}

function config(target = "127.0.0.1:5432"): TcpClientConfig {
  return {
    controlApi: "https://control.example",
    gatewayUrl: GATEWAY_URL,
    routeId: ROUTE,
    target,
    credential: () => CREDENTIAL,
  };
}
function ticket(target: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const resource = parseTcpTarget(target).resource;
  return {
    ticket: TOKEN,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    route_id: ROUTE,
    tenant_host: HOST,
    gateway_url: GATEWAY_URL,
    resource,
    resource_hash: createHash("sha256").update(resource).digest("hex"),
    ...extra,
  };
}

async function headers(socket: Socket): Promise<{ text: string; tail: Buffer }> {
  let tail: Buffer = Buffer.alloc(0);
  const lines: string[] = [];
  for (;;) {
    const next = await readLine(socket, 16384, 1000, tail);
    tail = next.tail;
    if (next.line === "\r") return { text: lines.join("\n"), tail };
    lines.push(next.line);
  }
}

async function gateway(handler: (socket: TLSSocket, request: string) => Promise<void>): Promise<{
  dial: NonNullable<TcpClientDependencies["dialGateway"]>;
  port: number;
  requests: string[];
  errors: unknown[];
}> {
  const sockets = new Set<Socket>();
  const requests: string[] = [];
  const errors: unknown[] = [];
  const server = tlsServer(
    { ...cert, allowHalfOpen: true, ALPNProtocols: ["http/1.1"] },
    (socket) => {
      sockets.add(socket);
      socket.on("error", () => undefined);
      socket.on("close", () => sockets.delete(socket));
      void headers(socket)
        .then(async (request) => {
          requests.push(request.text);
          await handler(socket, request.text);
        })
        .catch((error: unknown) => errors.push(error));
    },
  );
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("error", () => undefined);
    socket.on("close", () => sockets.delete(socket));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = (server.address() as AddressInfo).port;
  cleanups.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return {
    port,
    requests,
    errors,
    dial: (hostname, signal) =>
      verifiedTls(hostname, signal, { address: "127.0.0.1", port, ca: authority.certificate }),
  };
}

describe("the outbound TCP connector and loopback tunnel", () => {
  it("opens only the locally fixed target after attach and preserves binary bytes and both half-closes", async () => {
    let accepted = 0;
    const sent = Buffer.from([0, 1, 255, 13, 10, 23]);
    const received: Buffer[] = [];
    const targetSockets = new Set<Socket>();
    const target = netServer({ allowHalfOpen: true }, (socket) => {
      accepted += 1;
      targetSockets.add(socket);
      socket.on("error", () => undefined);
      const chunks: Buffer[] = [];
      socket.on("data", (bytes: Buffer) => chunks.push(bytes));
      socket.on("end", () => {
        received.push(Buffer.concat(chunks));
        socket.end(Buffer.from("target-reply"));
      });
    });
    target.listen(0, "127.0.0.1");
    await once(target, "listening");
    const targetAddress = `127.0.0.1:${(target.address() as AddressInfo).port}`;
    cleanups.push(async () => {
      for (const socket of targetSockets) socket.destroy();
      await new Promise<void>((resolve) => target.close(() => resolve()));
    });
    let attached = false;
    let reply = "";
    const remote = await gateway(async (socket) => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (attached) return;
      attached = true;
      expect(accepted).toBe(0);
      socket.end(Buffer.concat([Buffer.from('{"type":"attach"}\n'), sent]));
      const ready = await readLine(socket, 1024, 1000);
      expect(ready.line).toBe('{"type":"ready"}');
      const chunks: Buffer[] = [ready.tail];
      socket.on("data", (bytes: Buffer) => chunks.push(bytes));
      socket.on("end", () => {
        reply = Buffer.concat(chunks).toString();
      });
      socket.resume();
    });
    const fetcher = vi.fn(async (_input: unknown, init?: RequestInit) => {
      expect(init?.redirect).toBe("error");
      expect(JSON.parse(String(init?.body))).toEqual({ route_id: ROUTE, role: "connector" });
      return Response.json(ticket(targetAddress));
    });
    const connector = new TcpConnector(config(targetAddress), {
      fetch: fetcher,
      dialGateway: remote.dial,
    });
    cleanups.push(() => connector.close());
    connector.start();
    await until(() => reply === "target-reply");
    expect(received).toEqual([sent]);
    expect(accepted).toBe(1);
    expect(remote.requests[0]).toContain(`CONNECT ${ROUTE}:443 HTTP/1.1`);
    expect(remote.requests[0]).toContain(`Host: ${HOST}`);
    expect(remote.requests[0]).toContain("AgentSafe-TCP-Role: connector");
    expect(remote.requests[0]).not.toContain(CREDENTIAL);
    expect(remote.errors).toEqual([]);
    expect(connector.snapshot().waiting).toBeLessThanOrEqual(2);
  });

  it("binds only loopback, holds local bytes until CONNECT succeeds, and preserves coalesced server data", async () => {
    let requestBody = "";
    const remote = await gateway(async (socket, request) => {
      expect(request).toContain("AgentSafe-TCP-Role: client");
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\nserver-first:");
      const chunks: Buffer[] = [];
      socket.on("data", (chunk: Buffer) => chunks.push(chunk));
      socket.on("end", () => {
        requestBody = Buffer.concat(chunks).toString();
        socket.end("server-last");
      });
      socket.resume();
    });
    const tunnel = new TcpTunnel(config(), {
      fetch: async () => Response.json(ticket(config().target)),
      dialGateway: remote.dial,
    });
    cleanups.push(() => tunnel.close());
    const address = await tunnel.listen(0);
    expect(address.address).toBe("127.0.0.1");
    const client = connect({ host: address.address, port: address.port, allowHalfOpen: true });
    client.on("error", () => undefined);
    cleanups.push(async () => {
      client.destroy();
    });
    const chunks: Buffer[] = [];
    client.on("data", (chunk: Buffer) => chunks.push(chunk));
    const ended = once(client, "end");
    client.end("local-first");
    await ended;
    expect(Buffer.concat(chunks).toString()).toBe("server-first:server-last");
    expect(requestBody).toBe("local-first");
    expect(remote.errors).toEqual([]);
  });

  it("rejects every ticket binding mismatch and never dials a gateway or local target", async () => {
    const dialGateway = vi.fn(async () => {
      throw new Error("must not dial");
    });
    const dialTarget = vi.fn(async () => {
      throw new Error("must not dial");
    });
    for (const mismatch of [
      { route_id: "00000000-0000-4000-8000-000000000124" },
      { tenant_host: "other.example" },
      { gateway_url: "https://other.example" },
      { resource: "127.0.0.1:5433" },
      { resource_hash: "f".repeat(64) },
      { ticket: `${TOKEN}\r\nInjected: yes` },
      { expires_at: new Date(0).toISOString() },
      { role: "client" },
    ]) {
      const events: TcpClientEvent[] = [];
      const connector = new TcpConnector(config(), {
        fetch: async () => Response.json(ticket(config().target, mismatch)),
        dialGateway,
        dialTarget,
        report: (event) => events.push(event),
      });
      connector.start();
      await until(() => events.some((event) => event.code === "TCP_TICKET_BINDING_MISMATCH"));
      await connector.close();
    }
    expect(dialGateway).not.toHaveBeenCalled();
    expect(dialTarget).not.toHaveBeenCalled();
  });

  it("caps waiting legs and retries with backoff, issuing a new ticket for each new leg", async () => {
    let issued = 0;
    const presented: string[] = [];
    const remote = await gateway(async (socket, request) => {
      presented.push(request.match(/Authorization: Bearer ([^\r\n]+)/)?.[1] ?? "");
      socket.end("HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n");
    });
    const connector = new TcpConnector(config(), {
      fetch: async () =>
        Response.json(ticket(config().target, { ticket: String(++issued).padStart(43, "a") })),
      dialGateway: remote.dial,
      reconnectMinMs: 10,
      reconnectMaxMs: 20,
    });
    cleanups.push(() => connector.close());
    connector.start();
    await until(() => presented.length >= 4);
    expect(new Set(presented).size).toBe(presented.length);
    expect(connector.snapshot().waiting).toBeLessThanOrEqual(TCP_CLIENT_LIMITS.spareLegs);
    await connector.close();
    const stopped = issued;
    await settle(40);
    expect(issued).toBe(stopped);
  });

  it("keeps authenticated idle spares waiting and resets backoff before a later attachment", async () => {
    const targetSockets = new Set<Socket>();
    let received = "";
    const target = netServer({ allowHalfOpen: true }, (socket) => {
      targetSockets.add(socket);
      socket.on("error", () => undefined);
      socket.on("data", (chunk: Buffer) => {
        received += chunk.toString();
      });
    });
    target.listen(0, "127.0.0.1");
    await once(target, "listening");
    const targetAddress = `127.0.0.1:${(target.address() as AddressInfo).port}`;
    cleanups.push(async () => {
      for (const socket of targetSockets) socket.destroy();
      await new Promise<void>((resolve) => target.close(() => resolve()));
    });
    const waiting = new Set<TLSSocket>();
    const remote = await gateway(async (socket) => {
      waiting.add(socket);
      socket.on("close", () => waiting.delete(socket));
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    });
    const events: TcpClientEvent[] = [];
    const connector = new TcpConnector(config(targetAddress), {
      fetch: async () => Response.json(ticket(targetAddress)),
      dialGateway: remote.dial,
      reconnectMinMs: 10,
      reconnectMaxMs: 160,
      report: (event) => events.push(event),
    });
    cleanups.push(() => connector.close());
    const opened = (): number =>
      events.filter((event) => event.event === "TCP_CONNECTOR_WAITING").length;
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      connector.start();
      await until(() => opened() === 2);
      // A healthy idle connector must outlive the old local attach deadline.
      await vi.advanceTimersByTimeAsync(30_000);
      expect(opened()).toBe(2);
      expect(connector.snapshot()).toEqual({ waiting: 2, active: 0 });
      expect(targetSockets.size).toBe(0);
      for (let cycle = 0; cycle < 4; cycle += 1) {
        for (const socket of waiting) socket.destroy();
        await until(() => connector.snapshot().waiting === 0);
        // Each healthy CONNECT resets failures, so idle recycling never escalates this delay.
        await vi.advanceTimersByTimeAsync(40);
        await until(() => opened() === (cycle + 2) * 2);
        expect(connector.snapshot()).toEqual({ waiting: 2, active: 0 });
      }
      const socket = [...waiting][0];
      if (socket === undefined) throw new Error("missing waiting connector");
      socket.write('{"type":"attach"}\nlate-client-request');
      const ready = await readLine(socket, 1024, 1000);
      expect(ready.line).toBe('{"type":"ready"}');
      await until(() => received === "late-client-request");
      expect(targetSockets.size).toBe(1);
      expect(remote.errors).toEqual([]);
    } finally {
      await connector.close();
      vi.useRealTimers();
    }
  });

  it("verifies TLS peer trust and hostname, refuses hostname targets, and has fixed safe defaults", async () => {
    const remote = await gateway(async () => undefined);
    await expect(
      verifiedTls(HOST, new AbortController().signal, { address: "127.0.0.1", port: remote.port }),
    ).rejects.toMatchObject({ code: "TCP_CONNECT_FAILED" });
    await expect(
      verifiedTls("other.example", new AbortController().signal, {
        address: "127.0.0.1",
        port: remote.port,
        ca: authority.certificate,
      }),
    ).rejects.toMatchObject({ code: "TCP_CONNECT_FAILED" });
    for (const target of [
      "localhost:5432",
      "127.0.0.1",
      "127.0.0.1:0",
      "[::1]:65536",
      "127.0.0.1:5432\r\n",
    ]) {
      expect(() => parseTcpTarget(target)).toThrow("TCP_TARGET_INVALID");
    }
    expect(parseTcpTarget("[0:0:0:0:0:0:0:1]:5432").resource).toBe("[::1]:5432");
    expect(TCP_CLIENT_LIMITS).toMatchObject({
      maxLegs: 8,
      spareLegs: 2,
      connectTimeoutMs: 10000,
      idleTimeoutMs: 300000,
      sessionTimeoutMs: 3600000,
      maxBytes: 1073741824,
    });
  });

  it("caps pending local clients at eight and aborts every pending ticket on shutdown", async () => {
    let pending = 0;
    let cancelled = 0;
    const tunnel = new TcpTunnel(config(), {
      fetch: (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          pending += 1;
          init?.signal?.addEventListener(
            "abort",
            () => {
              cancelled += 1;
              reject(new Error("cancelled"));
            },
            { once: true },
          );
        }),
    });
    cleanups.push(() => tunnel.close());
    const address = await tunnel.listen(0);
    const clients = Array.from({ length: 16 }, () => {
      const socket = connect({ host: "127.0.0.1", port: address.port });
      socket.on("error", () => undefined);
      return socket;
    });
    cleanups.push(async () => {
      for (const socket of clients) socket.destroy();
    });
    await until(() => pending === 8);
    await settle(25);
    expect(pending).toBe(8);
    await tunnel.close();
    expect(cancelled).toBe(8);
  });

  it("reports an explicit error control when its fixed target cannot connect", async () => {
    const controls: string[] = [];
    const remote = await gateway(async (socket) => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n{"type":"attach"}\n');
      const answer = await readLine(socket, 1024, 1000);
      controls.push(answer.line);
    });
    const fixedTargets: string[] = [];
    const connector = new TcpConnector(config(), {
      fetch: async () => Response.json(ticket(config().target)),
      dialGateway: remote.dial,
      dialTarget: async (target) => {
        fixedTargets.push(target.resource);
        throw new Error("synthetic-target-failure-secret");
      },
    });
    cleanups.push(() => connector.close());
    connector.start();
    await until(() => controls.length === 2);
    expect(controls).toEqual(['{"type":"error"}', '{"type":"error"}']);
    expect(fixedTargets).toEqual([config().target, config().target]);
  });

  it("never exceeds eight connector legs even when every spare is immediately attached", async () => {
    const targetSockets = new Set<Socket>();
    const target = netServer({ allowHalfOpen: true }, (socket) => {
      targetSockets.add(socket);
      socket.on("error", () => undefined);
    });
    target.listen(0, "127.0.0.1");
    await once(target, "listening");
    const targetAddress = `127.0.0.1:${(target.address() as AddressInfo).port}`;
    cleanups.push(async () => {
      for (const socket of targetSockets) socket.destroy();
      await new Promise<void>((resolve) => target.close(() => resolve()));
    });
    const remote = await gateway(async (socket) => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n{"type":"attach"}\n');
      const ready = await readLine(socket, 1024, 1000);
      expect(ready.line).toBe('{"type":"ready"}');
    });
    let issued = 0;
    const connector = new TcpConnector(config(targetAddress), {
      fetch: async () => {
        issued += 1;
        return Response.json(ticket(targetAddress));
      },
      dialGateway: remote.dial,
    });
    cleanups.push(() => connector.close());
    connector.start();
    await until(() => connector.snapshot().active === 8);
    await settle(25);
    expect(connector.snapshot()).toEqual({ active: 8, waiting: 0 });
    expect(issued).toBe(8);
    expect(targetSockets.size).toBe(8);
    expect(remote.errors).toEqual([]);
  });
});
