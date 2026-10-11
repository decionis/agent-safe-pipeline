import { once } from "node:events";
import { connect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TcpBroker, type TcpBrokerLimits } from "../../src/http/TcpBroker.js";
import { controlLine } from "../../src/http/TcpRelayStreams.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";
import {
  connectLeg,
  readBytes,
  TestTcpControl,
  testTls,
  token,
  TENANT,
  ROUTE,
} from "../support/TcpRelayHarness.js";

describe("hosted TCP broker", () => {
  const brokers: TcpBroker[] = [];
  const ca = new TestCertificateAuthority();
  afterEach(async () => {
    await Promise.all(brokers.splice(0).map((broker) => broker.close()));
  });
  async function start(limits: Partial<TcpBrokerLimits> = {}) {
    const control = new TestTcpControl();
    const broker = new TcpBroker({ tls: testTls(ca), domain: "decionisedge.com", control, limits });
    brokers.push(broker);
    const { port } = await broker.listen(0, "127.0.0.1");
    return { control, broker, port };
  }
  async function pair(port: number, control: TestTcpControl, suffix = "") {
    const connector = await connectLeg(port, ca, control.issue("connector"), "connector");
    expect(connector.status).toBe(200);
    const waiting = connectLeg(port, ca, control.issue("client"), "client");
    expect((await controlLine(connector.socket, connector.head, 1_000)).line).toBe(
      '{"type":"attach"}',
    );
    connector.socket.write(`{"type":"ready"}\n${suffix}`);
    const client = await waiting;
    expect(client.status).toBe(200);
    return { connector, client };
  }
  it("pairs only redeemed roles and preserves binary bytes following the ready control line", async () => {
    const { control, port } = await start();
    const { connector, client } = await pair(port, control, "welcome");
    expect((await readBytes(client.socket, client.head, 7)).toString()).toBe("welcome");
    const binary = Buffer.from([0, 255, 1, 13, 10]);
    client.socket.write(binary);
    expect(await readBytes(connector.socket, Buffer.alloc(0), binary.length)).toEqual(binary);
    connector.socket.write(Buffer.from([42, 0, 88]));
    expect(await readBytes(client.socket, Buffer.alloc(0), 3)).toEqual(Buffer.from([42, 0, 88]));
  });
  it("preserves half-close so a target can send its final response after request EOF", async () => {
    const { control, port } = await start();
    const { connector, client } = await pair(port, control);
    const received: Buffer[] = [];
    connector.socket.on("data", (chunk: Buffer) => received.push(chunk));
    connector.socket.once("end", () => connector.socket.end("final response"));
    connector.socket.resume();
    const response = readBytes(client.socket, client.head, 14);
    client.socket.end("request");
    expect((await response).toString()).toBe("final response");
    expect(Buffer.concat(received).toString()).toBe("request");
  });
  it("refuses malformed authority, SNI, host and role before ticket redemption", async () => {
    const { control, port } = await start();
    for (const options of [
      { authority: "127.0.0.1:22" },
      { servername: TENANT },
      { host: "evil.example" },
      { headers: { "agentsafe-tcp-role": "admin" } },
      { headers: { authorization: "Bearer short" } },
    ]) {
      const result = await connectLeg(port, ca, token(), "client", options);
      expect(result.status).toBe(400);
      result.socket.destroy();
    }
    expect(control.redeemed).toHaveLength(0);
  });
  it("rejects used tickets and mismatched echoed grants", async () => {
    const { control, port } = await start();
    const key = control.issue("connector");
    const connected = await connectLeg(port, ca, key, "connector");
    expect(connected.status).toBe(200);
    expect((await connectLeg(port, ca, key, "connector")).status).toBe(403);
    expect(
      (await connectLeg(port, ca, control.issue("connector", { role: "client" }), "connector"))
        .status,
    ).toBe(403);
    expect(
      (
        await connectLeg(
          port,
          ca,
          control.issue("connector", { route_id: "00000000-0000-4000-8000-000000000003" }),
          "connector",
        )
      ).status,
    ).toBe(403);
    expect(control.redeemed.every((binding) => binding.route_id === ROUTE)).toBe(true);
  });
  it.each([
    { org_id: "00000000-0000-4000-8000-000000000009" },
    { generation: 2 },
    { resource_hash: "f".repeat(64) },
  ])("does not pair another organization, generation or resource binding %j", async (different) => {
    const { control, port } = await start({ pairMs: 80 });
    const connector = await connectLeg(port, ca, control.issue("connector"), "connector");
    const client = await connectLeg(port, ca, control.issue("client", different), "client");
    expect(client.status).toBe(504);
    connector.socket.destroy();
    await vi.waitFor(() => expect(control.released).toHaveLength(2));
  });
  it("enforces route and organization caps while preserving already admitted legs", async () => {
    const { control, port } = await start({ routeLegs: 1, organizationLegs: 2 });
    expect((await connectLeg(port, ca, control.issue("connector"), "connector")).status).toBe(200);
    expect((await connectLeg(port, ca, control.issue("connector"), "connector")).status).toBe(429);
    expect(control.released).toHaveLength(1);
  });
  it("bounds pending unauthenticated redemptions globally", async () => {
    const { control, port } = await start({ totalLegs: 1 });
    expect((await connectLeg(port, ca, control.issue("connector"), "connector")).status).toBe(200);
    expect((await connectLeg(port, ca, control.issue("connector"), "connector")).status).toBe(503);
    expect(control.redeemed).toHaveLength(1);
  });
  it("keeps an authenticated spare beyond client pairing deadlines and serves a later client", async () => {
    const { control, port } = await start({ pairMs: 30, refreshMs: 20 });
    const connector = await connectLeg(port, ca, control.issue("connector"), "connector");
    const attach = controlLine(connector.socket, connector.head, 1_000);
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(control.released).toHaveLength(0);
    const waiting = connectLeg(port, ca, control.issue("client"), "client");
    expect((await attach).line).toBe('{"type":"attach"}');
    connector.socket.write('{"type":"ready"}\n');
    const client = await waiting;
    expect(client.status).toBe(200);
    client.socket.write("later request");
    expect((await readBytes(connector.socket, Buffer.alloc(0), 13)).toString()).toBe(
      "later request",
    );
  });
  it("bounds an authenticated waiting connector's total lifetime", async () => {
    const { control, port } = await start({ pairMs: 20, sessionMs: 120, refreshMs: 20 });
    const connector = await connectLeg(port, ca, control.issue("connector"), "connector");
    const ended = once(connector.socket, "end");
    connector.socket.resume();
    await ended;
    expect(control.released).toHaveLength(1);
  });
  it("releases waiting connector capacity on disconnect and refuses unsolicited pre-attach bytes", async () => {
    const { control, port } = await start({ routeLegs: 1 });
    const first = await connectLeg(port, ca, control.issue("connector"), "connector");
    first.socket.destroy();
    await vi.waitFor(() => expect(control.released).toHaveLength(1));
    const next = await connectLeg(port, ca, control.issue("connector"), "connector");
    expect(next.status).toBe(200);
    next.socket.write('{"type":"ready"}\n');
    await vi.waitFor(() => expect(control.released).toHaveLength(2));
    next.socket.destroy();
  });
  it("rejects ready and payload sent during delayed redemption before pairing an existing client", async () => {
    const { control, port } = await start({ pairMs: 500 });
    const redeem = control.redeem.bind(control);
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.spyOn(control, "redeem").mockImplementation(async (ticket, binding) => {
      const grant = await redeem(ticket, binding);
      if (binding.role === "connector") await blocked;
      return grant;
    });
    const waiting = connectLeg(port, ca, control.issue("client"), "client");
    const socket = tlsConnect({
      host: "127.0.0.1",
      port,
      ca: ca.certificate,
      servername: "tcp-broker.decionisedge.com",
    });
    socket.on("error", () => undefined);
    const received: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => received.push(chunk));
    try {
      await once(socket, "secureConnect");
      await vi.waitFor(() => expect(control.redeemed).toHaveLength(1));
      socket.write(
        `CONNECT ${ROUTE}:443 HTTP/1.1\r\nHost: ${TENANT}\r\nAuthorization: Bearer ${control.issue("connector")}\r\nAgentSafe-TCP-Role: connector\r\n\r\n`,
      );
      await vi.waitFor(() => expect(control.redeemed).toHaveLength(2));
      // A separate TLS write lands after CONNECT parsing, while redemption is still pending.
      socket.write('{"type":"ready"}\nunsolicited-payload');
      await vi.waitFor(() => expect(socket.readableEnded).toBe(true));
      expect(Buffer.concat(received).length).toBe(0);
      expect(control.released.filter((grant) => grant.role === "connector")).toHaveLength(0);
      release();
      await vi.waitFor(() =>
        expect(control.released.filter((grant) => grant.role === "connector")).toHaveLength(1),
      );
      const client = await waiting;
      expect(client.status).toBe(504);
      expect(client.head.toString()).not.toContain("unsolicited-payload");
      expect(control.released).toHaveLength(2);
    } finally {
      release();
      socket.destroy();
      (await waiting).socket.destroy();
    }
  });
  it.each(["revocation", "changed binding"])("closes both active streams on %s", async (kind) => {
    const { control, port } = await start({ refreshMs: 40 });
    const { connector, client } = await pair(port, control);
    const closed = once(client.socket, "end");
    if (kind === "revocation") control.refreshRefused = true;
    else control.refreshOverride = { generation: 2 };
    client.socket.resume();
    connector.socket.resume();
    await closed;
    connector.socket.destroy();
    expect(control.released).toHaveLength(2);
  });
  it("closes before lease expiry even when refresh never succeeds", async () => {
    const { control, port } = await start();
    control.ttl = 600;
    const connector = await connectLeg(port, ca, control.issue("connector"), "connector");
    const closed = once(connector.socket, "end");
    connector.socket.resume();
    await closed;
    connector.socket.destroy();
    expect(control.released).toHaveLength(1);
  });
  it("refuses an oversized control line before client admission", async () => {
    const { control, port } = await start();
    const connector = await connectLeg(port, ca, control.issue("connector"), "connector");
    const waiting = connectLeg(port, ca, control.issue("client"), "client");
    await controlLine(connector.socket, connector.head, 1_000);
    connector.socket.write("x".repeat(1_025));
    expect((await waiting).status).toBe(502);
  });
  it("shuts down incomplete TLS handshakes without waiting for the TLS timeout", async () => {
    const { broker, port } = await start();
    const socket = connect({ host: "127.0.0.1", port });
    await once(socket, "connect");
    await broker.close();
    brokers.splice(brokers.indexOf(broker), 1);
    socket.destroy();
  });
  it("releases a late redeemed lease during shutdown without resurrecting its disconnected leg", async () => {
    const { broker, control, port } = await start();
    const redeem = control.redeem.bind(control);
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.spyOn(control, "redeem").mockImplementation(async (ticket, binding) => {
      const grant = await redeem(ticket, binding);
      await blocked;
      return grant;
    });
    const socket = tlsConnect({
      host: "127.0.0.1",
      port,
      ca: ca.certificate,
      servername: "tcp-broker.decionisedge.com",
    });
    socket.on("error", () => undefined);
    await once(socket, "secureConnect");
    socket.write(
      `CONNECT ${ROUTE}:443 HTTP/1.1\r\nHost: ${TENANT}\r\nAuthorization: Bearer ${control.issue("connector")}\r\nAgentSafe-TCP-Role: connector\r\n\r\n`,
    );
    await vi.waitFor(() => expect(control.redeemed).toHaveLength(1));
    socket.destroy();
    const stopped = broker.close();
    release();
    await stopped;
    brokers.splice(brokers.indexOf(broker), 1);
    expect(control.released).toHaveLength(1);
  });
  it.each(["idle", "lifetime", "bytes"])(
    "bounds session %s and cleans up both leases",
    async (kind) => {
      const { control, port } = await start({
        idleMs: kind === "idle" ? 40 : 3_000,
        sessionMs: kind === "lifetime" ? 40 : 3_000,
        maxBytes: kind === "bytes" ? 4 : 1_024,
      });
      const { connector, client } = await pair(port, control);
      const closed = once(client.socket, "end");
      client.socket.resume();
      connector.socket.resume();
      if (kind === "bytes") client.socket.write("12345");
      await closed;
      connector.socket.destroy();
      expect(control.released).toHaveLength(2);
    },
  );
});
