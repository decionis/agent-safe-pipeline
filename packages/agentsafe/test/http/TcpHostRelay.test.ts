import { request } from "node:https";
import type { IncomingMessage } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import { TcpBroker } from "../../src/http/TcpBroker.js";
import { TcpHostRelay } from "../../src/http/TcpHostRelay.js";
import { controlLine, TCP_TRANSPORT } from "../../src/http/TcpRelayStreams.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";
import {
  connectLeg,
  readBytes,
  TestTcpControl,
  testTls,
  token,
  TENANT,
} from "../support/TcpRelayHarness.js";

describe("fixed hosted TCP relay", () => {
  const ca = new TestCertificateAuthority();
  const hosts: GatewayHttpServer[] = [];
  const brokers: TcpBroker[] = [];
  afterEach(async () => {
    await Promise.all(hosts.splice(0).map((host) => host.close(0)));
    await Promise.all(brokers.splice(0).map((broker) => broker.close()));
  });
  async function start(options: { badBrokerCert?: boolean; maxLegs?: number } = {}) {
    const control = new TestTcpControl();
    const broker = new TcpBroker({
      tls: testTls(ca, options.badBrokerCert ? ["wrong.example"] : undefined),
      domain: "decionisedge.com",
      control,
    });
    brokers.push(broker);
    const address = await broker.listen(0, "127.0.0.1");
    const ports: number[] = [];
    for (let i = 0; i < 2; i++) {
      const relay = new TcpHostRelay({
        host: "127.0.0.1",
        port: address.port,
        domain: () => "decionisedge.com",
        ca: ca.certificate,
        ...(options.maxLegs ? { maxLegs: options.maxLegs } : {}),
      });
      const host = new GatewayHttpServer(() => null, {
        tls: testTls(ca),
        tcpRelay: relay,
        probe: { ready: () => true },
      });
      hosts.push(host);
      ports.push((await host.listen(0, "127.0.0.1")).port);
    }
    return { control, one: ports[0]!, two: ports[1]! };
  }
  function get(
    port: number,
    host = TENANT,
    servername = host,
    path = "/_agentsafe/tcp/capabilities",
  ) {
    return new Promise<{ status: number; body: unknown }>((resolve, reject) => {
      const req = request(
        {
          hostname: "127.0.0.1",
          port,
          ca: ca.certificate,
          servername,
          path,
          headers: { host },
          agent: false,
        },
        (res) => {
          let body = "";
          res.on("data", (chunk: Buffer) => {
            body += chunk.toString();
          });
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, body: JSON.parse(body) as unknown }),
          );
        },
      );
      req.on("error", reject);
      req.end();
    });
  }
  it("supports a TCP-only tenant and pairs legs accepted by separate host replicas", async () => {
    const { control, one, two } = await start();
    expect(await get(one)).toEqual({
      status: 200,
      body: { transport: TCP_TRANSPORT, ready: true },
    });
    expect((await get(one, TENANT, TENANT, "/ordinary-http")).status).toBe(421);
    const connector = await connectLeg(one, ca, control.issue("connector"), "connector", {
      servername: TENANT,
    });
    expect(connector.status).toBe(200);
    const waiting = connectLeg(two, ca, control.issue("client"), "client", { servername: TENANT });
    expect((await controlLine(connector.socket, connector.head, 1_000)).line).toBe(
      '{"type":"attach"}',
    );
    connector.socket.write('{"type":"ready"}\nhello');
    const client = await waiting;
    expect(client.status).toBe(200);
    expect((await readBytes(client.socket, client.head, 5)).toString()).toBe("hello");
    client.socket.write("request");
    expect((await readBytes(connector.socket, Buffer.alloc(0), 7)).toString()).toBe("request");
    expect(control.redeemed).toHaveLength(2);
  });
  it("rejects mismatched public SNI/Host and arbitrary destinations before the fixed broker", async () => {
    const { control, one } = await start();
    expect(
      (await connectLeg(one, ca, token(), "client", { servername: "other.decionisedge.com" }))
        .status,
    ).toBe(400);
    expect(
      (
        await connectLeg(one, ca, token(), "client", {
          servername: TENANT,
          authority: "10.0.0.1:5432",
        })
      ).status,
    ).toBe(400);
    expect((await get(one, TENANT, "other.decionisedge.com")).status).toBe(503);
    expect(control.redeemed).toHaveLength(0);
  });
  it("requires the fixed broker's certificate name and reports unavailable readiness", async () => {
    const { control, one } = await start({ badBrokerCert: true });
    expect(await get(one)).toEqual({
      status: 503,
      body: { transport: TCP_TRANSPORT, ready: false },
    });
    expect(
      (await connectLeg(one, ca, control.issue("connector"), "connector", { servername: TENANT }))
        .status,
    ).toBe(502);
    expect(control.redeemed).toHaveLength(0);
  });
  it("reports a broker control-plane readiness failure without making HTTP probes fail", async () => {
    const { control, one } = await start();
    control.readiness = false;
    expect((await get(one)).status).toBe(503);
    expect((await get(one, "127.0.0.1", TENANT, "/_agentsafe/readyz")).status).toBe(200);
  });
  it("bounds relay legs independently and cleans up on host shutdown", async () => {
    const { control, one } = await start({ maxLegs: 1 });
    expect(
      (await connectLeg(one, ca, control.issue("connector"), "connector", { servername: TENANT }))
        .status,
    ).toBe(200);
    expect(
      (await connectLeg(one, ca, control.issue("connector"), "connector", { servername: TENANT }))
        .status,
    ).toBe(503);
    await hosts[0]!.close(0);
    hosts.shift();
  });
  it("cancels a pending capability probe and never becomes ready after shutdown", async () => {
    const control = new TestTcpControl();
    let release!: () => void;
    const blocked = new Promise<boolean>((resolve) => {
      release = () => resolve(true);
    });
    const readiness = vi.spyOn(control, "ready").mockReturnValue(blocked);
    const broker = new TcpBroker({ tls: testTls(ca), domain: "decionisedge.com", control });
    brokers.push(broker);
    const address = await broker.listen(0, "127.0.0.1");
    const relay = new TcpHostRelay({
      host: "127.0.0.1",
      port: address.port,
      domain: () => "decionisedge.com",
      ca: ca.certificate,
    });
    const req = {
      headers: { host: TENANT },
      socket: { encrypted: true, servername: TENANT },
    } as unknown as IncomingMessage;
    const pending = relay.capabilities(req);
    await vi.waitFor(() => expect(readiness).toHaveBeenCalled());
    relay.close();
    expect(await pending).toBe(false);
    release();
    expect(await relay.capabilities(req)).toBe(false);
  });
});
