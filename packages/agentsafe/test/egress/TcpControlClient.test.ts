import { createServer, type Server } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TcpControlClient, validGrant } from "../../src/egress/TcpControlClient.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";
import { ORG, ROUTE, TENANT, token } from "../support/TcpRelayHarness.js";

describe("fixed TCP control API", () => {
  const ca = new TestCertificateAuthority();
  const servers: Server[] = [];
  const sockets = new Set<Socket>();
  afterEach(async () => {
    vi.restoreAllMocks();
    for (const socket of sockets) socket.destroy();
    await Promise.all(
      servers
        .splice(0)
        .map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
    );
  });
  async function start(handler: (req: IncomingMessage, res: ServerResponse) => void) {
    const cert = ca.issueServer(["control.example"]);
    const server = createServer({ cert: cert.cert, key: cert.key }, handler);
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const origin = new URL("https://127.0.0.1");
    origin.port = String((server.address() as AddressInfo).port);
    return origin.origin;
  }
  const binding = { route_id: ROUTE, tenant_host: TENANT, role: "connector" as const };
  const grant = () => ({
    ...binding,
    lease_id: "00000000-0000-4000-8000-000000000004",
    lease_token: token(),
    org_id: ORG,
    generation: 1,
    resource_hash: "b".repeat(64),
    expires_at: new Date(Date.now() + 30_000).toISOString(),
  });
  it("sends only dedicated service auth to fixed paths and validates all echoed fields", async () => {
    const key = "s".repeat(64);
    const original = grant();
    const seen: { path: string | undefined; auth: string | undefined; body: unknown }[] = [];
    const origin = await start((req, res) => {
      let body = "";
      req.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });
      req.on("end", () => {
        seen.push({
          path: req.url,
          auth: req.headers.authorization,
          body: JSON.parse(body) as unknown,
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(req.url?.endsWith("/close") ? { closed: true } : original));
      });
    });
    const client = new TcpControlClient(origin, () => key, ca.certificate);
    const ticket = token();
    expect(await client.redeem(ticket, binding)).toEqual(original);
    expect(await client.refresh(original, "active")).toEqual(original);
    await client.close(original);
    expect(seen.map((entry) => entry.path)).toEqual([
      "/v1/internal/gateway/tcp/redeem",
      "/v1/internal/gateway/tcp/leases/refresh",
      "/v1/internal/gateway/tcp/leases/close",
    ]);
    expect(seen.every((entry) => entry.auth === `Bearer ${key}`)).toBe(true);
    expect(seen[0]?.body).toEqual({ ticket, ...binding });
    expect(seen[1]?.body).toEqual({
      lease_id: original.lease_id,
      lease_token: original.lease_token,
      phase: "active",
    });
    expect(() => validGrant({ ...original, tenant_host: "wrong.example" }, binding)).toThrow();
    for (const changed of [
      { org_id: "00000000-0000-4000-8000-000000000005" },
      { generation: 2 },
      { lease_token: token() },
      { resource_hash: "c".repeat(64) },
      { expires_at: new Date(Date.now() + 60_000).toISOString() },
    ])
      expect(() => validGrant({ ...original, ...changed }, binding, original)).toThrow();
  });
  it("bounds all in-flight requests even when callers disconnect or release many leases", async () => {
    const replies: ServerResponse[] = [];
    const origin = await start((req, res) => {
      req.resume();
      replies.push(res);
    });
    const client = new TcpControlClient(origin, () => "s".repeat(64), ca.certificate);
    const original = grant();
    const pending = Array.from({ length: 128 }, () => client.close(original));
    await expect(client.redeem(token(), binding)).rejects.toThrow("TCP_CONTROL_CAPACITY_REACHED");
    await vi.waitFor(() => expect(replies).toHaveLength(128));
    for (const res of replies) res.end("{}");
    await Promise.all(pending);
  });
  it("authenticates readiness, expires stale proof, and immediately rejects a revoked token", async () => {
    let status = 200;
    let calls = 0;
    const origin = await start((req, res) => {
      req.resume();
      calls++;
      res.writeHead(status);
      res.end(JSON.stringify({ transport: "agentsafe-tcp-relay/1", ready: true }));
    });
    const client = new TcpControlClient(origin, () => "s".repeat(64), ca.certificate);
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    expect(await client.ready()).toBe(true);
    expect(await client.ready()).toBe(true);
    expect(calls).toBe(1);
    clock.mockReturnValue(now + 11_000);
    status = 503;
    expect(await client.ready()).toBe(true);
    clock.mockReturnValue(now + 22_000);
    status = 401;
    expect(await client.ready()).toBe(false);
    clock.mockReturnValue(now + 33_000);
    status = 503;
    expect(await client.ready()).toBe(false);
  });
  it("does not carry readiness across token rotation during an in-flight probe", async () => {
    let first: ServerResponse | null = null;
    let current = "s".repeat(64);
    const origin = await start((req, res) => {
      req.resume();
      if (req.headers.authorization === `Bearer ${"s".repeat(64)}`) first = res;
      else {
        res.writeHead(401);
        res.end("{}");
      }
    });
    const client = new TcpControlClient(origin, () => current, ca.certificate);
    const old = client.ready();
    await vi.waitFor(() => expect(first).not.toBeNull());
    current = "t".repeat(64);
    const fresh = client.ready();
    (first as unknown as ServerResponse).end(
      JSON.stringify({ transport: "agentsafe-tcp-relay/1", ready: true }),
    );
    expect(await old).toBe(false);
    expect(await fresh).toBe(false);
  });
  it("rejects redirects, malformed/oversized responses and untrusted TLS without leaking body text", async () => {
    let status = 302;
    let body = "private-control-error";
    const origin = await start((req, res) => {
      req.resume();
      res.writeHead(status, { location: "https://other.example/" });
      res.end(body);
    });
    const client = new TcpControlClient(origin, () => "s".repeat(64), ca.certificate);
    await expect(client.redeem(token(), binding)).rejects.toThrow("TCP_CONTROL_REFUSED");
    status = 200;
    await expect(client.redeem(token(), binding)).rejects.toThrow("TCP_CONTROL_RESPONSE_INVALID");
    body = "x".repeat(16_385);
    await expect(client.redeem(token(), binding)).rejects.toThrow("TCP_CONTROL_UNAVAILABLE");
    await expect(
      new TcpControlClient(origin, () => "s".repeat(64)).redeem(token(), binding),
    ).rejects.toThrow("TCP_CONTROL_UNAVAILABLE");
    expect(await new TcpControlClient(origin, () => "bad\nheader").ready()).toBe(false);
    expect(() => new TcpControlClient("http://api.example", () => "s".repeat(64))).toThrow(
      "TCP_CONTROL_API_INVALID",
    );
  });
});
