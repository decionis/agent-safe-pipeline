import { Agent, request, type AgentOptions } from "node:https";
import { connect, type ConnectionOptions, type TLSSocket } from "node:tls";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ExecutorHttpServer } from "../../src/http/ExecutorHttpServer.js";
import { RequestContext } from "../../src/http/RequestContext.js";
import { TLS12_CIPHERS, TlsListener, type TlsMinVersion } from "../../src/http/TlsListener.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";
import type { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { CALLER_TOKEN, collectedEvents } from "../support/Environment.js";
import {
  TestCertificateAuthority,
  type IssuedCertificate,
} from "../support/TestCertificateAuthority.js";

const propose = vi.fn(async () => ({
  outcome: "COMPLETED",
  principal: RequestContext.current()?.principal ?? null,
}));
const service = {
  mode: "ENFORCEMENT",
  escalationMode: "NONE",
  actions: ["forward_request"],
  propose,
  reconcile: vi.fn(),
  resume: vi.fn(),
} as unknown as TrustedExecutorService;

const ca = new TestCertificateAuthority("Synthetic Listener CA");
const clients = new TestCertificateAuthority("Synthetic Client CA");
const callerToken = SecretHandle.fromString("EXECUTOR_CALLER_TOKEN", CALLER_TOKEN);
let serverCert: IssuedCertificate;
let client: IssuedCertificate;
let outsider: IssuedCertificate;

interface Reply {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly protocol: string | null;
  readonly fingerprint: string;
  readonly alpn: string | false;
}

interface Running {
  readonly server: ExecutorHttpServer;
  readonly listener: TlsListener;
  readonly port: number;
  readonly lines: string[];
  close(): Promise<void>;
}

async function start(
  options: {
    readonly clientCa?: string | null;
    readonly minVersion?: TlsMinVersion;
    readonly cert?: () => IssuedCertificate;
    /** A door with nowhere to report: refusals must still be refusals. */
    readonly silent?: boolean;
  } = {},
): Promise<Running> {
  const lines: string[] = [];
  const events = collectedEvents(lines);
  const listener = new TlsListener({
    minVersion: options.minVersion ?? "TLSv1.3",
    material: () => {
      const issued = (options.cert ?? (() => serverCert))();
      return {
        cert: issued.cert,
        key: SecretHandle.fromString("EXECUTOR_TLS_KEY", issued.key),
        clientCa: options.clientCa ?? null,
      };
    },
    events,
  });
  const server = new ExecutorHttpServer(service, () => callerToken, {
    tls: listener,
    ...(options.silent === true ? {} : { events }),
  });
  const bound = await server.listen(0, "127.0.0.1");
  return { server, listener, port: bound.port, lines, close: () => server.close() };
}

function call(
  port: number,
  path: string,
  options: AgentOptions & { readonly token?: string | null; readonly body?: string } = {},
): Promise<Reply> {
  const { token, body, ...rest } = options;
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (token !== null) headers["authorization"] = `Bearer ${token ?? CALLER_TOKEN}`;
    // A fresh agent per call: every request is its own connection and handshake.
    const agent = new Agent({
      ca: ca.certificate,
      servername: "localhost",
      ALPNProtocols: ["http/1.1"],
      keepAlive: false,
      ...rest,
    });
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path,
        method: body === undefined ? "GET" : "POST",
        headers,
        agent,
      },
      (response) => {
        const chunks: Buffer[] = [];
        const socket = response.socket as TLSSocket;
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            status: response.statusCode ?? 0,
            body: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<
              string,
              unknown
            >,
            protocol: socket.getProtocol(),
            fingerprint: socket.getPeerCertificate().fingerprint256,
            alpn: socket.alpnProtocol ?? false,
          });
        });
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

function handshake(port: number, options: ConnectionOptions): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = connect({
      host: "127.0.0.1",
      port,
      ca: ca.certificate,
      servername: "localhost",
      ...options,
    });
    socket.once("secureConnect", () => resolve(socket));
    socket.once("error", reject);
  });
}

beforeAll(() => {
  serverCert = ca.issueServer(["localhost"], ["127.0.0.1"]);
  client = clients.issueClient("synthetic-workflow", [
    "spiffe://synthetic.example/ns/agents/sa/workflow",
  ]);
  outsider = ca.issueClient("synthetic-outsider");
});

afterAll(() => {
  callerToken.dispose();
});

describe("TlsListener", () => {
  it("serves HTTP/1.1 over TLS 1.3 with the configured certificate and refuses older protocols", async () => {
    const running = await start();
    const health = await call(running.port, "/health", { token: null });
    expect(health.status).toBe(200);
    expect(health.protocol).toBe("TLSv1.3");
    expect(health.alpn).toBe("http/1.1");
    expect(health.fingerprint).toHaveLength(95);
    await expect(handshake(running.port, { maxVersion: "TLSv1.2" })).rejects.toThrow();
    expect(running.listener.mutual).toBe(false);
    await running.close();
  });

  it("admits TLS 1.2 only when configured, and then only with an AEAD cipher and no renegotiation", async () => {
    const running = await start({ minVersion: "TLSv1.2" });
    const socket = await handshake(running.port, { maxVersion: "TLSv1.2", ciphers: TLS12_CIPHERS });
    expect(socket.getProtocol()).toBe("TLSv1.2");
    expect(socket.getCipher().name).toMatch(/GCM|CHACHA20/);
    const renegotiated = await new Promise<Error | null>((resolve) => {
      const closed = (): void => resolve(new Error("closed"));
      socket.once("close", closed);
      const started = socket.renegotiate({ rejectUnauthorized: true }, (error) => {
        socket.off("close", closed);
        resolve(error);
      });
      if (!started) resolve(new Error("refused"));
    });
    expect(renegotiated).toBeInstanceOf(Error);
    socket.destroy();
    await expect(
      handshake(running.port, { maxVersion: "TLSv1.2", ciphers: "AES128-SHA:AES256-SHA" }),
    ).rejects.toThrow();
    await running.close();
  });

  it("asks every connection for a client certificate when a client CA is set, admits a probe to the public routes, and requires the certificate everywhere else", async () => {
    const running = await start({ clientCa: clients.certificate });
    expect(running.listener.mutual).toBe(true);
    const probe = await call(running.port, "/health", { token: null });
    expect(probe.status).toBe(200);
    const withoutCert = await call(running.port, "/v1/actions", { body: "{}" });
    expect(withoutCert.status).toBe(401);
    expect(withoutCert.body).toEqual({ code: "CALLER_NOT_AUTHENTICATED" });
    const foreign = await call(running.port, "/v1/actions", {
      body: "{}",
      cert: outsider.cert,
      key: outsider.key,
    });
    expect(foreign.status).toBe(401);
    const admitted = await call(running.port, "/v1/actions", {
      body: "{}",
      cert: client.cert,
      key: client.key,
    });
    expect(admitted.status).toBe(200);
    expect(admitted.body).toEqual({ outcome: "COMPLETED", principal: "legacy-caller" });
    const certOnly = await call(running.port, "/v1/actions", {
      body: "{}",
      cert: client.cert,
      key: client.key,
      token: null,
    });
    expect(certOnly.status).toBe(401);
    const wrongToken = await call(running.port, "/v1/actions", {
      body: "{}",
      cert: client.cert,
      key: client.key,
      token: "wrong",
    });
    expect(wrongToken.status).toBe(401);
    const failures = running.lines
      .map((line) => JSON.parse(line) as { event: string; method?: string })
      .filter((event) => event.event === "AUTH_FAILED")
      .map((event) => event.method);
    expect(failures).toEqual(["mtls", "mtls", "bearer", "bearer"]);
    await running.close();
    const silent = await start({ clientCa: clients.certificate, silent: true });
    const unreported = await call(silent.port, "/v1/actions", { body: "{}" });
    expect(unreported.status).toBe(401);
    expect(silent.lines).toEqual([]);
    await silent.close();
  });

  it("replaces its context in place when told to, keeping open connections and serving new ones the new certificate", async () => {
    let current = serverCert;
    const running = await start({ cert: () => current });
    const before = await call(running.port, "/health", { token: null });
    const keepAlive = await handshake(running.port, {});
    current = ca.issueServer(["localhost"], ["127.0.0.1"]);
    running.server.rotateTls();
    const after = await call(running.port, "/health", { token: null });
    expect(after.status).toBe(200);
    expect(after.fingerprint).not.toBe(before.fingerprint);
    expect(keepAlive.destroyed).toBe(false);
    expect(keepAlive.getPeerCertificate().fingerprint256).toBe(before.fingerprint);
    keepAlive.destroy();
    expect(running.lines.map((line) => (JSON.parse(line) as { event: string }).event)).toEqual([
      "TLS_CONTEXT_ROTATED",
    ]);
    await running.close();
  });
});
