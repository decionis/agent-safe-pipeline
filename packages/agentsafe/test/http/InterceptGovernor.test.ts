import { once } from "node:events";
import { connect, createServer, type Socket } from "node:net";
import type { Readable } from "node:stream";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runIntercept } from "../../src/cli/Intercept.js";
import type { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import { GovernError, InterceptGovernor, replayed } from "../../src/http/InterceptGovernor.js";
import { LeafIssuer } from "../../src/intercept/LeafIssuer.js";
import { closedPort } from "../support/Environment.js";
import { fakeProcess, UpstreamDouble, type FakeProcess } from "../support/GatewayHarness.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 50));

/** One HTTP/1.1 exchange over an open socket: writes the request, reads to the end of the response. */
async function exchange(
  socket: Socket | TLSSocket,
  method: string,
  host: string,
  path: string,
  body: string,
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  socket.write(
    `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
  );
  const text = await new Promise<string>((resolve) => {
    let received = "";
    socket.on("data", (chunk: Buffer) => (received += chunk.toString("latin1")));
    socket.once("close", () => resolve(received));
  });
  const [head = "", ...rest] = text.split("\r\n\r\n");
  const [statusLine = "", ...headerLines] = head.split("\r\n");
  const headers: Record<string, string> = {};
  for (const line of headerLines) {
    const colon = line.indexOf(":");
    headers[line.slice(0, colon).toLowerCase()] = line.slice(colon + 1).trim();
  }
  return { status: Number(statusLine.split(" ")[1]), headers, body: rest.join("\r\n\r\n") };
}

describe("agentsafe intercept, governing", () => {
  const operator = new TestCertificateAuthority("Operator CA");
  let upstream = new UpstreamDouble();
  let io: FakeProcess;
  let httpPort: number;
  let httpsPort: number;
  /** The gateway's transport to the "real" host, pointed at the loopback double as a test does for the addressed gateway. */
  const upstreamFetch: typeof fetch = (input, init) =>
    fetch(String(input).replace(/^https?:\/\/provider\.example/, upstream.baseUrl), init);

  beforeEach(async () => {
    upstream = new UpstreamDouble();
    await upstream.start();
    httpPort = await closedPort();
    httpsPort = await closedPort();
  });

  afterEach(async () => {
    if (io !== undefined && io.exits.length === 0) {
      io.signals.get("SIGTERM")?.();
      for (let attempt = 0; attempt < 60 && io.exits.length === 0; attempt += 1) await settle();
    }
    await upstream.stop();
  });

  async function start(argv: readonly string[], env: Record<string, string> = {}): Promise<void> {
    io = fakeProcess({
      env,
      files: { "/run/ca.crt": operator.certificate, "/run/ca.key": operator.privateKeyPem },
    });
    await runIntercept(
      io,
      ["--http-port", String(httpPort), "--https-port", String(httpsPort), "--json", ...argv],
      { gateway: { upstreamFetch } },
    );
    expect(io.exits).toEqual([]);
  }

  const events = (): Record<string, unknown>[] =>
    io.out.map((line) => JSON.parse(line) as Record<string, unknown>);

  it("terminates a governed TLS connection under the operator's authority and governs each request", async () => {
    await start([
      "--govern",
      "provider.example",
      "--ca-cert",
      "/run/ca.crt",
      "--ca-key",
      "/run/ca.key",
    ]);
    expect(events()[1]).toMatchObject({
      event: "INTERCEPT_GOVERNING",
      hosts: ["provider.example"],
      unlisted: "passthrough",
      tls: true,
    });
    const client = tlsConnect({
      host: "127.0.0.1",
      port: httpsPort,
      servername: "provider.example",
      ca: [operator.certificate],
      ALPNProtocols: ["h2", "http/1.1"],
    });
    await once(client, "secureConnect");
    expect(client.authorized).toBe(true);
    expect(client.getPeerCertificate().subject.CN).toBe("provider.example");
    // A client that would speak HTTP/2 settles for HTTP/1.1, the one protocol offered.
    expect(client.alpnProtocol).toBe("http/1.1");
    const allowed = await exchange(
      client,
      "POST",
      "provider.example",
      "/payments",
      '{"amount": 1}',
    );
    expect(allowed.status).toBe(201);
    expect(allowed.headers["agentsafe-decision"]).toBe("ALLOW");
    expect(upstream.seen).toHaveLength(1);
    expect(upstream.seen[0]).toMatchObject({
      method: "POST",
      url: "/payments",
      body: '{"amount": 1}',
    });

    const held = tlsConnect({
      host: "127.0.0.1",
      port: httpsPort,
      servername: "provider.example",
      ca: [operator.certificate],
    });
    await once(held, "secureConnect");
    const escalated = await exchange(
      held,
      "POST",
      "provider.example",
      "/payments",
      '{"amount": 500}',
    );
    expect(escalated.status).toBe(202);
    expect(escalated.headers["agentsafe-execution"]).toBe("HELD");

    const refused = tlsConnect({
      host: "127.0.0.1",
      port: httpsPort,
      servername: "provider.example",
      ca: [operator.certificate],
    });
    await once(refused, "secureConnect");
    const blocked = await exchange(
      refused,
      "POST",
      "provider.example",
      "/payments",
      '{"amount": 5000}',
    );
    expect(blocked.status).toBe(403);
    expect(blocked.headers["agentsafe-state"]).toBe("BLOCK");
    expect(upstream.seen).toHaveLength(1);

    const observed = events().filter((event) => event["event"] === "INTERCEPT_OBSERVED");
    expect(observed).toHaveLength(3);
    for (const event of observed) {
      expect(event).toMatchObject({
        protocol: "TLS",
        host: "provider.example",
        port: 443,
        governed: true,
      });
    }
    expect(
      events().some(
        (event) =>
          event["event"] === "GATEWAY_STARTED" && event["gateway"] === "https://provider.example",
      ),
    ).toBe(true);
    expect(events().filter((event) => event["event"] === "INTERCEPT_REFUSED")).toEqual([]);

    io.signals.get("SIGTERM")?.();
    for (let attempt = 0; attempt < 60 && io.exits.length === 0; attempt += 1) await settle();
    expect(io.exits).toEqual([0]);
    const report = events().find((event) => event["event"] === "INTERCEPT_REPORT") as {
      intercept: {
        placed: number;
        destinations: Record<string, { governed: boolean; connections: number }>;
      };
    };
    expect(report.intercept.placed).toBe(3);
    // A governed destination is reported by the gateway's account of its
    // requests, not by bytes the hop never counted.
    expect(report.intercept.destinations["provider.example:443"]).toEqual({
      protocol: "TLS",
      governed: true,
      connections: 3,
      methods: {},
      gateway: {
        mode: "ENFORCEMENT",
        requests: { governed: 3, interceptions: 3, allows: 1, escalations: 1, blocks: 1 },
      },
    });
    expect(events().some((event) => event["event"] === "GATEWAY_STOPPED")).toBe(true);
  });

  it("governs a plaintext connection to a listed host without any authority, and splices the rest", async () => {
    await start(["--govern", "provider.example"]);
    expect(events()[1]).toMatchObject({ event: "INTERCEPT_GOVERNING", tls: false });
    const client = connect({ host: "127.0.0.1", port: httpPort });
    await once(client, "connect");
    const answer = await exchange(client, "POST", "provider.example", "/payments", '{"amount": 1}');
    expect(answer.status).toBe(201);
    expect(answer.headers["agentsafe-decision"]).toBe("ALLOW");
    expect(upstream.seen).toHaveLength(1);

    // An unlisted destination is spliced through as before: here to the double itself, by address.
    const other = connect({ host: "127.0.0.1", port: httpPort });
    await once(other, "connect");
    const passed = await exchange(
      other,
      "POST",
      `127.0.0.1:${new URL(upstream.baseUrl).port}`,
      "/payments",
      '{"amount": 5000}',
    );
    expect(passed.status).toBe(201);
    // The double forges a decision header on every answer; spliced through, it reaches the client as sent.
    expect(passed.headers["agentsafe-decision"]).toBe("FORGED");
    expect(upstream.seen).toHaveLength(2);
    const observed = events().filter((event) => event["event"] === "INTERCEPT_OBSERVED");
    expect(observed.map((event) => event["governed"])).toEqual([true, false]);

    // Governed TLS without an authority to mint with is refused by name, not passed through.
    const secured = tlsConnect({
      host: "127.0.0.1",
      port: httpsPort,
      servername: "provider.example",
      ca: [operator.certificate],
    });
    secured.on("error", () => undefined);
    await new Promise((resolve) => secured.once("close", resolve));
    const refusals = events().filter((event) => event["event"] === "INTERCEPT_REFUSED");
    expect(refusals).toHaveLength(1);
    expect(refusals[0]).toMatchObject({
      reason: "GOVERN_UNAVAILABLE",
      host: "provider.example",
      detail: "GOVERN_TLS_UNAVAILABLE",
    });
  });

  it("refuses every unlisted destination when told to", async () => {
    await start(["--govern", "provider.example", "--unlisted", "refuse"]);
    const other = connect({ host: "127.0.0.1", port: httpPort });
    await once(other, "connect");
    other.write("GET / HTTP/1.1\r\nHost: elsewhere.example\r\n\r\n");
    await once(other, "close");
    expect(events().at(-1)).toMatchObject({
      event: "INTERCEPT_REFUSED",
      reason: "UNLISTED_DESTINATION",
      host: "elsewhere.example",
      port: 80,
    });
    const listed = connect({ host: "127.0.0.1", port: httpPort });
    await once(listed, "connect");
    const answer = await exchange(listed, "POST", "provider.example", "/payments", '{"amount": 1}');
    expect(answer.status).toBe(201);
  });

  it("refuses to start on a setting it cannot govern with, naming it", async () => {
    const refusalOf = async (
      argv: readonly string[],
      env: Record<string, string> = {},
    ): Promise<{ code: number; reason: string }> => {
      const process = fakeProcess({
        env,
        files: {
          "/run/ca.crt": operator.certificate,
          "/run/ca.key": operator.privateKeyPem,
          "/run/leaf.crt": operator.issueServer(["x.example"]).cert,
        },
      });
      await runIntercept(process, ["--json", ...argv]);
      const reason = (JSON.parse(process.err.join("")) as { reason: string }).reason;
      return { code: process.exits[0] ?? -1, reason };
    };
    expect(await refusalOf(["--govern", "10.0.0.1"])).toEqual({
      code: 2,
      reason: "CONFIG_INVALID: govern (a host name, no port, no address)",
    });
    expect(await refusalOf(["--govern", "a.example:443"])).toEqual({
      code: 2,
      reason: "CONFIG_INVALID: govern (a host name, no port, no address)",
    });
    expect(await refusalOf([], { AGENTSAFE_INTERCEPT_GOVERN: "[::1]" })).toEqual({
      code: 2,
      reason: "CONFIG_INVALID: AGENTSAFE_INTERCEPT_GOVERN (a host name, no port, no address)",
    });
    expect(await refusalOf(["--unlisted", "maybe"])).toEqual({
      code: 2,
      reason: "CONFIG_INVALID: unlisted (passthrough or refuse)",
    });
    expect(await refusalOf(["--ca-cert", "/run/ca.crt"])).toEqual({
      code: 2,
      reason:
        "CONFIG_MISSING: AGENTSAFE_INTERCEPT_CA_KEY_FILE (the authority's certificate and key come together)",
    });
    expect(
      await refusalOf([
        "--govern",
        "a.example",
        "--ca-cert",
        "/run/none.crt",
        "--ca-key",
        "/run/ca.key",
      ]),
    ).toEqual({ code: 2, reason: "CONFIG_INVALID: AGENTSAFE_INTERCEPT_CA_CERT_FILE (unreadable)" });
    expect(
      await refusalOf([
        "--govern",
        "a.example",
        "--ca-cert",
        "/run/ca.crt",
        "--ca-key",
        "/run/none.key",
      ]),
    ).toEqual({ code: 2, reason: "CONFIG_INVALID: AGENTSAFE_INTERCEPT_CA_KEY_FILE (unreadable)" });
    expect(
      await refusalOf([
        "--govern",
        "a.example",
        "--ca-cert",
        "/run/leaf.crt",
        "--ca-key",
        "/run/ca.key",
      ]),
    ).toEqual({ code: 2, reason: "CA_NOT_AN_AUTHORITY: AGENTSAFE_INTERCEPT_CA_CERT_FILE" });
    // Production means Decionis; a governed destination with no key is a refusal, not a demo.
    const production = await refusalOf(
      ["--govern", "a.example", "--ca-cert", "/run/ca.crt", "--ca-key", "/run/ca.key"],
      { NODE_ENV: "production" },
    );
    expect(production.code).toBe(2);
    expect(production.reason).toMatch(/^CONFIG_(MISSING|INVALID): /);
  });
});

describe("InterceptGovernor", () => {
  it("refuses by name what it cannot take: no gateway, a handshake that fails, no authority", async () => {
    const operator = new TestCertificateAuthority("Operator CA");
    const issuer = new LeafIssuer({
      certificatePem: operator.certificate,
      keyPem: operator.privateKeyPem,
    });
    // The interceptor's listener allows half-open connections; so does this stand-in.
    const listener = createServer({ allowHalfOpen: true });
    listener.listen(0, "127.0.0.1");
    await once(listener, "listening");
    const port = (listener.address() as { port: number }).port;
    const accepted = new Promise<Socket>((resolve) => listener.once("connection", resolve));
    const client = connect({ host: "127.0.0.1", port });
    await once(client, "connect");
    const server = await accepted;
    const destination = { protocol: "TLS" as const, host: "a.example" };

    const noGateway = new InterceptGovernor(
      { hosts: new Set(["a.example"]), unlisted: "passthrough", issuer, handshakeTimeoutMs: 1_000 },
      { gatewayFor: () => Promise.reject(new Error("NO_KEY")) },
    );
    await expect(noGateway.take(server, Buffer.alloc(0), destination)).rejects.toMatchObject({
      code: "GOVERN_GATEWAY_UNAVAILABLE",
      detail: "NO_KEY",
      message: "GOVERN_GATEWAY_UNAVAILABLE: NO_KEY",
      name: "GovernError",
    });
    const noGatewayNoError = new InterceptGovernor(
      { hosts: new Set(["a.example"]), unlisted: "passthrough", issuer, handshakeTimeoutMs: 1_000 },
      { gatewayFor: () => Promise.reject("not an Error") },
    );
    await expect(noGatewayNoError.take(server, Buffer.alloc(0), destination)).rejects.toMatchObject(
      { code: "GOVERN_GATEWAY_UNAVAILABLE", detail: "UNKNOWN" },
    );
    expect(new GovernError("GOVERN_TLS_UNAVAILABLE").message).toBe("GOVERN_TLS_UNAVAILABLE");
    expect(new GovernError("GOVERN_TLS_UNAVAILABLE").detail).toBeNull();

    const gatewayFor = (): Promise<GatewayHttpServer> =>
      Promise.resolve({ accept: () => undefined } as unknown as GatewayHttpServer);
    const noAuthority = new InterceptGovernor(
      {
        hosts: new Set(["a.example"]),
        unlisted: "passthrough",
        issuer: null,
        handshakeTimeoutMs: 1_000,
      },
      { gatewayFor },
    );
    await expect(noAuthority.take(server, Buffer.alloc(0), destination)).rejects.toMatchObject({
      code: "GOVERN_TLS_UNAVAILABLE",
    });

    // Bytes that are a hello to the reader but not one OpenSSL can answer.
    const broken = new InterceptGovernor(
      { hosts: new Set(["a.example"]), unlisted: "passthrough", issuer, handshakeTimeoutMs: 1_000 },
      { gatewayFor },
    );
    const notAHello = Buffer.concat([
      Buffer.from([0x16, 0x03, 0x01, 0x00, 0x04]),
      Buffer.from([1, 0, 0, 0]),
    ]);
    const brokenRefusal = await broken
      .take(server, notAHello, destination)
      .catch((e: unknown) => e);
    expect(brokenRefusal).toBeInstanceOf(GovernError);
    expect((brokenRefusal as GovernError).code).toBe("GOVERN_HANDSHAKE_FAILED");
    // OpenSSL's own name for what went wrong, so the refusal says which.
    expect((brokenRefusal as GovernError).detail).toMatch(/^ERR_SSL_/);
    expect(server.destroyed).toBe(true);
    expect(broken.governs("a.example")).toBe(true);
    expect(broken.governs("b.example")).toBe(false);
    expect(broken.unlisted).toBe("passthrough");
    expect([...broken.hosts]).toEqual(["a.example"]);

    // A client that sends its hello and then nothing is given up on.
    const slow = new Promise<Socket>((resolve) => listener.once("connection", resolve));
    const quiet = connect({ host: "127.0.0.1", port });
    await once(quiet, "connect");
    const quietServer = await slow;
    const stalling = new InterceptGovernor(
      { hosts: new Set(["a.example"]), unlisted: "passthrough", issuer, handshakeTimeoutMs: 100 },
      { gatewayFor },
    );
    const captured = await capturedClientHello("a.example");
    await expect(stalling.take(quietServer, captured, destination)).rejects.toMatchObject({
      code: "GOVERN_HANDSHAKE_FAILED",
      detail: "TIMEOUT",
    });
    expect(quietServer.destroyed).toBe(true);

    // A client that goes away during the handshake, by a failure underneath
    // or by hanging up, is refused then and not when the timer says.
    const patient = new InterceptGovernor(
      { hosts: new Set(["a.example"]), unlisted: "passthrough", issuer, handshakeTimeoutMs: 5_000 },
      { gatewayFor },
    );
    for (const leave of [
      (_client: Socket, server: Socket) => server.destroy(new Error("wire gone")),
      (client: Socket) => client.destroy(),
      (client: Socket) => client.end(),
    ]) {
      const leaving = new Promise<Socket>((resolve) => listener.once("connection", resolve));
      const gone = connect({ host: "127.0.0.1", port });
      await once(gone, "connect");
      const goneServer = await leaving;
      const started = Date.now();
      const underneath = patient.take(goneServer, captured, destination);
      await settle();
      leave(gone, goneServer);
      await expect(underneath).rejects.toMatchObject({
        code: "GOVERN_HANDSHAKE_FAILED",
        detail: "CLOSED",
      });
      expect(Date.now() - started).toBeLessThan(2_000);
      expect(goneServer.destroyed).toBe(true);
      gone.destroy();
    }

    // A client that offers HTTP/2 alone is refused at the handshake, not misread.
    const h2Only = new Promise<Socket>((resolve) => listener.once("connection", resolve));
    const h2Client = tlsConnect({
      host: "127.0.0.1",
      port,
      servername: "a.example",
      ca: [operator.certificate],
      ALPNProtocols: ["h2"],
    });
    h2Client.on("error", () => undefined);
    const h2Server = await h2Only;
    const h2Hello = await new Promise<Buffer>((resolve) => h2Server.once("data", resolve));
    h2Server.pause();
    await expect(broken.take(h2Server, h2Hello, destination)).rejects.toMatchObject({
      code: "GOVERN_HANDSHAKE_FAILED",
      detail: expect.stringMatching(/^ERR_SSL_/) as string,
    });
    client.destroy();
    quiet.destroy();
    h2Client.destroy();
    listener.close();
  });

  it("keeps a governed connection past the handshake timeout, which bounds the handshake alone", async () => {
    const operator = new TestCertificateAuthority("Operator CA");
    const issuer = new LeafIssuer({
      certificatePem: operator.certificate,
      keyPem: operator.privateKeyPem,
    });
    // The interceptor's listener allows half-open connections; so does this stand-in.
    const listener = createServer({ allowHalfOpen: true });
    listener.listen(0, "127.0.0.1");
    await once(listener, "listening");
    const port = (listener.address() as { port: number }).port;
    const accepted: TLSSocket[] = [];
    const governor = new InterceptGovernor(
      { hosts: new Set(["a.example"]), unlisted: "passthrough", issuer, handshakeTimeoutMs: 400 },
      {
        gatewayFor: () =>
          Promise.resolve({
            accept: (connection: TLSSocket) => {
              accepted.push(connection);
              // The echo waits, so a client that has half-closed by then is
              // answered on the half still open.
              connection.on("data", (chunk: Buffer) =>
                setTimeout(() => connection.write(chunk), 100),
              );
            },
          } as unknown as GatewayHttpServer),
      },
    );
    const server = new Promise<Socket>((resolve) => listener.once("connection", resolve));
    const client = tlsConnect({
      host: "127.0.0.1",
      port,
      servername: "a.example",
      ca: [operator.certificate],
    });
    const raw = await server;
    const hello = await new Promise<Buffer>((resolve) => raw.once("data", resolve));
    raw.pause();
    await Promise.all([
      governor.take(raw, hello, { protocol: "TLS", host: "a.example" }),
      once(client, "secureConnect"),
    ]);
    await new Promise((resolve) => setTimeout(resolve, 900));
    expect(client.destroyed).toBe(false);
    expect(accepted[0]?.destroyed).toBe(false);
    client.write("still here");
    const [echoed] = (await once(client, "data")) as [Buffer];
    expect(echoed.toString()).toBe("still here");
    // The gateway may drop a governed connection with an error of its own
    // after the handshake; that error is the connection's, and is absorbed.
    accepted[0]?.destroy(new Error("dropped by the gateway"));
    await once(client, "close");
    expect(accepted[0]?.destroyed).toBe(true);
    client.destroy();

    // A client that half-closes after its request still gets the answer: the
    // end of the client's half is not the end of the connection.
    const halfServer = new Promise<Socket>((resolve) => listener.once("connection", resolve));
    const half = tlsConnect({
      host: "127.0.0.1",
      port,
      servername: "a.example",
      ca: [operator.certificate],
    });
    const halfRaw = await halfServer;
    const halfHello = await new Promise<Buffer>((resolve) => halfRaw.once("data", resolve));
    halfRaw.pause();
    await Promise.all([
      governor.take(halfRaw, halfHello, { protocol: "TLS", host: "a.example" }),
      once(half, "secureConnect"),
    ]);
    half.end("last words");
    const [answered] = (await Promise.race([
      once(half, "data"),
      new Promise<[Buffer]>((_, reject) =>
        setTimeout(() => reject(new Error("no answer after the half-close")), 1_000),
      ),
    ])) as [Buffer];
    expect(answered.toString()).toBe("last words");
    half.destroy();
    listener.close();
  });
});

describe("the replayed stream", () => {
  /** A connected socket pair on loopback: the interceptor's side, and the peer's. */
  async function pair(): Promise<{ mine: Socket; peer: Socket; close: () => void }> {
    const listener = createServer();
    listener.listen(0, "127.0.0.1");
    await once(listener, "listening");
    const accepted = new Promise<Socket>((resolve) => listener.once("connection", resolve));
    const peer = connect({
      host: "127.0.0.1",
      port: (listener.address() as { port: number }).port,
    });
    await once(peer, "connect");
    const mine = await accepted;
    mine.pause();
    return {
      mine,
      peer,
      close: () => {
        mine.destroy();
        peer.destroy();
        listener.close();
      },
    };
  }

  const collected = (stream: Readable): Promise<Buffer> =>
    new Promise((resolve) => {
      const chunks: Buffer[] = [];
      stream.on("data", (chunk: Buffer) => chunks.push(chunk));
      stream.once("end", () => resolve(Buffer.concat(chunks)));
    });

  it("delivers the head first, then the socket, and writes and ends through to the peer", async () => {
    const { mine, peer, close } = await pair();
    const adapter = replayed(mine, Buffer.from("head:"));
    const read = collected(adapter);
    const peerRead = collected(peer);
    peer.write("body");
    adapter.write("answer");
    await settle();
    adapter.end();
    await once(adapter, "finish");
    await once(peer, "end");
    peer.end();
    expect((await read).toString()).toBe("head:body");
    expect((await peerRead).toString()).toBe("answer");
    close();
  });

  it("pauses the socket while its reader is behind and resumes it when read", async () => {
    const { mine, peer, close } = await pair();
    const adapter = replayed(mine, Buffer.alloc(0));
    mine.resume();
    peer.write(Buffer.alloc(16, 1));
    await settle();
    // Room to spare: the socket flows.
    expect(mine.isPaused()).toBe(false);
    expect(adapter.readableLength).toBe(16);
    const payload = Buffer.alloc(adapter.readableHighWaterMark * 4, 2);
    peer.write(payload);
    await settle();
    // Behind by more than the buffer: the socket is paused, and the buffer is bounded.
    expect(mine.isPaused()).toBe(true);
    expect(adapter.readableLength).toBeLessThan(payload.length);
    peer.end();
    const all = await collected(adapter);
    expect(all.length).toBe(16 + payload.length);
    expect(all.subarray(16).every((byte) => byte === 2)).toBe(true);
    close();
  });

  it("is destroyed with the socket's error, and destroyed when the socket closes", async () => {
    const errored = await pair();
    const failing = replayed(errored.mine, Buffer.alloc(0));
    const failure = once(failing, "error");
    errored.mine.destroy(new Error("wire gone"));
    expect(((await failure)[0] as Error).message).toBe("wire gone");
    expect(failing.destroyed).toBe(true);
    errored.close();

    const closed = await pair();
    const orphaned = replayed(closed.mine, Buffer.alloc(0));
    orphaned.on("error", () => undefined);
    closed.mine.destroy();
    await once(orphaned, "close");
    expect(orphaned.destroyed).toBe(true);
    closed.close();

    const dropped = await pair();
    const dropping = replayed(dropped.mine, Buffer.alloc(0));
    dropping.destroy();
    await once(dropping, "close");
    expect(dropped.mine.destroyed).toBe(true);
    dropped.close();
  });
});

/** A real ClientHello for `servername`, as Node's client sends it, captured off a raw listener. */
async function capturedClientHello(servername: string): Promise<Buffer> {
  const sink = createServer();
  sink.listen(0, "127.0.0.1");
  await once(sink, "listening");
  const first = new Promise<Buffer>((resolve) =>
    sink.once("connection", (socket: Socket) =>
      socket.once("data", (chunk: Buffer) => {
        resolve(chunk);
        socket.destroy();
      }),
    ),
  );
  const client = tlsConnect({
    host: "127.0.0.1",
    port: (sink.address() as { port: number }).port,
    servername,
    ca: [new TestCertificateAuthority().certificate],
  });
  client.on("error", () => undefined);
  const hello = await first;
  client.destroy();
  sink.close();
  return hello;
}
