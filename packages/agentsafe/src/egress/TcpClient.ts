import { createHash, timingSafeEqual } from "node:crypto";
import { connect, createServer, isIP, type AddressInfo, type Server, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { readConnectResponse, readLine, requireControl, TcpClientError } from "../tcp/TcpWire.js";

export const TCP_CLIENT_LIMITS = {
  spareLegs: 2,
  maxLegs: 8,
  controlTimeoutMs: 10_000,
  connectTimeoutMs: 10_000,
  responseTimeoutMs: 35_000,
  // Waiting connector legs remain subject to broker leases, idle expiry, and this ceiling.
  attachTimeoutMs: 3_600_000,
  idleTimeoutMs: 300_000,
  sessionTimeoutMs: 3_600_000,
  maxBytes: 1024 * 1024 * 1024,
  reconnectMinMs: 1_000,
  reconnectMaxMs: 30_000,
} as const;

export type TcpRole = "connector" | "client";
export interface TcpTarget {
  readonly host: string;
  readonly port: number;
  readonly resource: string;
}
export interface TcpClientConfig {
  /** Fixed local configuration, never supplied by a broker or a ticket. */
  readonly controlApi: string;
  readonly gatewayUrl: string;
  readonly routeId: string;
  readonly target: string;
  /** Read a role-specific credential file again for each ticket; never a workspace key. */
  readonly credential: () => string;
}
export interface TcpClientEvent {
  readonly event: string;
  readonly route_id: string;
  readonly code?: string;
}
export interface TcpClientDependencies {
  readonly fetch?: FetchLike;
  readonly report?: (event: TcpClientEvent) => void;
  /** CLI test seam; production reads a bounded, owner-only regular file from one descriptor. */
  readonly readCredential?: (path: string) => string;
  /** Tests may supply a verified local TLS peer. Production always uses verifiedTls. */
  readonly dialGateway?: (hostname: string, signal: AbortSignal) => Promise<Socket>;
  readonly dialTarget?: (target: TcpTarget, signal: AbortSignal) => Promise<Socket>;
  readonly clock?: () => number;
  readonly reconnectMinMs?: number;
  readonly reconnectMaxMs?: number;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TICKET = /^[\w-]{43}$/;

export function parseTcpTarget(value: string): TcpTarget {
  const match = /^(?:\[([0-9a-f:.]+)\]|([0-9.]+)):(\d{1,5})$/i.exec(value);
  if (match === null) throw new TcpClientError("TCP_TARGET_INVALID");
  const host = match[1] ?? match[2] ?? "";
  const port = Number(match[3]);
  const family = isIP(host);
  if (port < 1 || port > 65535 || family === 0 || (match[1] !== undefined && family !== 6)) {
    throw new TcpClientError("TCP_TARGET_INVALID");
  }
  const canonicalHost =
    family === 6 ? new URL(`tcp://[${host}]:${port}`).hostname.slice(1, -1) : host;
  return {
    host: canonicalHost,
    port,
    resource: `${family === 6 ? `[${canonicalHost}]` : canonicalHost}:${port}`,
  };
}

function httpsOrigin(raw: string, gateway: boolean): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new TcpClientError("TCP_URL_INVALID");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    /[\r\n]/.test(raw) ||
    (gateway &&
      (url.port !== "" ||
        url.hostname.length > 253 ||
        !HOST.test(url.hostname) ||
        isIP(url.hostname) !== 0))
  ) {
    throw new TcpClientError("TCP_URL_INVALID");
  }
  return url;
}

/** Numeric dialing avoids DNS and cannot be redirected by the control plane. */
function targetDial(target: TcpTarget, signal: AbortSignal): Promise<Socket> {
  return connected(
    () => connect({ host: target.host, port: target.port, allowHalfOpen: true }),
    "connect",
    signal,
  );
}

/** Always verify the tenant hostname against public roots; no insecure client option. */
export function verifiedTls(
  hostname: string,
  signal: AbortSignal,
  transport: { readonly address?: string; readonly port?: number; readonly ca?: string } = {},
): Promise<Socket> {
  return connected(
    () =>
      tlsConnect({
        host: transport.address ?? hostname,
        port: transport.port ?? 443,
        servername: hostname,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        ALPNProtocols: ["http/1.1"],
        ...{ allowHalfOpen: true },
        ...(transport.ca === undefined ? {} : { ca: transport.ca }),
      }),
    "secureConnect",
    signal,
  );
}

function connected(
  make: () => Socket,
  event: "connect" | "secureConnect",
  signal: AbortSignal,
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new TcpClientError("TCP_STOPPED"));
      return;
    }
    const socket = make();
    // Every socket has an error listener even between framing and the raw splice.
    socket.on("error", () => undefined);
    const cleanup = (): void => {
      clearTimeout(timer);
      socket.removeListener("error", failed);
      socket.removeListener(event, ready);
      signal.removeEventListener("abort", aborted);
    };
    const failed = (): void => {
      cleanup();
      socket.destroy();
      reject(new TcpClientError("TCP_CONNECT_FAILED"));
    };
    const aborted = (): void => {
      cleanup();
      socket.destroy();
      reject(new TcpClientError("TCP_STOPPED"));
    };
    const ready = (): void => {
      cleanup();
      socket.pause();
      resolve(socket);
    };
    const timer = setTimeout(() => {
      cleanup();
      socket.destroy();
      reject(new TcpClientError("TCP_CONNECT_TIMEOUT"));
    }, TCP_CLIENT_LIMITS.connectTimeoutMs);
    socket.once("error", failed);
    socket.once(event, ready);
    signal.addEventListener("abort", aborted, { once: true });
  });
}

async function boundedJson(response: Response): Promise<unknown> {
  if (response.body === null) throw new TcpClientError("TCP_TICKET_INVALID");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.length;
      if (size > 8192) throw new TcpClientError("TCP_TICKET_INVALID");
      chunks.push(chunk.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new TcpClientError("TCP_TICKET_INVALID");
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

class RouteClient {
  public readonly target: TcpTarget;
  public readonly gateway: URL;
  private readonly control: URL;
  private readonly resourceHash: Buffer;

  public constructor(
    public readonly config: TcpClientConfig,
    protected readonly dependencies: TcpClientDependencies,
  ) {
    if (!UUID.test(config.routeId)) throw new TcpClientError("TCP_ROUTE_INVALID");
    this.target = parseTcpTarget(config.target);
    this.gateway = httpsOrigin(config.gatewayUrl, true);
    this.control = httpsOrigin(config.controlApi, false);
    this.resourceHash = createHash("sha256").update(this.target.resource).digest();
  }

  protected report(event: string, code?: string): void {
    this.dependencies.report?.({
      event,
      route_id: this.config.routeId,
      ...(code === undefined ? {} : { code }),
    });
  }

  protected async leg(
    role: TcpRole,
    signal: AbortSignal,
    track: (socket: Socket) => void,
  ): Promise<{ socket: Socket; tail: Buffer }> {
    const ticket = await this.ticket(role, signal);
    if (signal.aborted) throw new TcpClientError("TCP_STOPPED");
    const socket = await (this.dependencies.dialGateway ?? verifiedTls)(
      this.gateway.hostname,
      signal,
    );
    track(socket);
    if (signal.aborted) {
      socket.destroy();
      throw new TcpClientError("TCP_STOPPED");
    }
    socket.on("error", () => undefined);
    try {
      socket.write(
        `CONNECT ${this.config.routeId}:443 HTTP/1.1\r\nHost: ${this.gateway.hostname}\r\nAuthorization: Bearer ${ticket}\r\nAgentSafe-TCP-Role: ${role}\r\n\r\n`,
      );
      const response = await readConnectResponse(
        socket,
        16384,
        TCP_CLIENT_LIMITS.responseTimeoutMs,
        signal,
      );
      if (response.status !== 200) throw new TcpClientError("TCP_CONNECT_REFUSED");
      return { socket, tail: response.tail };
    } catch (error) {
      socket.destroy();
      throw error;
    }
  }

  private async ticket(role: TcpRole, signal: AbortSignal): Promise<string> {
    const credential = this.config.credential();
    if (!/^[\w.~-]{16,2048}$/.test(credential)) throw new TcpClientError("TCP_CREDENTIAL_INVALID");
    let response: Response;
    try {
      response = await (this.dependencies.fetch ?? fetch)(
        new URL("/v1/public/gateway/tcp/tickets", this.control),
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${credential}`,
            "content-type": "application/json",
            accept: "application/json",
          },
          body: JSON.stringify({ route_id: this.config.routeId, role }),
          redirect: "error",
          signal: AbortSignal.any([
            signal,
            AbortSignal.timeout(TCP_CLIENT_LIMITS.controlTimeoutMs),
          ]),
        },
      );
    } catch {
      throw new TcpClientError("TCP_TICKET_UNAVAILABLE");
    }
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      throw new TcpClientError("TCP_TICKET_REFUSED");
    }
    const raw = await boundedJson(response);
    if (typeof raw !== "object" || raw === null || Array.isArray(raw))
      throw new TcpClientError("TCP_TICKET_INVALID");
    const value = raw as Record<string, unknown>;
    const expiry = typeof value["expires_at"] === "string" ? Date.parse(value["expires_at"]) : NaN;
    const now = (this.dependencies.clock ?? Date.now)();
    if (
      value["route_id"] !== this.config.routeId ||
      value["tenant_host"] !== this.gateway.hostname ||
      value["gateway_url"] !== this.gateway.origin ||
      value["resource"] !== this.target.resource ||
      (value["role"] !== undefined && value["role"] !== role) ||
      typeof value["ticket"] !== "string" ||
      !TICKET.test(value["ticket"]) ||
      typeof value["resource_hash"] !== "string" ||
      !/^[a-f0-9]{64}$/.test(value["resource_hash"]) ||
      !Number.isFinite(expiry) ||
      expiry <= now ||
      expiry > now + 120_000
    ) {
      throw new TcpClientError("TCP_TICKET_BINDING_MISMATCH");
    }
    if (!timingSafeEqual(this.resourceHash, Buffer.from(value["resource_hash"], "hex"))) {
      throw new TcpClientError("TCP_TICKET_BINDING_MISMATCH");
    }
    return value["ticket"];
  }
}

/** Backpressure, buffered framing tails, half-close, and hard session/byte ceilings. */
export function spliceTcp(
  left: Socket,
  right: Socket,
  leftTail: Buffer,
  rightTail: Buffer,
  signal: AbortSignal,
): Promise<void> {
  return new Promise((resolve) => {
    let closed = false;
    let bytes = 0;
    const finish = (): void => {
      if (closed) return;
      closed = true;
      clearTimeout(lifetime);
      signal.removeEventListener("abort", finish);
      left.destroy();
      right.destroy();
      resolve();
    };
    const forward = (source: Socket, destination: Socket, chunk: Buffer): void => {
      bytes += chunk.length;
      if (bytes > TCP_CLIENT_LIMITS.maxBytes) {
        finish();
        return;
      }
      if (!destination.write(chunk)) source.pause();
    };
    const lifetime = setTimeout(finish, TCP_CLIENT_LIMITS.sessionTimeoutMs);
    for (const [source, destination] of [
      [left, right],
      [right, left],
    ] as const) {
      source.on("data", (chunk: Buffer) => forward(source, destination, chunk));
      source.on("drain", () => destination.resume());
      source.on("end", () => destination.end());
      source.once("error", finish);
      source.once("close", finish);
      source.setTimeout(TCP_CLIENT_LIMITS.idleTimeoutMs);
      source.on("timeout", finish);
    }
    signal.addEventListener("abort", finish, { once: true });
    if (signal.aborted || left.destroyed || right.destroyed) {
      finish();
      return;
    }
    if (leftTail.length > 0) forward(left, right, leftTail);
    if (rightTail.length > 0) forward(right, left, rightTail);
    if (left.readableEnded) right.end();
    if (right.readableEnded) left.end();
    if (!closed) {
      if (!right.writableNeedDrain) left.resume();
      if (!left.writableNeedDrain) right.resume();
    }
  });
}

interface ConnectorLeg {
  state: "waiting" | "active";
  readonly abort: AbortController;
  readonly sockets: Set<Socket>;
  done: Promise<void>;
}

/** Two waiting outbound legs, at most eight total legs, and one bounded retry timer. */
export class TcpConnector extends RouteClient {
  private readonly legs = new Set<ConnectorLeg>();
  private retry: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  private started = false;
  private failures = 0;

  public constructor(config: TcpClientConfig, dependencies: TcpClientDependencies = {}) {
    super(config, dependencies);
  }

  public start(): void {
    if (this.started || this.stopped) return;
    this.started = true;
    this.report("TCP_CONNECTOR_STARTED");
    this.fill();
  }

  public snapshot(): { readonly waiting: number; readonly active: number } {
    const waiting = [...this.legs].filter((leg) => leg.state === "waiting").length;
    return { waiting, active: this.legs.size - waiting };
  }

  public async close(): Promise<void> {
    this.stopped = true;
    if (this.retry !== null) clearTimeout(this.retry);
    this.retry = null;
    const remaining = [...this.legs];
    for (const leg of remaining) {
      leg.abort.abort();
      for (const socket of leg.sockets) socket.destroy();
    }
    await Promise.all(remaining.map((leg) => leg.done));
    this.report("TCP_CONNECTOR_STOPPED");
  }

  private fill(): void {
    if (this.stopped) return;
    while (
      this.legs.size < TCP_CLIENT_LIMITS.maxLegs &&
      this.snapshot().waiting < TCP_CLIENT_LIMITS.spareLegs
    ) {
      const leg: ConnectorLeg = {
        state: "waiting",
        abort: new AbortController(),
        sockets: new Set(),
        done: Promise.resolve(),
      };
      this.legs.add(leg);
      leg.done = this.run(leg).finally(() => {
        this.legs.delete(leg);
        this.schedule();
      });
    }
  }

  private schedule(): void {
    if (this.stopped || this.retry !== null) return;
    const min = this.dependencies.reconnectMinMs ?? TCP_CLIENT_LIMITS.reconnectMinMs;
    const max = this.dependencies.reconnectMaxMs ?? TCP_CLIENT_LIMITS.reconnectMaxMs;
    const delay = Math.min(max, min * 2 ** Math.min(this.failures, 5));
    this.retry = setTimeout(() => {
      this.retry = null;
      this.fill();
    }, delay);
  }

  private async run(leg: ConnectorLeg): Promise<void> {
    let remote: Socket | undefined;
    try {
      const opened = await this.leg("connector", leg.abort.signal, (socket) =>
        leg.sockets.add(socket),
      );
      remote = opened.socket;
      this.failures = 0;
      this.report("TCP_CONNECTOR_WAITING");
      const attach = await readLine(
        remote,
        1024,
        TCP_CLIENT_LIMITS.attachTimeoutMs,
        opened.tail,
        leg.abort.signal,
      );
      requireControl(attach.line, "attach");
      if (leg.abort.signal.aborted) throw new TcpClientError("TCP_STOPPED");
      // The only destination is this.target, fixed and validated before the ticket request.
      const local = await (this.dependencies.dialTarget ?? targetDial)(
        this.target,
        leg.abort.signal,
      );
      leg.sockets.add(local);
      if (leg.abort.signal.aborted || remote.destroyed) {
        local.destroy();
        throw new TcpClientError("TCP_STOPPED");
      }
      remote.write('{"type":"ready"}\n');
      leg.state = "active";
      this.failures = 0;
      this.report("TCP_CONNECTOR_ATTACHED");
      this.fill();
      await spliceTcp(remote, local, attach.tail, Buffer.alloc(0), leg.abort.signal);
    } catch (error) {
      if (!this.stopped) {
        this.failures += 1;
        this.report(
          "TCP_CONNECTOR_RETRY",
          error instanceof TcpClientError ? error.code : "TCP_CONNECTION_FAILED",
        );
        if (remote !== undefined && !remote.destroyed && remote.writable) {
          const socket = remote;
          await new Promise<void>((resolve) => {
            const timer = setTimeout(resolve, 1000);
            socket.end('{"type":"error"}\n', () => {
              clearTimeout(timer);
              resolve();
            });
          });
        }
      }
    } finally {
      for (const socket of leg.sockets) socket.destroy();
    }
  }
}

interface TunnelLeg {
  readonly local: Socket;
  readonly abort: AbortController;
  remote?: Socket;
  done: Promise<void>;
}

/** One loopback listener; never accepts a bind address or a destination from its clients. */
export class TcpTunnel extends RouteClient {
  private readonly server: Server;
  private readonly legs = new Set<TunnelLeg>();
  private stopped = false;
  private listening = false;

  public constructor(config: TcpClientConfig, dependencies: TcpClientDependencies = {}) {
    super(config, dependencies);
    this.server = createServer({ allowHalfOpen: true, pauseOnConnect: true }, (local) =>
      this.accept(local),
    );
    this.server.maxConnections = TCP_CLIENT_LIMITS.maxLegs;
  }

  public async listen(port: number): Promise<AddressInfo> {
    if (this.stopped || this.listening || !Number.isInteger(port) || port < 0 || port > 65535) {
      throw new TcpClientError("TCP_LISTEN_INVALID");
    }
    await new Promise<void>((resolve, reject) => {
      const failed = (): void => reject(new TcpClientError("TCP_LISTEN_FAILED"));
      this.server.once("error", failed);
      this.server.listen(port, "127.0.0.1", () => {
        this.server.removeListener("error", failed);
        resolve();
      });
    });
    this.listening = true;
    this.report("TCP_TUNNEL_STARTED");
    return this.server.address() as AddressInfo;
  }

  public async close(): Promise<void> {
    this.stopped = true;
    const remaining = [...this.legs];
    for (const leg of remaining) {
      leg.abort.abort();
      leg.local.destroy();
      leg.remote?.destroy();
    }
    if (this.listening) {
      await new Promise<void>((resolve) => this.server.close(() => resolve()));
      this.listening = false;
    }
    await Promise.all(remaining.map((leg) => leg.done));
    this.report("TCP_TUNNEL_STOPPED");
  }

  private accept(local: Socket): void {
    local.on("error", () => undefined);
    if (this.stopped || this.legs.size >= TCP_CLIENT_LIMITS.maxLegs) {
      local.destroy();
      return;
    }
    const leg: TunnelLeg = { local, abort: new AbortController(), done: Promise.resolve() };
    this.legs.add(leg);
    local.once("close", () => {
      leg.abort.abort();
      leg.remote?.destroy();
    });
    leg.done = this.run(leg).finally(() => {
      this.legs.delete(leg);
      local.destroy();
      leg.remote?.destroy();
    });
  }

  private async run(leg: TunnelLeg): Promise<void> {
    try {
      const opened = await this.leg("client", leg.abort.signal, (socket) => {
        leg.remote = socket;
      });
      this.report("TCP_TUNNEL_ATTACHED");
      await spliceTcp(leg.local, opened.socket, Buffer.alloc(0), opened.tail, leg.abort.signal);
    } catch (error) {
      if (!this.stopped)
        this.report(
          "TCP_TUNNEL_REFUSED",
          error instanceof TcpClientError ? error.code : "TCP_CONNECTION_FAILED",
        );
    }
  }
}
