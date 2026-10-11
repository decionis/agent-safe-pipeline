import { once } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Server } from "node:https";
import type { AddressInfo, Socket } from "node:net";
import type { Duplex } from "node:stream";
import type { TLSSocket } from "node:tls";
import type { TlsListener } from "./TlsListener.js";
import {
  type TcpBinding,
  type TcpControl,
  type TcpGrant,
  validGrant,
} from "../egress/TcpControlClient.js";
import {
  connectedTcp,
  controlLine,
  refuseTcp,
  spliceTcp,
  TCP_TICKET,
  TCP_TRANSPORT,
  TCP_UUID,
  tenantHostname,
} from "./TcpRelayStreams.js";

export const TCP_BROKER_SERVERNAME = "tcp-broker.decionisedge.com";
export const TCP_BROKER_LIMITS = Object.freeze({
  totalLegs: 128,
  organizationLegs: 16,
  routeLegs: 8,
  pairMs: 20_000,
  connectMs: 10_000,
  idleMs: 300_000,
  sessionMs: 3_600_000,
  maxBytes: 1024 ** 3,
  refreshMs: 10_000,
});
export type TcpBrokerLimits = { [Key in keyof typeof TCP_BROKER_LIMITS]: number };
type Limits = TcpBrokerLimits;
interface Leg {
  socket: Duplex;
  head: Buffer;
  binding: TcpBinding;
  grant: TcpGrant | null;
  closed: boolean;
  responded: boolean;
  paired: Leg | null;
  phase: "waiting" | "active";
  pairTimer: ReturnType<typeof setTimeout> | null;
  lifetimeTimer: ReturnType<typeof setTimeout> | null;
  expiryTimer: ReturnType<typeof setTimeout> | null;
  refreshTimer: ReturnType<typeof setInterval> | null;
  refreshing: boolean;
  waitingCleanup: (() => void) | null;
}

/** Validate before using a header in a dial, control-plane call or response. */
export function tcpRequest(
  request: IncomingMessage,
  domain: string | null,
  publicEdge: boolean,
): { binding: TcpBinding; ticket: string } | null {
  const tls = request.socket as TLSSocket;
  const host = request.headers.host;
  if (!tls.encrypted || !tenantHostname(host, domain)) return null;
  if (tls.servername !== (publicEdge ? host : TCP_BROKER_SERVERNAME)) return null;
  for (const name of ["host", "authorization", "agentsafe-tcp-role"]) {
    if (
      request.rawHeaders.filter(
        (_, index) => index % 2 === 0 && request.rawHeaders[index]?.toLowerCase() === name,
      ).length !== 1
    )
      return null;
  }
  const authority = request.url ?? "";
  const route = authority.endsWith(":443") ? authority.slice(0, -4) : "";
  const role = request.headers["agentsafe-tcp-role"];
  const auth = request.headers.authorization;
  if (
    !TCP_UUID.test(route) ||
    (role !== "connector" && role !== "client") ||
    !auth?.startsWith("Bearer ") ||
    !TCP_TICKET.test(auth.slice(7))
  )
    return null;
  if (
    request.headers["transfer-encoding"] ||
    (request.headers["content-length"] !== undefined && request.headers["content-length"] !== "0")
  )
    return null;
  return { binding: { route_id: route, tenant_host: host!, role }, ticket: auth.slice(7) };
}

/** One rendezvous process. The fleet never dials the target; the connector owns that socket. */
export class TcpBroker {
  private readonly server: Server;
  private readonly legs = new Set<Leg>();
  private readonly rawSockets = new Set<Socket>();
  private readonly admissions = new Set<Promise<void>>();
  private readonly closingLeases = new Set<Promise<void>>();
  private stopping = false;
  private readonly limits: Limits;
  public constructor(
    private readonly options: {
      tls: TlsListener;
      domain: string;
      control: TcpControl;
      limits?: Partial<Limits>;
    },
  ) {
    this.limits = { ...TCP_BROKER_LIMITS, ...options.limits };
    this.server = options.tls.createServer(
      (req, res) => {
        void this.health(req, res);
      },
      { handshakeTimeoutMs: 10_000 },
    );
    this.server.requestTimeout = 10_000;
    this.server.headersTimeout = 10_000;
    this.server.keepAliveTimeout = 1_000;
    this.server.maxConnections = this.limits.totalLegs * 2;
    this.server.on("connection", (socket) => {
      this.rawSockets.add(socket);
      socket.once("close", () => this.rawSockets.delete(socket));
    });
    this.server.on("connect", (request, socket, head) => {
      const admission = this.connect(request, socket, head);
      this.admissions.add(admission);
      void admission.finally(() => this.admissions.delete(admission)).catch(() => socket.destroy());
    });
    this.server.on("clientError", (_error, socket) => socket.destroy());
  }
  public async listen(port: number, host: string): Promise<AddressInfo> {
    this.server.listen(port, host);
    await once(this.server, "listening");
    return this.server.address() as AddressInfo;
  }
  public rotateTls(): void {
    this.options.tls.rotate(this.server);
  }
  public async close(): Promise<void> {
    this.stopping = true;
    for (const leg of [...this.legs]) this.finish(leg);
    for (const socket of this.rawSockets) socket.destroy();
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    // Control requests have their own five-second bound. A late redeemed ticket
    // must release its lease before the process exits, without reopening a leg.
    await Promise.allSettled([...this.admissions]);
    await Promise.allSettled([...this.closingLeases]);
  }
  private async health(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const live = !this.stopping;
    const known = req.method === "GET" && (req.url === "/healthz" || req.url === "/readyz");
    const ready =
      known &&
      live &&
      (req.url === "/healthz" || (await this.options.control.ready().catch(() => false)));
    const body = JSON.stringify({ transport: TCP_TRANSPORT, ready });
    res.writeHead(!known ? 404 : ready ? 200 : 503, {
      "content-type": "application/json",
      "cache-control": "no-store",
      "content-length": Buffer.byteLength(body),
    });
    res.end(body);
  }
  private async connect(request: IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
    socket.on("error", () => undefined);
    socket.pause();
    (socket as TLSSocket).allowHalfOpen = true;
    const parsed = tcpRequest(request, this.options.domain, false);
    if (!parsed || head.length > 65_536 || (parsed.binding.role === "connector" && head.length > 0))
      return refuseTcp(socket, 400, "TCP_REQUEST_INVALID");
    if (this.stopping || this.legs.size >= this.limits.totalLegs)
      return refuseTcp(socket, 503, "TCP_CAPACITY_REACHED");
    const leg: Leg = {
      socket,
      head,
      binding: parsed.binding,
      grant: null,
      closed: false,
      responded: false,
      paired: null,
      phase: "waiting",
      pairTimer: null,
      lifetimeTimer: null,
      expiryTimer: null,
      refreshTimer: null,
      refreshing: false,
      waitingCleanup: null,
    };
    this.legs.add(leg);
    socket.once("close", () => this.finish(leg));
    if (leg.binding.role === "connector") this.waitForClient(leg);
    try {
      const grant = validGrant(
        await this.options.control.redeem(parsed.ticket, parsed.binding),
        parsed.binding,
      );
      if (leg.closed) {
        this.release(grant);
        return;
      }
      leg.grant = grant;
      const organization = [...this.legs].filter(
        (other) => other !== leg && other.grant?.org_id === grant.org_id,
      );
      if (
        organization.length >= this.limits.organizationLegs ||
        organization.filter((other) => other.grant?.route_id === grant.route_id).length >=
          this.limits.routeLegs
      )
        return this.reject(leg, 429, "TCP_CAPACITY_REACHED");
      this.expiry(leg);
      leg.refreshTimer = setInterval(() => {
        void this.refresh(leg);
      }, this.limits.refreshMs);
      leg.refreshTimer.unref();
      // Spare connectors stay authenticated and ready between clients. The
      // client pairing deadline is not a reason to recycle a healthy spare.
      // All legs still have a total lifetime, including their waiting time.
      leg.lifetimeTimer = setTimeout(() => this.finish(leg), this.limits.sessionMs);
      leg.lifetimeTimer.unref();
      if (leg.binding.role === "client") {
        leg.pairTimer = setTimeout(
          () => this.reject(leg, 504, "TCP_PAIR_TIMEOUT"),
          this.limits.pairMs,
        );
        leg.pairTimer.unref();
      }
      if (leg.binding.role === "connector") {
        connectedTcp(socket);
        leg.responded = true;
      }
      const mate = [...this.legs].find(
        (other) =>
          other !== leg &&
          !other.closed &&
          !other.paired &&
          other.grant &&
          other.binding.role !== leg.binding.role &&
          this.sameRoute(grant, other.grant),
      );
      if (mate) void this.pair(leg, mate);
    } catch {
      this.reject(leg, 403, "TCP_TICKET_REFUSED");
    }
  }
  private sameRoute(a: TcpGrant, b: TcpGrant): boolean {
    return ["org_id", "route_id", "generation", "tenant_host", "resource_hash"].every(
      (key) => a[key as keyof TcpGrant] === b[key as keyof TcpGrant],
    );
  }
  private waitForClient(leg: Leg): void {
    // A spare sends nothing until attach. Read to observe FIN and refuse early
    // bytes instead of leaving a dead paused socket leasing capacity forever.
    const premature = (): void => this.finish(leg);
    const ended = (): void => this.finish(leg);
    leg.socket.on("data", premature);
    leg.socket.once("end", ended);
    leg.waitingCleanup = () => {
      leg.socket.pause();
      leg.socket.off("data", premature);
      leg.socket.off("end", ended);
    };
    leg.socket.resume();
  }
  private async pair(first: Leg, second: Leg): Promise<void> {
    const connector = first.binding.role === "connector" ? first : second;
    const client = first.binding.role === "client" ? first : second;
    if (connector.socket.readableLength > 0 || connector.socket.readableEnded) {
      this.finish(connector);
      return;
    }
    first.paired = second;
    second.paired = first;
    if (first.pairTimer) clearTimeout(first.pairTimer);
    if (second.pairTimer) clearTimeout(second.pairTimer);
    first.waitingCleanup?.();
    second.waitingCleanup?.();
    first.waitingCleanup = second.waitingCleanup = null;
    try {
      connector.socket.write('{"type":"attach"}\n');
      const reply = await controlLine(connector.socket, connector.head, this.limits.connectMs);
      if (reply.line !== '{"type":"ready"}' || connector.closed || client.closed)
        return this.reject(client, 502, "TCP_TARGET_UNAVAILABLE");
      if (
        !connector.grant ||
        !client.grant ||
        Date.parse(connector.grant.expires_at) <= Date.now() + 250 ||
        Date.parse(client.grant.expires_at) <= Date.now() + 250
      )
        return this.reject(client, 403, "TCP_LEASE_EXPIRED");
      connector.phase = "active";
      client.phase = "active";
      connectedTcp(client.socket);
      client.responded = true;
      spliceTcp(client.socket, connector.socket, {
        leftHead: client.head,
        rightHead: reply.tail,
        idleMs: this.limits.idleMs,
        lifetimeMs: this.limits.sessionMs,
        maxBytes: this.limits.maxBytes,
        closed: () => this.finish(client),
      });
    } catch {
      this.reject(client, 502, "TCP_TARGET_UNAVAILABLE");
    }
  }
  private expiry(leg: Leg): void {
    if (leg.expiryTimer) clearTimeout(leg.expiryTimer);
    leg.expiryTimer = setTimeout(
      () => this.finish(leg),
      Math.max(0, Date.parse(leg.grant!.expires_at) - Date.now() - 250),
    );
    leg.expiryTimer.unref();
  }
  private async refresh(leg: Leg): Promise<void> {
    if (leg.closed || !leg.grant || leg.refreshing) return;
    leg.refreshing = true;
    try {
      const grant = validGrant(
        await this.options.control.refresh(leg.grant, leg.phase),
        leg.binding,
        leg.grant,
      );
      if (!leg.closed) {
        leg.grant = grant;
        this.expiry(leg);
      }
    } catch {
      this.finish(leg);
    } finally {
      leg.refreshing = false;
    }
  }
  private reject(leg: Leg, status: number, code: string): void {
    if (!leg.closed && !leg.responded) {
      refuseTcp(leg.socket, status, code);
      this.finish(leg, false);
    } else this.finish(leg);
  }
  private finish(leg: Leg, destroy = true): void {
    if (leg.closed) return;
    leg.closed = true;
    this.legs.delete(leg);
    leg.waitingCleanup?.();
    if (leg.pairTimer) clearTimeout(leg.pairTimer);
    if (leg.lifetimeTimer) clearTimeout(leg.lifetimeTimer);
    if (leg.expiryTimer) clearTimeout(leg.expiryTimer);
    if (leg.refreshTimer) clearInterval(leg.refreshTimer);
    if (destroy) leg.socket.destroy();
    if (leg.grant) this.release(leg.grant);
    if (leg.paired) this.finish(leg.paired);
  }
  private release(grant: TcpGrant): void {
    const closing = this.options.control.close(grant).catch(() => undefined);
    this.closingLeases.add(closing);
    void closing.finally(() => this.closingLeases.delete(closing));
  }
}
