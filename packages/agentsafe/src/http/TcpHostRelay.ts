import type { IncomingMessage } from "node:http";
import { request } from "node:https";
import type { Duplex } from "node:stream";
import type { TLSSocket } from "node:tls";
import { TCP_BROKER_LIMITS, TCP_BROKER_SERVERNAME, tcpRequest } from "./TcpBroker.js";
import {
  connectedTcp,
  refuseTcp,
  spliceTcp,
  TCP_TRANSPORT,
  tenantHostname,
} from "./TcpRelayStreams.js";

/** The host's sole TCP destination is operator configuration, never a request field. */
export class TcpHostRelay {
  private readonly legs = new Set<() => void>();
  private stopped = false;
  private probing: Promise<boolean> | null = null;
  private lastProbe = 0;
  private lastReady = false;
  private cancelProbe: (() => void) | null = null;
  public constructor(
    private readonly options: {
      host: string;
      port: number;
      domain: () => string | null;
      ca?: string;
      maxLegs?: number;
    },
  ) {
    if (
      !/^[a-z0-9.-]{1,253}$/i.test(options.host) ||
      !Number.isInteger(options.port) ||
      options.port < 1 ||
      options.port > 65_535
    )
      throw new Error("TCP_BROKER_ADDRESS_INVALID");
  }
  public async capabilities(req: IncomingMessage): Promise<boolean> {
    const socket = req.socket as TLSSocket;
    if (
      this.stopped ||
      !socket.encrypted ||
      socket.servername !== req.headers.host ||
      !tenantHostname(req.headers.host, this.options.domain())
    )
      return false;
    if (Date.now() - this.lastProbe < 1_000) return this.lastReady;
    if (this.probing) return !this.stopped && (await this.probing) && !this.stopped;
    this.probing = this.probe()
      .then((ready) => {
        this.lastReady = ready && !this.stopped;
        this.lastProbe = Date.now();
        return this.lastReady;
      })
      .finally(() => {
        this.probing = null;
      });
    return await this.probing;
  }
  public connect(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    socket.on("error", () => undefined);
    socket.pause();
    (socket as TLSSocket).allowHalfOpen = true;
    const parsed = tcpRequest(req, this.options.domain(), true);
    if (!parsed || head.length > 65_536) return refuseTcp(socket, 400, "TCP_REQUEST_INVALID");
    if (this.stopped || this.legs.size >= (this.options.maxLegs ?? TCP_BROKER_LIMITS.totalLegs))
      return refuseTcp(socket, 503, "TCP_CAPACITY_REACHED");
    let upstream: Duplex | null = null;
    let done = false;
    let relayed = false;
    const stop = (): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      this.legs.delete(stop);
      pending.destroy();
      upstream?.destroy();
      socket.destroy();
    };
    const reject = (status: number, code: string): void => {
      if (done) return;
      if (!relayed) {
        refuseTcp(socket, status, code);
        done = true;
        clearTimeout(timer);
        this.legs.delete(stop);
        pending.destroy();
        upstream?.destroy();
      } else stop();
    };
    const pending = request({
      hostname: this.options.host,
      port: this.options.port,
      servername: TCP_BROKER_SERVERNAME,
      method: "CONNECT",
      path: `${parsed.binding.route_id}:443`,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
      agent: false,
      ...(this.options.ca ? { ca: this.options.ca } : {}),
      headers: {
        host: parsed.binding.tenant_host,
        authorization: `Bearer ${parsed.ticket}`,
        "agentsafe-tcp-role": parsed.binding.role,
      },
    });
    const timer = setTimeout(() => reject(504, "TCP_BROKER_TIMEOUT"), 45_000);
    timer.unref();
    this.legs.add(stop);
    socket.once("close", stop);
    pending.once("error", () => reject(502, "TCP_BROKER_UNAVAILABLE"));
    pending.once("connect", (response, peer, tail) => {
      if (done) {
        peer.destroy();
        return;
      }
      upstream = peer;
      peer.on("error", () => undefined);
      peer.pause();
      peer.allowHalfOpen = true;
      clearTimeout(timer);
      if (response.statusCode !== 200)
        return reject(
          [400, 401, 403, 409, 429, 503, 504].includes(response.statusCode ?? 0)
            ? response.statusCode!
            : 502,
          "TCP_BROKER_REFUSED",
        );
      relayed = true;
      connectedTcp(socket);
      spliceTcp(socket, peer, {
        leftHead: head,
        rightHead: tail,
        idleMs: TCP_BROKER_LIMITS.idleMs,
        lifetimeMs: TCP_BROKER_LIMITS.sessionMs,
        maxBytes: TCP_BROKER_LIMITS.maxBytes + 2_048,
        closed: stop,
      });
    });
    pending.once("response", (response) => {
      response.destroy();
      reject(502, "TCP_BROKER_REFUSED");
    });
    pending.end();
  }
  public close(): void {
    this.stopped = true;
    this.cancelProbe?.();
    for (const stop of [...this.legs]) stop();
  }
  private async probe(): Promise<boolean> {
    return await new Promise((resolve) => {
      let done = false;
      const finish = (ready: boolean): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        this.cancelProbe = null;
        req.destroy();
        resolve(ready && !this.stopped);
      };
      const req = request(
        {
          hostname: this.options.host,
          port: this.options.port,
          servername: TCP_BROKER_SERVERNAME,
          path: "/readyz",
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
          agent: false,
          ...(this.options.ca ? { ca: this.options.ca } : {}),
          headers: { host: TCP_BROKER_SERVERNAME },
        },
        (response) => {
          let size = 0;
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > 1_024) finish(false);
            else chunks.push(chunk);
          });
          response.once("error", () => finish(false));
          response.once("end", () => {
            try {
              const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
              finish(
                response.statusCode === 200 &&
                  typeof value === "object" &&
                  value !== null &&
                  "transport" in value &&
                  value.transport === TCP_TRANSPORT &&
                  "ready" in value &&
                  value.ready === true,
              );
            } catch {
              finish(false);
            }
          });
        },
      );
      const timer = setTimeout(() => finish(false), 7_000);
      this.cancelProbe = () => finish(false);
      timer.unref();
      req.once("error", () => finish(false));
      req.end();
    });
  }
}
