import { createHash, timingSafeEqual } from "node:crypto";
import { once } from "node:events";
import {
  createServer,
  type IncomingMessage,
  type RequestListener,
  type Server,
  type ServerResponse,
} from "node:http";
import type { Server as HttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import {
  GATEWAY_PREFIX,
  RESUME_TOKEN_HEADER,
  type Gateway,
  type GatewayResponse,
} from "../gateway/Gateway.js";
import { TENANT_KEY_HEADER } from "../gateway/GatewayConfig.js";
import type { InterceptedRequest } from "../gateway/InterceptedRequest.js";
import { METRICS_CONTENT_TYPE, RESPONSE_HEADERS } from "./Routes.js";
import type { TlsListener } from "./TlsListener.js";

const REQUEST_TIMEOUT_MS = 30_000;
const HEADERS_TIMEOUT_MS = 10_000;
const KEEP_ALIVE_TIMEOUT_MS = 5_000;
/** The gateway's own routes, under its prefix; anything else under the prefix is 404. */
const OWN_ROUTES = ["healthz", "readyz", "status", "metrics"] as const;
const ESCALATIONS = `${GATEWAY_PREFIX}/v1/escalations/`;
const INTENT_ID = /^[0-9a-f-]{36}$/;

/**
 * The challenge a missing or wrong tenant key is answered with: the scheme
 * names the header the key travels in, so a 401 says what it wants.
 */
export const TENANT_KEY_CHALLENGE = "AgentSafe-Tenant-Key";

class GuardError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly headers: Readonly<Record<string, string>> = {},
  ) {
    super(code);
    this.name = "GuardError";
  }
}

export interface GatewayHttpServerOptions {
  /**
   * A bearer token the metrics route requires; open when null, which is the
   * local default. A hosted gateway's status and metrics answer only this
   * token, the operator's, and are not there at all without one.
   */
  readonly metricsToken?: string | null;
  /**
   * Answers `healthz` and `readyz` for a request whose host no gateway serves:
   * a platform probes a pod by its address, not by any tenant's name. Without
   * it such a request is refused with 421 like any other.
   */
  readonly probe?: { readonly ready: () => boolean };
  /**
   * Terminate TLS here, with the executor's listener (TLS 1.3, or 1.2 with
   * AEAD ciphers only): the hosted fleet's edge is a layer-4 load balancer
   * and nothing else. Every response then carries HSTS, this listener's
   * once, and a relayed upstream's own is dropped.
   */
  readonly tls?: TlsListener | null;
  /**
   * The page a host no tenant has answers at `/`, when it is this hostname:
   * a hosted fleet's apex names its operator. Both are read per request, so
   * a reload changes them in place; null serves nothing.
   */
  readonly apex?: { readonly hostname: () => string | null; readonly page: () => string | null };
}

/** HSTS for a listener that terminates TLS: a year, every subdomain. */
export const HSTS = "max-age=31536000; includeSubDomains";

/** The apex page's own policy: inline style, nothing else, never framed. */
const APEX_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";

/**
 * Which gateway answers a request, by the host it was addressed to. One
 * listener can front many gateways this way, each with its own upstream,
 * key, tenant and mode: the hosted shape, where every governed endpoint is
 * a host name and none is a separate implementation. `null` refuses the
 * host with 421.
 */
export type GatewaySelector = (hostname: string | null) => Gateway | null;

/**
 * The interception listener. Every request is either the gateway's own
 * (under `/_agentsafe`), passed through unchanged, or governed: the body is
 * read in full under the configured bound and handed to the gateway with the
 * method, path, query and headers, and what comes back is written as it is.
 * A refusal the listener makes itself is a status and a code, never a
 * message from the request, with `agentsafe-execution: NOT_FORWARDED`.
 */
export class GatewayHttpServer {
  private readonly server: Server;
  private readonly select: GatewaySelector;

  public constructor(
    gateway: Gateway | GatewaySelector,
    private readonly options: GatewayHttpServerOptions = {},
  ) {
    this.select = typeof gateway === "function" ? gateway : () => gateway;
    const handler: RequestListener = (request, response) => {
      if (this.options.tls) response.setHeader("strict-transport-security", HSTS);
      void this.handle(request, response);
    };
    this.server = this.options.tls ? this.options.tls.createServer(handler) : createServer(handler);
    this.server.requestTimeout = REQUEST_TIMEOUT_MS;
    this.server.headersTimeout = HEADERS_TIMEOUT_MS;
    this.server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;
  }

  public async listen(port: number, host: string): Promise<AddressInfo> {
    this.server.listen(port, host);
    await once(this.server, "listening");
    return this.server.address() as AddressInfo;
  }

  /**
   * Hands the listener a connection it did not accept itself: the transparent
   * interceptor's, already terminated where TLS was spoken. The stream is read
   * as any accepted socket is, and closed with the rest on `close`.
   */
  public accept(connection: Duplex): void {
    this.server.emit("connection", connection);
  }

  /** Presents the current certificate and key to new connections; open ones keep theirs. */
  public rotateTls(): void {
    this.options.tls?.rotate(this.server as HttpsServer);
  }

  /** Stops accepting, lets requests in flight finish for a grace period, then closes what is left. */
  public async close(graceMs = 10_000): Promise<void> {
    const closed = new Promise<void>((resolve) => this.server.close(() => resolve()));
    this.server.closeIdleConnections();
    const timer = setTimeout(() => this.server.closeAllConnections(), graceMs);
    await closed;
    clearTimeout(timer);
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      // Stryker disable next-line all: Node sets `url` on every request it hands out; the fallback satisfies the type.
      const url = new URL(request.url ?? "/", "http://gateway.invalid");
      const method = (request.method ?? "GET").toUpperCase();
      const gateway = this.select(GatewayHttpServer.hostnameOf(request));
      if (gateway === null) return this.unserved(request, method, url, response);
      if (url.pathname === GATEWAY_PREFIX || url.pathname.startsWith(`${GATEWAY_PREFIX}/`)) {
        return await this.own(gateway, method, url, request, response);
      }
      // The tenant's traffic, and only it, needs the tenant's key; the gateway's
      // own routes answer platform probes and the operator.
      const presented = request.headers[TENANT_KEY_HEADER];
      const refusal = gateway.keyRefusal(typeof presented === "string" ? presented : undefined);
      if (refusal !== null) {
        throw new GuardError(401, refusal, { "www-authenticate": TENANT_KEY_CHALLENGE });
      }
      const rate = gateway.rate();
      if (!rate.admitted) {
        throw new GuardError(429, "RATE_LIMITED", {
          "retry-after": String(rate.retryAfterSeconds),
        });
      }
      const plan = gateway.plan(method, url.pathname);
      const body = await GatewayHttpServer.readBody(
        request,
        plan.kind === "GOVERN"
          ? gateway.config.interception.maxBodyBytes
          : gateway.config.upstream.maxResponseBytes,
      );
      const intercepted: InterceptedRequest = {
        method,
        path: url.pathname,
        search: url.search,
        headers: GatewayHttpServer.headersOf(request),
        body,
        remoteAddress: request.socket.remoteAddress ?? null,
        encrypted: (request.socket as { encrypted?: boolean }).encrypted === true,
      };
      const answer =
        plan.kind === "GOVERN"
          ? await gateway.govern(intercepted, plan.action)
          : await gateway.passthrough(intercepted);
      this.write(response, answer);
    } catch (error) {
      // A refusal is the listener's own, made before anything was forwarded;
      // any other failure may come after a forward, so it claims neither way.
      if (error instanceof GuardError) {
        GatewayHttpServer.reply(
          response,
          error.status,
          { code: error.code },
          { ...error.headers, "agentsafe-execution": "NOT_FORWARDED" },
        );
      } else {
        GatewayHttpServer.reply(
          response,
          500,
          { code: "INTERNAL_ERROR" },
          { "agentsafe-execution": "INDETERMINATE" },
        );
      }
    }
  }

  /** The host a request was addressed to, lower-cased and without a port; null when it named none. */
  private static hostnameOf(request: IncomingMessage): string | null {
    const host = request.headers.host?.trim().toLowerCase();
    if (host === undefined || host === "") return null;
    if (host.startsWith("[")) return host.slice(0, host.indexOf("]") + 1);
    const separator = host.indexOf(":");
    return separator === -1 ? host : host.slice(0, separator);
  }

  private async own(
    gateway: Gateway,
    method: string,
    url: URL,
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    if (url.pathname.startsWith(ESCALATIONS)) {
      const rest = url.pathname.slice(ESCALATIONS.length).split("/");
      const intentId = rest[0] ?? "";
      if (!INTENT_ID.test(intentId)) throw new GuardError(404, "NOT_FOUND");
      const resumeToken = GatewayHttpServer.resumeTokenOf(request);
      if (rest.length === 1 && method === "GET") {
        const held = gateway.escalation(intentId, resumeToken);
        if (held === "ESCALATION_NOT_HELD") throw new GuardError(404, held);
        if (held === "RESUME_TOKEN_INVALID") throw new GuardError(403, held);
        return GatewayHttpServer.reply(response, 200, held);
      }
      if (rest.length === 2 && rest[1] === "resume" && method === "POST") {
        // The body, if any, is read and discarded: the gateway holds the intent.
        await GatewayHttpServer.readBody(request, 1024);
        return this.write(response, await gateway.resume(intentId, resumeToken));
      }
      throw new GuardError(
        rest.length === 1 || rest[1] === "resume" ? 405 : 404,
        rest.length === 1 || rest[1] === "resume" ? "METHOD_NOT_ALLOWED" : "NOT_FOUND",
      );
    }
    const name = url.pathname.slice(GATEWAY_PREFIX.length + 1);
    if (!(OWN_ROUTES as readonly string[]).includes(name)) throw new GuardError(404, "NOT_FOUND");
    if (method !== "GET") throw new GuardError(405, "METHOD_NOT_ALLOWED");
    switch (name as (typeof OWN_ROUTES)[number]) {
      case "healthz":
        return GatewayHttpServer.reply(response, 200, { status: "ok" });
      case "readyz": {
        const readiness = gateway.readiness();
        return GatewayHttpServer.reply(response, readiness.ready ? 200 : 503, readiness.body);
      }
      case "status":
        // Status names the upstream, the routes and the shadow tally: the
        // tenant's business, and a hosted gateway answers it to the operator only.
        if (gateway.config.hosted) this.requireOperator(request);
        return GatewayHttpServer.reply(response, 200, gateway.status());
      case "metrics": {
        if (gateway.config.hosted) this.requireOperator(request);
        const token = this.options.metricsToken ?? null;
        if (token !== null && !GatewayHttpServer.bearerIs(request, token)) {
          throw new GuardError(401, "UNAUTHORIZED");
        }
        response.writeHead(200, { ...RESPONSE_HEADERS, "content-type": METRICS_CONTENT_TYPE });
        response.end(gateway.metricsText());
        return;
      }
    }
  }

  /**
   * A host no gateway serves: the operator's apex page at `/` when it is the
   * apex, a probe of the process itself, or 421.
   */
  private unserved(
    request: IncomingMessage,
    method: string,
    url: URL,
    response: ServerResponse,
  ): void {
    const apex = this.options.apex;
    const hostname = GatewayHttpServer.hostnameOf(request);
    if (apex !== undefined && hostname !== null && hostname === apex.hostname()) {
      if (url.pathname === "/" && (method === "GET" || method === "HEAD")) {
        const page = apex.page();
        if (page !== null) {
          response.writeHead(200, {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "public, max-age=300",
            "content-security-policy": APEX_CSP,
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
          });
          response.end(method === "HEAD" ? undefined : page);
          return;
        }
      }
      if (!url.pathname.startsWith(`${GATEWAY_PREFIX}/`)) {
        throw new GuardError(404, "NOT_FOUND");
      }
    }
    const probe = this.options.probe;
    const route = url.pathname.slice(GATEWAY_PREFIX.length + 1);
    if (
      probe === undefined ||
      method !== "GET" ||
      !url.pathname.startsWith(`${GATEWAY_PREFIX}/`) ||
      (route !== "healthz" && route !== "readyz")
    ) {
      throw new GuardError(421, "HOST_NOT_SERVED");
    }
    if (route === "healthz") return GatewayHttpServer.reply(response, 200, { status: "ok" });
    const ready = probe.ready();
    return GatewayHttpServer.reply(response, ready ? 200 : 503, { ready });
  }

  /** The operator's token, or the route is not there (no token) or refused (another one). */
  private requireOperator(request: IncomingMessage): void {
    const token = this.options.metricsToken ?? null;
    if (token === null) throw new GuardError(404, "NOT_FOUND");
    if (!GatewayHttpServer.bearerIs(request, token)) throw new GuardError(401, "UNAUTHORIZED");
  }

  /** Whether the request presents exactly this bearer token, compared in constant time. */
  private static bearerIs(request: IncomingMessage, token: string): boolean {
    const digest = (value: string): Buffer => createHash("sha256").update(value, "utf8").digest();
    return timingSafeEqual(digest(request.headers.authorization ?? ""), digest(`Bearer ${token}`));
  }

  /** The resume token the caller presents, from its header only; null when absent or repeated. */
  private static resumeTokenOf(request: IncomingMessage): string | null {
    const value = request.headers[RESUME_TOKEN_HEADER];
    return typeof value === "string" && value !== "" ? value : null;
  }

  /** The whole body under a bound; declared or streamed, the bound is the bound. */
  private static async readBody(request: IncomingMessage, maxBytes: number): Promise<Buffer> {
    const declared = Number(request.headers["content-length"]);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new GuardError(413, "BODY_TOO_LARGE");
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      const buffer = chunk as Buffer;
      size += buffer.length;
      if (size > maxBytes) throw new GuardError(413, "BODY_TOO_LARGE");
      chunks.push(buffer);
    }
    return Buffer.concat(chunks);
  }

  /** Header names lower-cased, repeated values joined as Node joins them, `set-cookie` aside. */
  private static headersOf(request: IncomingMessage): Record<string, string> {
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      if (value === undefined) continue;
      headers[name] = Array.isArray(value) ? value.join(", ") : value;
    }
    return headers;
  }

  private write(response: ServerResponse, answer: GatewayResponse): void {
    // Stryker disable next-line ConditionalExpression: a reply is written once per request; the guard is defensive.
    if (response.headersSent) return;
    for (const [name, value] of answer.headers) {
      // A listener that terminates TLS has set its host's HSTS already: the
      // transport policy of this host is the operator's, never an upstream's.
      if (this.options.tls && name === "strict-transport-security") continue;
      response.appendHeader(name, value);
    }
    response.setHeader("content-length", String(answer.body.length));
    response.writeHead(answer.status);
    response.end(answer.body);
  }

  private static reply(
    response: ServerResponse,
    status: number,
    body: unknown,
    headers: Readonly<Record<string, string>> = {},
  ): void {
    // Stryker disable next-line ConditionalExpression: a reply is written once per request; the guard is defensive.
    if (response.headersSent) return;
    response.writeHead(status, { ...RESPONSE_HEADERS, ...headers });
    response.end(JSON.stringify(body));
  }
}
