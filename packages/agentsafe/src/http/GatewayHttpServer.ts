import { once } from "node:events";
import {
  createServer,
  type IncomingMessage,
  type RequestListener,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { GATEWAY_PREFIX, type Gateway, type GatewayResponse } from "../gateway/Gateway.js";
import type { InterceptedRequest } from "../gateway/InterceptedRequest.js";
import { METRICS_CONTENT_TYPE, RESPONSE_HEADERS } from "./Routes.js";

const REQUEST_TIMEOUT_MS = 30_000;
const HEADERS_TIMEOUT_MS = 10_000;
const KEEP_ALIVE_TIMEOUT_MS = 5_000;
/** The gateway's own routes, under its prefix; anything else under the prefix is 404. */
const OWN_ROUTES = ["healthz", "readyz", "status", "metrics"] as const;
const ESCALATIONS = `${GATEWAY_PREFIX}/v1/escalations/`;
const INTENT_ID = /^[0-9a-f-]{36}$/;

class GuardError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(code);
    this.name = "GuardError";
  }
}

export interface GatewayHttpServerOptions {
  /** A bearer token the metrics route requires; open when null, which is the local default. */
  readonly metricsToken?: string | null;
}

/**
 * The interception listener. Every request is either the gateway's own
 * (under `/_agentsafe`), passed through unchanged, or governed: the body is
 * read in full under the configured bound and handed to the gateway with the
 * method, path, query and headers, and what comes back is written as it is.
 * A refusal the listener makes itself is a status and a code, never a
 * message from the request.
 */
export class GatewayHttpServer {
  private readonly server: Server;

  public constructor(
    private readonly gateway: Gateway,
    private readonly options: GatewayHttpServerOptions = {},
  ) {
    const handler: RequestListener = (request, response) => {
      void this.handle(request, response);
    };
    this.server = createServer(handler);
    this.server.requestTimeout = REQUEST_TIMEOUT_MS;
    this.server.headersTimeout = HEADERS_TIMEOUT_MS;
    this.server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;
  }

  public async listen(port: number, host: string): Promise<AddressInfo> {
    this.server.listen(port, host);
    await once(this.server, "listening");
    return this.server.address() as AddressInfo;
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
      if (url.pathname === GATEWAY_PREFIX || url.pathname.startsWith(`${GATEWAY_PREFIX}/`)) {
        return await this.own(method, url, request, response);
      }
      const plan = this.gateway.plan(method, url.pathname);
      const body = await GatewayHttpServer.readBody(
        request,
        plan.kind === "GOVERN"
          ? this.gateway.config.interception.maxBodyBytes
          : this.gateway.config.upstream.maxResponseBytes,
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
          ? await this.gateway.govern(intercepted, plan.action)
          : await this.gateway.passthrough(intercepted);
      GatewayHttpServer.write(response, answer);
    } catch (error) {
      if (error instanceof GuardError) {
        GatewayHttpServer.reply(response, error.status, { code: error.code });
      } else {
        GatewayHttpServer.reply(response, 500, { code: "INTERNAL_ERROR" });
      }
    }
  }

  private async own(
    method: string,
    url: URL,
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    if (url.pathname.startsWith(ESCALATIONS)) {
      const rest = url.pathname.slice(ESCALATIONS.length).split("/");
      const intentId = rest[0] ?? "";
      if (!INTENT_ID.test(intentId)) throw new GuardError(404, "NOT_FOUND");
      if (rest.length === 1 && method === "GET") {
        const held = this.gateway.escalation(intentId);
        if (held === null) throw new GuardError(404, "ESCALATION_NOT_HELD");
        return GatewayHttpServer.reply(response, 200, held);
      }
      if (rest.length === 2 && rest[1] === "resume" && method === "POST") {
        // The body, if any, is read and discarded: the gateway holds the intent.
        await GatewayHttpServer.readBody(request, 1024);
        return GatewayHttpServer.write(response, await this.gateway.resume(intentId));
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
        const readiness = this.gateway.readiness();
        return GatewayHttpServer.reply(response, readiness.ready ? 200 : 503, readiness.body);
      }
      case "status":
        return GatewayHttpServer.reply(response, 200, this.gateway.status());
      case "metrics": {
        const token = this.options.metricsToken ?? null;
        if (token !== null && request.headers.authorization !== `Bearer ${token}`) {
          throw new GuardError(401, "UNAUTHORIZED");
        }
        response.writeHead(200, { ...RESPONSE_HEADERS, "content-type": METRICS_CONTENT_TYPE });
        response.end(this.gateway.metricsText());
        return;
      }
    }
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

  private static write(response: ServerResponse, answer: GatewayResponse): void {
    // Stryker disable next-line ConditionalExpression: a reply is written once per request; the guard is defensive.
    if (response.headersSent) return;
    for (const [name, value] of answer.headers) response.appendHeader(name, value);
    response.setHeader("content-length", String(answer.body.length));
    response.writeHead(answer.status);
    response.end(answer.body);
  }

  private static reply(response: ServerResponse, status: number, body: unknown): void {
    // Stryker disable next-line ConditionalExpression: a reply is written once per request; the guard is defensive.
    if (response.headersSent) return;
    response.writeHead(status, RESPONSE_HEADERS);
    response.end(JSON.stringify(body));
  }
}
