import { once } from "node:events";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { RESPONSE_HEADERS } from "./Routes.js";

export interface RedirectServerOptions {
  /** The domain whose hosts are redirected: itself and every host under it; null redirects nothing. */
  readonly domain: () => string | null;
}

/**
 * The plain-HTTP listener of a host that terminates TLS itself: it answers
 * every request with a redirect to the same host and path over HTTPS, and
 * nothing else. Only the fleet's own domain and the hosts under it are
 * redirected; any other `Host` is 421, so the listener can never be made to
 * send a client somewhere the fleet does not serve. GET and HEAD move with
 * 301; any other method with 308, which keeps the method and the body, so a
 * client that sent a request in the clear is told where to send it, and its
 * request is never acted on here.
 */
export class RedirectServer {
  private readonly server: Server;

  public constructor(private readonly options: RedirectServerOptions) {
    this.server = createServer((request, response) => this.handle(request, response));
    this.server.requestTimeout = 10_000;
    this.server.headersTimeout = 5_000;
    this.server.keepAliveTimeout = 5_000;
  }

  public async listen(port: number, host: string): Promise<AddressInfo> {
    this.server.listen(port, host);
    await once(this.server, "listening");
    return this.server.address() as AddressInfo;
  }

  public async close(): Promise<void> {
    const closed = new Promise<void>((resolve) => this.server.close(() => resolve()));
    this.server.closeAllConnections();
    await closed;
  }

  private handle(request: IncomingMessage, response: ServerResponse): void {
    // The body, if any, is never read: nothing here acts on a request.
    request.resume();
    const host = RedirectServer.hostnameOf(request);
    const domain = this.options.domain();
    if (host === null || domain === null || (host !== domain && !host.endsWith(`.${domain}`))) {
      response.writeHead(421, RESPONSE_HEADERS);
      response.end(JSON.stringify({ code: "HOST_NOT_SERVED" }));
      return;
    }
    const method = (request.method ?? "GET").toUpperCase();
    // Stryker disable next-line all: Node sets `url` on every request it hands out; the fallback satisfies the type.
    const target = new URL(request.url ?? "/", `https://${host}`);
    response.writeHead(method === "GET" || method === "HEAD" ? 301 : 308, {
      ...RESPONSE_HEADERS,
      location: `https://${host}${target.pathname}${target.search}`,
    });
    response.end(JSON.stringify({ code: "HTTPS_REQUIRED" }));
  }

  /** The host a request named, lower-cased, without a port; null when it named none or not a name. */
  private static hostnameOf(request: IncomingMessage): string | null {
    const host = request.headers.host?.trim().toLowerCase();
    if (host === undefined || host === "") return null;
    const name = host.replace(/:\d{1,5}$/, "");
    return /^[a-z0-9.-]+$/.test(name) ? name : null;
  }
}
