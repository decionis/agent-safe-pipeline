import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { ExecutorCardClient } from "../adapters/stripe/ExecutorCardClient.js";
import type { StripeBridgeSettings } from "../adapters/stripe/StripeBridgeSettings.js";
import { StripeIssuingBridge, type BridgeReply } from "../adapters/stripe/StripeIssuingBridge.js";

/** Stripe's real-time authorization endpoint (enforce only). */
export const STRIPE_AUTHORIZATION_REQUESTS_PATH = "/v1/stripe/issuing/authorization-requests";
/** Stripe's ordinary webhook endpoint for `issuing_authorization.created`. */
export const STRIPE_EVENTS_PATH = "/v1/stripe/issuing/events";

/** An Issuing event is a few kilobytes; anything near this is not one. */
const MAX_BODY_BYTES = 256 * 1024;

/**
 * The bridge's listener. Plain HTTP on the host's loopback by default: Stripe only posts to
 * HTTPS, so TLS ends at the operator's ingress in front of it. Two routes, POST only, a
 * bounded body read raw (the signature covers the exact bytes), nothing else.
 */
export class StripeBridgeServer {
  private readonly server: Server;

  public constructor(private readonly bridge: StripeIssuingBridge) {
    this.server = createServer((request, response) => {
      void this.handle(request, response);
    });
  }

  /** A bridge wired to the executor over HTTP, from settings. */
  public static fromSettings(
    settings: StripeBridgeSettings,
    log: (line: Readonly<Record<string, unknown>>) => void,
    read: (path: string) => string = (path) => readFileSync(path, "utf8"),
  ): StripeBridgeServer {
    // Read per call, so a rotated token file is picked up without a restart.
    const token = () => read(settings.executorTokenFile).trim();
    const client = new ExecutorCardClient(settings.executorUrl, token);
    return new StripeBridgeServer(
      new StripeIssuingBridge(settings, client, { nowMs: Date.now, log }),
    );
  }

  public listen(port: number, host: string): Promise<{ readonly port: number }> {
    return new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(port, host, () => {
        const address = this.server.address();
        resolve({ port: typeof address === "object" && address !== null ? address.port : port });
      });
    });
  }

  public close(): Promise<void> {
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      const path = new URL(request.url ?? "/", "http://bridge").pathname;
      if (path === "/health" && request.method === "GET") {
        return StripeBridgeServer.send(response, {
          status: 200,
          headers: { "content-type": "application/json" },
          body: '{"status":"ok"}',
        });
      }
      if (path !== STRIPE_AUTHORIZATION_REQUESTS_PATH && path !== STRIPE_EVENTS_PATH) {
        return StripeBridgeServer.send(response, StripeBridgeServer.plain(404, "NOT_FOUND"));
      }
      if (request.method !== "POST") {
        return StripeBridgeServer.send(
          response,
          StripeBridgeServer.plain(405, "METHOD_NOT_ALLOWED"),
        );
      }
      const body = await StripeBridgeServer.read(request);
      if (body === null) {
        return StripeBridgeServer.send(response, StripeBridgeServer.plain(413, "BODY_TOO_LARGE"));
      }
      const signature = request.headers["stripe-signature"];
      const header = typeof signature === "string" ? signature : undefined;
      const reply =
        path === STRIPE_AUTHORIZATION_REQUESTS_PATH
          ? await this.bridge.authorizationRequest(body, header)
          : await this.bridge.event(body, header);
      StripeBridgeServer.send(response, reply);
    } catch {
      StripeBridgeServer.send(response, StripeBridgeServer.plain(500, "INTERNAL_ERROR"));
    }
  }

  private static read(request: IncomingMessage): Promise<Buffer | null> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let refused = false;
      request.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          refused = true;
          request.destroy();
          resolve(null);
          return;
        }
        chunks.push(chunk);
      });
      request.on("end", () => {
        if (!refused) resolve(Buffer.concat(chunks));
      });
      request.on("error", (error) => {
        if (!refused) reject(error);
      });
    });
  }

  private static plain(status: number, code: string): BridgeReply {
    return {
      status,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code }),
    };
  }

  private static send(response: ServerResponse, reply: BridgeReply): void {
    if (response.headersSent) return;
    response.writeHead(reply.status, {
      ...reply.headers,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
    response.end(reply.body);
  }
}
