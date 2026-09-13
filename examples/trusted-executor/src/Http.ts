import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { ServiceError, type TrustedExecutorService } from "./Service.js";

/** The payload limit on every route, in bytes. */
export const MAX_BODY_BYTES = 100 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;
const HEADERS_TIMEOUT_MS = 5_000;
const KEEP_ALIVE_TIMEOUT_MS = 5_000;

export interface RouteDefinition {
  readonly method: "GET" | "POST";
  readonly path: string;
  /** Public routes answer without the caller token; they carry no state. */
  readonly public: boolean;
}

/** The whole surface. The README's table is checked against this list. */
export const ROUTES = [
  { method: "GET", path: "/health", public: true },
  { method: "GET", path: "/ready", public: true },
  { method: "POST", path: "/v1/actions", public: false },
  { method: "POST", path: "/v1/reconciliations", public: false },
] as const satisfies readonly RouteDefinition[];

/** Every response, success or refusal, carries the same protective headers. */
export const RESPONSE_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
} as const;

class GuardError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(code);
    this.name = "GuardError";
  }
}

/**
 * The process's one listener. The caller token is compared in constant time
 * against a digest and never kept in clear; the body is bounded before it is
 * read; a failure is a status and a code, never a message, a stack, or
 * anything from the request.
 */
export class ExecutorHttpServer {
  private readonly server: Server;
  private readonly expectedToken: Buffer;

  public constructor(
    private readonly service: TrustedExecutorService,
    callerToken: string,
  ) {
    this.expectedToken = ExecutorHttpServer.digest(callerToken);
    this.server = createServer((request, response) => {
      void this.handle(request, response);
    });
    this.server.requestTimeout = REQUEST_TIMEOUT_MS;
    this.server.headersTimeout = HEADERS_TIMEOUT_MS;
    this.server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;
  }

  public async listen(port: number, address: string): Promise<AddressInfo> {
    await new Promise<void>((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(port, address, () => {
        this.server.off("error", reject);
        resolve();
      });
    });
    return this.server.address() as AddressInfo;
  }

  public async close(): Promise<void> {
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      const pathname = new URL(request.url ?? "/", "http://executor.invalid").pathname;
      const route = ROUTES.find((candidate) => candidate.path === pathname);
      if (route === undefined) throw new GuardError(404, "NOT_FOUND");
      if (route.method !== request.method) throw new GuardError(405, "METHOD_NOT_ALLOWED");
      if (!route.public) this.authenticate(request);
      switch (route.path) {
        case "/health":
          return ExecutorHttpServer.reply(response, 200, { status: "ok" });
        case "/ready":
          return ExecutorHttpServer.reply(response, 200, {
            status: "ready",
            mode: this.service.mode,
            actions: this.service.actions,
          });
        case "/v1/actions":
          return ExecutorHttpServer.reply(
            response,
            200,
            await this.service.propose(await ExecutorHttpServer.readJson(request)),
          );
        case "/v1/reconciliations":
          return ExecutorHttpServer.reply(
            response,
            200,
            await this.service.reconcile(await ExecutorHttpServer.readJson(request)),
          );
      }
    } catch (error) {
      if (error instanceof GuardError || error instanceof ServiceError) {
        ExecutorHttpServer.reply(response, error.status, { code: error.code });
      } else {
        ExecutorHttpServer.reply(response, 500, { code: "INTERNAL_ERROR" });
      }
    }
  }

  private authenticate(request: IncomingMessage): void {
    const header = request.headers.authorization ?? "";
    const presented = header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
    if (presented.length === 0) throw new GuardError(401, "CALLER_NOT_AUTHENTICATED");
    if (!timingSafeEqual(ExecutorHttpServer.digest(presented), this.expectedToken)) {
      throw new GuardError(401, "CALLER_NOT_AUTHENTICATED");
    }
  }

  private static async readJson(request: IncomingMessage): Promise<unknown> {
    const declared = Number(request.headers["content-length"] ?? "0");
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      throw new GuardError(413, "BODY_TOO_LARGE");
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      const buffer = chunk as Buffer;
      size += buffer.length;
      if (size > MAX_BODY_BYTES) throw new GuardError(413, "BODY_TOO_LARGE");
      chunks.push(buffer);
    }
    const text = Buffer.concat(chunks).toString("utf8");
    if (text.trim() === "") throw new GuardError(400, "BODY_REQUIRED");
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new GuardError(400, "BODY_NOT_JSON");
    }
  }

  private static reply(response: ServerResponse, status: number, body: unknown): void {
    if (response.headersSent) return;
    response.writeHead(status, RESPONSE_HEADERS);
    response.end(JSON.stringify(body));
  }

  private static digest(value: string): Buffer {
    return createHash("sha256").update(value).digest();
  }
}
