import { createHash, timingSafeEqual } from "node:crypto";
import { once } from "node:events";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { ServiceError } from "../service/ServiceError.js";
import type { TrustedExecutorService } from "../service/TrustedExecutorService.js";
import { MAX_BODY_BYTES, RESPONSE_HEADERS, ROUTES } from "./Routes.js";

const REQUEST_TIMEOUT_MS = 15_000;
const HEADERS_TIMEOUT_MS = 5_000;
const KEEP_ALIVE_TIMEOUT_MS = 5_000;

class GuardError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(code);
    // Stryker disable next-line StringLiteral: the name is diagnostic and never reaches a response.
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
    this.server.listen(port, address);
    // Resolves on "listening" and rejects on an "error" emitted before it.
    await once(this.server, "listening");
    return this.server.address() as AddressInfo;
  }

  public async close(): Promise<void> {
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      // Stryker disable next-line all: Node sets `url` on every request it hands out; the fallback satisfies the type.
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
            escalation: this.service.escalationMode,
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
        case "/v1/escalations":
          return ExecutorHttpServer.reply(
            response,
            200,
            await this.service.resume(await ExecutorHttpServer.readJson(request)),
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
    const header = request.headers.authorization;
    if (header === undefined || !header.startsWith("Bearer ")) {
      throw new GuardError(401, "CALLER_NOT_AUTHENTICATED");
    }
    // HTTP parsers trim the value's whitespace, so a bare scheme never reaches
    // here; whatever follows it is compared as a digest, however short.
    const presented = header.slice("Bearer ".length).trim();
    if (!timingSafeEqual(ExecutorHttpServer.digest(presented), this.expectedToken)) {
      throw new GuardError(401, "CALLER_NOT_AUTHENTICATED");
    }
  }

  private static async readJson(request: IncomingMessage): Promise<unknown> {
    // Absent or unparseable is NaN, which is not finite and so not refused here;
    // the streamed count below still bounds what is read.
    const declared = Number(request.headers["content-length"]);
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
    // Stryker disable next-line ConditionalExpression: a reply is written once per request; the guard is defensive.
    if (response.headersSent) return;
    response.writeHead(status, RESPONSE_HEADERS);
    response.end(JSON.stringify(body));
  }

  private static digest(value: string): Buffer {
    return createHash("sha256").update(value).digest();
  }
}
