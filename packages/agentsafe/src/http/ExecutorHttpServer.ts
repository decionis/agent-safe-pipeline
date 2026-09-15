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
import type { TLSSocket } from "node:tls";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import type { SecretHandle } from "../secrets/SecretHandle.js";
import { ServiceError } from "../service/ServiceError.js";
import type { TrustedExecutorService } from "../service/TrustedExecutorService.js";
import { LEGACY_CALLER_PRINCIPAL, RequestContext } from "./RequestContext.js";
import { MAX_BODY_BYTES, RESPONSE_HEADERS, ROUTES } from "./Routes.js";
import type { TlsListener } from "./TlsListener.js";

const REQUEST_TIMEOUT_MS = 15_000;
const HEADERS_TIMEOUT_MS = 5_000;
const KEEP_ALIVE_TIMEOUT_MS = 5_000;

export interface ExecutorHttpServerOptions {
  /** The TLS listener; plaintext when null, which the configuration allows outside production only. */
  readonly tls?: TlsListener | null;
  /** Where a refusal at the door is reported. */
  readonly events?: SecurityEvents;
}

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
 * against the digest of the current handle, so a rotated token is honoured
 * from the next request on and the old one is refused; when a client CA is
 * configured a non-public route also requires the connection to carry an
 * authorized client certificate; the body is bounded before it is read; a
 * failure is a status and a code, never a message, a stack, or anything
 * from the request. Every authenticated request runs inside a request
 * scope, so the evidence lines it causes name the caller.
 */
export class ExecutorHttpServer {
  private readonly server: Server;
  private readonly tls: TlsListener | null;
  private readonly events: SecurityEvents | null;

  public constructor(
    private readonly service: TrustedExecutorService,
    private readonly callerToken: () => SecretHandle,
    options: ExecutorHttpServerOptions = {},
  ) {
    this.tls = options.tls ?? null;
    this.events = options.events ?? null;
    const handler: RequestListener = (request, response) => {
      void this.handle(request, response);
    };
    this.server = this.tls === null ? createServer(handler) : this.tls.createServer(handler);
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

  /** Replaces the TLS context from the current material; connections already open keep theirs. */
  public rotateTls(): void {
    if (this.tls === null) return;
    this.tls.rotate(this.server as HttpsServer);
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      // Stryker disable next-line all: Node sets `url` on every request it hands out; the fallback satisfies the type.
      const pathname = new URL(request.url ?? "/", "http://executor.invalid").pathname;
      const route = ROUTES.find((candidate) => candidate.path === pathname);
      if (route === undefined) throw new GuardError(404, "NOT_FOUND");
      if (route.method !== request.method) throw new GuardError(405, "METHOD_NOT_ALLOWED");
      if (route.public) {
        await this.dispatch(route.path, request, response);
        return;
      }
      this.authenticate(request);
      if ("role" in route) throw new GuardError(403, "OPERATOR_NOT_CONFIGURED");
      await RequestContext.run({ principal: LEGACY_CALLER_PRINCIPAL }, () =>
        this.dispatch(route.path, request, response),
      );
    } catch (error) {
      if (error instanceof GuardError || error instanceof ServiceError) {
        ExecutorHttpServer.reply(response, error.status, { code: error.code });
      } else {
        ExecutorHttpServer.reply(response, 500, { code: "INTERNAL_ERROR" });
      }
    }
  }

  private async dispatch(
    path: Exclude<(typeof ROUTES)[number], { role: string }>["path"],
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    switch (path) {
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
  }

  private authenticate(request: IncomingMessage): void {
    if (this.tls?.mutual === true && (request.socket as TLSSocket).authorized !== true) {
      this.events?.emit({ event: "AUTH_FAILED", method: "mtls" });
      throw new GuardError(401, "CALLER_NOT_AUTHENTICATED");
    }
    const header = request.headers.authorization;
    if (header === undefined || !header.startsWith("Bearer ")) {
      this.events?.emit({ event: "AUTH_FAILED", method: "bearer" });
      throw new GuardError(401, "CALLER_NOT_AUTHENTICATED");
    }
    // HTTP parsers trim the value's whitespace, so a bare scheme never reaches
    // here; whatever follows it is compared as a digest, however short.
    const presented = header.slice("Bearer ".length).trim();
    if (!timingSafeEqual(ExecutorHttpServer.digest(presented), this.callerToken().digestBytes())) {
      this.events?.emit({ event: "AUTH_FAILED", method: "bearer" });
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
