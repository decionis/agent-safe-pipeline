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
import {
  AuthError,
  type AuthenticatedPrincipal,
  type Authenticator,
} from "../identity/Authenticator.js";
import { peerIdentity, type PeerSocket } from "../identity/PeerIdentity.js";
import { ServiceError } from "../service/ServiceError.js";
import type { TrustedExecutorService } from "../service/TrustedExecutorService.js";
import { RequestContext } from "./RequestContext.js";
import {
  MAX_BODY_BYTES,
  METRICS_CONTENT_TYPE,
  RESPONSE_HEADERS,
  ROUTES,
  type RoutePath,
} from "./Routes.js";
import type { TlsListener } from "./TlsListener.js";

const REQUEST_TIMEOUT_MS = 15_000;
const HEADERS_TIMEOUT_MS = 5_000;
const KEEP_ALIVE_TIMEOUT_MS = 5_000;

export interface ExecutorHttpServerOptions {
  /** The TLS listener; plaintext when null, which the configuration allows outside production only. */
  readonly tls?: TlsListener | null;
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
 * The process's one listener. Every route that is not public goes through
 * the authenticator, which decides who the caller is and whether the route
 * is theirs; the body is bounded before it is read; a failure is a status
 * and a code, never a message, a stack, or anything from the request.
 * Every authenticated request runs inside a request scope, so the evidence
 * lines it causes name the principal.
 */
export class ExecutorHttpServer {
  private readonly server: Server;
  private readonly tls: TlsListener | null;

  public constructor(
    private readonly service: TrustedExecutorService,
    private readonly authenticator: Authenticator,
    options: ExecutorHttpServerOptions = {},
  ) {
    this.tls = options.tls ?? null;
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
      // Liveness stays 200 while halted: a halt is a decision to stop taking
      // work, not a reason for the orchestrator to restart the process and
      // lose what it knows.
      if (route.path === "/health")
        return ExecutorHttpServer.reply(response, 200, { status: "ok" });
      if (route.path === "/ready") {
        const readiness = this.service.readiness();
        return ExecutorHttpServer.reply(response, readiness.ready ? 200 : 503, readiness.body);
      }
      const caller = await this.authenticator.authenticate({
        authorization: request.headers.authorization,
        peer: peerIdentity(request.socket as PeerSocket),
        route,
      });
      await RequestContext.run({ principal: caller.principal.id }, () =>
        this.dispatch(route.path, request, response, caller),
      );
    } catch (error) {
      if (
        error instanceof GuardError ||
        error instanceof ServiceError ||
        error instanceof AuthError
      ) {
        ExecutorHttpServer.reply(
          response,
          error.status,
          error instanceof ServiceError && error.body !== undefined
            ? error.body
            : { code: error.code },
          error instanceof ServiceError && error.retryAfterSeconds !== undefined
            ? { "retry-after": String(error.retryAfterSeconds) }
            : {},
        );
      } else {
        ExecutorHttpServer.reply(response, 500, { code: "INTERNAL_ERROR" });
      }
    }
  }

  private async dispatch(
    path: Exclude<RoutePath, "/health" | "/ready">,
    request: IncomingMessage,
    response: ServerResponse,
    caller: AuthenticatedPrincipal,
  ): Promise<void> {
    switch (path) {
      case "/v1/actions":
        return ExecutorHttpServer.reply(
          response,
          200,
          await this.service.propose(await ExecutorHttpServer.readJson(request), caller.principal),
        );
      case "/v1/reconciliations":
        return ExecutorHttpServer.reply(
          response,
          200,
          await this.service.reconcile(
            await ExecutorHttpServer.readJson(request),
            caller.principal,
          ),
        );
      case "/v1/escalations":
        return ExecutorHttpServer.reply(
          response,
          200,
          await this.service.resume(await ExecutorHttpServer.readJson(request), caller.principal),
        );
      case "/v1/control/status":
        return ExecutorHttpServer.reply(response, 200, this.service.status(caller.principal));
      case "/v1/control/halt":
        return ExecutorHttpServer.reply(
          response,
          200,
          this.service.halt(await ExecutorHttpServer.readJson(request), caller.principal),
        );
      case "/v1/control/resume":
        return ExecutorHttpServer.reply(
          response,
          200,
          this.service.resumeWork(await ExecutorHttpServer.readJson(request), caller.principal),
        );
      case "/v1/control/open-attempts":
        return ExecutorHttpServer.reply(response, 200, this.service.openAttempts(caller.principal));
      case "/v1/control/secrets/reload":
        return ExecutorHttpServer.reply(
          response,
          200,
          await this.service.reloadSecrets(caller.principal),
        );
      case "/metrics":
        return ExecutorHttpServer.replyText(response, this.service.metricsText(caller.principal));
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

  private static replyText(response: ServerResponse, text: string): void {
    // Stryker disable next-line ConditionalExpression: a reply is written once per request; the guard is defensive.
    if (response.headersSent) return;
    response.writeHead(200, { ...RESPONSE_HEADERS, "content-type": METRICS_CONTENT_TYPE });
    response.end(text);
  }
}
