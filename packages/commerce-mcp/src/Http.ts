import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { MAX_STDIO_IN_FLIGHT, MAX_STDIO_REQUEST_BYTES, MCP_SERVER_BUSY_CODE } from "./Server.js";

/**
 * Streamable HTTP, the stateless kind Amazon Bedrock AgentCore Runtime proxies
 * to: one `POST /mcp` per JSON-RPC message (or batch), a JSON answer, no
 * server-initiated stream. The runtime adds an `Mcp-Session-Id` header for its
 * own session isolation; it is echoed and otherwise ignored, because nothing
 * here keeps state between requests. `GET /ping` is the health check.
 *
 * Every limit the stdio server applies applies here too: a bounded request
 * body, a bounded number of requests in flight, a busy answer rather than a
 * queue.
 */
export const DEFAULT_HTTP_PORT = 8000;
export const DEFAULT_HTTP_HOST = "0.0.0.0";
export const MCP_HTTP_PATH = "/mcp";
export const PING_HTTP_PATH = "/ping";

type JsonRpcResponse = Record<string, unknown>;
type Handler = (message: unknown) => Promise<JsonRpcResponse | null>;

export interface HttpServerOptions {
  port?: number;
  host?: string;
  maximumRequestBytes?: number;
  maximumInFlight?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function error(id: unknown, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function idOf(message: unknown): unknown {
  return isRecord(message) && "id" in message ? message.id : null;
}

function isNotification(message: unknown): boolean {
  return (
    isRecord(message) &&
    message.jsonrpc === "2.0" &&
    typeof message.method === "string" &&
    !("id" in message)
  );
}

async function readBody(request: IncomingMessage, maximumBytes: number): Promise<Buffer | null> {
  const declared = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(declared) && declared > maximumBytes) return null;
  const chunks: Buffer[] = [];
  let received = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    received += buffer.length;
    if (received > maximumBytes) return null;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

function send(
  response: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  const payload = body === undefined ? "" : JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    ...headers,
    "content-length": Buffer.byteLength(payload),
  });
  response.end(payload);
}

export class CommerceGateHttpServer {
  private inFlight = 0;

  constructor(
    private readonly handler: Handler,
    private readonly options: HttpServerOptions = {},
  ) {
    const bytes = options.maximumRequestBytes ?? MAX_STDIO_REQUEST_BYTES;
    const inFlight = options.maximumInFlight ?? MAX_STDIO_IN_FLIGHT;
    if (!Number.isSafeInteger(bytes) || bytes < 1) {
      throw new TypeError("maximumRequestBytes must be a positive safe integer");
    }
    if (!Number.isSafeInteger(inFlight) || inFlight < 1) {
      throw new TypeError("maximumInFlight must be a positive safe integer");
    }
  }

  /** The Node server, unbound; `listen()` binds it. Tests bind it to port 0. */
  create(): Server {
    const server = createServer((request, response) => {
      void this.route(request, response);
    });
    server.requestTimeout = 30_000;
    server.headersTimeout = 10_000;
    server.keepAliveTimeout = 5_000;
    return server;
  }

  async listen(): Promise<Server> {
    const server = this.create();
    const port = this.options.port ?? DEFAULT_HTTP_PORT;
    const host = this.options.host ?? DEFAULT_HTTP_HOST;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.off("error", reject);
        resolve();
      });
    });
    return server;
  }

  private async route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? "/", "http://localhost");
    if (url.pathname === PING_HTTP_PATH) {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return send(response, 405, { error: "method_not_allowed" }, { allow: "GET" });
      }
      return send(response, 200, { status: "Healthy" });
    }
    if (url.pathname !== MCP_HTTP_PATH) {
      return send(response, 404, { error: "not_found" });
    }
    if (request.method !== "POST") {
      // No server-initiated stream: there is nothing to GET, nothing to DELETE.
      return send(response, 405, { error: "method_not_allowed" }, { allow: "POST" });
    }
    const contentType = String(request.headers["content-type"] ?? "");
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return send(response, 415, { error: "unsupported_media_type" });
    }
    const echo: Record<string, string> = {};
    const session = request.headers["mcp-session-id"];
    if (typeof session === "string" && session.length <= 256) echo["mcp-session-id"] = session;

    const body = await readBody(
      request,
      this.options.maximumRequestBytes ?? MAX_STDIO_REQUEST_BYTES,
    );
    if (body === null) {
      return send(response, 413, error(null, -32600, "Request too large"), echo);
    }
    let message: unknown;
    try {
      message = JSON.parse(body.toString("utf8"));
    } catch {
      return send(response, 400, error(null, -32700, "Parse error"), echo);
    }
    const messages = Array.isArray(message) ? message : [message];
    if (messages.length === 0) {
      return send(response, 400, error(null, -32600, "Invalid JSON-RPC 2.0 request"), echo);
    }

    const limit = this.options.maximumInFlight ?? MAX_STDIO_IN_FLIGHT;
    if (this.inFlight >= limit) {
      const busy = messages
        .filter((item) => !isNotification(item))
        .map((item) =>
          error(
            idOf(item),
            MCP_SERVER_BUSY_CODE,
            "CommerceGate is busy. The request was not processed; retry later.",
          ),
        );
      return send(response, 503, Array.isArray(message) ? busy : busy[0], {
        ...echo,
        "retry-after": "1",
      });
    }

    this.inFlight += 1;
    try {
      const answers: JsonRpcResponse[] = [];
      for (const item of messages) {
        let answer: JsonRpcResponse | null;
        try {
          answer = await this.handler(item);
        } catch {
          answer = isNotification(item) ? null : error(idOf(item), -32603, "Internal error");
        }
        if (answer) answers.push(answer);
      }
      if (answers.length === 0) return send(response, 202, undefined, echo);
      return send(response, 200, Array.isArray(message) ? answers : answers[0], echo);
    } finally {
      this.inFlight -= 1;
    }
  }
}
