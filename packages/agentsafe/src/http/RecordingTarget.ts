/**
 * The synthetic target `agentsafe test` fires at: a loopback service that
 * records what reaches it and answers the way a plain API would (200 to a
 * read, 201 to a write, 204 to a delete), echoing what it received. It is
 * the whole point of the test that this is the only thing a probe can
 * touch: nothing it records is real, nothing outside this process is
 * called, and it listens on the loopback interface alone.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

/** One request as the target saw it: enough to say what arrived, never more. */
export interface ReceivedRequest {
  readonly method: string;
  readonly path: string;
  /** Header names only, lowercased; a value is never kept. */
  readonly headerNames: readonly string[];
  readonly bodyBytes: number;
}

const LOOPBACK = "127.0.0.1";
const MAX_BODY_BYTES = 1024 * 1024;

export class RecordingTarget {
  public readonly received: ReceivedRequest[] = [];
  private server: Server | null = null;
  private port = 0;

  public get baseUrl(): string {
    return `http://${LOOPBACK}:${String(this.port)}`;
  }

  public async start(): Promise<void> {
    if (this.server !== null) return;
    const server = createServer((request, response) => {
      void this.handle(request, response);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, LOOPBACK, () => {
        server.off("error", reject);
        resolve();
      });
    });
    const address = server.address();
    this.port = typeof address === "object" && address !== null ? address.port : 0;
    this.server = server;
  }

  public async stop(): Promise<void> {
    const server = this.server;
    if (server === null) return;
    this.server = null;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    let bodyBytes = 0;
    for await (const chunk of request) {
      bodyBytes += (chunk as Buffer).length;
      if (bodyBytes > MAX_BODY_BYTES) {
        request.destroy();
        return;
      }
    }
    const method = request.method ?? "GET";
    const path = (request.url ?? "/").split("?")[0] ?? "/";
    this.received.push({
      method,
      path,
      headerNames: Object.keys(request.headers).map((name) => name.toLowerCase()),
      bodyBytes,
    });
    const status = method === "GET" || method === "HEAD" ? 200 : method === "DELETE" ? 204 : 201;
    if (status === 204) {
      response.writeHead(status);
      response.end();
      return;
    }
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify({ received: { method, path, body_bytes: bodyBytes } }));
  }
}
