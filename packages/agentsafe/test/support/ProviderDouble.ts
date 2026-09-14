import { createServer, type IncomingMessage, type Server } from "node:http";

const LOOPBACK_ORIGIN = "http://127.0.0.1";

/**
 * A downstream provider with the two properties that matter: it deduplicates
 * on the idempotency key, and it can lose a response after taking effect.
 */
export class ProviderDouble {
  public readonly effects = new Set<string>();
  public readonly requests: {
    readonly path: string;
    readonly headers: IncomingMessage["headers"];
  }[] = [];
  private loseNextResponse = false;
  private server: Server | null = null;
  private port = 0;

  public get baseUrl(): string {
    return `${LOOPBACK_ORIGIN}:${this.port}`;
  }

  public get dispatches(): number {
    return this.requests.filter((request) => request.path === "/dispatches").length;
  }

  public loseNext(): void {
    this.loseNextResponse = true;
  }

  public async start(): Promise<void> {
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        const path = request.url ?? "/";
        this.requests.push({ path, headers: request.headers });
        const reply = (status: number, body: unknown): void => {
          response.writeHead(status, { "content-type": "application/json" });
          response.end(JSON.stringify(body));
        };
        if (request.method === "POST" && path === "/dispatches") {
          const key = String(request.headers["idempotency-key"] ?? "");
          if (this.effects.has(key)) return reply(200, { duplicate: true });
          this.effects.add(key);
          if (this.loseNextResponse) {
            this.loseNextResponse = false;
            request.socket.destroy();
            return;
          }
          return reply(202, { accepted: true });
        }
        if (request.method === "GET" && path.startsWith("/dispatches/")) {
          const key = decodeURIComponent(path.slice("/dispatches/".length));
          return this.effects.has(key) ? reply(200, { effected: true }) : reply(404, {});
        }
        reply(404, {});
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    this.port = typeof address === "object" && address !== null ? address.port : 0;
    this.server = server;
  }

  public async stop(): Promise<void> {
    const server = this.server;
    if (server === null) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
