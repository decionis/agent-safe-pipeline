import { createServer, type IncomingMessage, type Server } from "node:http";

const LOOPBACK_ORIGIN = "http://127.0.0.1";

export interface ScriptedAnswer {
  readonly status: number;
  readonly body: unknown;
  /** The provider's effect receipt to answer with, when it is a verifying provider; built from the request when a function. */
  readonly receipt?: string | ((headers: IncomingMessage["headers"]) => string);
}

/**
 * A core banking provider, as the reference transport requires one: it
 * answers a posted action, it can be read back by provider reference or by
 * idempotency key, and every answer is scripted so a test can say exactly
 * what the provider claimed. Nothing here deduplicates: what the executor
 * does with a repeated key is the executor's business, and a test that wants
 * a duplicate says so.
 */
export class BankingDouble {
  public readonly requests: {
    readonly method: string;
    readonly path: string;
    readonly headers: IncomingMessage["headers"];
    readonly body: string;
  }[] = [];
  /** What the next POST answers with; the last entry repeats. */
  public answers: ScriptedAnswer[] = [{ status: 202, body: { status: "ACCEPTED" } }];
  /** What a read-back answers with; null answers 404. */
  public readBack: ScriptedAnswer | null = null;
  /** Destroys the socket of the next POST, after the effect. */
  private loseNextResponse = false;
  private server: Server | null = null;
  private port = 0;

  public get baseUrl(): string {
    return `${LOOPBACK_ORIGIN}:${this.port}`;
  }

  public get executeUrl(): string {
    return `${this.baseUrl}/actions`;
  }

  public get lookupByReferenceUrl(): string {
    return `${this.baseUrl}/actions/by-reference/{provider_reference}`;
  }

  public get lookupByKeyUrl(): string {
    return `${this.baseUrl}/actions/by-key/{idempotency_key}`;
  }

  public get posts(): number {
    return this.requests.filter((request) => request.method === "POST").length;
  }

  public answer(...answers: ScriptedAnswer[]): void {
    this.answers = answers;
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
        const method = request.method ?? "GET";
        this.requests.push({
          method,
          path,
          headers: request.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
        const reply = (
          status: number,
          body: unknown,
          headers: Record<string, string> = {},
        ): void => {
          response.writeHead(status, { "content-type": "application/json", ...headers });
          response.end(typeof body === "string" ? body : JSON.stringify(body));
        };
        if (method === "POST" && path === "/actions") {
          if (this.loseNextResponse) {
            this.loseNextResponse = false;
            request.socket.destroy();
            return;
          }
          const next = this.answers.length > 1 ? this.answers.shift() : this.answers[0];
          // A verifying provider's receipt of the effect, when the script names one.
          const receipt =
            typeof next?.receipt === "function" ? next.receipt(request.headers) : next?.receipt;
          return reply(
            next?.status ?? 202,
            next?.body ?? { status: "ACCEPTED" },
            receipt === undefined ? {} : { "x-agent-safe-effect-receipt": receipt },
          );
        }
        if (method === "GET" && path.startsWith("/actions/")) {
          const answer = this.readBack;
          return answer === null ? reply(404, {}) : reply(answer.status, answer.body);
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
