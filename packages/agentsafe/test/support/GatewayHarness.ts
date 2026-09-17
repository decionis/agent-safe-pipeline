import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  GatewayConfigLoader,
  type GatewayConfig,
  type GatewayFlags,
} from "../../src/gateway/GatewayConfig.js";
import type { CliFiles, CliProcess } from "../../src/cli/CliProcess.js";
import type { GatewayIo } from "../../src/gateway/Gateway.js";

export const LOOPBACK_ORIGIN = "http://127.0.0.1";

/** One request as the upstream double saw it. */
export interface SeenRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: string;
}

/**
 * A loopback stand-in for the service behind the gateway. It answers by
 * path: `/fail` with 500, `/refuse` with 422, `/slow` after a delay,
 * `/redirect` with 302, `/big` with more bytes than the relay allows,
 * `/hang` never; anything else with 201 for a write and 200 for a read,
 * echoing what it received so a test can check the bytes.
 */
export class UpstreamDouble {
  public readonly seen: SeenRequest[] = [];
  private server: Server | null = null;
  private port = 0;

  public get baseUrl(): string {
    return `${LOOPBACK_ORIGIN}:${this.port}`;
  }

  public async start(): Promise<void> {
    const server = createServer((request, response) => {
      void this.handle(request, response);
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
    this.server = null;
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const body = Buffer.concat(chunks).toString("utf8");
    const url = request.url ?? "/";
    this.seen.push({ method: request.method ?? "", url, headers: request.headers, body });
    const path = url.replace(/^\/base/, "");
    if (path.startsWith("/hang")) return;
    if (path.startsWith("/slow")) await new Promise((resolve) => setTimeout(resolve, 300));
    if (path.startsWith("/redirect")) {
      response.writeHead(302, { location: "/elsewhere" });
      response.end();
      return;
    }
    if (path.startsWith("/big")) {
      response.writeHead(200, { "content-type": "application/octet-stream" });
      response.end(Buffer.alloc(3 * 1024 * 1024, 1));
      return;
    }
    const status = path.startsWith("/fail")
      ? 500
      : path.startsWith("/refuse")
        ? 422
        : request.method === "GET"
          ? 200
          : 201;
    response.writeHead(status, {
      "content-type": "application/json",
      "x-upstream": "double",
      "set-cookie": ["a=1; Path=/", "b=2; Path=/"],
      // An upstream's own spelling of the gateway's headers, which the relay must drop.
      "agentsafe-decision": "FORGED",
      connection: "close",
    });
    response.end(JSON.stringify({ ok: status < 400, method: request.method, url, body }));
  }
}

/** A configuration for a test: the upstream double, the demo authority unless overridden, human output off. */
export function testConfig(
  upstream: string,
  overrides: {
    readonly flags?: GatewayFlags;
    readonly env?: Record<string, string | undefined>;
    readonly file?: unknown;
  } = {},
): GatewayConfig {
  return GatewayConfigLoader.load({
    flags: { upstream, port: 1, json: true, ...(overrides.flags ?? {}) },
    env: overrides.env ?? {},
    file: overrides.file ?? null,
    credentials: null,
    version: "0.0.0-test",
  });
}

/** Lines collected from the gateway's two streams. */
export interface CollectedIo extends GatewayIo {
  readonly out: string[];
  readonly err: string[];
}

export function collectedIo(): CollectedIo {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    color: false,
    stdout: (line) => {
      out.push(line);
    },
    stderr: (line) => {
      err.push(line);
    },
  };
}

/** A process for a command: in-memory files, collected output, a scripted stdin. */
export interface FakeProcess extends CliProcess {
  readonly out: string[];
  readonly err: string[];
  readonly exits: number[];
  readonly stored: Map<string, { text: string; mode: number | undefined }>;
  readonly signals: Map<string, () => void>;
}

export function fakeProcess(
  options: {
    readonly env?: Record<string, string | undefined>;
    readonly cwd?: string;
    readonly files?: Record<string, string>;
    readonly lines?: readonly string[];
    readonly fetch?: typeof fetch;
    readonly isTTY?: boolean;
  } = {},
): FakeProcess {
  const stored = new Map<string, { text: string; mode: number | undefined }>();
  for (const [path, text] of Object.entries(options.files ?? {}))
    stored.set(path, { text, mode: undefined });
  const out: string[] = [];
  const err: string[] = [];
  const exits: number[] = [];
  const signals = new Map<string, () => void>();
  const lines = [...(options.lines ?? [])];
  const files: CliFiles = {
    exists: (path) => stored.has(path),
    read: (path) => stored.get(path)?.text ?? null,
    write: (path, text, mode) => {
      stored.set(path, { text, mode });
    },
    mkdir: () => undefined,
    remove: (path) => {
      stored.delete(path);
    },
  };
  return {
    env: options.env ?? {},
    cwd: options.cwd ?? "/work",
    home: "/home/synthetic",
    isTTY: options.isTTY ?? false,
    color: false,
    stdout: (text) => {
      out.push(text);
    },
    stderr: (text) => {
      err.push(text);
    },
    exit: (code) => {
      exits.push(code);
    },
    onSignal: (signal, handler) => {
      signals.set(signal, handler);
    },
    files,
    readLine: async () => lines.shift() ?? "",
    fetch: options.fetch ?? (() => Promise.reject(new Error("NO_NETWORK_IN_TEST"))),
    out,
    err,
    exits,
    stored,
    signals,
  };
}
