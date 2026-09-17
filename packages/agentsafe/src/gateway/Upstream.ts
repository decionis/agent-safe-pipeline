import type { FetchLike } from "../handlers/HandlerRegistration.js";
import type { InterceptedRequest } from "./InterceptedRequest.js";

/** What came back from the upstream: the status, the headers a client may see, the bytes. */
export interface UpstreamResult {
  readonly status: number;
  readonly headers: readonly (readonly [string, string])[];
  readonly body: Buffer;
}

/** Thrown when the upstream's response body is longer than the gateway relays. */
export class UpstreamResponseTooLarge extends Error {
  public constructor() {
    super("UPSTREAM_RESPONSE_TOO_LARGE");
    this.name = "UpstreamResponseTooLarge";
  }
}

/** Headers that describe one hop and are never carried to the next. */
const HOP_BY_HOP: ReadonlySet<string> = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);
/** Request headers the gateway sets itself, so a client's value never stands in for them. */
const REQUEST_OWNED: ReadonlySet<string> = new Set([
  "host",
  "content-length",
  "expect",
  "accept-encoding",
  "x-forwarded-proto",
  "x-forwarded-host",
]);
/** Response headers the relay recomputes, because it relays decoded bytes of a known length. */
const RESPONSE_OWNED: ReadonlySet<string> = new Set(["content-length", "content-encoding"]);
const BODYLESS_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD"]);

export interface UpstreamOptions {
  readonly url: string;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly fetch: FetchLike;
}

/**
 * The one way the gateway reaches the upstream. It rebuilds the request
 * from what it is given: the upstream origin from the configuration, the
 * path and query from the caller, the client's headers minus the ones that
 * belong to a hop, the body bytes verbatim. Redirects are relayed, never
 * followed, so the client, and not this process, decides where to go next.
 */
export class Upstream {
  private readonly origin: URL;

  public constructor(private readonly options: UpstreamOptions) {
    this.origin = new URL(options.url);
  }

  public get url(): string {
    return this.options.url;
  }

  public get timeoutMs(): number {
    return this.options.timeoutMs;
  }

  /** The upstream URL for a path and query, under the configured base path. */
  public target(path: string, search: string): string {
    const base = this.origin.pathname.replace(/\/$/, "");
    return `${this.origin.origin}${base}${path}${search}`;
  }

  /** The headers the upstream receives for a client's request, plus what the gateway adds. */
  public headersFor(
    request: InterceptedRequest,
    extra: Readonly<Record<string, string>> = {},
  ): Record<string, string> {
    const connectionNamed = new Set(
      (request.headers["connection"] ?? "")
        .split(",")
        .map((name) => name.trim().toLowerCase())
        .filter((name) => name !== ""),
    );
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      if (HOP_BY_HOP.has(name) || REQUEST_OWNED.has(name) || connectionNamed.has(name)) continue;
      headers[name] = value;
    }
    const forwardedFor = request.headers["x-forwarded-for"];
    if (request.remoteAddress !== null) {
      headers["x-forwarded-for"] =
        forwardedFor === undefined
          ? request.remoteAddress
          : `${forwardedFor}, ${request.remoteAddress}`;
    }
    headers["x-forwarded-proto"] = request.encrypted ? "https" : "http";
    if (request.headers["host"] !== undefined)
      headers["x-forwarded-host"] = request.headers["host"];
    // Identity between the gateway and the upstream: the bytes relayed are
    // the bytes received, and no header describes an encoding they lack.
    headers["accept-encoding"] = "identity";
    for (const [name, value] of Object.entries(extra)) headers[name.toLowerCase()] = value;
    return headers;
  }

  /**
   * Sends one request and reads the whole answer, bounded. A transport
   * failure throws; the caller decides what a failure after dispatch means.
   */
  public async send(
    method: string,
    path: string,
    search: string,
    headers: Readonly<Record<string, string>>,
    body: Buffer,
    signal: AbortSignal,
  ): Promise<UpstreamResult> {
    const response = await this.options.fetch(this.target(path, search), {
      method,
      headers,
      ...(BODYLESS_METHODS.has(method) || body.length === 0 ? {} : { body: new Uint8Array(body) }),
      redirect: "manual",
      signal,
    });
    const relayed: (readonly [string, string])[] = [];
    for (const [name, value] of response.headers) {
      if (HOP_BY_HOP.has(name) || RESPONSE_OWNED.has(name) || name === "set-cookie") continue;
      relayed.push([name, value]);
    }
    for (const cookie of response.headers.getSetCookie()) relayed.push(["set-cookie", cookie]);
    return {
      status: response.status,
      headers: relayed,
      body: await Upstream.read(response, this.options.maxResponseBytes),
    };
  }

  /** The whole body, or a refusal once it passes the bound; never a partial relay. */
  private static async read(response: Response, maxBytes: number): Promise<Buffer> {
    if (response.body === null) return Buffer.alloc(0);
    const chunks: Uint8Array[] = [];
    let size = 0;
    const reader = response.body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) throw new UpstreamResponseTooLarge();
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
      if (size > maxBytes) await response.body.cancel().catch(() => undefined);
    }
    return Buffer.concat(chunks);
  }

  /** The signal for one send: the configured ceiling, or a tighter budget the caller holds. */
  public signal(budgetMs: number = this.options.timeoutMs): AbortSignal {
    return AbortSignal.timeout(Math.max(Math.min(budgetMs, this.options.timeoutMs), 1));
  }
}
