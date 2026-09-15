import { X509Certificate } from "node:crypto";
import { lookup } from "node:dns/promises";
import { Agent as HttpAgent, request as httpRequest, type IncomingMessage } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import type { LookupFunction } from "node:net";
import { checkServerIdentity, type DetailedPeerCertificate, type PeerCertificate } from "node:tls";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import { EgressError, type EgressCode } from "./EgressError.js";
import { EgressPolicy, type EgressDestination } from "./EgressPolicy.js";

export interface ResolvedAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

/** Name resolution, injectable so a test can answer a name with any address. */
export type AddressResolver = (hostname: string) => Promise<readonly ResolvedAddress[]>;

export interface GuardedFetchOptions {
  readonly policy: EgressPolicy;
  readonly events: SecurityEvents;
  readonly maxResponseBytes: number;
  /** A transport to delegate to after the policy check; the `node:https` transport when absent. */
  readonly transport?: FetchLike;
  readonly resolve?: AddressResolver;
  /** The executor's own ceiling on any one request, headers and body included. */
  readonly timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const REDIRECTS: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);
const NULL_BODY: ReadonlySet<number> = new Set([204, 205, 304]);
const TLS_FAILURE =
  /^(?:ERR_TLS_|ERR_SSL_|ERR_OSSL_|EPROTO$|UNABLE_TO_|SELF_SIGNED|DEPTH_ZERO|CERT_)/;

async function systemResolver(hostname: string): Promise<readonly ResolvedAddress[]> {
  const addresses = await lookup(hostname, { all: true });
  return addresses.map((entry) => ({ address: entry.address, family: entry.family === 6 ? 6 : 4 }));
}

/**
 * The one way this process opens a connection. Every request is checked
 * against the sealed policy before a socket exists; a name is resolved once
 * and refused if it answers with an address the policy forbids; TLS is
 * verified against the destination's own anchor and pins; redirects are
 * never followed; the body is bounded and returned whole. What comes back
 * is a standard `Response`, which is what the gate, the verifier, the
 * Presence transport, and the handlers expect from a fetch. Every refusal
 * is a code on the security stream with the origin and nothing else.
 */
export class GuardedFetch {
  public readonly fetch: FetchLike;
  private readonly agents = new Map<string, HttpAgent | HttpsAgent>();
  private readonly resolve: AddressResolver;
  private readonly timeoutMs: number;

  public constructor(private readonly options: GuardedFetchOptions) {
    this.resolve = options.resolve ?? systemResolver;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetch = (input, init) => this.guarded(input, init ?? {});
  }

  public close(): void {
    for (const agent of this.agents.values()) agent.destroy();
    this.agents.clear();
  }

  private async guarded(input: string | URL | Request, init: RequestInit): Promise<Response> {
    if (typeof input !== "string" && !(input instanceof URL)) {
      throw this.refuse(null, "EGRESS_INIT_UNSUPPORTED");
    }
    let url: URL;
    try {
      url = new URL(input);
    } catch {
      throw this.refuse(null, "EGRESS_ORIGIN_NOT_ALLOWED");
    }
    const origin = url.origin === "null" ? null : url.origin;
    const check = this.options.policy.check(url);
    if (!check.allowed) throw this.refuse(origin, check.code);
    if (init.redirect !== undefined && init.redirect !== "manual" && init.redirect !== "error") {
      throw this.refuse(origin, "EGRESS_INIT_UNSUPPORTED");
    }
    const response =
      this.options.transport === undefined
        ? await this.request(url, check.destination, init)
        : await this.options.transport(input, init);
    if (REDIRECTS.has(response.status)) this.inspectRedirect(url, response.headers.get("location"));
    return response;
  }

  private request(url: URL, destination: EgressDestination, init: RequestInit): Promise<Response> {
    const origin = url.origin;
    let body: Buffer | null;
    try {
      body = GuardedFetch.body(init.body);
    } catch (error) {
      throw this.refuse(origin, (error as EgressError).code);
    }
    const headers = GuardedFetch.headers(init.headers, body);
    const method = (init.method ?? "GET").toUpperCase();
    const signal = init.signal ?? null;
    const transport = url.protocol === "https:" ? httpsRequest : httpRequest;
    return new Promise<Response>((resolve, reject) => {
      let settled = false;
      let pending: EgressError | null = null;
      let timer: ReturnType<typeof setTimeout> | null = null;
      const settle = (outcome: () => void): void => {
        if (settled) return;
        settled = true;
        if (timer !== null) clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        outcome();
      };
      const fail = (error: unknown): void => {
        settle(() => reject(this.classify(origin, pending ?? error)));
      };
      const request = transport(
        url,
        { method, headers, agent: this.agentFor(destination) },
        (response) => {
          this.collect(origin, response, (error) => {
            pending = error;
            response.destroy(error);
          })
            .then((built) => settle(() => resolve(built)))
            .catch(fail);
        },
      );
      const onAbort = (): void => {
        request.destroy(GuardedFetch.abortReason(signal));
      };
      request.on("error", fail);
      timer = setTimeout(() => {
        pending = new EgressError("EGRESS_TIMEOUT", origin);
        request.destroy(pending);
      }, this.timeoutMs);
      timer.unref();
      if (signal !== null) {
        if (signal.aborted) onAbort();
        else signal.addEventListener("abort", onAbort, { once: true });
      }
      if (body !== null) request.write(body);
      request.end();
    });
  }

  /** Reads the whole body under the bound and builds the `Response` the caller expects. */
  private async collect(
    origin: string,
    response: IncomingMessage,
    abort: (error: EgressError) => void,
  ): Promise<Response> {
    const status = response.statusCode ?? 0;
    if (status < 200 || status > 599) {
      const invalid = new EgressError("EGRESS_RESPONSE_INVALID", origin);
      abort(invalid);
      throw invalid;
    }
    const max = this.options.maxResponseBytes;
    const declared = Number(response.headers["content-length"]);
    if (Number.isFinite(declared) && declared > max) {
      const large = new EgressError("EGRESS_BODY_TOO_LARGE", origin);
      abort(large);
      throw large;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of response) {
      const buffer = chunk as Buffer;
      size += buffer.length;
      if (size > max) {
        const large = new EgressError("EGRESS_BODY_TOO_LARGE", origin);
        abort(large);
        throw large;
      }
      chunks.push(buffer);
    }
    try {
      const headers = new Headers();
      for (const [name, value] of Object.entries(response.headers)) {
        if (value === undefined) continue;
        for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
      }
      return new Response(NULL_BODY.has(status) ? null : Buffer.concat(chunks), {
        status,
        statusText: response.statusMessage ?? "",
        headers,
      });
    } catch {
      throw new EgressError("EGRESS_RESPONSE_INVALID", origin);
    }
  }

  private inspectRedirect(url: URL, location: string | null): void {
    if (location === null) return;
    let target: URL;
    try {
      target = new URL(location, url);
    } catch {
      this.refuse(url.origin, "EGRESS_REDIRECT_REFUSED");
      return;
    }
    if (target.origin !== url.origin) this.refuse(url.origin, "EGRESS_REDIRECT_REFUSED");
  }

  /** Every refusal is an event with the origin and the code; the error carries the same and no more. */
  private refuse(origin: string | null, code: EgressCode): EgressError {
    this.options.events.emit({ event: "EGRESS_REFUSED", origin, code });
    return new EgressError(code, origin);
  }

  /** A failure of the executor's own making is reported; the caller's abort and the network's failures pass through. */
  private classify(origin: string, error: unknown): unknown {
    if (error instanceof EgressError) {
      this.options.events.emit({ event: "EGRESS_REFUSED", origin, code: error.code });
      return error;
    }
    const code = (error as { code?: unknown } | null)?.code;
    if (typeof code === "string" && TLS_FAILURE.test(code)) {
      return this.refuse(origin, "EGRESS_TLS_REJECTED");
    }
    return error;
  }

  private agentFor(destination: EgressDestination): HttpAgent | HttpsAgent {
    const existing = this.agents.get(destination.origin);
    if (existing !== undefined) return existing;
    const loopback = EgressPolicy.isLoopbackHost(new URL(destination.origin).hostname);
    // The name may answer with several admitted addresses (a dual-stack
    // loopback, a service with two records); Node tries them in order and
    // connects to the first that answers, all of them from the one resolution.
    const common = {
      keepAlive: true,
      maxSockets: 16,
      lookup: this.lookupFor(destination.origin, loopback),
      autoSelectFamily: true,
    };
    const agent = destination.origin.startsWith("https:")
      ? new HttpsAgent({
          ...common,
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
          ...(destination.ca === null ? {} : { ca: destination.ca }),
          checkServerIdentity: (hostname, cert) =>
            GuardedFetch.identity(hostname, cert, destination),
        })
      : new HttpAgent(common);
    this.agents.set(destination.origin, agent);
    return agent;
  }

  /** Resolves once and connects only to what was resolved; one forbidden answer refuses the whole name. */
  private lookupFor(origin: string, loopback: boolean): LookupFunction {
    return (hostname, options, callback) => {
      this.resolve(hostname).then(
        (all) => {
          const wanted = options.family === 4 || options.family === 6 ? options.family : null;
          const addresses = all.filter((entry) => wanted === null || entry.family === wanted);
          const refused =
            addresses.length === 0 ||
            addresses.some((entry) => EgressPolicy.addressRefused(entry.address, loopback));
          if (refused) {
            callback(new EgressError("EGRESS_ADDRESS_REFUSED", origin), "", undefined);
            return;
          }
          if (options.all === true) {
            callback(
              null,
              addresses.map((entry) => ({ ...entry })),
              undefined,
            );
            return;
          }
          const first = addresses[0] as ResolvedAddress;
          callback(null, first.address, first.family);
        },
        (error: unknown) => {
          callback(error as Error, "", undefined);
        },
      );
    };
  }

  /** Hostname verification as usual, then the pins: any certificate in the chain may match. */
  private static identity(
    hostname: string,
    cert: PeerCertificate,
    destination: EgressDestination,
  ): Error | undefined {
    const failure = checkServerIdentity(hostname, cert);
    if (failure !== undefined) return failure;
    if (destination.pins.length === 0) return undefined;
    let current: DetailedPeerCertificate | undefined = cert as DetailedPeerCertificate;
    while (current !== undefined) {
      const spki = new X509Certificate(current.raw).publicKey.export({
        type: "spki",
        format: "der",
      });
      if (destination.pins.includes(EgressPolicy.spkiPin(spki))) return undefined;
      const issuer: DetailedPeerCertificate | undefined = current.issuerCertificate;
      current = issuer === undefined || issuer === current ? undefined : issuer;
    }
    return new EgressError("EGRESS_TLS_PIN_MISMATCH", destination.origin);
  }

  private static body(body: BodyInit | null | undefined): Buffer | null {
    if (body === undefined || body === null) return null;
    if (typeof body === "string") return Buffer.from(body, "utf8");
    if (body instanceof Uint8Array) return Buffer.from(body);
    if (body instanceof ArrayBuffer) return Buffer.from(body);
    if (body instanceof URLSearchParams) return Buffer.from(body.toString(), "utf8");
    throw new EgressError("EGRESS_INIT_UNSUPPORTED");
  }

  private static headers(
    init: HeadersInit | undefined,
    body: Buffer | null,
  ): Record<string, string> {
    const record: Record<string, string> = {};
    new Headers(init).forEach((value, name) => {
      record[name] = value;
    });
    if (body !== null && record["content-length"] === undefined) {
      record["content-length"] = String(body.length);
    }
    return record;
  }

  private static abortReason(signal: AbortSignal | null): Error {
    const reason: unknown = signal?.reason;
    return reason instanceof Error
      ? reason
      : new DOMException("This operation was aborted", "AbortError");
  }
}
