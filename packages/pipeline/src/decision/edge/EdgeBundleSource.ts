import { readFile } from "node:fs/promises";
import { AuthorityBaseUrl } from "../../http/AuthorityBaseUrl.js";
import { BoundedResponseBody } from "../../http/BoundedResponseBody.js";
import { userAgent, type ClientSource } from "../../http/ClientIdentification.js";
import { credentialReader, type Credential } from "../../http/Credential.js";

/**
 * What a source produced: a signed bundle as a compact JWS, or a code saying
 * why not. A code is an identifier chosen here; no status text, header,
 * body or credential from the attempt is carried, so it is safe to log.
 */
export type BundleRead =
  | { readonly ok: true; readonly signedBundle: string }
  | { readonly ok: false; readonly code: string };

/** Where signed policy bundles come from. */
export interface EdgeBundleSource {
  /** `url` fetches from Decionis; `file` reads what an operator placed on disk. */
  readonly kind: "url" | "file";
  read(): Promise<BundleRead>;
}

/** Three non-empty base64url segments: the only shape `load_bundle` accepts. */
const COMPACT_JWS = /^[\w-]+\.[\w-]+\.[\w-]+$/;
/** `load_bundle` refuses inputs over 4 MiB; a bundle near that is refused here first. */
const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;

/**
 * Takes the signed bundle out of what a source returned: the issuance
 * response (`{"signed_bundle": …}`), or the compact JWS on its own, which is
 * what an operator copying a bundle by hand will most likely place.
 */
export function signedBundleOf(text: string): BundleRead {
  const trimmed = text.trim();
  let candidate: unknown = trimmed;
  if (trimmed.startsWith("{")) {
    try {
      candidate = (JSON.parse(trimmed) as { readonly signed_bundle?: unknown }).signed_bundle;
    } catch {
      return { ok: false, code: "BUNDLE_RESPONSE_INVALID" };
    }
  }
  return typeof candidate === "string" && COMPACT_JWS.test(candidate)
    ? { ok: true, signedBundle: candidate }
    : { ok: false, code: "BUNDLE_RESPONSE_INVALID" };
}

export interface UrlBundleSourceOptions {
  /** The Decionis API base URL, the same one the hosted gate calls. */
  readonly baseUrl: string;
  /** The organisation's API key (`policy:read`), read at the moment of each request. */
  readonly apiKey: Credential;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  readonly allowInsecureLoopback?: boolean;
  readonly source?: ClientSource;
}

/** `GET /v1/edge/policy-bundles/current`, authenticated with the organisation's API key. */
export class UrlBundleSource implements EdgeBundleSource {
  public readonly kind = "url";
  private readonly url: string;
  private readonly apiKey: () => string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly userAgent: string;

  public constructor(options: UrlBundleSourceOptions) {
    const base = AuthorityBaseUrl.normalize(
      options.baseUrl,
      options.allowInsecureLoopback === true,
    );
    this.url = `${base}/v1/edge/policy-bundles/current`;
    this.apiKey = credentialReader(options.apiKey);
    this.timeoutMs = Math.min(Math.max(options.timeoutMs ?? 10_000, 1), 30_000);
    this.fetchImpl = options.fetch ?? fetch;
    this.userAgent = userAgent(options.source);
  }

  public async read(): Promise<BundleRead> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(this.url, {
        method: "GET",
        headers: {
          authorization: `Bearer ${this.apiKey()}`,
          accept: "application/json",
          "user-agent": this.userAgent,
        },
        signal: controller.signal,
      });
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        return { ok: false, code: `BUNDLE_HTTP_${response.status}` };
      }
      const text = await BoundedResponseBody.read(response, MAX_BUNDLE_BYTES);
      return text === null ? { ok: false, code: "BUNDLE_TOO_LARGE" } : signedBundleOf(text);
    } catch {
      return { ok: false, code: "BUNDLE_FETCH_FAILED" };
    } finally {
      clearTimeout(timeout);
    }
  }
}

/**
 * A file an operator replaces by hand, for a deployment with no route to
 * Decionis. It is read on every refresh; the manager loads it only when it
 * holds a bundle other than the one already loaded.
 */
export class FileBundleSource implements EdgeBundleSource {
  public readonly kind = "file";

  public constructor(private readonly path: string) {}

  public async read(): Promise<BundleRead> {
    let text: string;
    try {
      const bytes = await readFile(this.path);
      if (bytes.byteLength > MAX_BUNDLE_BYTES) return { ok: false, code: "BUNDLE_TOO_LARGE" };
      text = bytes.toString("utf8");
    } catch {
      return { ok: false, code: "BUNDLE_FILE_UNREADABLE" };
    }
    return signedBundleOf(text);
  }
}
