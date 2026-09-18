/**
 * The signed record itself, at the end of a run. `enforce-and-bind` names
 * the Decision Dossier it left; this fetches that record with the caller's
 * key from `GET /v1/protocol/dossiers/{id}`, reads the proof bundle it
 * carries, and prints what a person needs to know it is signed: the
 * algorithm, the key, when it was issued, how many artifacts it covers and
 * under which issuer tier. The signature check itself is `@decionis/verify`'s
 * (the `decionis:verify` script, or the public page); this shows the proof,
 * it does not re-implement it.
 */
import { AuthorityBaseUrl } from "../http/AuthorityBaseUrl.js";
import { BoundedResponseBody } from "../http/BoundedResponseBody.js";
import { userAgent, type ClientSource } from "../http/ClientIdentification.js";

export interface DossierFetchOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly tenantId: string;
  readonly dossierId: string;
  readonly allowInsecureLoopback?: boolean;
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
  readonly source?: ClientSource;
}

/** What the proof bundle says about the record, for a person to read. */
export interface SignedDossierSummary {
  readonly dossierId: string;
  readonly outcome: string | null;
  readonly generatedAt: string | null;
  readonly algorithm: string | null;
  readonly keyId: string | null;
  readonly issuedAt: string | null;
  readonly artifacts: number;
  /** The issuer tier the record carries, `provisional_anonymous` for a workspace without an account. */
  readonly issuerTier: string | null;
  readonly bytes: number;
}

export class DossierFetchError extends Error {
  public constructor(
    public readonly code:
      | "DOSSIER_UNAVAILABLE"
      | "DOSSIER_REFUSED"
      | "DOSSIER_NOT_FOUND"
      | "DOSSIER_RESPONSE_INVALID"
      | "DOSSIER_TIMED_OUT",
    public readonly status: number | null,
  ) {
    super(code);
    this.name = "DossierFetchError";
  }
}

/** A signed record with its inputs snapshot can be large; the reader's own bound. */
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const DOSSIER_ID_PATTERN = /^[\w-]{1,200}$/;

type Json = Readonly<Record<string, unknown>>;

function record(value: unknown): Json | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Json)
    : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= 500 ? value : null;
}

/** The summary of one `GET /v1/protocol/dossiers/{id}` body; null when it holds no signed payload. */
export function summarizeDossier(body: unknown, bytes: number): SignedDossierSummary | null {
  const payload = record(record(record(body)?.["dossier"])?.["dossier_payload"]);
  if (payload === null) return null;
  const dossierId = text(payload["dossier_id"]);
  if (dossierId === null) return null;
  const routing = record(payload["routing_decision"]);
  const bundle = record(record(payload["integrity"])?.["proof_bundle"]);
  const artifacts = bundle?.["artifacts"];
  const portable = record(payload["portable_artifact"]);
  const issuer = record(portable?.["issuer_context"]) ?? record(payload["issuer_context"]) ?? null;
  return {
    dossierId,
    outcome: text(routing?.["outcome"]),
    generatedAt: text(payload["generated_at"]),
    algorithm: text(bundle?.["algorithm"]),
    keyId: text(bundle?.["key_id"]),
    issuedAt: text(bundle?.["issued_at"]),
    artifacts: Array.isArray(artifacts) ? artifacts.length : 0,
    issuerTier: text(issuer?.["tier"]),
    bytes,
  };
}

/** Fetches the signed record with the caller's key and summarizes its proof. */
export async function fetchSignedDossier(
  options: DossierFetchOptions,
): Promise<{ readonly summary: SignedDossierSummary; readonly body: unknown }> {
  if (!DOSSIER_ID_PATTERN.test(options.dossierId)) {
    throw new DossierFetchError("DOSSIER_RESPONSE_INVALID", null);
  }
  const baseUrl = AuthorityBaseUrl.normalize(
    options.baseUrl,
    options.allowInsecureLoopback ?? false,
  );
  const url = `${baseUrl}/v1/protocol/dossiers/${encodeURIComponent(options.dossierId)}?org_id=${encodeURIComponent(options.tenantId)}`;
  const doFetch = options.fetch ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let response: Response;
  try {
    response = await doFetch(url, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${options.apiKey}`,
        "user-agent": userAgent(options.source),
      },
      redirect: "error",
      signal: controller.signal,
    });
  } catch {
    clearTimeout(timer);
    throw new DossierFetchError(
      controller.signal.aborted ? "DOSSIER_TIMED_OUT" : "DOSSIER_UNAVAILABLE",
      null,
    );
  }
  let raw: string | null;
  try {
    raw = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
  } catch {
    raw = null;
  } finally {
    clearTimeout(timer);
  }
  if (response.status === 404) throw new DossierFetchError("DOSSIER_NOT_FOUND", 404);
  if (response.status === 401 || response.status === 403) {
    throw new DossierFetchError("DOSSIER_REFUSED", response.status);
  }
  if (response.status >= 500) throw new DossierFetchError("DOSSIER_UNAVAILABLE", response.status);
  if (response.status !== 200 || raw === null) {
    throw new DossierFetchError("DOSSIER_RESPONSE_INVALID", response.status);
  }
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    throw new DossierFetchError("DOSSIER_RESPONSE_INVALID", response.status);
  }
  const summary = summarizeDossier(body, Buffer.byteLength(raw, "utf8"));
  if (summary === null) throw new DossierFetchError("DOSSIER_RESPONSE_INVALID", response.status);
  return { summary, body };
}

/** The signed record, in three lines a person can read. */
export function printSignedDossier(
  summary: SignedDossierSummary,
  options: { readonly out?: { write(chunk: string): unknown } } = {},
): void {
  const out = options.out ?? process.stdout;
  const signed =
    summary.keyId === null
      ? "unsigned record"
      : `${summary.algorithm ?? "signed"} by key ${summary.keyId}${summary.issuedAt === null ? "" : ` at ${summary.issuedAt}`}`;
  out.write(
    `signed dossier: ${summary.dossierId} (${String(summary.bytes)} bytes${summary.outcome === null ? "" : `, ${summary.outcome}`})\n`,
  );
  out.write(`  ${signed}, ${String(summary.artifacts)} signed artifact(s)\n`);
  out.write(
    `  issuer: ${summary.issuerTier ?? "not stated"}${summary.issuerTier === "provisional_anonymous" ? " (a workspace without an account; claim it to keep it)" : ""}\n`,
  );
}
