import {
  createLocalJWKSet,
  decodeProtectedHeader,
  errors,
  jwtVerify,
  type JSONWebKeySet,
  type JWTPayload,
} from "jose";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import type { SecurityEvents } from "../incident/SecurityEvents.js";

export type JwtCode =
  | "JWT_SIGNATURE_INVALID"
  | "JWT_AUDIENCE_MISMATCH"
  | "JWT_ISSUER_UNKNOWN"
  | "JWT_EXPIRED"
  | "JWT_ALGORITHM_REFUSED"
  | "JWT_SUBJECT_UNKNOWN"
  | "JWT_CLAIM_MISMATCH"
  | "JWKS_UNAVAILABLE";

export class JwtError extends Error {
  public constructor(public readonly code: JwtCode) {
    super(code);
    this.name = "JwtError";
  }
}

export interface VerifiedJwt {
  readonly issuer: string;
  readonly subject: string;
  readonly audiences: readonly string[];
  readonly claims: JWTPayload;
}

export interface JwksRefresh {
  readonly url: string;
  /** The guarded fetch: the JWKS address is a sealed destination like any other. */
  readonly fetch: FetchLike;
  readonly intervalSeconds: number;
  readonly events: SecurityEvents;
}

export interface WorkloadJwtVerifierOptions {
  /** Every audience a token may carry: the executor's own, and any a principal names. */
  readonly audiences: readonly string[];
  readonly keys: JSONWebKeySet;
  readonly clockToleranceSeconds: number;
  readonly maxTokenAgeSeconds?: number;
  readonly refresh?: JwksRefresh;
}

/** Asymmetric only: a workload's token is signed by its platform, never by a shared secret. */
export const JWT_ALGORITHMS = ["RS256", "ES256", "EdDSA"] as const;
const MAX_TOKEN_AGE_SECONDS = 24 * 60 * 60;
const MAX_JWKS_BYTES = 256 * 1024;

/**
 * Verifies a workload's token against a JWKS the platform team placed on
 * disk, optionally refreshed from a URL through the guarded fetch with the
 * last good set kept on any failure. Signature, algorithm, audience, age
 * and the four required claims are checked here; who the issuer and subject
 * are is the registry's question. There is no `jti` cache by design: a
 * projected token is a bearer for its lifetime, replay of a request is
 * defeated by the idempotency key, the intent hash and the single-use
 * grant, and a signed request exists for per-request proof.
 */
export class WorkloadJwtVerifier {
  private keys: ReturnType<typeof createLocalJWKSet>;
  private timer: ReturnType<typeof setInterval> | null = null;

  public constructor(private readonly options: WorkloadJwtVerifierOptions) {
    this.keys = createLocalJWKSet(options.keys);
  }

  /** A JWKS document: an object with a `keys` array of objects that each name a key type. */
  public static parseJwks(text: string): JSONWebKeySet {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new JwtError("JWKS_UNAVAILABLE");
    }
    const keys = (parsed as { keys?: unknown } | null)?.keys;
    const valid =
      Array.isArray(keys) &&
      keys.length > 0 &&
      keys.every(
        (key) =>
          typeof key === "object" &&
          key !== null &&
          typeof (key as { kty?: unknown }).kty === "string",
      );
    if (!valid) throw new JwtError("JWKS_UNAVAILABLE");
    return parsed as JSONWebKeySet;
  }

  public async verify(token: string): Promise<VerifiedJwt> {
    let algorithm: string | undefined;
    try {
      algorithm = decodeProtectedHeader(token).alg;
    } catch {
      throw new JwtError("JWT_SIGNATURE_INVALID");
    }
    if (!(JWT_ALGORITHMS as readonly string[]).includes(algorithm ?? "")) {
      throw new JwtError("JWT_ALGORITHM_REFUSED");
    }
    let payload: JWTPayload;
    try {
      payload = (
        await jwtVerify(token, this.keys, {
          audience: [...this.options.audiences],
          algorithms: [...JWT_ALGORITHMS],
          maxTokenAge: this.options.maxTokenAgeSeconds ?? MAX_TOKEN_AGE_SECONDS,
          clockTolerance: this.options.clockToleranceSeconds,
          requiredClaims: ["iss", "sub", "exp", "iat"],
        })
      ).payload;
    } catch (error) {
      throw new JwtError(WorkloadJwtVerifier.code(error));
    }
    return {
      issuer: String(payload.iss),
      subject: String(payload.sub),
      audiences: typeof payload.aud === "string" ? [payload.aud] : (payload.aud ?? []),
      claims: payload,
    };
  }

  /** Begins refreshing from the URL on the interval; a failure keeps the last good set. */
  public start(): void {
    const refresh = this.options.refresh;
    if (refresh === undefined || this.timer !== null) return;
    this.timer = setInterval(() => {
      void this.refreshNow();
    }, refresh.intervalSeconds * 1_000);
    this.timer.unref();
  }

  public stop(): void {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
  }

  /** One refresh; true when a new set became current. */
  public async refreshNow(): Promise<boolean> {
    const refresh = this.options.refresh;
    if (refresh === undefined) return false;
    let text: string;
    let status = 0;
    try {
      const response = await refresh.fetch(refresh.url, {
        method: "GET",
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });
      status = response.status;
      text = response.ok ? await response.text() : "";
    } catch {
      refresh.events.emit({ event: "JWKS_REFRESH_FAILED", code: "JWKS_UNREACHABLE" });
      return false;
    }
    if (status !== 200 || text.length > MAX_JWKS_BYTES) {
      refresh.events.emit({ event: "JWKS_REFRESH_FAILED", code: `JWKS_HTTP_${status}` });
      return false;
    }
    let keys: JSONWebKeySet;
    try {
      keys = WorkloadJwtVerifier.parseJwks(text);
    } catch {
      refresh.events.emit({ event: "JWKS_REFRESH_FAILED", code: "JWKS_INVALID" });
      return false;
    }
    this.keys = createLocalJWKSet(keys);
    refresh.events.emit({ event: "JWKS_REFRESHED", keys: keys.keys.length });
    return true;
  }

  private static code(error: unknown): JwtCode {
    if (error instanceof errors.JWTExpired) return "JWT_EXPIRED";
    if (error instanceof errors.JWTClaimValidationFailed) {
      return error.claim === "aud" ? "JWT_AUDIENCE_MISMATCH" : "JWT_CLAIM_MISMATCH";
    }
    if (error instanceof errors.JOSEAlgNotAllowed || error instanceof errors.JOSENotSupported) {
      return "JWT_ALGORITHM_REFUSED";
    }
    return "JWT_SIGNATURE_INVALID";
  }
}
