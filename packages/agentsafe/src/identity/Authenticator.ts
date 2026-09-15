import type { RouteDefinition } from "../http/Routes.js";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import type { PeerIdentity } from "./PeerIdentity.js";
import type { Principal, PrincipalRegistry } from "./PrincipalRegistry.js";
import type { LockoutRule, RateLimiter, RateLimitRule } from "./RateLimiter.js";
import { JwtError, type WorkloadJwtVerifier } from "./WorkloadJwtVerifier.js";

export type AuthMethod = "bearer" | "jwt" | "mtls" | "none";

export interface AuthenticationInput {
  readonly authorization: string | undefined;
  /** The client certificate the connection presented, or null when it presented none. */
  readonly peer: PeerIdentity | null;
  readonly route: RouteDefinition;
}

export interface AuthenticatedPrincipal {
  readonly principal: Principal;
  readonly method: AuthMethod;
}

/** A refusal at the door: a status and a code, never a message from the request. */
export class AuthError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(code);
    this.name = "AuthError";
  }
}

export interface AuthenticatorOptions {
  readonly registry: PrincipalRegistry;
  readonly jwt: WorkloadJwtVerifier | null;
  /** The executor's own audience; a principal may name its own instead. */
  readonly audience: string | null;
  readonly limits: RateLimiter;
  readonly unauthenticated: RateLimitRule;
  readonly lockout: LockoutRule | null;
  /** Legacy mode with a client CA: every caller must present a certificate and the token. */
  readonly requireCertificate: boolean;
  readonly events: SecurityEvents;
}

/** The key of the one window for requests that never became a principal. */
export const UNAUTHENTICATED_KEY = "*";
const BEARER = "Bearer ";
const COMPACT_JWS = /^[\w-]+\.[\w-]+\.[\w-]+$/;

class Refusal {
  public constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly method: AuthMethod,
    public readonly principal: Principal | null,
  ) {}
}

/**
 * The one chokepoint every non-public request passes, in a fixed,
 * fail-closed order: the window for failed attempts; a certificate and a
 * bearer together, which is ambiguous and refused; the certificate, by SAN
 * URI and optional pin; the bearer, by digest across every bearer principal
 * in constant time, then as a workload token; the lock, only once the
 * principal is known so no lock is an existence oracle; the principal's
 * own window; the route's role; the route's scope. Every refusal is one
 * `AUTH_FAILED` event with the method and the code, and nothing else.
 */
export class Authenticator {
  public constructor(private readonly options: AuthenticatorOptions) {}

  public async authenticate(input: AuthenticationInput): Promise<AuthenticatedPrincipal> {
    try {
      return await this.identify(input);
    } catch (error) {
      if (!(error instanceof Refusal)) throw error;
      this.options.events.emit({ event: "AUTH_FAILED", method: error.method, code: error.code });
      if (error.principal === null) {
        this.options.limits.allow(UNAUTHENTICATED_KEY, this.options.unauthenticated);
      } else if (error.status === 401) {
        const locked = this.options.limits.recordFailure(error.principal.id, this.options.lockout);
        if (locked) {
          this.options.events.emit({ event: "PRINCIPAL_LOCKED", principal: error.principal.id });
        }
      }
      throw new AuthError(error.status, error.code);
    }
  }

  private async identify(input: AuthenticationInput): Promise<AuthenticatedPrincipal> {
    const { registry, limits } = this.options;
    if (limits.exhausted(UNAUTHENTICATED_KEY, this.options.unauthenticated)) {
      throw new Refusal(429, "RATE_LIMITED", "none", null);
    }
    let principal: Principal;
    let method: AuthMethod;
    if (this.options.requireCertificate) {
      if (input.peer === null || !input.peer.authorized) {
        throw new Refusal(401, "CALLER_NOT_AUTHENTICATED", "mtls", null);
      }
      principal = this.bearer(input.authorization);
      method = "bearer";
    } else if (input.peer !== null) {
      if (input.authorization !== undefined) {
        throw new Refusal(401, "AUTH_AMBIGUOUS", "none", null);
      }
      if (!input.peer.authorized) throw new Refusal(401, "CALLER_NOT_AUTHENTICATED", "mtls", null);
      const found = registry.byCertificate(input.peer.sanUris, input.peer.fingerprint);
      if (found === null) throw new Refusal(401, "CALLER_NOT_AUTHENTICATED", "mtls", null);
      principal = found;
      method = "mtls";
    } else {
      const presented = Authenticator.presented(input.authorization);
      const found = registry.byBearerDigest(presented);
      if (found !== null) {
        principal = found;
        method = "bearer";
      } else {
        if (this.options.jwt === null || !COMPACT_JWS.test(presented)) {
          throw new Refusal(401, "CALLER_NOT_AUTHENTICATED", "bearer", null);
        }
        principal = await this.workload(this.options.jwt, presented);
        method = "jwt";
      }
    }
    if (limits.locked(principal.id)) throw new Refusal(423, "PRINCIPAL_LOCKED", method, principal);
    if (principal.rateLimit !== null && !limits.allow(principal.id, principal.rateLimit)) {
      throw new Refusal(429, "RATE_LIMITED", method, principal);
    }
    if (input.route.role !== principal.role) {
      throw new Refusal(403, "ROLE_FORBIDDEN", method, principal);
    }
    if (input.route.scope !== undefined && !principal.scopes.has(input.route.scope)) {
      throw new Refusal(403, "SCOPE_FORBIDDEN", method, principal);
    }
    return { principal, method };
  }

  /** The bearer path alone: the digest scan, and nothing after it. */
  private bearer(authorization: string | undefined): Principal {
    const found = this.options.registry.byBearerDigest(Authenticator.presented(authorization));
    if (found === null) throw new Refusal(401, "CALLER_NOT_AUTHENTICATED", "bearer", null);
    return found;
  }

  private async workload(verifier: WorkloadJwtVerifier, token: string): Promise<Principal> {
    let verified;
    try {
      verified = await verifier.verify(token);
    } catch (error) {
      const code = error instanceof JwtError ? error.code : "JWT_SIGNATURE_INVALID";
      throw new Refusal(401, code, "jwt", null);
    }
    const { registry } = this.options;
    if (!registry.issuerKnown(verified.issuer)) {
      throw new Refusal(401, "JWT_ISSUER_UNKNOWN", "jwt", null);
    }
    const named = registry.byJwt(verified.issuer, verified.subject);
    if (named === null) throw new Refusal(401, "JWT_SUBJECT_UNKNOWN", "jwt", null);
    // The registry narrowed to the workload kind, so the credential here is
    // that kind and needs no second check of its own.
    const { principal, credential } = named;
    // A principal's own audience wins over the configured one; with neither,
    // no token is accepted, because "any audience" is not a thing to accept.
    const audience = credential.audience ?? this.options.audience;
    // Two different operator problems, so two different codes: a deployment
    // that named no audience at all accepts no token, and saying that is
    // "the token's audience was wrong" would send someone to the caller.
    if (audience === null) {
      throw new Refusal(401, "JWT_AUDIENCE_UNCONFIGURED", "jwt", principal);
    }
    if (!verified.audiences.includes(audience)) {
      throw new Refusal(401, "JWT_AUDIENCE_MISMATCH", "jwt", principal);
    }
    for (const [claim, expected] of Object.entries(credential.requiredClaims)) {
      if (verified.claims[claim] !== expected) {
        throw new Refusal(401, "JWT_CLAIM_MISMATCH", "jwt", principal);
      }
    }
    return principal;
  }

  private static presented(authorization: string | undefined): string {
    if (authorization === undefined || !authorization.startsWith(BEARER)) {
      throw new Refusal(401, "CALLER_NOT_AUTHENTICATED", "bearer", null);
    }
    return authorization.slice(BEARER.length).trim();
  }
}
