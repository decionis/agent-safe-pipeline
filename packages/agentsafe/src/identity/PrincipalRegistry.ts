import { createHash, timingSafeEqual } from "node:crypto";
import { normaliseFingerprint } from "./PeerIdentity.js";
import {
  PrincipalsError,
  type OperatorScope,
  type PrincipalEntry,
  type PrincipalCredentialEntry,
} from "./PrincipalsFile.js";
import { RateLimiter, type RateLimitRule } from "./RateLimiter.js";

export type Role = "PROPOSER" | "OPERATOR";
export type ClaimValue = string | number | boolean;

export interface PrincipalActor {
  readonly id: string;
  readonly type: string;
  readonly runtime?: string;
}

export type PrincipalCredential =
  | { readonly kind: "BEARER"; readonly digest: () => Uint8Array }
  | { readonly kind: "MTLS"; readonly sanUri: string; readonly fingerprint: string | null }
  | {
      readonly kind: "WORKLOAD_JWT";
      readonly issuer: string;
      readonly subject: string;
      readonly audience: string | null;
      readonly requiredClaims: Readonly<Record<string, ClaimValue>>;
    };

export interface Principal {
  readonly id: string;
  readonly role: Role;
  /** A proposer's tenant and actor: what its intents carry. Null for an operator. */
  readonly tenantId: string | null;
  readonly actor: PrincipalActor | null;
  readonly allowedActions: ReadonlySet<string>;
  readonly scopes: ReadonlySet<OperatorScope>;
  readonly credential: PrincipalCredential;
  readonly rateLimit: RateLimitRule | null;
}

/** The one caller a configuration without a principals file has. */
export const LEGACY_CALLER_ID = "legacy-caller";

/** One credential kind's own shape, for a lookup that narrowed to it. */
type CredentialOf<TKind extends PrincipalCredential["kind"]> = Extract<
  PrincipalCredential,
  { readonly kind: TKind }
>;

export type Comparator = (a: Uint8Array, b: Uint8Array) => boolean;

export interface RegistryContext {
  readonly registeredActions: Iterable<string>;
  readonly jwtConfigured: boolean;
  readonly mutualTls: boolean;
}

export interface LegacyContext {
  readonly tenantId: string;
  readonly actor: PrincipalActor;
  readonly registeredActions: Iterable<string>;
  /** The caller token's current digest; read at each comparison so rotation is followed. */
  readonly callerToken: () => Uint8Array;
}

/**
 * Who may call this process and as what. Built once, from the principals
 * file or from the legacy caller the configuration names, and never changed
 * while running. A bearer lookup hashes what was presented and compares it
 * with every bearer digest in constant time, without stopping at a match,
 * so timing says nothing about which principal, if any, it was.
 */
export class PrincipalRegistry {
  private readonly byId: ReadonlyMap<string, Principal>;

  public constructor(
    private readonly principals: readonly Principal[],
    public readonly legacy: boolean,
    private readonly compare: Comparator = (a, b) => timingSafeEqual(a, b),
  ) {
    this.byId = new Map(principals.map((principal) => [principal.id, principal]));
  }

  /** The principals a file names, checked against what this process can run and verify. */
  public static fromEntries(
    entries: readonly PrincipalEntry[],
    context: RegistryContext,
    compare?: Comparator,
  ): PrincipalRegistry {
    const registered = new Set(context.registeredActions);
    const principals = entries.map((entry): Principal => {
      if (entry.credential.kind === "WORKLOAD_JWT" && !context.jwtConfigured) {
        throw new PrincipalsError("PRINCIPALS_JWT_UNCONFIGURED", entry.id);
      }
      if (entry.credential.kind === "MTLS" && !context.mutualTls) {
        throw new PrincipalsError("PRINCIPALS_MTLS_UNCONFIGURED", entry.id);
      }
      if (entry.role === "PROPOSER") {
        for (const action of entry.allowed_actions) {
          if (!registered.has(action)) {
            throw new PrincipalsError("PRINCIPALS_UNKNOWN_ACTION", `${entry.id}/${action}`);
          }
        }
      }
      // The two roles carry different things, so they are built separately
      // rather than by three checks of the same field with a fallback each.
      const shared = {
        id: entry.id,
        role: entry.role,
        credential: PrincipalRegistry.credential(entry.credential),
        rateLimit:
          entry.rate_limit === undefined
            ? null
            : RateLimiter.parseRule(entry.rate_limit, `principals/${entry.id}/rate_limit`),
      };
      if (entry.role === "OPERATOR") {
        return {
          ...shared,
          tenantId: null,
          actor: null,
          allowedActions: new Set<string>(),
          scopes: new Set(entry.scopes),
        };
      }
      return {
        ...shared,
        tenantId: entry.tenant_id,
        actor: {
          id: entry.actor.id,
          type: entry.actor.type,
          // Absent rather than undefined: the actor travels inside the hashed
          // intent, and a key with no value is not the same canonical form.
          ...(entry.actor.runtime === undefined ? {} : { runtime: entry.actor.runtime }),
        },
        allowedActions: new Set(entry.allowed_actions),
        scopes: new Set<OperatorScope>(),
      };
    });
    return new PrincipalRegistry(principals, false, compare);
  }

  /** The legacy caller: one proposer, every registered action, the caller token as its credential. */
  public static legacy(context: LegacyContext, compare?: Comparator): PrincipalRegistry {
    return new PrincipalRegistry(
      [
        {
          id: LEGACY_CALLER_ID,
          role: "PROPOSER",
          tenantId: context.tenantId,
          actor: context.actor,
          allowedActions: new Set(context.registeredActions),
          scopes: new Set(),
          credential: { kind: "BEARER", digest: context.callerToken },
          rateLimit: null,
        },
      ],
      true,
      compare,
    );
  }

  public get size(): number {
    return this.principals.length;
  }

  public get all(): readonly Principal[] {
    return this.principals;
  }

  public get proposers(): readonly Principal[] {
    return this.principals.filter((principal) => principal.role === "PROPOSER");
  }

  public get operators(): readonly Principal[] {
    return this.principals.filter((principal) => principal.role === "OPERATOR");
  }

  public principal(id: string): Principal | null {
    return this.byId.get(id) ?? null;
  }

  /**
   * The principals holding one kind of credential, narrowed once here rather
   * than by a kind check inside every lookup. A lookup then reads only the
   * fields its own kind has, and there is one place where the narrowing
   * could be wrong.
   */
  private ofKind<TKind extends PrincipalCredential["kind"]>(
    kind: TKind,
  ): { readonly principal: Principal; readonly credential: CredentialOf<TKind> }[] {
    const found: { readonly principal: Principal; readonly credential: CredentialOf<TKind> }[] = [];
    for (const principal of this.principals) {
      if (principal.credential.kind === kind) {
        found.push({ principal, credential: principal.credential as CredentialOf<TKind> });
      }
    }
    return found;
  }

  /** Every bearer digest is compared, in constant time, whether or not an earlier one matched. */
  public byBearerDigest(presented: string): Principal | null {
    const digest = createHash("sha256").update(presented).digest();
    let found: Principal | null = null;
    for (const { principal, credential } of this.ofKind("BEARER")) {
      if (this.compare(digest, credential.digest())) found = principal;
    }
    return found;
  }

  /** The principal a client certificate names by SAN URI, and pins by fingerprint when the file says so. */
  public byCertificate(sanUris: readonly string[], fingerprint: string): Principal | null {
    const presented = normaliseFingerprint(fingerprint);
    for (const { principal, credential } of this.ofKind("MTLS")) {
      if (!sanUris.includes(credential.sanUri)) continue;
      if (credential.fingerprint !== null && credential.fingerprint !== presented) return null;
      return principal;
    }
    return null;
  }

  public issuerKnown(issuer: string): boolean {
    return this.ofKind("WORKLOAD_JWT").some((entry) => entry.credential.issuer === issuer);
  }

  /**
   * The principal a workload token names, with its own credential, so the
   * caller reads the issuer, audience and required claims without narrowing
   * a second time.
   */
  public byJwt(
    issuer: string,
    subject: string,
  ): { readonly principal: Principal; readonly credential: CredentialOf<"WORKLOAD_JWT"> } | null {
    for (const entry of this.ofKind("WORKLOAD_JWT")) {
      if (entry.credential.issuer === issuer && entry.credential.subject === subject) return entry;
    }
    return null;
  }

  /** The audiences named per principal, so the verifier accepts each; the global one is the default. */
  public audiences(): readonly string[] {
    const named = new Set<string>();
    for (const { credential } of this.ofKind("WORKLOAD_JWT")) {
      if (credential.audience !== null) named.add(credential.audience);
    }
    return [...named];
  }

  private static credential(entry: PrincipalCredentialEntry): PrincipalCredential {
    switch (entry.kind) {
      case "BEARER": {
        const digest = Buffer.from(entry.token_sha256, "hex");
        return { kind: "BEARER", digest: () => digest };
      }
      case "MTLS":
        return {
          kind: "MTLS",
          sanUri: entry.san_uri,
          fingerprint: entry.cert_fingerprint_sha256 ?? null,
        };
      case "WORKLOAD_JWT":
        return {
          kind: "WORKLOAD_JWT",
          issuer: entry.issuer,
          subject: entry.subject,
          audience: entry.audience ?? null,
          requiredClaims: entry.required_claims ?? {},
        };
    }
  }
}
