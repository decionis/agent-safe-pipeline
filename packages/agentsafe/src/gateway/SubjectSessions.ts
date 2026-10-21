import { createHash, randomBytes } from "node:crypto";
import { JwtError, type WorkloadJwtVerifier } from "../identity/WorkloadJwtVerifier.js";
import { SESSION_HEADER, SUBJECT_TOKEN_HEADER } from "./GatewayConfig.js";

/** RFC 8693's grant type, and the token types a subject token may be stated as. */
export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_TOKEN_TYPES: ReadonlySet<string> = new Set([
  "urn:ietf:params:oauth:token-type:jwt",
  "urn:ietf:params:oauth:token-type:id_token",
  "urn:ietf:params:oauth:token-type:access_token",
]);
/** What the exchange issues: an opaque token for this gateway, never a bearer anywhere else. */
export const ISSUED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
/** The most sessions held at once; beyond it a new one is refused rather than an old one dropped. */
export const MAX_SESSIONS = 10_000;
/** The longest a subject token may be, in characters; a longer one is not a short-lived token. */
const MAX_TOKEN_LENGTH = 8_192;
/** How old a subject token may be: a short-lived token, minted for the conversation at hand. */
export const MAX_SUBJECT_TOKEN_AGE_SECONDS = 3_600;

/** A subject the gateway has pinned: who, until when, and a short digest that names the session in evidence. */
export interface SubjectSession {
  readonly subject: string;
  readonly expiresAt: number;
  /** `sha256:` and 12 hex characters of the token's digest; never the token. */
  readonly id: string;
}

/** Why a request's session does not stand: the code a caller sees and the evidence records. */
export type SessionRefusal =
  "SUBJECT_SESSION_INVALID" | "SUBJECT_TOKEN_INVALID" | "SUBJECT_TOKEN_AMBIGUOUS";

/** A verified subject token: the subject it names and when it expires, in epoch milliseconds. */
export interface VerifiedSubject {
  readonly subject: string;
  readonly expiresAt: number;
}

/** Turns a subject token into the subject it names, or throws `JwtError`. */
export interface SubjectTokenVerifier {
  verify(token: string): Promise<VerifiedSubject>;
}

/**
 * The operator's identity provider: a signature from its key set, its issuer
 * exactly, the gateway's audience, a token at most an hour old, and the
 * subject in the configured claim, a string or a number of at most 200
 * characters. Who the customer is, is the provider's statement; the gateway
 * only pins it.
 */
export class IssuerSubjectVerifier implements SubjectTokenVerifier {
  public constructor(
    private readonly jwt: WorkloadJwtVerifier,
    private readonly issuer: string,
    private readonly claim: string,
  ) {}

  public async verify(token: string): Promise<VerifiedSubject> {
    const verified = await this.jwt.verify(token);
    if (verified.issuer !== this.issuer) throw new JwtError("JWT_ISSUER_UNKNOWN");
    const raw = verified.claims[this.claim];
    const subject =
      typeof raw === "string"
        ? raw
        : typeof raw === "number" && Number.isFinite(raw)
          ? String(raw)
          : null;
    if (subject === null || subject.length === 0 || subject.length > 200) {
      throw new JwtError("JWT_SUBJECT_UNKNOWN");
    }
    return { subject, expiresAt: Number(verified.claims.exp) * 1_000 };
  }
}

/** The token exchange's answer: RFC 8693 §2.2, or an RFC 6749 §5.2 error. */
export type ExchangeAnswer =
  | {
      readonly status: 200;
      readonly body: {
        readonly access_token: string;
        readonly issued_token_type: typeof ISSUED_TOKEN_TYPE;
        readonly token_type: "N_A";
        readonly expires_in: number;
      };
      /** The session, for the evidence line; its token is in the body only. */
      readonly session: SubjectSession;
    }
  | {
      readonly status: 400 | 503;
      readonly body: { readonly error: string; readonly error_description: string };
    };

/**
 * Subject-bound sessions. The app that starts an agent (a contact centre, a
 * CRM, a customer's own portal) holds a short-lived token from its identity
 * provider naming the customer in context. It gives the gateway that token,
 * and the gateway pins the subject for the session:
 *
 * - by RFC 8693 token exchange: `POST /_agentsafe/v1/sessions` returns an
 *   opaque session token, which the agent presents in `AgentSafe-Session`;
 *   the gateway keeps only the token's digest, beside the subject;
 * - or per request, the provider's token itself in `AgentSafe-Subject-Token`.
 *
 * Either way the subject comes from the provider's signature and nothing the
 * agent sends can change it: the session token maps to a subject held here,
 * and the provider's token is verified on every request. Both headers end at
 * the gateway. A session lasts as long as this gateway process: it is held in
 * memory, so behind several replicas present the provider's token per
 * request, or keep a caller on one replica.
 */
export class SubjectSessions {
  private readonly sessions = new Map<string, SubjectSession>();

  public constructor(
    private readonly verifier: SubjectTokenVerifier,
    private readonly options: {
      readonly ttlSeconds: number;
      readonly clock: () => number;
      readonly maxSessions?: number;
    },
  ) {}

  /** The sessions held now, expired ones dropped first. */
  public get size(): number {
    this.expire();
    return this.sessions.size;
  }

  /**
   * RFC 8693 token exchange: a subject token in, a session token out. The
   * request is the form the RFC defines; an actor token (delegation) is not
   * accepted, and the only token issued is this gateway's session token. A
   * token that does not verify is `invalid_request`, as the RFC says, with
   * the stable code as its description and nothing from the token.
   */
  public async exchange(form: URLSearchParams): Promise<ExchangeAnswer> {
    const refuse = (error: string, description: string): ExchangeAnswer => ({
      status: 400,
      body: { error, error_description: description },
    });
    const single = (name: string): string | null => {
      const values = form.getAll(name);
      return values.length === 1 ? (values[0] ?? null) : null;
    };
    const grantType = single("grant_type");
    if (grantType !== TOKEN_EXCHANGE_GRANT) {
      return refuse("unsupported_grant_type", "TOKEN_EXCHANGE_ONLY");
    }
    const token = single("subject_token");
    const tokenType = single("subject_token_type");
    if (token === null || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
      return refuse("invalid_request", "SUBJECT_TOKEN_MISSING");
    }
    if (tokenType === null || !JWT_TOKEN_TYPES.has(tokenType)) {
      return refuse("invalid_request", "SUBJECT_TOKEN_TYPE_UNSUPPORTED");
    }
    const requested = form.getAll("requested_token_type");
    if (requested.length > 1 || (requested.length === 1 && requested[0] !== ISSUED_TOKEN_TYPE)) {
      return refuse("invalid_request", "REQUESTED_TOKEN_TYPE_UNSUPPORTED");
    }
    if (form.has("actor_token") || form.has("actor_token_type")) {
      return refuse("invalid_request", "ACTOR_TOKEN_UNSUPPORTED");
    }
    let verified: VerifiedSubject;
    try {
      verified = await this.verifier.verify(token);
    } catch (error) {
      return refuse("invalid_request", error instanceof JwtError ? error.code : "JWT_INVALID");
    }
    this.expire();
    if (this.sessions.size >= (this.options.maxSessions ?? MAX_SESSIONS)) {
      return {
        status: 503,
        body: { error: "temporarily_unavailable", error_description: "SESSION_CAPACITY_EXCEEDED" },
      };
    }
    const now = this.options.clock();
    const expiresAt = Math.min(now + this.options.ttlSeconds * 1_000, verified.expiresAt);
    const sessionToken = randomBytes(32).toString("base64url");
    const digest = SubjectSessions.digest(sessionToken);
    const session: SubjectSession = {
      subject: verified.subject,
      expiresAt,
      id: `sha256:${digest.slice(0, 12)}`,
    };
    this.sessions.set(digest, session);
    return {
      status: 200,
      body: {
        access_token: sessionToken,
        issued_token_type: ISSUED_TOKEN_TYPE,
        token_type: "N_A",
        expires_in: Math.max(Math.floor((expiresAt - now) / 1_000), 0),
      },
      session,
    };
  }

  /**
   * The session a request presents: null when it presents none, the session
   * when it stands, and the refusal otherwise. A request may present one of
   * the two headers, never both, since two would be two answers to whose
   * session it is.
   */
  public async resolve(
    headers: Readonly<Record<string, string>>,
  ): Promise<SubjectSession | SessionRefusal | null> {
    const sessionToken = headers[SESSION_HEADER];
    const subjectToken = headers[SUBJECT_TOKEN_HEADER];
    if (sessionToken !== undefined && subjectToken !== undefined) return "SUBJECT_TOKEN_AMBIGUOUS";
    if (sessionToken !== undefined) {
      const digest = SubjectSessions.digest(sessionToken.trim());
      const session = this.sessions.get(digest);
      if (session === undefined) return "SUBJECT_SESSION_INVALID";
      if (session.expiresAt <= this.options.clock()) {
        this.sessions.delete(digest);
        return "SUBJECT_SESSION_INVALID";
      }
      return session;
    }
    if (subjectToken === undefined) return null;
    const token = subjectToken.trim();
    if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) return "SUBJECT_TOKEN_INVALID";
    try {
      const verified = await this.verifier.verify(token);
      if (verified.expiresAt <= this.options.clock()) return "SUBJECT_TOKEN_INVALID";
      return {
        subject: verified.subject,
        expiresAt: verified.expiresAt,
        id: `sha256:${SubjectSessions.digest(token).slice(0, 12)}`,
      };
    } catch {
      return "SUBJECT_TOKEN_INVALID";
    }
  }

  private expire(): void {
    const now = this.options.clock();
    for (const [digest, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(digest);
    }
  }

  private static digest(token: string): string {
    return createHash("sha256").update(token, "utf8").digest("hex");
  }
}
