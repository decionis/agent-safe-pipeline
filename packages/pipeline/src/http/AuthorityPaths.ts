/**
 * Every execution-authority path this package calls, in one place, as the
 * REST resources Decionis serves them (`decionis-outcome-infrastructure`
 * plan §3.0): a decision binds a grant, and a grant has claims, receipts and
 * reconciliations, each created by a POST. The verb routes these replace
 * stay registered on the authority as aliases of the same handlers, and are
 * named here only for the one case that needs them: a grant whose id cannot
 * be read from its token.
 *
 * A grant's id is its `jti`: the id the authority returns as
 * `execution_token_jti`, records with the grant, and signs into the token.
 */
export class AuthorityPaths {
  /** Evaluate an intent and bind a single-use grant: `POST`. */
  public static readonly GRANTS = "/v1/authority/grants";

  /**
   * The verb routes the REST resources replace. Deprecated on the authority
   * and kept there as aliases on the same handlers, for clients that predate
   * the resources.
   */
  public static readonly LEGACY = Object.freeze({
    enforceAndBind: "/v1/authority/enforce-and-bind",
    verifyToken: "/v1/execution/verify-token",
    claimToken: "/v1/execution/claim-token",
    finalizeToken: "/v1/execution/finalize-token",
  });

  /** Read and verify one grant: `GET`. */
  public static grant(grantId: string): string {
    return `${AuthorityPaths.GRANTS}/${encodeURIComponent(grantId)}`;
  }

  /** Claim a grant, once, immediately before the write: `POST`. */
  public static claims(grantId: string): string {
    return `${AuthorityPaths.grant(grantId)}/claims`;
  }

  /** Record how the claimed attempt ended (finalize): `POST`. */
  public static receipts(grantId: string): string {
    return `${AuthorityPaths.grant(grantId)}/receipts`;
  }

  /** Report how an attempt finalized `INDETERMINATE` resolved: `POST`. */
  public static reconciliations(grantId: string): string {
    return `${AuthorityPaths.grant(grantId)}/reconciliations`;
  }

  /** One managed escalation: `GET` its state, `DELETE` to cancel it. */
  public static escalation(escalationId: string): string {
    return `/v1/authority/escalations/${encodeURIComponent(escalationId)}`;
  }

  /** Where to claim the grant an execution token stands for. */
  public static claimFor(executionToken: string): string {
    const grantId = AuthorityPaths.grantIdOf(executionToken);
    return grantId === null ? AuthorityPaths.LEGACY.claimToken : AuthorityPaths.claims(grantId);
  }

  /** Where to record the receipt for the grant an execution token stands for. */
  public static receiptFor(executionToken: string): string {
    const grantId = AuthorityPaths.grantIdOf(executionToken);
    return grantId === null
      ? AuthorityPaths.LEGACY.finalizeToken
      : AuthorityPaths.receipts(grantId);
  }

  /**
   * The grant id a Decionis execution token names (its `jti`), read without
   * verifying anything: it only addresses the resource, and the authority
   * verifies the token itself and refuses a path whose id is not the
   * token's. Null for a token that is not a JWT or whose `jti` is not a UUID
   * (the only grant id the authority routes), in which case the caller uses
   * the legacy alias.
   */
  public static grantIdOf(executionToken: string): string | null {
    const parts = executionToken.split(".");
    const payload = parts[1];
    if (parts.length !== 3 || payload === undefined || payload.length === 0) return null;
    try {
      const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as unknown;
      const jti = (claims as { readonly jti?: unknown } | null)?.jti;
      return typeof jti === "string" && GRANT_ID.test(jti) ? jti : null;
    } catch {
      return null;
    }
  }
}

/** A grant id as the authority mints and routes it: a UUID, which no path segment has to escape. */
const GRANT_ID = /^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i;
