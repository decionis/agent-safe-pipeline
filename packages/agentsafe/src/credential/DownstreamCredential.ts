/** The authorization a dispatch executes under, as a credential may bind it into the request. */
export interface DownstreamGrant {
  /** The grant's own identity, the authority's `jti`. */
  readonly id: string;
  readonly decisionId: string;
  /**
   * The authority's signed proof that this grant was claimed, when it gave
   * one. A credential that signs covers it, so the downstream can tell that
   * the executor sent it and the authority claimed it, and that neither was
   * swapped for another.
   */
  readonly claimAttestation?: string;
}

/** What a handler knows about the request it is about to send, for a credential that signs or scopes. */
export interface DownstreamRequest {
  readonly method: "GET" | "POST";
  readonly url: string;
  readonly body: string | null;
  readonly idempotencyKey: string;
  readonly intentHash: string;
  /**
   * Present on a dispatch, absent on a read-only reconciliation: a lookup
   * executes under no grant, and a credential that signs one covers only
   * what the request actually carries.
   */
  readonly grant?: DownstreamGrant;
}

/**
 * How the executor proves itself to the downstream. A handler asks for the
 * headers at the moment of dispatch and never holds a credential value of its
 * own; the credential resolves the current secret behind the boundary and
 * follows rotation.
 */
export interface DownstreamCredential {
  readonly kind: "STATIC_HEADER" | "PRIVATE_KEY_JWT" | "SIGNED_REQUEST";
  headersFor(request: DownstreamRequest): Promise<Readonly<Record<string, string>>>;
}
