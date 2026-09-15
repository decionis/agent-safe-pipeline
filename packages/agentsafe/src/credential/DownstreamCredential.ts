/** What a handler knows about the request it is about to send, for a credential that signs or scopes. */
export interface DownstreamRequest {
  readonly method: "GET" | "POST";
  readonly url: string;
  readonly body: string | null;
  readonly idempotencyKey: string;
  readonly intentHash: string;
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
