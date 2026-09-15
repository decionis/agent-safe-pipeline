/** Every way the sealed egress refuses a request, as a stable code. */
export type EgressCode =
  | "EGRESS_SCHEME_NOT_ALLOWED"
  | "EGRESS_ORIGIN_NOT_ALLOWED"
  | "EGRESS_PATH_NOT_ALLOWED"
  | "EGRESS_ADDRESS_REFUSED"
  | "EGRESS_TLS_REJECTED"
  | "EGRESS_TLS_PIN_MISMATCH"
  | "EGRESS_BODY_TOO_LARGE"
  | "EGRESS_TIMEOUT"
  | "EGRESS_REDIRECT_REFUSED"
  | "EGRESS_RESPONSE_INVALID"
  | "EGRESS_INIT_UNSUPPORTED"
  | "EGRESS_GLOBAL_FETCH_LOCKED";

/**
 * A refusal by the executor's own egress policy: the code, and the origin it
 * concerned. Never the path, the headers, or anything from the request or
 * the response.
 */
export class EgressError extends Error {
  public constructor(
    public readonly code: EgressCode,
    public readonly origin: string | null = null,
  ) {
    super(code);
    this.name = "EgressError";
  }
}
