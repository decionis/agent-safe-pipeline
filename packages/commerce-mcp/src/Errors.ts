export type CommerceGateErrorCode =
  | "CONFIGURATION_REQUIRED"
  | "CONFIGURATION_INVALID"
  | "INVALID_INPUT"
  | "AUTHENTICATION_FAILED"
  | "AUTHORIZATION_FAILED"
  | "NOT_FOUND"
  | "REQUEST_REJECTED"
  | "CONFLICT"
  | "RATE_LIMITED"
  | "UPSTREAM_TIMEOUT"
  | "UPSTREAM_UNREACHABLE"
  | "UPSTREAM_UNAVAILABLE"
  | "INVALID_UPSTREAM_RESPONSE"
  | "UNEXPECTED_FAILURE";

/** An intentionally safe error whose message can be returned to an MCP client. */
export class CommerceGateError extends Error {
  constructor(
    readonly code: CommerceGateErrorCode,
    message: string,
    readonly options: { status?: number; retryable?: boolean } = {},
  ) {
    super(message);
    this.name = "CommerceGateError";
  }
}

export interface SafeFailure {
  ok: false;
  error: {
    code: CommerceGateErrorCode;
    message: string;
    status: number | null;
    retryable: boolean;
  };
  safety: {
    fail_closed: true;
    no_downstream_action_executed: true;
    credentials_redacted: true;
  };
}

/** Convert any failure into a bounded, credential-free response. */
export function toSafeFailure(error: unknown): SafeFailure {
  const safe =
    error instanceof CommerceGateError
      ? error
      : new CommerceGateError(
          "UNEXPECTED_FAILURE",
          "CommerceGate failed safely. No downstream commerce action was executed.",
        );
  return {
    ok: false,
    error: {
      code: safe.code,
      message: safe.message,
      status: safe.options.status ?? null,
      retryable: safe.options.retryable ?? false,
    },
    safety: {
      fail_closed: true,
      no_downstream_action_executed: true,
      credentials_redacted: true,
    },
  };
}
