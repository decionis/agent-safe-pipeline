/**
 * A refusal the service meant: a status and a stable code, nothing echoed.
 * A refusal that the caller is expected to act on rather than merely read,
 * a halt above all, carries the answer in the shape the caller already
 * parses and the seconds after which retrying is sensible.
 */
export class ServiceError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
    /** The body to answer with, when `{ code }` is not enough. */
    public readonly body?: unknown,
    /** Seconds; becomes `Retry-After` when present. */
    public readonly retryAfterSeconds?: number,
  ) {
    super(code);
    this.name = "ServiceError";
  }
}
