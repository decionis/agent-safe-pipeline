/** A refusal the service meant: a status and a stable code, nothing echoed. */
export class ServiceError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(code);
    this.name = "ServiceError";
  }
}
