/** A downstream credential that could not be produced: the code, never the material. */
export class CredentialError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "CredentialError";
  }
}
