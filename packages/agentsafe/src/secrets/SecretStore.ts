import type { SECRET_KEYS } from "../config/ConfigKeys.js";
import type { SecretHandle } from "./SecretHandle.js";

export type SecretName = (typeof SECRET_KEYS)[number];

export type ReloadReason = "WATCH" | "POLL" | "SIGHUP" | "OPERATOR";

export interface ReloadReport {
  readonly reason: ReloadReason;
  /** Secrets whose value changed and whose new handle is now current. */
  readonly rotated: readonly SecretName[];
  /** Secrets whose new file was refused; the previous handle stays current. */
  readonly refused: readonly { readonly name: SecretName; readonly code: string }[];
}

/**
 * Where the executor's secrets come from and how they change. A store hands
 * out the current handle by name; a consumer that must follow rotation reads
 * the handle at the moment of use, or subscribes. Every failure names the
 * variable and never a value.
 */
export interface SecretStore {
  has(name: SecretName): boolean;
  /** The current handle; throws `SECRET_UNKNOWN` for a name this store does not hold. */
  get(name: SecretName): SecretHandle;
  /** Notified after a rotation, with the new handle; returns the unsubscribe. */
  onRotate(name: SecretName, listener: (next: SecretHandle) => void): () => void;
  /** Re-reads every source; atomic per secret, never partial. */
  reload(reason: ReloadReason): Promise<ReloadReport>;
  close(): void;
}

/** A refusal at start-up or reload: the code and the variable, never the value. */
export class SecretError extends Error {
  public constructor(
    public readonly code: string,
    public readonly secret: SecretName,
  ) {
    super(`${code}: ${secret}`);
    this.name = "SecretError";
  }
}
