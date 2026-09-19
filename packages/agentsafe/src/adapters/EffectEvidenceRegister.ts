import type { VerifiedAuthorization } from "@decionis/agent-safe-pipeline";
import type { JsonObject } from "@decionis/agent-safe-pipeline";
import type { ReceiptComparison, ReceiptStatus } from "./EffectComparison.js";

/** What the handler observed, waiting for the verifier that finalizes the grant. */
export interface RegisteredEffect {
  readonly evidence: JsonObject;
  readonly outcome: "COMMITTED" | "FAILED" | "INDETERMINATE";
  readonly comparison: "MATCH" | "MISMATCH" | "PENDING";
  readonly mismatched: readonly string[];
  readonly confirmation: "PENDING" | "CONFIRMED" | "NOT_EFFECTED" | "REVERSED" | "UNKNOWN";
  readonly observedEffectDigest: string | null;
  readonly expectedEffectDigest: string;
  readonly responseDigest: string | null;
  readonly providerReference: string | null;
  readonly observationMethod: string;
  readonly evidenceDigest: string;
  readonly reasonCodes: readonly string[];
  /** The provider's receipt against this account: absent, silent, agreeing or contradicting. */
  readonly receipt: {
    readonly comparison: ReceiptComparison;
    readonly status: ReceiptStatus | null;
    readonly digest: string | null;
  };
}

/**
 * The handoff between the handler, which observes the effect, and the
 * verifier, which finalizes the grant with the authority moments later.
 * Keyed by the frozen authorization the pipeline handed both of them, in a
 * `WeakMap`, so an entry cannot outlive the attempt it belongs to and one
 * attempt can never read another's: there is no shared identifier to guess
 * and nothing to clear.
 */
export class EffectEvidenceRegister {
  private readonly entries = new WeakMap<VerifiedAuthorization, RegisteredEffect>();

  public attach(authorization: VerifiedAuthorization, effect: RegisteredEffect): void {
    this.entries.set(authorization, effect);
  }

  public take(authorization: VerifiedAuthorization): RegisteredEffect | null {
    const effect = this.entries.get(authorization) ?? null;
    if (effect !== null) this.entries.delete(authorization);
    return effect;
  }
}
