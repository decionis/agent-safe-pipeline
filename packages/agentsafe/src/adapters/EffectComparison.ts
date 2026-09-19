import type { JsonObject, JsonValue } from "@decionis/agent-safe-pipeline";

export type Comparison = "MATCH" | "MISMATCH" | "PENDING";

/**
 * How the provider's receipt (the Verifying Provider Profile, VP-3) relates to
 * this executor's own account of the attempt. `ABSENT` is no receipt, or one
 * whose statement could not be read; `SILENT` is a receipt whose status
 * agrees with the outcome but that names no effect digest to compare;
 * `MISMATCH` is a receipt that contradicts the outcome, the authorised
 * effect, or what this executor observed; `MATCH` is agreement on all three.
 */
export type ReceiptComparison = "MATCH" | "MISMATCH" | "SILENT" | "ABSENT";

export type ReceiptStatus = "EFFECTED" | "REFUSED" | "INDETERMINATE";

/** What a receipt says it did, read without verifying it. */
export interface ReceiptStatement {
  readonly status: ReceiptStatus;
  readonly digest: string | null;
}

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const MAX_RECEIPT_LENGTH = 20_000;

export interface EffectComparisonResult {
  readonly comparison: Comparison;
  /** The projected fields that differ, in the projection's own order. */
  readonly mismatched: readonly string[];
}

/**
 * The expected effect against the observed one, field by field over the
 * projection and nothing else. A provider that returns more than the
 * projection asks about cannot cause a mismatch, and a provider that
 * returns less cannot hide one: a field the observation does not carry is a
 * difference, because the projection is exactly the set of things that had
 * to be true for this to be the effect that was authorised.
 *
 * An observation that does not exist yet is `PENDING`, which is not a
 * match: an acknowledgement is not a confirmation.
 */
export function compareEffect(
  expected: JsonObject,
  observed: JsonObject | null,
): EffectComparisonResult {
  if (observed === null) return { comparison: "PENDING", mismatched: [] };
  const mismatched = Object.keys(expected).filter(
    (field) => !sameValue(expected[field], observed[field]),
  );
  return {
    comparison: mismatched.length === 0 ? "MATCH" : "MISMATCH",
    mismatched,
  };
}

/**
 * Structural equality over JSON values, so nothing is compared by reference
 * and nothing is compared by coercion. A field the observation does not
 * carry arrives here as `undefined`, which equals no value the expectation
 * can hold, so an absent field is a difference rather than a match. An array
 * is only ever equal to an array: an object that happens to have the same
 * indices, or a `length`, is a different value, and a provider's body is not
 * trusted to be the shape it resembles.
 */
function sameValue(expected: JsonValue | undefined, observed: JsonValue | undefined): boolean {
  if (expected === null || observed === null) return expected === observed;
  if (typeof expected !== "object" || typeof observed !== "object") return expected === observed;
  if (Array.isArray(expected)) {
    return (
      Array.isArray(observed) &&
      expected.length === observed.length &&
      expected.every((item, index) => sameValue(item, observed[index]))
    );
  }
  if (Array.isArray(observed)) return false;
  const left = expected as Record<string, JsonValue>;
  const right = observed as Record<string, JsonValue>;
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((key) => sameValue(left[key], right[key]))
  );
}

/**
 * The provider's statement in its receipt: the `effect` block's status and
 * digest, and nothing else. The signature is not verified here and the
 * claims are not trusted; the authority does that at finalization. What this
 * reads is what the provider *says*, so the executor can record whether the
 * provider's account of the effect agrees with its own, which neither party
 * can tell alone. Null when there is no receipt, or when the value is not a
 * compact JWS whose payload carries an effect with a status the profile
 * defines and, when present, a digest in the profile's form.
 */
export function receiptStatement(receipt: string | null | undefined): ReceiptStatement | null {
  if (typeof receipt !== "string" || receipt.length > MAX_RECEIPT_LENGTH) return null;
  const parts = receipt.split(".");
  if (parts.length !== 3) return null;
  try {
    // A payload that is not an object with an effect object reads as no
    // statement: the property reads give undefined, or throw on null, and
    // both end here.
    const payload = JSON.parse(
      Buffer.from(parts[1] as string, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    const { status, digest } = payload["effect"] as Record<string, unknown>;
    if (status !== "EFFECTED" && status !== "REFUSED" && status !== "INDETERMINATE") return null;
    if (digest === undefined || digest === null) return { status, digest: null };
    return typeof digest === "string" && SHA256.test(digest) ? { status, digest } : null;
  } catch {
    return null;
  }
}

/**
 * The receipt's statement against this executor's account: the outcome the
 * provider answered with, the effect the grant authorised, and the effect
 * the adapter observed. A status that contradicts the outcome is a mismatch
 * whatever the digest says; a digest is compared with the authorised effect
 * and, when there is one, with the observation; a receipt that names no
 * digest can agree with nothing and disagree with nothing, and is `SILENT`.
 */
export function compareReceipt(
  outcome: "COMMITTED" | "FAILED" | "INDETERMINATE",
  expectedDigest: string,
  observedDigest: string | null,
  statement: ReceiptStatement | null,
): ReceiptComparison {
  if (statement === null) return "ABSENT";
  const agreed =
    (outcome === "COMMITTED" && statement.status === "EFFECTED") ||
    (outcome === "FAILED" && statement.status === "REFUSED") ||
    (outcome === "INDETERMINATE" && statement.status === "INDETERMINATE");
  if (!agreed) return "MISMATCH";
  if (statement.digest === null) return "SILENT";
  if (statement.digest !== expectedDigest) return "MISMATCH";
  if (observedDigest !== null && statement.digest !== observedDigest) return "MISMATCH";
  return "MATCH";
}
