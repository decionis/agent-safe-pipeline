import type { JsonObject, JsonValue } from "@decionis/agent-safe-pipeline";

export type Comparison = "MATCH" | "MISMATCH" | "PENDING";

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
