import { createHash } from "node:crypto";
import { CanonicalIntentHasher, type JsonValue } from "@decionis/agent-safe-pipeline";

/** A digest in the one form every wire field in this repository uses. */
export type Sha256 = `sha256:${string}`;

export class JcsError extends Error {
  public constructor(public readonly code: "JCS_NOT_I_JSON" | "JCS_NUMBER_NOT_FINITE") {
    super(code);
    this.name = "JcsError";
  }
}

/**
 * The canonical digest BEAP asks for: SHA-256 over the RFC 8785 canonical
 * form of the value. The canonicaliser is the pipeline's own, which sorts
 * keys by UTF-16 code unit and serialises numbers and strings the way
 * ECMAScript does; for I-JSON input those rules and RFC 8785's coincide,
 * which the conformance vectors and the authority's independent
 * canonicaliser both hold this repository to.
 *
 * What the canonicaliser does not do is refuse input that is not I-JSON, so
 * this adds that gate: a lone surrogate would serialise differently in
 * another language's JSON writer, and a non-finite number has no JSON form
 * at all. Both are refused here rather than producing a digest two
 * implementations would disagree about.
 */
export function jcsDigest(value: JsonValue): Sha256 {
  assertIJson(value);
  const canonical = CanonicalIntentHasher.stringify(value);
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

/** The canonical text itself, for a caller that wants to see what was hashed. */
export function jcsCanonical(value: JsonValue): string {
  assertIJson(value);
  return CanonicalIntentHasher.stringify(value);
}

/**
 * Whether a string is well-formed UTF-16: every surrogate paired. Written
 * out rather than taken from `String.prototype.isWellFormed`, which this
 * repository's ES2022 target does not declare, and small enough that
 * depending on the newer library for it would be the larger change.
 *
 * The string iterator does the pairing: it yields a well-formed pair as one
 * two-unit character, and anything unpaired as a single unit. So a lone
 * surrogate is exactly a one-unit character whose code is in the surrogate
 * range, and there is no index arithmetic to get wrong.
 */
export function isWellFormedUtf16(value: string): boolean {
  for (const character of value) {
    if (character.length === 1) {
      const unit = character.charCodeAt(0);
      if (unit >= 0xd800 && unit <= 0xdfff) return false;
    }
  }
  return true;
}

/**
 * Every string well-formed UTF-16, every number finite. Recurses through
 * arrays and objects, and checks keys as well as values, because a key is
 * as much of the canonical form as a value is.
 */
export function assertIJson(value: JsonValue): void {
  if (typeof value === "string") {
    if (!isWellFormedUtf16(value)) throw new JcsError("JCS_NOT_I_JSON");
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new JcsError("JCS_NUMBER_NOT_FINITE");
    return;
  }
  // Only null has to be turned away here: `Object.entries` walks an array's
  // indices and a boolean's absent properties correctly, so a case for each
  // would be a branch no input could tell apart from this one.
  if (value === null) return;
  for (const [key, entry] of Object.entries(value)) {
    if (!isWellFormedUtf16(key)) throw new JcsError("JCS_NOT_I_JSON");
    // A key whose value is `undefined` is a key the canonical form drops,
    // so there is nothing under it to check.
    if (entry !== undefined) assertIJson(entry as JsonValue);
  }
}
