import { createHash } from "node:crypto";
import {
  Rfc8785,
  type JsonObject,
  type JsonValue,
  type TargetPrecondition,
} from "@decionis/agent-safe-pipeline";
import { compareEffect } from "../adapters/EffectComparison.js";
import type { RegisteredEffect } from "../adapters/EffectEvidenceRegister.js";

/** The record the gateway writes for what it read back, beside the executor's BEAP record. */
export const GATEWAY_EFFECT_PROFILE = "agent-safe.gateway-effect/1";

export type Sha256 = `sha256:${string}`;

/**
 * Why an attempt's effect stays `PENDING`: what the gateway was not asked to
 * read back, or could not.
 *
 * - `EFFECT_UNDECLARED`: the write's operation names no effect, or no read;
 * - `EFFECT_UNSTATED`: the call states none of the values its effect names;
 * - `EFFECT_NOT_BOUND`: facts-only privacy, where no digest of the call's
 *   values may leave the gateway, so the grant commits to none;
 * - `EFFECT_NOT_READ`: the upstream answered with a redirect, not a `2xx`;
 * - `EFFECT_UNREADABLE`: the read after the write did not answer.
 */
export type EffectPending =
  | "EFFECT_UNDECLARED"
  | "EFFECT_UNSTATED"
  | "EFFECT_NOT_BOUND"
  | "EFFECT_NOT_READ"
  | "EFFECT_UNREADABLE";

/** What a write expects its read to state once it has landed, and the digest the grant commits to. */
export interface ExpectedEffect {
  readonly expected: JsonObject;
  readonly digest: Sha256;
}

/** What the gateway says about one forwarded attempt's effect, in the confirmation vocabulary. */
export interface EffectStatement {
  readonly confirmation: "CONFIRMED" | "UNKNOWN" | "PENDING";
  readonly reasonCodes: readonly string[];
}

/** One read after a write: the record the finalization carries, and what the report says. */
export interface ObservedEffect {
  readonly record: RegisteredEffect;
  readonly statement: EffectStatement;
}

/** What a read after a refusal showed: the target where it was, moved, or not stated. */
export type RefusalOutcome = "UNCHANGED" | "CHANGED" | "UNREADABLE";

function digest(value: JsonValue): Sha256 {
  return `sha256:${createHash("sha256").update(Rfc8785.stringify(value)).digest("hex")}`;
}

/**
 * The digest of an effect projection: SHA-256 over the RFC 8785 form of the
 * operation that names it (`<profile>#<operation>`) and the projection. The
 * one function makes the expected digest at capture and the observed one
 * after the read, so equal projections are equal digests, which is all the
 * authority compares. Only this gateway computes either, so it is total: a
 * value another language's JSON writer would spell differently still has one
 * digest here.
 */
export function effectDigest(operation: string, projection: JsonObject): Sha256 {
  return digest({ operation, effect: projection });
}

/**
 * What a write's call lets the grant commit to: nothing when its operation
 * names no effect (`null`), when the call states none of it (`{}`), or under
 * facts-only privacy; otherwise the expectation and its digest.
 */
export function expectEffect(
  operation: string,
  expected: JsonObject | null,
  factsOnly: boolean,
): ExpectedEffect | EffectPending {
  if (expected === null) return "EFFECT_UNDECLARED";
  if (factsOnly) return "EFFECT_NOT_BOUND";
  if (Object.keys(expected).length === 0) return "EFFECT_UNSTATED";
  return { expected, digest: effectDigest(operation, expected) };
}

/**
 * The record of one read after a write, as the finalization carries it: the
 * expectation against what the read stated, `null` when it did not answer.
 * A match is `CONFIRMED`, the gateway's read-back being a method a profile
 * declared; the authority still records it so only from an observer on its
 * own allowlist. A difference is `UNKNOWN` with `EFFECT_MISMATCH`: something
 * landed, and what it was is exactly what nobody can say. No answer is
 * `PENDING`. The record carries digests, pointers and statuses: no value of
 * the call or the answer.
 */
export function effectRecord(input: {
  readonly operation: string;
  readonly effect: ExpectedEffect;
  readonly observed: JsonObject | null;
  readonly observedAt: string;
}): ObservedEffect {
  const { comparison, mismatched } = compareEffect(input.effect.expected, input.observed);
  const confirmation =
    comparison === "MATCH" ? "CONFIRMED" : comparison === "MISMATCH" ? "UNKNOWN" : "PENDING";
  const observedEffectDigest =
    input.observed === null ? null : effectDigest(input.operation, input.observed);
  const evidence: JsonObject = {
    profile: GATEWAY_EFFECT_PROFILE,
    type: "EFFECT_EVIDENCE",
    operation: input.operation,
    observation_method: "READ_AFTER_WRITE",
    expected_effect_digest: input.effect.digest,
    observed_effect_digest: observedEffectDigest,
    comparison,
    mismatched_fields: [...mismatched],
    confirmation: { status: confirmation },
    evidence_status: input.observed === null ? "INCOMPLETE" : "COMPLETE",
    observed_at: input.observedAt,
  };
  const reasonCodes =
    comparison === "MATCH"
      ? []
      : [comparison === "MISMATCH" ? "EFFECT_MISMATCH" : "EFFECT_UNREADABLE"];
  return {
    record: {
      evidence,
      outcome: "COMMITTED",
      comparison,
      mismatched,
      confirmation,
      observedEffectDigest,
      expectedEffectDigest: input.effect.digest,
      responseDigest: null,
      providerReference: null,
      observationMethod: "READ_AFTER_WRITE",
      evidenceDigest: digest(evidence),
      reasonCodes,
      receipt: { comparison: "ABSENT", status: null, digest: null },
    },
    statement: { confirmation, reasonCodes },
  };
}

/**
 * A read after a refusal against the read before the decision: the version
 * the same, another, or none stated. Unchanged says no write landed on that
 * resource between the two reads, by any route; it says nothing about any
 * other resource or any other time.
 */
export function refusalOutcome(
  before: TargetPrecondition,
  after: TargetPrecondition | null,
): RefusalOutcome {
  if (after === null) return "UNREADABLE";
  return after.version === before.version ? "UNCHANGED" : "CHANGED";
}
