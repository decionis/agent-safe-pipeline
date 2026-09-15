import type { AuthorityEffectEvidence, JsonObject } from "@decionis/agent-safe-pipeline";
import { jcsDigest, type Sha256 } from "./JcsDigest.js";
import { compareEffect, type Comparison } from "./EffectComparison.js";
import type { PreparedAction, ProviderResult } from "./EffectAdapter.js";
import type { RegisteredEffect } from "./EffectEvidenceRegister.js";

export type ConfirmationStatus = "PENDING" | "CONFIRMED" | "NOT_EFFECTED" | "REVERSED" | "UNKNOWN";
export type EffectOutcome = "COMMITTED" | "FAILED" | "INDETERMINATE";

export interface EvidenceInput {
  readonly prepared: PreparedAction;
  readonly result: ProviderResult | null;
  /** Set when the provider neither committed nor refused. */
  readonly indeterminate?: { readonly reason: string; readonly providerStatus: string | null };
  readonly observer: { readonly id: string; readonly version: string };
  readonly correlationId: string;
  readonly idempotencyKey: string;
  readonly observedAt: string;
}

/**
 * What confirmation an observation actually supports. An acknowledgement is
 * never a confirmation: a provider saying "accepted" has told you it took
 * the request, not that the effect exists, so the confirmation stays
 * `PENDING` until something read the effect back and it matched. A
 * mismatch is `UNKNOWN`, not `NOT_EFFECTED`: something happened, and what
 * it was is exactly what nobody can yet say.
 */
export function confirmationFor(
  outcome: EffectOutcome,
  comparison: Comparison,
  method: string,
): ConfirmationStatus {
  if (outcome === "INDETERMINATE") return "UNKNOWN";
  if (outcome === "FAILED") return "NOT_EFFECTED";
  if (comparison === "MISMATCH") return "UNKNOWN";
  if (comparison === "PENDING") return "PENDING";
  return method === "DOWNSTREAM_ACK" ? "PENDING" : "CONFIRMED";
}

/**
 * The effect record for one attempt: what was expected, what was observed,
 * whether they agree, and what that supports. It carries digests,
 * identifiers, statuses and codes; no provider body, no parameter, no
 * credential. The record is digested over its own canonical form, so a
 * later reader can tell that the record they hold is the record that was
 * made.
 */
export function buildEffectRecord(input: EvidenceInput): RegisteredEffect {
  const { prepared, result, indeterminate } = input;
  const outcome: EffectOutcome =
    indeterminate !== undefined ? "INDETERMINATE" : (result?.status ?? "INDETERMINATE");
  const observed = outcome === "COMMITTED" ? (result?.observed ?? null) : null;
  const { comparison, mismatched } = compareEffect(prepared.expectedEffect, observed);
  const observationMethod = result?.observationMethod ?? "DOWNSTREAM_ACK";
  const confirmation = confirmationFor(outcome, comparison, observationMethod);
  const observedEffectDigest: Sha256 | null = observed === null ? null : jcsDigest(observed);
  const reasonCodes = [
    ...(indeterminate === undefined ? [] : ["INDETERMINATE_OUTCOME"]),
    ...(comparison === "MISMATCH" ? ["EFFECT_MISMATCH"] : []),
    ...(result?.failureReason === null || result?.failureReason === undefined
      ? []
      : [result.failureReason]),
  ];
  const evidence: JsonObject = {
    profile: "decionis.beap/v0.1",
    type: "EFFECT_EVIDENCE",
    domain: prepared.domain,
    action: prepared.actionType,
    intent_digest: prepared.intentDigest,
    execution: {
      adapter: input.observer.id,
      correlation_id: input.correlationId,
      idempotency_key: input.idempotencyKey,
      attempt: 1,
      observed_at: input.observedAt,
    },
    outcome: {
      status: outcome,
      provider_status: result?.providerStatus ?? indeterminate?.providerStatus ?? null,
      provider_reference: result?.providerReference ?? null,
      response_digest: result?.responseDigest ?? null,
      failure_reason: result?.failureReason ?? indeterminate?.reason ?? null,
    },
    effect: {
      effect_type: prepared.effectType,
      resource_ref: prepared.resourceRef,
      expected_effect_digest: prepared.expectedEffectDigest,
      observed_effect_digest: observedEffectDigest,
      observation_method: observationMethod,
      comparison,
      ...(mismatched.length === 0 ? {} : { mismatched_fields: [...mismatched] }),
    },
    confirmation: { status: confirmation },
    provenance: {
      source: result?.source ?? "ADAPTER_OBSERVATION",
      provider_generated: result?.providerGenerated ?? false,
      observer: { id: input.observer.id, version: input.observer.version },
    },
    evidence_status: observed === null ? "INCOMPLETE" : "COMPLETE",
    observed_at: input.observedAt,
  };
  return {
    evidence,
    outcome,
    comparison,
    mismatched,
    confirmation,
    observedEffectDigest,
    expectedEffectDigest: prepared.expectedEffectDigest,
    responseDigest: result?.responseDigest ?? null,
    providerReference: result?.providerReference ?? null,
    observationMethod,
    evidenceDigest: jcsDigest(evidence),
    reasonCodes,
  };
}

/**
 * The same observation in the authority's own Protocol 1.1 shape. The
 * authority binds it to the grant by the expected-effect digest and the
 * commit correlation id, and refuses a whole finalization whose evidence it
 * cannot bind, so nothing is invented here: the digests and the correlation
 * id are the ones the attempt actually used, and a `MISMATCH` is reported as
 * `UNCONFIRMED` with the digest that was observed rather than hidden.
 */
export function authorityEffectEvidence(
  effect: RegisteredEffect,
  correlationId: string,
  observer: { readonly id: string; readonly version: string },
): AuthorityEffectEvidence {
  return {
    version: "1.0",
    status: effect.confirmation === "CONFIRMED" ? "CONFIRMED" : "UNCONFIRMED",
    observation_method: effect.observationMethod as AuthorityEffectEvidence["observation_method"],
    observer: { id: observer.id, version: observer.version },
    expected_effect_digest: effect.expectedEffectDigest,
    observed_effect_digest: effect.observedEffectDigest,
    observed_at: String((effect.evidence as { observed_at?: unknown }).observed_at ?? null),
    evidence_digest: effect.evidenceDigest,
    evidence_reference: null,
    execution_correlation_id: correlationId,
  };
}
