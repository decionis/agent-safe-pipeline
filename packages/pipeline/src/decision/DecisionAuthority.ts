import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import { immutableDecisionGate } from "./ImmutableDecisionGate.js";

export type DecisionVerdict = "ALLOW" | "ESCALATE" | "BLOCK";

/**
 * `ENFORCEMENT` evaluations may produce execution authority. `SHADOW`
 * evaluations are observational: the authority records the same intent and
 * dossier evidence but never issues a grant.
 */
export type DecisionEvaluationMode = "ENFORCEMENT" | "SHADOW";

/** Ceremony methods currently supported by Decionis-managed Presence orchestration. */
export type ManagedEscalationVerificationMethod = "WEBAUTHN" | "ACTIVE_LIVENESS";

export interface ManagedEscalationRequest {
  readonly mode: "MANAGED";
  /** Trusted routing constraints. Decionis still resolves the principal and effective role. */
  readonly approver?: {
    readonly principal_id?: string;
    readonly role_id?: string;
  };
  readonly verification_requirements?: {
    readonly methods: readonly ManagedEscalationVerificationMethod[];
    readonly level?: "STANDARD" | "HIGH_CONFIDENCE";
  };
}

export interface DecisionEvaluationOptions {
  /**
   * Requests Decionis-owned Presence orchestration outside the canonical
   * execution intent. The authority binds these constraints to the resulting
   * escalation; they are never approval evidence.
   */
  readonly escalation?: ManagedEscalationRequest;
}

export type ManagedEscalationStatus =
  | "PENDING_PRESENCE"
  | "PRESENCE_REQUESTED"
  | "AWAITING_APPROVER"
  | "PRESENCE_VERIFIED"
  | "REAUTHORIZING"
  | "GRANT_READY"
  | "EXPIRED"
  | "REJECTED"
  | "BLOCKED"
  | "CANCELLED"
  | "FAILED";

export type ManagedEscalationOutcome = "ESCALATE_PENDING" | "ALLOW" | "BLOCK" | "ERROR";

/** Safe Decionis-owned orchestration metadata. It never contains an invitation or a grant. */
export interface ManagedEscalationState {
  readonly escalationId: string;
  readonly intentId: string;
  readonly status: ManagedEscalationStatus;
  readonly outcome: ManagedEscalationOutcome;
  readonly expiresAt: string;
  readonly reasonCodes: readonly string[];
}

export interface HumanApprovalEvidence {
  readonly provider: "presence";
  readonly requestId: string;
  readonly receiptDossierId: string;
}

/**
 * A presence provider's signed attestation (a compact Ed25519 JWS, at most
 * 20,000 characters) that a person was present for this exact intent, such
 * as a cardholder tapping their own card. It is evidence for a fresh
 * evaluation and never authority: the authority verifies the signature
 * against the key the organisation registered, binds it to the intent hash,
 * and an `ESCALATE` becomes `ALLOW` only when policy has a rule matching the
 * approval facts. This package carries the token bounded and shaped, never
 * reads it, and never writes it to a record.
 */
export interface AttestedHumanApprovalEvidence {
  readonly provider: "attestation";
  readonly attestation: string;
}

export interface DecisionEvidence {
  readonly humanApproval?: HumanApprovalEvidence | AttestedHumanApprovalEvidence;
}

/**
 * What Decionis said about the same intent when a hosted evaluation ran
 * beside a local authority. It carries no grant: the grant, when one exists,
 * is on the decision this record is attached to, and only when `governs` is
 * true did the hosted verdict choose it.
 */
export interface HostedEvaluation {
  readonly mode: DecisionEvaluationMode;
  /** True when the attached decision is the hosted one; false when the local authority's decision stood. */
  readonly governs: boolean;
  readonly verdict: DecisionVerdict;
  readonly decisionId: string;
  readonly dossierId: string | null;
  readonly reasonCodes: readonly string[];
  /** True when the hosted call did not answer the policy question and was recorded as BLOCK. */
  readonly failClosed: boolean;
  /**
   * The public page that verifies the dossier without an account, when the
   * authority attached one to the decision; null until it does.
   */
  readonly verificationUrl: string | null;
}

/**
 * Where an `ESCALATE` goes, as the authority read it from the policy: which
 * authority the policy requires (its kind and role, never a person) and who
 * proves that person, by which method. `decionis` names Decionis Presence;
 * any other provider is a third party whose signed attestation resumes the
 * hold (a cardholder's card tap through the issuer's app). Routing, never
 * authority: only a fresh evaluation with the proof as evidence can turn the
 * hold into a grant.
 */
export interface EscalationRequirement {
  readonly requirementId: string | null;
  readonly expiresAt: string;
  readonly selector: {
    readonly kind: "ROLE" | "PRINCIPAL";
    readonly roleId?: string;
  } | null;
  readonly verification: {
    readonly provider: string;
    readonly methods: readonly string[];
    readonly level: "STANDARD" | "HIGH_CONFIDENCE";
  } | null;
}

export interface DecisionGate {
  readonly verdict: DecisionVerdict;
  readonly decisionId: string;
  readonly dossierId: string | null;
  readonly intentHash: string;
  readonly reasonCodes: readonly string[];
  readonly authorization: {
    readonly token: string;
    readonly expiresAt: string;
  } | null;
  readonly failClosed: boolean;
  /** The public page that verifies the dossier, when the authority attached one. */
  readonly verificationUrl?: string;
  /** Evidence the authority evaluated with; a claim must present the same evidence. */
  readonly evidence?: DecisionEvidence;
  /** Present only when Decionis, rather than the executor, orchestrates Presence. */
  readonly managedEscalation?: ManagedEscalationState;
  /** Present only when a hosted Decionis evaluation ran beside the local authority. */
  readonly hosted?: HostedEvaluation;
  /** Present on an `ESCALATE` when the authority said where it goes. */
  readonly escalationRequirement?: EscalationRequirement;
}

export interface DecisionAuthority {
  /**
   * Declared evaluation mode, when the authority knows it. `ShadowPipeline`
   * refuses an authority that declares `ENFORCEMENT` so observational traffic
   * cannot be sent through a grant-issuing path by mistake.
   */
  readonly evaluationMode?: DecisionEvaluationMode;
  evaluate(
    intent: CapturedIntent,
    evidence?: DecisionEvidence,
    options?: DecisionEvaluationOptions,
  ): Promise<DecisionGate>;
}

export class FailClosedDecision {
  public static create(intentHash: string, reasonCode: string): DecisionGate {
    return immutableDecisionGate({
      verdict: "BLOCK",
      decisionId: "unavailable",
      dossierId: null,
      intentHash,
      reasonCodes: [reasonCode],
      authorization: null,
      failClosed: true,
    });
  }
}
