import type { DecisionGate } from "../decision/DecisionAuthority.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type { ExecutionFinalization, VerifiedAuthorization } from "./AuthorizationVerifier.js";
import type { ExecutionPermit } from "./NativeExecutor.js";

/**
 * Every governed run ends in exactly one of these. They answer one question,
 * "may the caller retry the side effect?", and the answers never overlap:
 *
 * | Outcome                   | Meaning                                                        |
 * | ------------------------- | -------------------------------------------------------------- |
 * | `BLOCKED`                 | No valid execution authority reached the executor              |
 * | `HELD`                    | Admitted; the grant waits, unclaimed, for the native boundary  |
 * | `FAILED_BEFORE_DISPATCH`  | A grant was consumed and nothing was sent                      |
 * | `COMPLETED`               | The platform effected the action                               |
 * | `DEFINITELY_NOT_EXECUTED` | The platform was reached and refused; nothing was effected     |
 * | `UNKNOWN_AFTER_DISPATCH`  | The write left, and nobody can yet say what happened           |
 */
export type ExecutionOutcome =
  | "BLOCKED"
  | "HELD"
  | "FAILED_BEFORE_DISPATCH"
  | "COMPLETED"
  | "DEFINITELY_NOT_EXECUTED"
  | "UNKNOWN_AFTER_DISPATCH";

export type ExecutionBlockReason =
  | "DECISION_NOT_AUTHORITATIVE"
  | "DECISION_NOT_ALLOW"
  | "DOSSIER_MISSING"
  | "INTENT_BINDING_MISMATCH"
  | "INTENT_CONFORMANCE_FAILED"
  | "AUTHORIZATION_MISSING"
  | "AUTHORIZATION_INVALID"
  | "RECOVERY_BINDING_MISMATCH"
  | "RECOVERY_ATTEMPT_UNKNOWN"
  | "BOUNDARY_MISMATCH"
  | "WORKLOAD_MISMATCH"
  | "AUDIT_UNAVAILABLE"
  | "CAPABILITY_UNAVAILABLE"
  | "IDEMPOTENCY_KEY_DISPATCHED"
  | "JOURNAL_UNAVAILABLE";

/** Where an executor reads back the authorizations it dispatched an intent under. */
export interface DispatchedAttempts {
  /** Every authorization journaled for this intent, oldest first; none when it was never dispatched here. */
  authorizationsOf(captured: CapturedIntent): Promise<readonly VerifiedAuthorization[]>;
}

export type ExecutionPreDispatchFailureReason =
  "HANDLER_FAILED_BEFORE_DISPATCH" | "AUDIT_UNAVAILABLE" | "JOURNAL_UNAVAILABLE";

/**
 * What a caller presents back to reconcile an attempt whose outcome was
 * lost. The fields are listed rather than inherited, because this is a
 * versioned wire object: a field that appears on `VerifiedAuthorization`
 * later must be added here deliberately or not at all.
 */
export interface ExecutionRecoveryReference {
  readonly version: "agent-safe.recovery/1";
  readonly decisionId: string;
  readonly dossierId: string;
  readonly grantId: string;
  readonly intentHash: string;
  readonly expiresAt: string;
  readonly idempotencyKey: string;
}

export interface ExecutionBlockedResult {
  readonly outcome: "BLOCKED";
  readonly executed: false;
  readonly reason: ExecutionBlockReason;
  /** Why, more narrowly, when the runner knows: a capability gap, a journal refusal. */
  readonly code?: string;
  /**
   * Present only when the decision failed closed and the posture is not
   * strict: what the surface may do with an action nobody could decide. The
   * runner itself never writes it; an ungoverned continuation is the
   * surface's act, and the evidence line reports it as one.
   */
  readonly unavailable?: {
    readonly posture: "BOUNDED_CONTINUITY" | "CUSTOM";
    readonly disposition: "NOT_FORWARDED" | "HELD" | "FORWARDED_UNGOVERNED";
  };
  readonly result: null;
  readonly authorization: null;
}

/**
 * The provider refused, definitively, after the dispatch boundary. The grant
 * was consumed and the request was sent, and nothing was effected: the
 * outcome is a fact, not an unknown, so there is nothing to reconcile and no
 * recovery reference to present. A caller that wants the action after all
 * needs a fresh decision and a fresh grant, because the refusal was about
 * this attempt.
 */
export interface ProviderRefusedResult {
  readonly outcome: "DEFINITELY_NOT_EXECUTED";
  readonly executed: false;
  readonly recovered: false;
  /** The provider's own reason, as the handler reported it. */
  readonly reason: string;
  readonly result: null;
  readonly authorization: VerifiedAuthorization;
}

export interface ProviderOutcomeUnknownResult {
  readonly outcome: "UNKNOWN_AFTER_DISPATCH";
  readonly executed: null;
  readonly reason: "PROVIDER_OUTCOME_UNKNOWN";
  readonly result: null;
  readonly authorization: VerifiedAuthorization;
  readonly recovery: ExecutionRecoveryReference;
}

/**
 * Every outcome that consumed a grant reports whether the attempt's commit
 * evidence reached the authority. Finalization is evidence, not authority;
 * it never changes `outcome` or `executed`.
 */
export type SafeExecutionResult<TResult = unknown> =
  | {
      readonly outcome: "COMPLETED";
      readonly executed: true;
      readonly recovered: false;
      readonly result: TResult;
      readonly authorization: VerifiedAuthorization;
      readonly finalization: ExecutionFinalization;
    }
  | ExecutionBlockedResult
  | {
      readonly outcome: "FAILED_BEFORE_DISPATCH";
      readonly executed: false;
      readonly reason: ExecutionPreDispatchFailureReason;
      /** Why the handler refused, when it threw a `PreDispatchRefusal`. */
      readonly code?: string;
      readonly result: null;
      readonly authorization: VerifiedAuthorization;
      readonly finalization: ExecutionFinalization;
    }
  | (ProviderRefusedResult & { readonly finalization: ExecutionFinalization })
  | (ProviderOutcomeUnknownResult & { readonly finalization: ExecutionFinalization });

export type FailedBeforeDispatchResult = Extract<
  SafeExecutionResult<never>,
  { outcome: "FAILED_BEFORE_DISPATCH" }
>;

export type ExecutionReconciliationResult<TResult = unknown> =
  | {
      readonly outcome: "COMPLETED";
      readonly executed: true;
      readonly recovered: true;
      readonly result: TResult;
      readonly authorization: VerifiedAuthorization;
    }
  | {
      readonly outcome: "DEFINITELY_NOT_EXECUTED";
      readonly executed: false;
      readonly recovered: true;
      readonly reason: "PROVIDER_CONFIRMED_NOT_EXECUTED";
      readonly result: null;
      readonly authorization: VerifiedAuthorization;
    }
  | ExecutionBlockedResult
  | ProviderOutcomeUnknownResult;

/**
 * A grant admitted for a later claim. Every check a run makes before it
 * consumes a grant has passed, and nothing has been consumed: the grant is
 * still the authority's to hand out once. Only a hold issues one, only the
 * runner that issued it can claim it, and it is claimed at most once.
 *
 * This is for an effect that another system performs at a moment this
 * process does not choose, such as a card authorization the issuer asks
 * about in milliseconds or a posting an ERP makes when a clerk posts: the
 * decision is made before, the grant waits here, and the claim happens when
 * that system presents its permit.
 */
export interface HeldExecution {
  readonly captured: CapturedIntent;
  readonly decision: DecisionGate;
  /** The grant's own expiry: after it there is nothing left to claim. */
  readonly expiresAt: string;
}

export interface ExecutionHeldResult {
  readonly outcome: "HELD";
  readonly executed: false;
  readonly result: null;
  readonly authorization: null;
  readonly held: HeldExecution;
}

/** A held permit-style execution: the hold, and the permit the native boundary presents. */
export interface PermitHeldResult extends ExecutionHeldResult {
  readonly permit: ExecutionPermit;
}

export type HeldClaimResult =
  | { readonly outcome: "CLAIMED"; readonly authorization: VerifiedAuthorization }
  | ExecutionBlockedResult
  | FailedBeforeDispatchResult;

/** A presented permit, claimed: what the boundary writes with. */
export type PermitPresentationResult =
  | {
      readonly outcome: "CLAIMED";
      readonly authorization: VerifiedAuthorization;
      readonly permit: ExecutionPermit;
    }
  | ExecutionBlockedResult
  | FailedBeforeDispatchResult;

/**
 * How a held execution's receipt settled it. A receipt is accepted once: a
 * second one, or one for a permit nobody presented, is refused and changes
 * nothing that was recorded.
 */
export type ExecutionSettlement<TResult = unknown> =
  | {
      readonly status: "SETTLED";
      readonly outcome: "COMPLETED" | "DEFINITELY_NOT_EXECUTED" | "UNKNOWN_AFTER_DISPATCH";
      readonly executed: boolean | null;
      readonly result: TResult | null;
      readonly reason: string | null;
      readonly authorization: VerifiedAuthorization;
      readonly finalization: ExecutionFinalization;
      /** Present when the receipt left the outcome unknown: what a reconciliation is held against. */
      readonly recovery?: ExecutionRecoveryReference;
    }
  | {
      readonly status: "REFUSED";
      readonly reason: "RECEIPT_DUPLICATE" | "PERMIT_NOT_PRESENTED";
    };
