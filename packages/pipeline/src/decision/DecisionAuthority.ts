import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import { immutableGateDecision } from "./ImmutableGateDecision.js";

export type DecisionVerdict = "ALLOW" | "ESCALATE" | "BLOCK";

/**
 * `ENFORCEMENT` evaluations may produce execution authority. `SHADOW`
 * evaluations are observational: the authority records the same intent and
 * dossier evidence but never issues a grant.
 */
export type DecisionEvaluationMode = "ENFORCEMENT" | "SHADOW";

export interface HumanApprovalEvidence {
  readonly provider: "presence";
  readonly requestId: string;
  readonly receiptDossierId: string;
}

export interface DecisionEvidence {
  readonly humanApproval?: HumanApprovalEvidence;
}

export interface GateDecision {
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
}

export interface DecisionAuthority {
  /**
   * Declared evaluation mode, when the authority knows it. `ShadowPipeline`
   * refuses an authority that declares `ENFORCEMENT` so observational traffic
   * cannot be sent through a grant-issuing path by mistake.
   */
  readonly evaluationMode?: DecisionEvaluationMode;
  evaluate(intent: CapturedIntent, evidence?: DecisionEvidence): Promise<GateDecision>;
}

export class FailClosedDecision {
  public static create(intentHash: string, reasonCode: string): GateDecision {
    return immutableGateDecision({
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
