import type { CapturedIntent } from "../intent/ExecutionIntent.js";

export type DecisionVerdict = "ALLOW" | "ESCALATE" | "BLOCK";

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
  evaluate(intent: CapturedIntent, evidence?: DecisionEvidence): Promise<GateDecision>;
}

export class FailClosedDecision {
  public static create(intentHash: string, reasonCode: string): GateDecision {
    return Object.freeze({
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
