import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import {
  FailClosedDecision,
  type DecisionAuthority,
  type DecisionEvaluationMode,
  type DecisionEvaluationOptions,
  type DecisionEvidence,
  type DecisionVerdict,
  type GateDecision,
} from "./DecisionAuthority.js";
import { immutableGateDecision } from "./ImmutableGateDecision.js";

/** Higher is more restrictive. The Decionis contract has no fourth verdict. */
const RESTRICTIVENESS: Readonly<Record<DecisionVerdict, number>> = Object.freeze({
  ALLOW: 0,
  ESCALATE: 1,
  BLOCK: 2,
});

/**
 * Runs a local authority and a hosted Decionis gate against the same intent.
 *
 * `SHADOW`: the local decision governs execution exactly as it would alone,
 * and the hosted evaluation rides along as `hosted` for display and audit. A
 * hosted failure is recorded and changes nothing, so setting a key cannot
 * break an integration that works today.
 *
 * `ENFORCEMENT`: the hosted decision governs, because only its grant can be
 * claimed by the enforcement verifier. The local authority can still tighten
 * it: when the local verdict is strictly more restrictive, that decision is
 * returned instead, and it carries no hosted grant.
 *
 * Neither mode returns a decision less restrictive than the local authority's.
 */
export class ShadowGate implements DecisionAuthority {
  public readonly evaluationMode?: DecisionEvaluationMode;

  public constructor(
    private readonly local: DecisionAuthority,
    private readonly hosted: DecisionAuthority,
    private readonly mode: DecisionEvaluationMode,
  ) {
    if (mode !== "SHADOW" && mode !== "ENFORCEMENT") {
      throw new Error("DECIONIS_GATE_MODE_INVALID");
    }
    const declared = mode === "ENFORCEMENT" ? mode : local.evaluationMode;
    if (declared !== undefined) this.evaluationMode = declared;
  }

  public async evaluate(
    captured: CapturedIntent,
    evidence?: DecisionEvidence,
    options: DecisionEvaluationOptions = {},
  ): Promise<GateDecision> {
    const [local, hosted] = await Promise.all([
      this.local.evaluate(captured, evidence, options),
      this.hostedDecision(captured, evidence, options),
    ]);
    const governs =
      this.mode === "ENFORCEMENT" &&
      RESTRICTIVENESS[hosted.verdict] >= RESTRICTIVENESS[local.verdict];
    return immutableGateDecision({
      ...(governs ? hosted : local),
      hosted: {
        mode: this.mode,
        governs,
        verdict: hosted.verdict,
        decisionId: hosted.decisionId,
        dossierId: hosted.dossierId,
        reasonCodes: hosted.reasonCodes,
        failClosed: hosted.failClosed,
      },
    });
  }

  /**
   * The hosted side never rejects and never answers about another intent:
   * either would let a network fault or a misbound service reach execution.
   */
  private async hostedDecision(
    captured: CapturedIntent,
    evidence: DecisionEvidence | undefined,
    options: DecisionEvaluationOptions,
  ): Promise<GateDecision> {
    let decision: GateDecision;
    try {
      decision = await this.hosted.evaluate(captured, evidence, options);
    } catch {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_UNAVAILABLE");
    }
    if (decision.intentHash !== captured.intentHash) {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_BINDING_MISMATCH");
    }
    return decision;
  }
}
