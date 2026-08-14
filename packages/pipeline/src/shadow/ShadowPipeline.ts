import type { DecisionAuthority, GateDecision } from "../decision/DecisionAuthority.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";

export interface ShadowComparison<TResult> {
  readonly mode: "SHADOW";
  readonly productionResult: TResult;
  readonly hypotheticalDecision: GateDecision;
}

export class ShadowPipeline {
  public constructor(private readonly authority: DecisionAuthority) {}

  public async compare<TResult>(
    captured: CapturedIntent,
    existingExecution: () => Promise<TResult> | TResult,
  ): Promise<ShadowComparison<TResult>> {
    const [productionResult, hypotheticalDecision] = await Promise.all([
      existingExecution(),
      this.authority.evaluate(captured),
    ]);
    return { mode: "SHADOW", productionResult, hypotheticalDecision };
  }
}
