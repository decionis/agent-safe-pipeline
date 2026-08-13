import type { GateDecision } from "../decision/DecisionAuthority.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type { ActionRegistry } from "./ActionRegistry.js";
import type { AuthorizationVerifier, VerifiedAuthorization } from "./AuthorizationVerifier.js";

export type ExecutionBlockReason =
  | "DECISION_NOT_ALLOW"
  | "INTENT_BINDING_MISMATCH"
  | "AUTHORIZATION_MISSING"
  | "AUTHORIZATION_INVALID";

export type SafeExecutionResult<TResult = unknown> =
  | {
      readonly executed: true;
      readonly result: TResult;
      readonly authorization: VerifiedAuthorization;
    }
  | {
      readonly executed: false;
      readonly reason: ExecutionBlockReason;
      readonly result: null;
      readonly authorization: null;
    };

export class SafeExecutor {
  public constructor(
    private readonly registry: ActionRegistry,
    private readonly verifier: AuthorizationVerifier,
  ) {}

  public async run<TResult = unknown>(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<SafeExecutionResult<TResult>> {
    if (decision.verdict !== "ALLOW" || decision.failClosed) {
      return SafeExecutor.blocked("DECISION_NOT_ALLOW");
    }
    if (decision.intentHash !== captured.intentHash) {
      return SafeExecutor.blocked("INTENT_BINDING_MISMATCH");
    }
    if (decision.authorization === null) {
      return SafeExecutor.blocked("AUTHORIZATION_MISSING");
    }
    this.registry.validate(captured);
    const authorization = await this.verifier.verifyAndConsume(captured, decision);
    if (authorization === null) return SafeExecutor.blocked("AUTHORIZATION_INVALID");
    const result = (await this.registry.execute(captured, authorization)) as TResult;
    return { executed: true, result, authorization };
  }

  private static blocked(reason: ExecutionBlockReason): SafeExecutionResult<never> {
    return { executed: false, reason, result: null, authorization: null };
  }
}
