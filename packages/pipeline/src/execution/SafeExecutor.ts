import type { GateDecision } from "../decision/DecisionAuthority.js";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type { ActionRegistry } from "./ActionRegistry.js";
import type { AuthorizationVerifier, VerifiedAuthorization } from "./AuthorizationVerifier.js";

export type ExecutionBlockReason =
  | "DECISION_NOT_ALLOW"
  | "INTENT_BINDING_MISMATCH"
  | "INTENT_CONFORMANCE_FAILED"
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
  private readonly hasher = new CanonicalIntentHasher();

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
    if (!this.intentConforms(captured)) {
      return SafeExecutor.blocked("INTENT_CONFORMANCE_FAILED");
    }
    this.registry.validate(captured);
    let authorization: VerifiedAuthorization | null;
    try {
      authorization = await this.verifier.verifyAndConsume(captured, decision);
    } catch {
      return SafeExecutor.blocked("AUTHORIZATION_INVALID");
    }
    if (authorization === null) return SafeExecutor.blocked("AUTHORIZATION_INVALID");
    const authorizationExpiry = Date.parse(authorization.expiresAt);
    if (
      authorization.decisionId !== decision.decisionId ||
      authorization.dossierId !== decision.dossierId ||
      authorization.grantId.length === 0 ||
      authorization.intentHash !== captured.intentHash ||
      Math.floor(authorizationExpiry / 1_000) !==
        Math.floor(Date.parse(decision.authorization.expiresAt) / 1_000) ||
      authorizationExpiry <= Date.now() ||
      authorizationExpiry > Date.parse(captured.intent.expiresAt)
    ) {
      return SafeExecutor.blocked("AUTHORIZATION_INVALID");
    }
    if (!this.intentConforms(captured)) {
      return SafeExecutor.blocked("INTENT_CONFORMANCE_FAILED");
    }
    let result: TResult;
    try {
      result = (await this.registry.execute(captured, authorization)) as TResult;
    } catch {
      throw new Error("ACTION_EXECUTION_FAILED");
    }
    return { executed: true, result, authorization };
  }

  private intentConforms(captured: CapturedIntent): boolean {
    let recomputed: CapturedIntent | null = null;
    try {
      recomputed = this.hasher.capture(captured.intent);
    } catch {
      // Malformed runtime objects are non-conformant.
    }
    return (
      recomputed !== null &&
      recomputed.intentHash === captured.intentHash &&
      recomputed.canonicalIntent === captured.canonicalIntent &&
      recomputed.byteLength === captured.byteLength
    );
  }

  private static blocked(reason: ExecutionBlockReason): SafeExecutionResult<never> {
    return { executed: false, reason, result: null, authorization: null };
  }
}
