import type { ExecutionFinalization } from "./AuthorizationVerifier.js";
import type { ExecutionOutcome } from "./ExecutionOutcome.js";
import type { AuthorityState, FailurePosture, UnavailableDisposition } from "./ExecutionPosture.js";
import type {
  NATIVE_EXECUTOR_CONTRACT,
  ExecutionStyle,
  ExecutorScope,
  PlatformId,
} from "./NativeExecutor.js";

export const EXECUTOR_EVIDENCE_VERSION = "agent-safe.executor-evidence/1";

/** Which step of a governed execution a line records. */
export type EvidenceStage = "RUN" | "PRESENTATION" | "SETTLEMENT" | "RECONCILIATION";

/**
 * One line per step of a governed execution, written by the runner and by
 * nothing else: which executor ran what, under which decision and grant, and
 * how it ended. It is the evidence an operator counts governed writes with,
 * and it carries identifiers, statuses and timings only — never a parameter,
 * a token, a receipt, a credential or a response body. Snake case, because
 * it is a wire object other languages read.
 */
export interface ExecutorEvidenceLine {
  readonly version: typeof EXECUTOR_EVIDENCE_VERSION;
  readonly contract: typeof NATIVE_EXECUTOR_CONTRACT;
  readonly at: string;
  readonly stage: EvidenceStage;
  readonly executor: {
    readonly platform: PlatformId;
    readonly version: string;
    readonly style: ExecutionStyle;
  };
  readonly action_type: string;
  readonly intent_id: string;
  readonly intent_hash: string;
  readonly decision_id: string | null;
  readonly dossier_id: string | null;
  readonly verdict: string | null;
  readonly grant_id: string | null;
  /** The step's result: an outcome, or `CLAIMED` for a presented permit. */
  readonly outcome: ExecutionOutcome | "CLAIMED";
  readonly executed: boolean | null;
  readonly reason: string | null;
  readonly code: string | null;
  /** True only when a grant governed the step: held, claimed or consumed. */
  readonly governed: boolean;
  readonly authority_state: AuthorityState;
  readonly posture: FailurePosture;
  /** What became of an action nobody could decide; null when the authority decided. */
  readonly disposition: UnavailableDisposition | null;
  readonly finalization: ExecutionFinalization | null;
  readonly duration_ms: number;
  readonly scope: {
    readonly org_id: string;
    readonly workspace_id: string;
    readonly connection_id: string;
    readonly connection_revision: string;
    readonly environment: "sandbox" | "production";
  } | null;
}

/**
 * Where evidence lines go. A sink is told after the fact and may be slow or
 * fail: the runner awaits it, ignores its errors, and never lets it change an
 * outcome, because evidence is not authority.
 */
export interface ExecutorEvidenceSink {
  emit(line: ExecutorEvidenceLine): void | Promise<void>;
}

/** The scope as a line carries it: the connection, never the company or store names. */
export function evidenceScope(scope: ExecutorScope | null): ExecutorEvidenceLine["scope"] {
  if (scope === null) return null;
  return {
    org_id: scope.orgId,
    workspace_id: scope.workspaceId,
    connection_id: scope.connectionId,
    connection_revision: scope.connectionRevision,
    environment: scope.environment,
  };
}
