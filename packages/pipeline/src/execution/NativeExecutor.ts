import type {
  AgentProposal,
  CapturedIntent,
  DownstreamTarget,
  PolicyProjection,
} from "../intent/ExecutionIntent.js";
import type { JsonObject } from "../intent/JsonValue.js";
import type { ProviderDispatch } from "./ActionRegistry.js";
import type { AuthorityEffectEvidence, VerifiedAuthorization } from "./AuthorizationVerifier.js";
import type { MonotonicDeadline } from "./ExecutionDeadline.js";

/**
 * `agent-safe.executors.native/1`: the one contract every native executor
 * implements, whatever system of record it writes to. It generalizes the
 * banking execution profile's adapter (BEAP v1.0 §20) beyond banking, adds
 * `capabilities` from Commerce's executor seam, and distinguishes the two
 * ways a write reaches a system of record:
 *
 * - **dispatch**: the executor performs the write itself, once, inside the
 *   dispatch the runner opened (a core banking transfer, a Walmart price
 *   feed).
 * - **permit**: the platform performs the write and must present the permit
 *   it was issued (a Business Central posting, a card issuer's
 *   authorization). A later receipt settles it.
 *
 * An executor never calls the authority, signs anything, maps a verdict,
 * retries, or decides an outcome: `GovernedExecutionRunner` does all of that,
 * once, for every executor. What an executor knows is its platform: how to
 * describe an action to the authority, how to write it, and how to read what
 * the platform said back.
 */
export const NATIVE_EXECUTOR_CONTRACT = "agent-safe.executors.native/1";

export type ExecutionStyle = "dispatch" | "permit";

/** The platforms the contract names today; any other identifier is a platform too. */
export type KnownPlatformId =
  "business-central" | "walmart-marketplace" | "aws-agentcore" | "card-issuer" | "core-banking";

export type PlatformId = KnownPlatformId | (string & Record<never, never>);

/** An action type as the intent names it (`agent-safe.intent/1` `action.type`). */
export type ActionType = string;

/** A digest in the one form every wire field in this contract uses. */
export type Sha256Digest = `sha256:${string}`;

/**
 * The connection an action is executed under. Resolved by the server from
 * the authenticated connection; never supplied by the client, because a
 * scope a caller could name is a scope a caller could borrow.
 */
export interface ExecutorScope {
  readonly orgId: string;
  readonly workspaceId: string;
  readonly connectionId: string;
  readonly connectionRevision: string;
  readonly company?: string;
  readonly store?: string;
  readonly environment: "sandbox" | "production";
}

/**
 * What one executor can write for one action type, and what is still needed
 * when it cannot. Field for field the capability Commerce's executor seam
 * reports (`core/contracts/src/executor/CommerceExecutor.ts`), so one
 * capability matrix reads both.
 */
export interface ExecutionCapability {
  readonly platform: PlatformId;
  readonly actionType: ActionType;
  /** True only when connected, scope-granted and switched on for this connection. */
  readonly enabled: boolean;
  readonly scopeGranted: boolean;
  readonly connected: boolean;
  /** Plain words: what is still needed before the write path is live; empty when nothing is. */
  readonly requirement: string;
}

/**
 * What `prepare` worked out before anything left the process: the action as
 * the authority will bind it, and the platform facts it decides with.
 * Everything here is either bound into the intent's hash or evidence beside
 * it; none of it is a secret, a credential or a response body.
 */
export interface PreparedAction {
  /** One of the executor's `actionTypes`; the intent's action type. */
  readonly actionType: ActionType;
  /** The proposal as `agent-safe.intent/1` binds it: action, resource and parameters. */
  readonly proposal: AgentProposal;
  /** The system of record and the operation, as the binding's `downstream_target` names them. */
  readonly downstreamTarget: DownstreamTarget;
  /** The retry identity bound into the intent and handed to the platform's own idempotency. */
  readonly idempotencyKey: string;
  /** The digest of the effect the action asks for, bound as `expected_effect_digest` when known. */
  readonly expectedEffectDigest: Sha256Digest | null;
  /** The digest of what will be sent, so a later reader can tell what was asked. */
  readonly requestDigest: Sha256Digest;
  /** Platform facts the authority evaluates, carried in the intent's trusted context. */
  readonly facts: JsonObject;
  /**
   * The policy path the authority decides the action under, bound into the
   * intent as `policy_projection`, when the policy names the write other than
   * by its action type. Absent, the authority evaluates the action type.
   */
  readonly policyProjection?: PolicyProjection;
}

/**
 * The permit a native boundary presents with its write. It stands for one
 * single-use grant bound to one intent hash, and it is void after
 * `expiresAt`. It carries no token: the grant stays with the runner, and the
 * boundary is told only what identifies it.
 */
export interface ExecutionPermit {
  /** The grant the permit stands for (the authority's grant id), when the grant names one. */
  readonly permitId: string | null;
  readonly intentHash: Sha256Digest;
  readonly expiresAt: string;
  /**
   * Proof of the claim the boundary can verify without trusting this process,
   * once the permit was presented and claimed; absent before that.
   */
  readonly claimAttestation?: string;
}

/**
 * One execution the runner admitted and, for dispatch style, claimed. The
 * executor writes with it, once; it never sees the execution token, and the
 * idempotency key is the one bound into the intent.
 */
export interface ClaimedExecution<TAction> {
  readonly action: TAction;
  readonly prepared: PreparedAction;
  readonly intent: CapturedIntent;
  readonly scope: ExecutorScope | null;
  /** The claimed grant. */
  readonly authorization: VerifiedAuthorization;
  readonly idempotencyKey: string;
  /** What is left of the smallest of the configured timeout, the grant and the claim lease. */
  readonly deadline: MonotonicDeadline;
  /**
   * The dispatch boundary. A dispatch-style executor puts the platform write
   * inside `dispatch.run`; an error before it is a failure before dispatch,
   * one after it is an outcome nobody knows until a reconciliation says.
   */
  readonly dispatch: ProviderDispatch;
}

/**
 * What `execute` returns, before anything interprets it.
 *
 * - `DISPATCHED`: the write left the process and the platform answered (or
 *   did not); `receipt` is the platform's native answer as the executor read
 *   it, which `observe` turns into an outcome.
 * - `NOT_DISPATCHED`: nothing was sent; `code` says why, in upper snake case.
 * - `PERMIT`: permit style; the boundary performs the write with `permit`,
 *   and a receipt arrives later.
 *
 * A signed effect receipt the platform returned (a compact JWS) rides in
 * `signedReceipt`, verbatim, for the authority to verify.
 */
export type ExecutionEffect<TReceipt = JsonObject> =
  | {
      readonly kind: "DISPATCHED";
      readonly receipt: TReceipt | null;
      readonly signedReceipt?: string | null;
    }
  | { readonly kind: "NOT_DISPATCHED"; readonly code?: string | undefined }
  | { readonly kind: "PERMIT"; readonly permit: ExecutionPermit }
  | {
      /** A permit-style receipt reported by the boundary after its write. */
      readonly kind: "RECEIPT";
      readonly receipt: TReceipt;
      readonly signedReceipt?: string | null;
    };

/** The commit outcomes the authority records, as `observe` reads them from a receipt. */
export type ObservedStatus = "COMMITTED" | "FAILED" | "INDETERMINATE";

/**
 * What the platform's native receipt means. `observe` is pure: it reads the
 * receipt it was given, never asks the platform again, and never reads
 * silence as success. A receipt it cannot read is `INDETERMINATE`.
 */
export interface EffectObservation<TResult = unknown> {
  readonly status: ObservedStatus;
  /** The platform's reason code when it refused (`FAILED`); null otherwise. */
  readonly reason: string | null;
  /** What the caller is handed on `COMMITTED`: the platform's result as the executor reads it. */
  readonly result: TResult | null;
  /** The platform's signed effect receipt, verbatim, when it gave one. */
  readonly signedReceipt?: string | null;
  /** An observation of the effect for the authority (Protocol 1.1 `EffectEvidence`), when the executor made one. */
  readonly evidence?: AuthorityEffectEvidence;
}

/** What a reconciliation is asked about: the attempt, by the identifiers it was bound to. */
export interface ReconcileContext {
  readonly intent: CapturedIntent;
  readonly prepared: PreparedAction;
  readonly idempotencyKey: string;
  readonly scope: ExecutorScope | null;
  /** The platform's reference for the attempt, when an earlier answer carried one. */
  readonly providerReference: string | null;
}

/**
 * What the platform says it did with an attempt whose outcome was lost.
 * `COMPLETED` carries the result as a commit would have; `NOT_EXECUTED` is
 * proof that nothing happened; `UNKNOWN` is the honest default.
 */
export type ReconcileResult<TResult = unknown> =
  | {
      readonly status: "COMPLETED";
      readonly result: TResult;
      readonly evidence?: AuthorityEffectEvidence;
    }
  | { readonly status: "NOT_EXECUTED"; readonly evidence?: AuthorityEffectEvidence }
  | { readonly status: "UNKNOWN" };

/**
 * The interface every native executor implements. The runner calls it in one
 * order: `capabilities` and `prepare` at admission, `execute` once after the
 * claim (dispatch) or at presentation (permit), `observe` on the platform's
 * answer, and `reconcile` only after an indeterminate observation or a
 * missing receipt.
 */
export interface NativeExecutor<TAction = unknown, TReceipt = JsonObject, TResult = unknown> {
  readonly platform: PlatformId;
  readonly version: string;
  readonly style: ExecutionStyle;
  readonly actionTypes: readonly ActionType[];
  /** What can be executed now, and what is missing when it cannot (scope, switch, connection). */
  capabilities(scope: ExecutorScope): Promise<readonly ExecutionCapability[]>;
  /** Platform facts + `agent-safe.intent/1` binding + idempotency identity. No I/O side effects. */
  prepare(action: TAction, scope: ExecutorScope | null): Promise<PreparedAction>;
  /** dispatch: write once with the claimed grant. permit: return the permit the native boundary must present. */
  execute(run: ClaimedExecution<TAction>): Promise<ExecutionEffect<TReceipt>>;
  /** Map the native receipt (posting entry, feed ID, HTTP status) to COMMITTED | FAILED | INDETERMINATE. */
  observe(
    effect: ExecutionEffect<TReceipt>,
    prepared: PreparedAction,
  ): Promise<EffectObservation<TResult>>;
  /** Called only after INDETERMINATE or a missing receipt: COMPLETED | NOT_EXECUTED | UNKNOWN. */
  reconcile(context: ReconcileContext): Promise<ReconcileResult<TResult>>;
}
