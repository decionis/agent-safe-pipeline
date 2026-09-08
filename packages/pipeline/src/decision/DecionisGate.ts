import { z } from "zod";
import { AuthorityBaseUrl } from "../http/AuthorityBaseUrl.js";
import { BoundedResponseBody } from "../http/BoundedResponseBody.js";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import {
  FailClosedDecision,
  type DecisionAuthority,
  type DecisionEvaluationMode,
  type DecisionEvaluationOptions,
  type DecisionEvidence,
  type GateDecision,
  type ManagedEscalationRequest,
  type ManagedEscalationState,
  type ManagedEscalationStatus,
} from "./DecisionAuthority.js";
import { immutableGateDecision } from "./ImmutableGateDecision.js";

const boundedIdentifier = z
  .string()
  .min(1)
  .max(200)
  .refine(hasNoControlCharacters, { message: "IDENTIFIER_INVALID" });
const intentHash = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const reasonCodes = z.array(boundedIdentifier).max(50);
const roleIdentifier = z.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/);

const ManagedEscalationRequestSchema = z
  .object({
    mode: z.literal("MANAGED"),
    approver: z
      .object({
        principal_id: boundedIdentifier.optional(),
        role_id: roleIdentifier.optional(),
      })
      .strict()
      .refine((approver) => approver.principal_id !== undefined || approver.role_id !== undefined, {
        message: "MANAGED_ESCALATION_APPROVER_EMPTY",
      })
      .optional(),
    verification_requirements: z
      .object({
        methods: z
          .array(z.enum(["WEBAUTHN", "ACTIVE_LIVENESS"]))
          .min(1)
          .max(3)
          .refine((methods) => new Set(methods).size === methods.length, {
            message: "MANAGED_ESCALATION_METHOD_DUPLICATE",
          }),
        level: z.enum(["STANDARD", "HIGH_CONFIDENCE"]).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

const managedEscalationStatuses = [
  "PENDING_PRESENCE",
  "PRESENCE_REQUESTED",
  "AWAITING_APPROVER",
  "PRESENCE_VERIFIED",
  "REAUTHORIZING",
  "GRANT_READY",
  "EXPIRED",
  "REJECTED",
  "BLOCKED",
  "CANCELLED",
  "FAILED",
] as const;
const managedEscalationPendingStatuses = new Set<string>([
  "PENDING_PRESENCE",
  "PRESENCE_REQUESTED",
  "AWAITING_APPROVER",
  "PRESENCE_VERIFIED",
  "REAUTHORIZING",
]);

const ManagedEscalationWireSchema = z
  .object({
    outcome: z.enum(["ESCALATE_PENDING", "ALLOW", "BLOCK", "ERROR"]),
    escalation_id: boundedIdentifier,
    intent_id: boundedIdentifier,
    status: z.enum(managedEscalationStatuses),
    expires_at: z.string().datetime(),
    reason_codes: reasonCodes,
  })
  .strict()
  .superRefine((value, context) => {
    const expectedOutcome =
      value.status === "GRANT_READY"
        ? "ALLOW"
        : value.status === "FAILED"
          ? "ERROR"
          : managedEscalationPendingStatuses.has(value.status)
            ? "ESCALATE_PENDING"
            : "BLOCK";
    if (value.outcome !== expectedOutcome) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "MANAGED_ESCALATION_STATE_OUTCOME_MISMATCH",
      });
    }
  });

/**
 * Mirrors `ExecutionAuthorityDecision` in the Decionis OpenAPI contract, which
 * declares `additionalProperties: false`; an undocumented field therefore fails
 * closed instead of being interpreted as execution semantics.
 */
const AuthorityResponseSchema = z
  .object({
    decision_id: boundedIdentifier,
    chain_id: boundedIdentifier.nullable(),
    status: z.enum(["ALLOW", "BLOCK", "ESCALATE", "REVIEW_REQUIRED", "ERROR"]),
    should_execute: z.boolean(),
    reason_codes: reasonCodes,
    action_hash: intentHash,
    policy_version: boundedIdentifier.nullable().optional(),
    mode: z.enum(["SHADOW", "PARALLEL", "ENFORCEMENT"]).nullable().optional(),
    execution_token: z.string().min(1).max(20_000).nullable(),
    execution_token_expires_at: z.string().datetime().nullable(),
    dossier_id: boundedIdentifier.nullable(),
    dossier_sha256: boundedIdentifier.nullable().optional(),
    dossier_url: z.string().min(1).max(2_000).nullable(),
    approval_request_id: boundedIdentifier.nullable().optional(),
    ledger_entry_id: boundedIdentifier.nullable().optional(),
    authority_classification: z.enum(["AUTHORITATIVE", "OBSERVATIONAL"]).optional(),
    execution_eligible: z.boolean().optional(),
    execution_binding_digest: intentHash.nullable().optional(),
    execution_token_jti: boundedIdentifier.nullable().optional(),
    execution_token_key_id: boundedIdentifier.nullable().optional(),
    managed_escalation: ManagedEscalationWireSchema.nullable().optional(),
  })
  .strict();

const ManagedEscalationStatusResponseSchema = z
  .object({
    escalation_id: boundedIdentifier,
    intent_id: boundedIdentifier,
    action_hash: intentHash,
    status: z.enum(managedEscalationStatuses),
    outcome: z.enum(["ESCALATE_PENDING", "ALLOW", "BLOCK", "ERROR"]),
    expires_at: z.string().datetime(),
    reason_codes: reasonCodes,
    decision: AuthorityResponseSchema.nullable(),
  })
  .strict();

type AuthorityResponse = z.infer<typeof AuthorityResponseSchema>;
type ManagedStatusResponse = z.infer<typeof ManagedEscalationStatusResponseSchema>;

export type ManagedEscalationPendingStatus =
  | "PENDING_PRESENCE"
  | "PRESENCE_REQUESTED"
  | "AWAITING_APPROVER"
  | "PRESENCE_VERIFIED"
  | "REAUTHORIZING";
export type ManagedEscalationBlockedStatus = "EXPIRED" | "REJECTED" | "BLOCKED" | "CANCELLED";

interface ManagedEscalationStatusBase {
  readonly escalationId: string;
  readonly intentId: string;
  readonly actionHash: string;
  readonly expiresAt: string;
  readonly reasonCodes: readonly string[];
}

/** Strict, secret-free view of one Decionis-managed Presence escalation. */
export type ManagedEscalationStatusResult = ManagedEscalationStatusBase &
  (
    | {
        readonly status: ManagedEscalationPendingStatus;
        readonly outcome: "ESCALATE_PENDING";
        readonly decision: null;
      }
    | {
        readonly status: "GRANT_READY";
        readonly outcome: "ALLOW";
        readonly decision: GateDecision;
      }
    | {
        readonly status: ManagedEscalationBlockedStatus;
        readonly outcome: "BLOCK";
        readonly decision: null;
      }
    | {
        readonly status: "FAILED";
        readonly outcome: "ERROR";
        readonly decision: null;
      }
  );

export interface ManagedEscalationStatusOptions {
  readonly signal?: AbortSignal;
  /** Injectable epoch-millisecond clock for deterministic tests. */
  readonly clock?: () => number;
}

export interface ManagedAuthorizationWaitOptions extends ManagedEscalationStatusOptions {
  readonly maxAttempts?: number;
  readonly initialDelayMs?: number;
  readonly maxDelayMs?: number;
  readonly sleep?: (delayMs: number, signal?: AbortSignal) => Promise<void>;
  /** Injectable [0, 1] jitter source for deterministic tests. */
  readonly random?: () => number;
}

interface WaitConfiguration {
  /** Null means the binding expiry is the only default polling deadline. */
  readonly maxAttempts: number | null;
  readonly initialDelayMs: number;
  readonly maxDelayMs: number;
  readonly clock: () => number;
  readonly sleep: (delayMs: number, signal?: AbortSignal) => Promise<void>;
  readonly random: () => number;
}

interface ManagedStateResolution {
  readonly state?: ManagedEscalationState;
  readonly reasonCode?: string;
}

const WAITING_STATUS_RANK: Readonly<Record<ManagedEscalationPendingStatus, number>> = Object.freeze(
  {
    PENDING_PRESENCE: 0,
    PRESENCE_REQUESTED: 1,
    AWAITING_APPROVER: 2,
    PRESENCE_VERIFIED: 3,
    REAUTHORIZING: 4,
  },
);
const MAX_RESPONSE_BYTES = 100 * 1024;
const DEFAULT_MANAGED_INITIAL_DELAY_MS = 500;
const DEFAULT_MANAGED_MAX_DELAY_MS = 5_000;
const MAX_MANAGED_DELAY_MS = 5_000;
const MAX_MANAGED_ATTEMPTS = 1_000;

export interface DecionisGateOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  readonly allowInsecureLoopback?: boolean;
  /**
   * `ENFORCEMENT` (default) asks Decionis for an executable decision.
   * `SHADOW` asks Decionis to evaluate and record the exact intent without
   * issuing a grant; the gate then never returns an authorization, even if a
   * response carries one.
   */
  readonly mode?: DecisionEvaluationMode;
}

export class DecionisGate implements DecisionAuthority {
  public readonly evaluationMode: DecisionEvaluationMode;
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly pendingAuthorizationWaits = new Map<string, Promise<GateDecision>>();
  public constructor(options: DecionisGateOptions) {
    this.baseUrl = AuthorityBaseUrl.normalize(
      options.baseUrl,
      options.allowInsecureLoopback === true,
    );
    this.apiKey = options.apiKey;
    this.timeoutMs = Math.min(Math.max(options.timeoutMs ?? 4_000, 1), 15_000);
    this.fetchImpl = options.fetch ?? fetch;
    const mode = options.mode ?? "ENFORCEMENT";
    if (mode !== "ENFORCEMENT" && mode !== "SHADOW") {
      throw new Error("DECIONIS_GATE_MODE_INVALID");
    }
    this.evaluationMode = mode;
  }

  public async evaluate(
    captured: CapturedIntent,
    evidence?: DecisionEvidence,
    options: DecisionEvaluationOptions = {},
  ): Promise<GateDecision> {
    const escalation = this.validEscalationRequest(options.escalation);
    if (escalation === null) {
      return FailClosedDecision.create(captured.intentHash, "MANAGED_ESCALATION_REQUEST_INVALID");
    }
    if (escalation !== undefined && this.evaluationMode !== "ENFORCEMENT") {
      return FailClosedDecision.create(captured.intentHash, "MANAGED_ESCALATION_SHADOW_FORBIDDEN");
    }
    if (escalation !== undefined && evidence !== undefined) {
      return FailClosedDecision.create(
        captured.intentHash,
        "MANAGED_ESCALATION_EVIDENCE_FORBIDDEN",
      );
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}/v1/authority/enforce-and-bind`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
          // The contract requires the header to equal the signed intent_id;
          // intent_id is the authority's grant-issuance boundary.
          "idempotency-key": captured.intent.intentId,
        },
        body: JSON.stringify({
          ...CanonicalIntentHasher.bindingOf(captured.intent),
          intent_hash: captured.intentHash,
          mode: this.evaluationMode,
          ...(evidence === undefined ? {} : { evidence }),
          ...(escalation === undefined ? {} : { escalation }),
        }),
        signal: controller.signal,
      });
      const text = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
      if (text === null) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_RESPONSE_TOO_LARGE");
      }
      if (!response.ok) {
        return DecionisGate.failedResponse(captured, text);
      }
      const parsed = AuthorityResponseSchema.parse(JSON.parse(text));
      const managed = this.initialManagedState(captured, parsed, escalation);
      if (managed.reasonCode !== undefined) {
        return FailClosedDecision.create(captured.intentHash, managed.reasonCode);
      }
      return this.decisionFromResponse(captured, parsed, evidence, managed.state);
    } catch {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_UNAVAILABLE");
    } finally {
      clearTimeout(timeout);
    }
  }

  /** Performs one authenticated, read-only status lookup against Decionis. */
  public async getManagedEscalationStatus(
    captured: CapturedIntent,
    escalation: ManagedEscalationState,
    options: ManagedEscalationStatusOptions = {},
  ): Promise<ManagedEscalationStatusResult> {
    const expectedFailure = this.expectedStateFailure(captured, escalation);
    if (expectedFailure !== null) {
      return this.failedManagedStatus(captured, escalation, expectedFailure);
    }

    const now = DecionisGate.clockNow(options.clock ?? Date.now);
    if (now === null) {
      return this.failedManagedStatus(captured, escalation, "MANAGED_ESCALATION_CLOCK_INVALID");
    }
    const deadline = this.managedDeadline(captured, escalation);
    if (deadline === null) {
      return this.failedManagedStatus(captured, escalation, "MANAGED_ESCALATION_EXPIRY_INVALID");
    }
    if (now >= deadline) return this.expiredManagedStatus(captured, escalation);
    if (options.signal?.aborted === true) {
      return this.failedManagedStatus(captured, escalation, "MANAGED_ESCALATION_ABORTED");
    }

    const controller = new AbortController();
    let callerAborted = false;
    const onAbort = (): void => {
      callerAborted = true;
      controller.abort();
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });
    if (DecionisGate.signalAborted(options.signal)) onAbort();
    const timeout = setTimeout(
      () => controller.abort(),
      Math.max(1, Math.min(this.timeoutMs, deadline - now)),
    );
    try {
      const response = await this.fetchImpl(
        `${this.baseUrl}/v1/authority/escalations/${encodeURIComponent(escalation.escalationId)}`,
        {
          method: "GET",
          headers: { authorization: `Bearer ${this.apiKey}` },
          signal: controller.signal,
        },
      );
      const text = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
      if (text === null) {
        return this.failedManagedStatus(
          captured,
          escalation,
          "MANAGED_ESCALATION_RESPONSE_TOO_LARGE",
        );
      }
      if (!response.ok) {
        return this.failedManagedStatus(captured, escalation, "MANAGED_ESCALATION_STATUS_FAILED");
      }
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        return this.failedManagedStatus(
          captured,
          escalation,
          "MANAGED_ESCALATION_RESPONSE_INVALID",
        );
      }
      const result = ManagedEscalationStatusResponseSchema.safeParse(body);
      if (!result.success) {
        return this.failedManagedStatus(
          captured,
          escalation,
          "MANAGED_ESCALATION_RESPONSE_INVALID",
        );
      }
      const parsed = result.data;
      const mismatch = this.statusBindingFailure(captured, escalation, parsed);
      if (mismatch !== null) return this.failedManagedStatus(captured, escalation, mismatch);

      const after = DecionisGate.clockNow(options.clock ?? Date.now);
      if (after === null) {
        return this.failedManagedStatus(captured, escalation, "MANAGED_ESCALATION_CLOCK_INVALID");
      }
      if (after >= deadline) return this.expiredManagedStatus(captured, escalation);
      return this.statusResult(captured, parsed);
    } catch {
      if (callerAborted) {
        return this.failedManagedStatus(captured, escalation, "MANAGED_ESCALATION_ABORTED");
      }
      const after = DecionisGate.clockNow(options.clock ?? Date.now);
      if (after !== null && after >= deadline) {
        return this.expiredManagedStatus(captured, escalation);
      }
      return this.failedManagedStatus(captured, escalation, "MANAGED_ESCALATION_STATUS_FAILED");
    } finally {
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", onAbort);
    }
  }

  /**
   * Waits only on Decionis. Presence credentials, invitation locators, and
   * receipt evidence never cross this client boundary in managed mode.
   */
  public async waitForAuthorization(
    captured: CapturedIntent,
    pendingDecision: GateDecision,
    options: ManagedAuthorizationWaitOptions = {},
  ): Promise<GateDecision> {
    const escalation = pendingDecision.managedEscalation;
    if (
      escalation === undefined ||
      pendingDecision.verdict !== "ESCALATE" ||
      pendingDecision.authorization !== null ||
      pendingDecision.intentHash !== captured.intentHash ||
      !DecionisGate.validManagedStateSemantics(escalation) ||
      this.expectedStateFailure(captured, escalation) !== null
    ) {
      return FailClosedDecision.create(captured.intentHash, "MANAGED_ESCALATION_REFERENCE_INVALID");
    }

    const configuration = DecionisGate.waitConfiguration(options);
    if (configuration === null) {
      return this.failedWaitDecision(
        captured,
        pendingDecision,
        escalation,
        "MANAGED_ESCALATION_POLLING_OPTIONS_INVALID",
      );
    }

    // Default waits for the same exact binding share one read-only poll loop.
    // Custom scheduling or cancellation stays caller-local.
    if (Object.keys(options).length === 0) {
      const key = `${captured.intentHash}\u0000${escalation.escalationId}`;
      const existing = this.pendingAuthorizationWaits.get(key);
      if (existing !== undefined) return await existing;
      const wait = this.waitForAuthorizationInternal(
        captured,
        pendingDecision,
        escalation,
        configuration,
        options.signal,
      ).finally(() => this.pendingAuthorizationWaits.delete(key));
      this.pendingAuthorizationWaits.set(key, wait);
      return await wait;
    }

    return await this.waitForAuthorizationInternal(
      captured,
      pendingDecision,
      escalation,
      configuration,
      options.signal,
    );
  }

  private async waitForAuthorizationInternal(
    captured: CapturedIntent,
    pendingDecision: GateDecision,
    escalation: ManagedEscalationState,
    configuration: WaitConfiguration,
    signal?: AbortSignal,
  ): Promise<GateDecision> {
    const deadline = this.managedDeadline(captured, escalation);
    if (deadline === null) {
      return this.failedWaitDecision(
        captured,
        pendingDecision,
        escalation,
        "MANAGED_ESCALATION_EXPIRY_INVALID",
      );
    }
    let lastStatus = DecionisGate.isPendingStatus(escalation.status)
      ? escalation.status
      : undefined;

    for (
      let attempt = 0;
      configuration.maxAttempts === null || attempt < configuration.maxAttempts;
      attempt += 1
    ) {
      const boundary = this.waitBoundaryFailure(configuration.clock, deadline, signal);
      if (boundary !== null) {
        return boundary === "INTENT_EXPIRED"
          ? this.expiredWaitDecision(captured, pendingDecision, escalation)
          : this.failedWaitDecision(captured, pendingDecision, escalation, boundary);
      }

      const status = await this.getManagedEscalationStatus(captured, escalation, {
        ...(signal === undefined ? {} : { signal }),
        clock: configuration.clock,
      });
      const afterLookup = this.waitBoundaryFailure(configuration.clock, deadline, signal);
      if (afterLookup !== null) {
        return afterLookup === "INTENT_EXPIRED"
          ? this.expiredWaitDecision(captured, pendingDecision, escalation)
          : this.failedWaitDecision(captured, pendingDecision, escalation, afterLookup);
      }

      if (!DecionisGate.isPendingStatus(escalation.status) && status.status !== escalation.status) {
        return this.failedWaitDecision(
          captured,
          pendingDecision,
          escalation,
          "MANAGED_ESCALATION_STATE_REGRESSION",
        );
      }
      if (status.status === "GRANT_READY") return status.decision;
      if (status.outcome !== "ESCALATE_PENDING") {
        return this.terminalWaitDecision(captured, pendingDecision, status);
      }
      if (
        lastStatus === undefined ||
        WAITING_STATUS_RANK[status.status] < WAITING_STATUS_RANK[lastStatus]
      ) {
        return this.failedWaitDecision(
          captured,
          pendingDecision,
          escalation,
          "MANAGED_ESCALATION_STATE_REGRESSION",
        );
      }
      lastStatus = status.status;

      if (configuration.maxAttempts !== null && attempt + 1 >= configuration.maxAttempts) {
        return this.failedWaitDecision(
          captured,
          pendingDecision,
          escalation,
          "MANAGED_ESCALATION_TIMEOUT",
        );
      }
      const delay = DecionisGate.backoffDelay(configuration, attempt);
      if (delay === null) {
        return this.failedWaitDecision(
          captured,
          pendingDecision,
          escalation,
          "MANAGED_ESCALATION_POLLING_RANDOM_INVALID",
        );
      }
      const now = DecionisGate.clockNow(configuration.clock);
      if (now === null) {
        return this.failedWaitDecision(
          captured,
          pendingDecision,
          escalation,
          "MANAGED_ESCALATION_CLOCK_INVALID",
        );
      }
      const remaining = deadline - now;
      if (remaining <= 0) return this.expiredWaitDecision(captured, pendingDecision, escalation);
      const slept = await DecionisGate.boundedSleep(
        configuration.sleep,
        Math.min(delay, remaining),
        remaining,
        signal,
      );
      if (slept !== null) {
        return slept === "INTENT_EXPIRED"
          ? this.expiredWaitDecision(captured, pendingDecision, escalation)
          : this.failedWaitDecision(captured, pendingDecision, escalation, slept);
      }
    }

    return this.failedWaitDecision(
      captured,
      pendingDecision,
      escalation,
      "MANAGED_ESCALATION_TIMEOUT",
    );
  }

  private decisionFromResponse(
    captured: CapturedIntent,
    parsed: AuthorityResponse,
    evidence?: DecisionEvidence,
    managedEscalation?: ManagedEscalationState,
  ): GateDecision {
    if (parsed.action_hash !== captured.intentHash) {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_BINDING_MISMATCH");
    }
    const mode = parsed.mode ?? null;
    if (mode !== null && mode !== this.evaluationMode) {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_MODE_MISMATCH");
    }
    const verdict =
      parsed.status === "ALLOW"
        ? "ALLOW"
        : parsed.status === "ESCALATE" || parsed.status === "REVIEW_REQUIRED"
          ? "ESCALATE"
          : "BLOCK";
    if (this.evaluationMode === "SHADOW") {
      return immutableGateDecision({
        verdict,
        decisionId: parsed.decision_id,
        dossierId: parsed.dossier_id,
        intentHash: parsed.action_hash,
        reasonCodes: parsed.reason_codes,
        authorization: null,
        failClosed: parsed.status === "ERROR",
        ...(evidence === undefined ? {} : { evidence }),
      });
    }
    const canExecute =
      verdict === "ALLOW" &&
      parsed.should_execute &&
      mode === "ENFORCEMENT" &&
      (parsed.authority_classification === undefined ||
        parsed.authority_classification === "AUTHORITATIVE") &&
      (parsed.execution_eligible === undefined || parsed.execution_eligible === true) &&
      (parsed.execution_binding_digest === undefined || parsed.execution_binding_digest !== null) &&
      (parsed.execution_token_jti === undefined || parsed.execution_token_jti !== null) &&
      (parsed.execution_token_key_id === undefined || parsed.execution_token_key_id !== null) &&
      parsed.dossier_id !== null &&
      parsed.execution_token !== null &&
      parsed.execution_token_expires_at !== null &&
      Date.parse(parsed.execution_token_expires_at) > Date.now() &&
      Date.parse(parsed.execution_token_expires_at) <= Date.parse(captured.intent.expiresAt);
    if (verdict === "ALLOW" && !canExecute) {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_GRANT_MISSING");
    }
    return immutableGateDecision({
      verdict,
      decisionId: parsed.decision_id,
      dossierId: parsed.dossier_id,
      intentHash: parsed.action_hash,
      reasonCodes: parsed.reason_codes,
      authorization: canExecute
        ? {
            token: parsed.execution_token as string,
            expiresAt: parsed.execution_token_expires_at as string,
          }
        : null,
      failClosed: parsed.status === "ERROR",
      ...(evidence === undefined ? {} : { evidence }),
      ...(managedEscalation === undefined ? {} : { managedEscalation }),
    });
  }

  private initialManagedState(
    captured: CapturedIntent,
    response: AuthorityResponse,
    requested?: ManagedEscalationRequest,
  ): ManagedStateResolution {
    const managed = response.managed_escalation ?? undefined;
    if (managed === undefined) {
      return requested !== undefined &&
        (response.status === "ESCALATE" || response.status === "REVIEW_REQUIRED")
        ? { reasonCode: "MANAGED_ESCALATION_MISSING" }
        : {};
    }
    if (requested === undefined) return { reasonCode: "MANAGED_ESCALATION_UNEXPECTED" };
    if (
      response.status !== "ESCALATE" ||
      response.should_execute ||
      response.execution_token !== null ||
      response.execution_token_expires_at !== null ||
      response.execution_eligible === true ||
      response.execution_binding_digest != null ||
      response.execution_token_jti != null ||
      response.execution_token_key_id != null
    ) {
      return { reasonCode: "MANAGED_ESCALATION_PENDING_GRANT_FORBIDDEN" };
    }
    const state = DecionisGate.managedStateFromWire(managed);
    const failure = this.expectedStateFailure(captured, state);
    return failure === null ? { state } : { reasonCode: failure };
  }

  private statusResult(
    captured: CapturedIntent,
    response: ManagedStatusResponse,
  ): ManagedEscalationStatusResult {
    const base: ManagedEscalationStatusBase = {
      escalationId: response.escalation_id,
      intentId: response.intent_id,
      actionHash: response.action_hash,
      expiresAt: response.expires_at,
      reasonCodes: Object.freeze([...response.reason_codes]),
    };

    if (DecionisGate.isPendingStatus(response.status)) {
      if (response.outcome !== "ESCALATE_PENDING" || response.decision !== null) {
        return this.failedStatusFromBase(base, "MANAGED_ESCALATION_RESPONSE_INVALID");
      }
      return Object.freeze({
        ...base,
        status: response.status,
        outcome: "ESCALATE_PENDING",
        decision: null,
      });
    }

    if (response.status === "GRANT_READY") {
      if (
        response.outcome !== "ALLOW" ||
        response.decision === null ||
        response.decision.managed_escalation != null
      ) {
        return this.failedStatusFromBase(base, "MANAGED_ESCALATION_GRANT_INVALID");
      }
      const state = DecionisGate.managedStateFromStatus(response);
      const decision = this.decisionFromResponse(captured, response.decision, undefined, state);
      if (decision.verdict !== "ALLOW" || decision.authorization === null || decision.failClosed) {
        return this.failedStatusFromBase(
          base,
          decision.reasonCodes[0] ?? "MANAGED_ESCALATION_GRANT_INVALID",
        );
      }
      return Object.freeze({
        ...base,
        status: "GRANT_READY",
        outcome: "ALLOW",
        decision,
      });
    }

    if (response.status === "FAILED") {
      if (response.outcome !== "ERROR" || response.decision !== null) {
        return this.failedStatusFromBase(base, "MANAGED_ESCALATION_RESPONSE_INVALID");
      }
      return Object.freeze({ ...base, status: "FAILED", outcome: "ERROR", decision: null });
    }

    if (response.outcome !== "BLOCK" || response.decision !== null) {
      return this.failedStatusFromBase(base, "MANAGED_ESCALATION_RESPONSE_INVALID");
    }
    return Object.freeze({
      ...base,
      status: response.status,
      outcome: "BLOCK",
      decision: null,
    });
  }

  private expectedStateFailure(
    captured: CapturedIntent,
    escalation: ManagedEscalationState,
  ): string | null {
    if (!DecionisGate.isBoundedIdentifier(escalation.escalationId)) {
      return "MANAGED_ESCALATION_ID_INVALID";
    }
    if (escalation.intentId !== captured.intent.intentId) {
      return "MANAGED_ESCALATION_INTENT_MISMATCH";
    }
    const expiresAt = Date.parse(escalation.expiresAt);
    const intentExpiresAt = Date.parse(captured.intent.expiresAt);
    if (
      !Number.isFinite(expiresAt) ||
      !Number.isFinite(intentExpiresAt) ||
      expiresAt > intentExpiresAt ||
      expiresAt <= Date.parse(captured.intent.capturedAt)
    ) {
      return "MANAGED_ESCALATION_EXPIRY_INVALID";
    }
    return null;
  }

  private statusBindingFailure(
    captured: CapturedIntent,
    expected: ManagedEscalationState,
    actual: ManagedStatusResponse,
  ): string | null {
    if (actual.escalation_id !== expected.escalationId) {
      return "MANAGED_ESCALATION_ID_MISMATCH";
    }
    if (actual.intent_id !== expected.intentId || actual.intent_id !== captured.intent.intentId) {
      return "MANAGED_ESCALATION_INTENT_MISMATCH";
    }
    if (actual.action_hash !== captured.intentHash) return "AUTHORITY_BINDING_MISMATCH";
    if (actual.expires_at !== expected.expiresAt) return "MANAGED_ESCALATION_EXPIRY_MISMATCH";
    return null;
  }

  private managedDeadline(
    captured: CapturedIntent,
    escalation: ManagedEscalationState,
  ): number | null {
    const intentExpiresAt = Date.parse(captured.intent.expiresAt);
    const escalationExpiresAt = Date.parse(escalation.expiresAt);
    return Number.isFinite(intentExpiresAt) && Number.isFinite(escalationExpiresAt)
      ? Math.min(intentExpiresAt, escalationExpiresAt)
      : null;
  }

  private waitBoundaryFailure(
    clock: () => number,
    deadline: number,
    signal?: AbortSignal,
  ): string | null {
    if (signal?.aborted === true) return "MANAGED_ESCALATION_ABORTED";
    const now = DecionisGate.clockNow(clock);
    if (now === null) return "MANAGED_ESCALATION_CLOCK_INVALID";
    return now >= deadline ? "INTENT_EXPIRED" : null;
  }

  private terminalWaitDecision(
    captured: CapturedIntent,
    pending: GateDecision,
    status: Exclude<ManagedEscalationStatusResult, { status: ManagedEscalationPendingStatus }>,
  ): GateDecision {
    const fallback =
      status.status === "EXPIRED"
        ? ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"]
        : status.status === "REJECTED"
          ? ["PRESENCE_REJECTED"]
          : status.status === "BLOCKED"
            ? ["REAUTHORIZATION_BLOCKED"]
            : status.status === "CANCELLED"
              ? ["CANCELLED"]
              : ["MANAGED_ESCALATION_FAILED"];
    const codes = status.reasonCodes.length === 0 ? fallback : status.reasonCodes;
    return immutableGateDecision({
      verdict: "BLOCK",
      decisionId: pending.decisionId,
      dossierId: pending.dossierId,
      intentHash: captured.intentHash,
      reasonCodes: codes,
      authorization: null,
      failClosed: status.outcome === "ERROR",
      managedEscalation: DecionisGate.managedStateFromStatusResult(status),
    });
  }

  private expiredWaitDecision(
    captured: CapturedIntent,
    pending: GateDecision,
    escalation: ManagedEscalationState,
  ): GateDecision {
    return immutableGateDecision({
      verdict: "BLOCK",
      decisionId: pending.decisionId,
      dossierId: pending.dossierId,
      intentHash: captured.intentHash,
      reasonCodes: ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"],
      authorization: null,
      failClosed: false,
      managedEscalation: {
        ...escalation,
        status: "EXPIRED",
        outcome: "BLOCK",
        reasonCodes: ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"],
      },
    });
  }

  private failedWaitDecision(
    captured: CapturedIntent,
    pending: GateDecision,
    escalation: ManagedEscalationState,
    reasonCode: string,
  ): GateDecision {
    return immutableGateDecision({
      verdict: "BLOCK",
      decisionId: pending.decisionId,
      dossierId: pending.dossierId,
      intentHash: captured.intentHash,
      reasonCodes: [reasonCode],
      authorization: null,
      failClosed: true,
      managedEscalation: {
        ...escalation,
        status: "FAILED",
        outcome: "ERROR",
        reasonCodes: [reasonCode],
      },
    });
  }

  private failedManagedStatus(
    captured: CapturedIntent,
    escalation: ManagedEscalationState,
    reasonCode: string,
  ): ManagedEscalationStatusResult {
    return this.failedStatusFromBase(
      {
        escalationId: escalation.escalationId,
        intentId: escalation.intentId,
        actionHash: captured.intentHash,
        expiresAt: escalation.expiresAt,
        reasonCodes: Object.freeze([reasonCode]),
      },
      reasonCode,
    );
  }

  private expiredManagedStatus(
    captured: CapturedIntent,
    escalation: ManagedEscalationState,
  ): ManagedEscalationStatusResult {
    return Object.freeze({
      escalationId: escalation.escalationId,
      intentId: escalation.intentId,
      actionHash: captured.intentHash,
      expiresAt: escalation.expiresAt,
      reasonCodes: Object.freeze(["INTENT_EXPIRED", "RECAPTURE_REQUIRED"]),
      status: "EXPIRED",
      outcome: "BLOCK",
      decision: null,
    });
  }

  private failedStatusFromBase(
    base: ManagedEscalationStatusBase,
    reasonCode: string,
  ): ManagedEscalationStatusResult {
    return Object.freeze({
      ...base,
      reasonCodes: Object.freeze([reasonCode]),
      status: "FAILED",
      outcome: "ERROR",
      decision: null,
    });
  }

  private validEscalationRequest(
    value: ManagedEscalationRequest | undefined,
  ): ManagedEscalationRequest | null | undefined {
    if (value === undefined) return undefined;
    const parsed = ManagedEscalationRequestSchema.safeParse(value);
    if (!parsed.success) return null;
    return {
      mode: parsed.data.mode,
      ...(parsed.data.approver === undefined
        ? {}
        : {
            approver: {
              ...(parsed.data.approver.principal_id === undefined
                ? {}
                : { principal_id: parsed.data.approver.principal_id }),
              ...(parsed.data.approver.role_id === undefined
                ? {}
                : { role_id: parsed.data.approver.role_id }),
            },
          }),
      ...(parsed.data.verification_requirements === undefined
        ? {}
        : {
            verification_requirements: {
              methods: parsed.data.verification_requirements.methods,
              ...(parsed.data.verification_requirements.level === undefined
                ? {}
                : { level: parsed.data.verification_requirements.level }),
            },
          }),
    };
  }

  private static managedStateFromWire(
    value: z.infer<typeof ManagedEscalationWireSchema>,
  ): ManagedEscalationState {
    return {
      escalationId: value.escalation_id,
      intentId: value.intent_id,
      status: value.status,
      outcome: value.outcome,
      expiresAt: value.expires_at,
      reasonCodes: value.reason_codes,
    };
  }

  private static managedStateFromStatus(value: ManagedStatusResponse): ManagedEscalationState {
    return {
      escalationId: value.escalation_id,
      intentId: value.intent_id,
      status: value.status,
      outcome: value.outcome,
      expiresAt: value.expires_at,
      reasonCodes: value.reason_codes,
    };
  }

  private static managedStateFromStatusResult(
    value: ManagedEscalationStatusResult,
  ): ManagedEscalationState {
    return {
      escalationId: value.escalationId,
      intentId: value.intentId,
      status: value.status,
      outcome: value.outcome,
      expiresAt: value.expiresAt,
      reasonCodes: value.reasonCodes,
    };
  }

  private static isPendingStatus(
    status: ManagedEscalationStatus,
  ): status is ManagedEscalationPendingStatus {
    return Object.hasOwn(WAITING_STATUS_RANK, status);
  }

  private static validManagedStateSemantics(state: ManagedEscalationState): boolean {
    if (DecionisGate.isPendingStatus(state.status)) {
      return state.outcome === "ESCALATE_PENDING";
    }
    if (state.status === "GRANT_READY") return state.outcome === "ALLOW";
    if (state.status === "FAILED") return state.outcome === "ERROR";
    return state.outcome === "BLOCK";
  }

  private static waitConfiguration(
    options: ManagedAuthorizationWaitOptions,
  ): WaitConfiguration | null {
    const maxAttempts = options.maxAttempts ?? null;
    const initialDelayMs = options.initialDelayMs ?? DEFAULT_MANAGED_INITIAL_DELAY_MS;
    const maxDelayMs = options.maxDelayMs ?? DEFAULT_MANAGED_MAX_DELAY_MS;
    if (
      (maxAttempts !== null &&
        (!Number.isInteger(maxAttempts) ||
          maxAttempts < 1 ||
          maxAttempts > MAX_MANAGED_ATTEMPTS)) ||
      !Number.isInteger(initialDelayMs) ||
      initialDelayMs < 1 ||
      initialDelayMs > MAX_MANAGED_DELAY_MS ||
      !Number.isInteger(maxDelayMs) ||
      maxDelayMs < initialDelayMs ||
      maxDelayMs > MAX_MANAGED_DELAY_MS ||
      (options.clock !== undefined && typeof options.clock !== "function") ||
      (options.sleep !== undefined && typeof options.sleep !== "function") ||
      (options.random !== undefined && typeof options.random !== "function")
    ) {
      return null;
    }
    return {
      maxAttempts,
      initialDelayMs,
      maxDelayMs,
      clock: options.clock ?? Date.now,
      sleep: options.sleep ?? DecionisGate.sleep,
      random: options.random ?? Math.random,
    };
  }

  private static backoffDelay(configuration: WaitConfiguration, attempt: number): number | null {
    let random: number;
    try {
      random = configuration.random();
    } catch {
      return null;
    }
    if (!Number.isFinite(random) || random < 0 || random > 1) return null;
    const exponential = configuration.initialDelayMs * 2 ** Math.min(attempt, 30);
    const capped = Math.min(exponential, configuration.maxDelayMs);
    return Math.max(1, Math.floor(capped * (0.5 + random * 0.5)));
  }

  private static async boundedSleep(
    sleep: (delayMs: number, signal?: AbortSignal) => Promise<void>,
    delayMs: number,
    remainingMs: number,
    signal?: AbortSignal,
  ): Promise<string | null> {
    if (signal?.aborted === true) return "MANAGED_ESCALATION_ABORTED";
    return await new Promise<string | null>((resolve) => {
      let settled = false;
      const settle = (reason: string | null): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        resolve(reason);
      };
      const onAbort = (): void => settle("MANAGED_ESCALATION_ABORTED");
      const timer = setTimeout(() => settle("INTENT_EXPIRED"), remainingMs);
      signal?.addEventListener("abort", onAbort, { once: true });
      void Promise.resolve()
        .then(async () => await sleep(delayMs, signal))
        .then(
          () => settle(null),
          () =>
            settle(
              signal?.aborted === true
                ? "MANAGED_ESCALATION_ABORTED"
                : "MANAGED_ESCALATION_UNAVAILABLE",
            ),
        );
    });
  }

  private static async sleep(delayMs: number, signal?: AbortSignal): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      if (signal?.aborted === true) {
        reject(new Error("MANAGED_ESCALATION_ABORTED"));
        return;
      }
      const onAbort = (): void => {
        clearTimeout(timer);
        reject(new Error("MANAGED_ESCALATION_ABORTED"));
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, delayMs);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  private static clockNow(clock: () => number): number | null {
    try {
      const now = clock();
      return Number.isFinite(now) ? now : null;
    } catch {
      return null;
    }
  }

  private static signalAborted(signal?: AbortSignal): boolean {
    return signal?.aborted === true;
  }

  private static isBoundedIdentifier(value: string): boolean {
    return value.length > 0 && value.length <= 200 && hasNoControlCharacters(value);
  }

  /**
   * The contract returns an `ERROR` decision body on 409 and 503 so the
   * refusal is evidence-bearing. Anything else fails closed generically.
   */
  private static failedResponse(captured: CapturedIntent, text: string): GateDecision {
    try {
      const parsed = AuthorityResponseSchema.parse(JSON.parse(text));
      if (parsed.status !== "ERROR" || parsed.action_hash !== captured.intentHash) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_REQUEST_FAILED");
      }
      return immutableGateDecision({
        verdict: "BLOCK",
        decisionId: parsed.decision_id,
        dossierId: parsed.dossier_id,
        intentHash: captured.intentHash,
        reasonCodes:
          parsed.reason_codes.length === 0 ? ["AUTHORITY_REQUEST_FAILED"] : parsed.reason_codes,
        authorization: null,
        failClosed: true,
      });
    } catch {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_REQUEST_FAILED");
    }
  }
}

function hasNoControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return false;
  }
  return true;
}
