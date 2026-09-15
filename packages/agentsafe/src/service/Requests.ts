import { z } from "zod";
import {
  JsonObjectSchema,
  type CapturedIntent,
  type ExecutionRecoveryReference,
} from "@decionis/agent-safe-pipeline";
import type { ExecutorMode } from "../config/ExecutorConfig.js";
import type { EscalationHandoff } from "./EscalationResolver.js";

const identifier = z.string().trim().min(1).max(200);

/**
 * What the caller sends. `proposal` is the agent's part and nothing else:
 * tenant, actor, downstream target and credentials come from the executor's
 * own configuration, and a request that tries to supply them is refused by
 * the strict schema. The idempotency key and correlation id are the caller's,
 * derived from its own record of the work, never from the model.
 */
export const ProposalRequestSchema = z.strictObject({
  proposal: z.strictObject({
    action: z.string().trim().min(1).max(120),
    target: z.string().trim().min(1).max(500),
    parameters: JsonObjectSchema.optional(),
  }),
  idempotency_key: z.string().trim().min(1).max(180),
  correlation_id: identifier.optional(),
});

export type ProposalRequest = z.infer<typeof ProposalRequestSchema>;

/** The recovery reference the executor returned, presented back verbatim with the intent. */
export const ReconciliationRequestSchema = z.strictObject({
  intent: z.record(z.string(), z.unknown()),
  reference: z.strictObject({
    version: z.literal("agent-safe.recovery/1"),
    decisionId: identifier,
    dossierId: identifier,
    grantId: identifier,
    intentHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    expiresAt: z.string().datetime(),
    idempotencyKey: z.string().trim().min(1).max(180),
  }),
});

export type ReconciliationRequest = z.infer<typeof ReconciliationRequestSchema>;

/**
 * An operator's reason for stopping or resuming the executor. It is written
 * to the security stream verbatim, so it is bounded and it is the
 * operator's own words: nothing from a proposal ever reaches it.
 */
export const HaltRequestSchema = z.strictObject({
  reason: z.string().trim().min(1).max(200),
});

export const ResumeRequestSchema = HaltRequestSchema;

export type HaltRequest = z.infer<typeof HaltRequestSchema>;

/** The consumed binding, as evidence. The token itself never leaves the process. */
export interface AuthorizationBinding {
  readonly decision_id: string;
  readonly dossier_id: string;
  readonly grant_id: string;
  readonly expires_at: string;
}

export interface ActionResponse {
  readonly mode: ExecutorMode;
  readonly intent_id: string;
  readonly intent_hash: string;
  readonly verdict: "ALLOW" | "ESCALATE" | "BLOCK" | null;
  readonly decision_id: string | null;
  readonly dossier_id: string | null;
  readonly reason_codes: readonly string[];
  readonly fail_closed: boolean;
  /**
   * Shadow: the observation status. Enforcement: the executor outcome, or
   * `ESCALATE_PENDING` while a person has yet to answer.
   */
  readonly outcome: string;
  readonly executed: boolean | null;
  readonly authorization: AuthorizationBinding | null;
  readonly finalization: "RECORDED" | "PENDING" | "UNSUPPORTED" | null;
  readonly result: unknown;
  /**
   * What the adapter observed about the effect, for an action family that has
   * an effect plane: statuses, digests and the projected fields that differ.
   * Null for an action with no adapter, and never a provider body, a
   * parameter, or a credential.
   */
  readonly effect: Readonly<Record<string, unknown>> | null;
  /** Present only for `UNKNOWN_AFTER_DISPATCH`: what to present to reconcile. */
  readonly recovery: {
    readonly intent: CapturedIntent["intent"];
    readonly reference: ExecutionRecoveryReference;
  } | null;
  /** Present while an escalation is open: what to present to resume. */
  readonly escalation: EscalationHandoff | null;
}

export interface ReconciliationResponse {
  readonly intent_id: string;
  readonly intent_hash: string;
  readonly outcome: string;
  readonly executed: boolean | null;
  readonly recovered: boolean;
  readonly reason_codes: readonly string[];
  readonly authorization: AuthorizationBinding | null;
  readonly result: unknown;
  readonly effect: Readonly<Record<string, unknown>> | null;
}
