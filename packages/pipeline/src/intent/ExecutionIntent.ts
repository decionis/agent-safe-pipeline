import { z } from "zod";
import { JsonObjectSchema, type JsonObject } from "./JsonValue.js";
import { ExecutionSignalsSchema } from "./ExecutionSignals.js";

const boundedId = z.string().trim().min(1).max(200);
const actionName = z
  .string()
  .trim()
  .min(1)
  .max(120)
  .regex(/^[a-z][a-z0-9._:-]*$/);
/** The Decionis contract's digest form, verbatim: `sha256:` and 64 lowercase hex. */
const sha256Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);

export const AgentProposalSchema = z
  .object({
    action: actionName,
    target: z.string().trim().min(1).max(500),
    parameters: JsonObjectSchema.default({}),
  })
  .strict();

export const IntentActorSchema = z
  .object({
    id: boundedId,
    type: boundedId,
    runtime: boundedId.optional(),
    trustLevel: z.string().trim().min(1).max(80).optional(),
  })
  .strict();

export const DownstreamTargetSchema = z
  .object({
    system: boundedId,
    operation: boundedId,
    environment: boundedId.optional(),
    endpoint: z.string().trim().min(1).max(500).optional(),
  })
  .strict();

const projectionValue = z.string().trim().min(1).max(120);

/**
 * The policy path the authority decides an intent under: its decision type,
 * transaction type, workflow key and channel. Without one, Decionis evaluates
 * `action.type` as the decision type, transaction type and workflow key, which
 * is right when an action's name is its policy vocabulary. An executor whose
 * policy names its writes differently (an order acknowledgement decided as
 * `ORDER_ACCEPTANCE`) states the projection, and the binding carries it inside
 * the hash, so a claim re-validates the policy path the grant was decided on.
 * A null field is one the authority leaves out of the evaluation.
 *
 * The trusted runtime's to state, never the agent's: an agent that could name
 * its projection could choose the policy it is evaluated under.
 */
export const PolicyProjectionSchema = z
  .object({
    decisionType: projectionValue,
    transactionType: projectionValue.nullable(),
    workflowKey: projectionValue.nullable(),
    channel: projectionValue.nullable(),
  })
  .strict();

/**
 * The trusted idempotency key travels inside the hashed wire `context` under
 * this reserved key, because the Decionis `ExecutionIntentBinding` contract
 * has no top-level idempotency field and rejects unknown properties.
 */
export const RESERVED_CONTEXT_IDEMPOTENCY_KEY = "idempotency_key";

export const TrustedIntentContextSchema = z
  .object({
    tenantId: z.string().uuid(),
    actor: IntentActorSchema,
    downstreamTarget: DownstreamTargetSchema,
    context: JsonObjectSchema.default({}),
    correlationId: boundedId.optional(),
    expectedEffectDigest: sha256Digest.optional(),
    /** The policy path the intent is decided under, when it is not `action.type`. */
    policyProjection: PolicyProjectionSchema.optional(),
    idempotencyKey: z.string().trim().min(1).max(180),
    /**
     * What the trusted runtime knows about itself and the workload it is
     * standing in front of. The capture stamps these into the hashed context
     * under reserved keys; a caller may not write those keys by hand.
     */
    signals: ExecutionSignalsSchema.optional(),
  })
  .strict();

export const ExecutionIntentSchema = z
  .object({
    version: z.literal("agent-safe.intent/1"),
    intentId: z.string().uuid(),
    tenantId: z.string().uuid(),
    capturedAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
    actor: IntentActorSchema,
    action: actionName,
    target: z.string().trim().min(1).max(500),
    parameters: JsonObjectSchema,
    downstreamTarget: DownstreamTargetSchema,
    context: JsonObjectSchema,
    correlationId: boundedId.optional(),
    expectedEffectDigest: sha256Digest.optional(),
    policyProjection: PolicyProjectionSchema.optional(),
    idempotencyKey: z.string().trim().min(1).max(180),
  })
  .strict();

export type PolicyProjection = z.infer<typeof PolicyProjectionSchema>;
export type AgentProposal = z.infer<typeof AgentProposalSchema>;
export type IntentActor = z.infer<typeof IntentActorSchema>;
export type DownstreamTarget = z.infer<typeof DownstreamTargetSchema>;
export type TrustedIntentContext = z.infer<typeof TrustedIntentContextSchema>;
export type ExecutionIntent = z.infer<typeof ExecutionIntentSchema>;

export interface CapturedIntent {
  readonly intent: Readonly<ExecutionIntent>;
  readonly canonicalIntent: string;
  readonly intentHash: `sha256:${string}`;
  readonly byteLength: number;
}

/** Wire shape of the Decionis `ExecutionIntentBinding` contract. */
export interface AuthorityIntentBinding {
  readonly protocol_version: "agent-safe.intent/1";
  readonly tenant_id: string;
  readonly intent_id: string;
  readonly captured_at: string;
  readonly expires_at: string;
  readonly actor: {
    readonly id: string;
    readonly type: string;
    readonly runtime?: string;
    readonly trust_level?: string;
  };
  readonly action: {
    readonly type: string;
    readonly resource: string;
    readonly parameters: JsonObject;
  };
  readonly context: JsonObject & { readonly idempotency_key: string };
  readonly downstream_target: {
    readonly system: string;
    readonly operation: string;
    readonly environment?: string;
    readonly endpoint?: string;
  };
  /**
   * The policy path the authority decides the intent under. Absent unless the
   * trusted runtime stated one, so an intent without it produces exactly the
   * binding, canonical JSON, and hash it produced before this property existed.
   */
  readonly policy_projection?: {
    readonly decision_type: string;
    readonly transaction_type: string | null;
    readonly workflow_key: string | null;
    readonly channel: string | null;
  };
  /**
   * Digest-only commitment to the downstream state predicted before dispatch.
   * Absent unless the trusted runtime supplied one, so an intent that does not
   * use it produces exactly the binding, canonical JSON, and hash it produced
   * before this property existed.
   */
  readonly expected_effect_digest?: string;
}
