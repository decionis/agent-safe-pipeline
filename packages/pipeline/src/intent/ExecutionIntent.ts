import { z } from "zod";
import { JsonObjectSchema, type JsonObject } from "./JsonValue.js";

const boundedId = z.string().trim().min(1).max(200);
const actionName = z
  .string()
  .trim()
  .min(1)
  .max(120)
  .regex(/^[a-z][a-z0-9._:-]*$/);

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
    endpoint: z.string().trim().min(1).max(500).optional(),
  })
  .strict();

export const TrustedIntentContextSchema = z
  .object({
    tenantId: z.string().uuid(),
    actor: IntentActorSchema,
    downstreamTarget: DownstreamTargetSchema,
    context: JsonObjectSchema.default({}),
    correlationId: boundedId.optional(),
    idempotencyKey: z.string().trim().min(1).max(180),
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
    idempotencyKey: z.string().trim().min(1).max(180),
  })
  .strict();

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
  readonly context: JsonObject;
  readonly downstream_target: {
    readonly system: string;
    readonly operation: string;
    readonly endpoint?: string;
  };
}
