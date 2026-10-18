import { z } from "zod";
import { EXECUTOR_EVIDENCE_VERSION } from "./ExecutorEvidence.js";
import { NATIVE_EXECUTOR_CONTRACT } from "./NativeExecutor.js";

export const NATIVE_EXECUTOR_SCHEMA_ID =
  "https://github.com/decionis/agent-safe-pipeline/blob/master/spec/executors/native/v1/schema.json";

const identifier = z.string().min(1).max(200);
const code = z.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/);
const actionType = z
  .string()
  .min(1)
  .max(120)
  .regex(/^[a-z][a-z0-9._:-]*$/);
const sha256Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
/** A bare SHA-256, as the wire profile's `intent_sha256` carries it. */
const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/);
const instant = z.iso.datetime();

const OUTCOMES = [
  "BLOCKED",
  "HELD",
  "FAILED_BEFORE_DISPATCH",
  "COMPLETED",
  "DEFINITELY_NOT_EXECUTED",
  "UNKNOWN_AFTER_DISPATCH",
] as const;

export const ExecutionOutcomeSchema = z.enum(OUTCOMES);

/** Who carries the action out, as `POST /v1/authority/grants` accepts it in `executor`. */
export const ExecutorIdentitySchema = z.strictObject({
  platform: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9][a-z0-9._-]*$/),
  style: z.enum(["dispatch", "permit"]),
  version: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[^\W_][\w.+-]*$/),
});

/** What one executor can write for one action type: `ExecutionCapability`, on the wire. */
export const ExecutionCapabilitySchema = z.strictObject({
  platform: identifier,
  action_type: actionType,
  enabled: z.boolean(),
  scope_granted: z.boolean(),
  connected: z.boolean(),
  requirement: z.string().max(500),
});

/**
 * Permit wire profile, step 1: `POST /v1/connections/{connectionId}/executions`.
 * The connection, organisation and environment come from the authenticated
 * connection, never from this body.
 */
export const ExecutionRequestSchema = z.strictObject({
  executor: ExecutorIdentitySchema,
  action_type: actionType,
  /** The platform's own description of the action, as the executor's `prepare` reads it. */
  action: z.record(z.string(), z.unknown()),
  correlation_id: identifier.optional(),
});

/**
 * Permit wire profile, step 2: what the executor host answers. `permit_id`,
 * `intent_sha256` and `expires_at` are present only when the outcome is
 * `HELD`: there is a permit to present.
 */
export const ExecutionResponseSchema = z.strictObject({
  execution_id: identifier,
  outcome: z.enum(["HELD", "BLOCKED"]),
  /** The authority's verdict in the vocabulary the platform reads (`PROCEED`, `HOLD`, `BLOCK`, …). */
  decision: code,
  reason_codes: z.array(code).max(32),
  dossier_id: identifier.nullable(),
  permit_id: identifier.nullable(),
  intent_sha256: sha256Hex.nullable(),
  expires_at: instant.nullable(),
});

/**
 * Permit wire profile, step 4: `POST …/executions/{executionId}/receipts`.
 * The platform's native receipt, verbatim in its own vocabulary; the
 * executor's `observe` reads it into an outcome.
 */
export const NativeReceiptSchema = z.strictObject({
  permit_id: identifier,
  /** Exactly what `POST /v1/authority/grants/{grantId}/receipts` accepts as `native_receipt`. */
  native_receipt: z.strictObject({
    platform: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[a-z0-9][a-z0-9._-]*$/),
    kind: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[a-z][a-z0-9._-]*$/),
    reference: z.string().trim().min(1).max(500),
    status: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[^\W\d_][\w.-]*$/),
    observed_at: instant,
    digest: sha256Digest.optional(),
  }),
  /** A signed effect receipt (compact JWS), when the platform issues one. */
  signed_receipt: z
    .string()
    .max(20_000)
    .regex(/^[\w-]+\.[\w-]+\.[\w-]+$/)
    .optional(),
});

/** How a receipt settled the execution, or why it was refused. */
export const ReceiptResponseSchema = z.union([
  z.strictObject({
    execution_id: identifier,
    status: z.literal("SETTLED"),
    outcome: z.enum(["COMPLETED", "DEFINITELY_NOT_EXECUTED", "UNKNOWN_AFTER_DISPATCH"]),
    finalization: z.enum(["RECORDED", "PENDING", "UNSUPPORTED"]),
  }),
  z.strictObject({
    execution_id: identifier,
    status: z.literal("REFUSED"),
    reason: z.enum(["RECEIPT_DUPLICATE", "PERMIT_NOT_PRESENTED"]),
  }),
]);

/** `POST …/executions/{executionId}/reconciliations`: ask the executor what happened, read-only. */
export const ReconciliationRequestSchema = z.strictObject({
  permit_id: identifier,
});

export const ReconciliationResponseSchema = z.strictObject({
  execution_id: identifier,
  outcome: z.enum(["COMPLETED", "DEFINITELY_NOT_EXECUTED", "UNKNOWN_AFTER_DISPATCH", "BLOCKED"]),
});

/** One `agent-safe.executor-evidence/1` line, as the runner writes it. */
export const ExecutorEvidenceLineSchema = z.strictObject({
  version: z.literal(EXECUTOR_EVIDENCE_VERSION),
  contract: z.literal(NATIVE_EXECUTOR_CONTRACT),
  at: instant,
  stage: z.enum(["RUN", "PRESENTATION", "SETTLEMENT", "RECONCILIATION"]),
  executor: ExecutorIdentitySchema,
  action_type: actionType,
  intent_id: identifier,
  intent_hash: sha256Digest,
  decision_id: identifier.nullable(),
  dossier_id: identifier.nullable(),
  verdict: code.nullable(),
  grant_id: identifier.nullable(),
  outcome: z.enum([...OUTCOMES, "CLAIMED"]),
  executed: z.boolean().nullable(),
  reason: code.nullable(),
  code: code.nullable(),
  governed: z.boolean(),
  authority_state: z.enum(["DECIDED", "AUTHORITY_UNAVAILABLE"]),
  posture: z.enum(["STRICT", "BOUNDED_CONTINUITY", "CUSTOM"]),
  disposition: z.enum(["NOT_FORWARDED", "HELD", "FORWARDED_UNGOVERNED"]).nullable(),
  finalization: z.enum(["RECORDED", "PENDING", "UNSUPPORTED"]).nullable(),
  duration_ms: z.number().int().min(0),
  scope: z
    .strictObject({
      org_id: identifier,
      workspace_id: identifier,
      connection_id: identifier,
      connection_revision: identifier,
      environment: z.enum(["sandbox", "production"]),
    })
    .nullable(),
});

const VectorExpectationSchema = z.strictObject({
  outcome: z.enum([...OUTCOMES, "CLAIMED", "REFUSED"]),
  executed: z.boolean().nullable().optional(),
  reason: identifier.optional(),
  code: code.optional(),
  /** What the authority recorded for the grant after the step, when it records one. */
  finalized: z.enum(["COMMITTED", "FAILED", "INDETERMINATE"]).nullable().optional(),
  /** Whether a permit came back with the step. */
  permit: z.boolean().optional(),
  disposition: z.enum(["NOT_FORWARDED", "HELD", "FORWARDED_UNGOVERNED"]).optional(),
  /** How many times the executor's write was attempted, cumulatively. */
  writes: z.number().int().min(0).optional(),
});

const VectorStepSchema = z.discriminatedUnion("op", [
  z.strictObject({
    op: z.literal("run"),
    /** What the executor's write does. */
    write: z.enum([
      "COMMIT",
      "REFUSE",
      "INDETERMINATE",
      "FAIL_BEFORE_DISPATCH",
      "THROW_AFTER_DISPATCH",
    ]),
    expect: VectorExpectationSchema,
  }),
  z.strictObject({ op: z.literal("hold"), expect: VectorExpectationSchema }),
  z.strictObject({ op: z.literal("present"), expect: VectorExpectationSchema }),
  z.strictObject({
    op: z.literal("receipt"),
    /** The native receipt's status, in the vector platform's vocabulary. */
    status: z.enum(["POSTED", "REJECTED", "UNREADABLE"]),
    expect: VectorExpectationSchema,
  }),
  z.strictObject({
    op: z.literal("reconcile"),
    /** What the platform answers when asked about the attempt. */
    answer: z.enum(["COMPLETED", "NOT_EXECUTED", "UNKNOWN"]),
    expect: VectorExpectationSchema,
  }),
  z.strictObject({
    op: z.literal("advance"),
    /** Milliseconds the clock moves before the next step. */
    ms: z.number().int().min(1),
  }),
]);

/** One conformance vector: a decision, a posture, and the steps an executor is held to. */
export const ExecutorVectorSchema = z.strictObject({
  description: z.string().min(1).max(500),
  contract: z.literal(NATIVE_EXECUTOR_CONTRACT),
  style: z.enum(["dispatch", "permit"]),
  posture: z.enum(["STRICT", "BOUNDED_CONTINUITY", "CUSTOM"]),
  /** For `CUSTOM` posture: the disposition the institution's rule chooses. */
  custom_disposition: z.enum(["NOT_FORWARDED", "HELD", "FORWARDED_UNGOVERNED"]).optional(),
  decision: z.strictObject({
    verdict: z.enum(["ALLOW", "ESCALATE", "BLOCK"]),
    /** True when the authority could not be reached and the gate failed closed. */
    fail_closed: z.boolean(),
  }),
  steps: z.array(VectorStepSchema).min(1).max(16),
});

export type ExecutorVector = z.infer<typeof ExecutorVectorSchema>;

const DEFINITIONS = {
  ExecutionOutcome: ExecutionOutcomeSchema,
  ExecutorIdentity: ExecutorIdentitySchema,
  ExecutionCapability: ExecutionCapabilitySchema,
  ExecutionRequest: ExecutionRequestSchema,
  ExecutionResponse: ExecutionResponseSchema,
  NativeReceipt: NativeReceiptSchema,
  ReceiptResponse: ReceiptResponseSchema,
  ReconciliationRequest: ReconciliationRequestSchema,
  ReconciliationResponse: ReconciliationResponseSchema,
  ExecutorEvidenceLine: ExecutorEvidenceLineSchema,
  ExecutorVector: ExecutorVectorSchema,
} as const;

/**
 * The published JSON Schema of the contract's wire objects, generated from
 * the validators this package runs, so the document a third party validates
 * against and the reference implementation are one definition.
 */
export function nativeExecutorJsonSchema(): Record<string, unknown> {
  const definitions: Record<string, unknown> = {};
  for (const [name, schema] of Object.entries(DEFINITIONS)) {
    const generated = z.toJSONSchema(schema, { target: "draft-2020-12", io: "input" });
    const definition: Record<string, unknown> = { ...generated };
    delete definition["$schema"];
    definitions[name] = definition;
  }
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: NATIVE_EXECUTOR_SCHEMA_ID,
    title: NATIVE_EXECUTOR_CONTRACT,
    $defs: definitions,
  };
}
