import { z } from "zod";
import type { JsonObject } from "./JsonValue.js";

/**
 * Signals the trusted runtime binds into an intent so that policy can reason
 * about them and evidence can carry them.
 *
 * They ride inside the hashed `context` under reserved keys rather than as
 * new top-level properties, for the same reason the idempotency key does
 * (`RESERVED_CONTEXT_IDEMPOTENCY_KEY`): the Decionis `ExecutionIntentBinding`
 * contract declares `unevaluatedProperties: false` at the top level and
 * `additionalProperties: true` on `context`. Every property of `context` is
 * inside the canonical hash, so a signal bound here is bound as tightly as
 * the action itself — an authority is issued against these exact bytes, and
 * a signal changed after authorization no longer conforms.
 *
 * This is deliberately an extension of `agent-safe.intent/1` rather than a
 * new protocol version: an intent that carries no signals hashes exactly as
 * it did before, so every published conformance vector still holds.
 */

const bounded = (max: number): z.ZodString => z.string().trim().min(1).max(max);

/** A value a policy may match on: never free text from a request. */
const token = z
  .string()
  .trim()
  .min(1)
  .max(200)
  .regex(/^[a-z0-9][\w.:/-]*$/i);

export const RESERVED_CONTEXT_BOUNDARY = "enforcement_boundary";
export const RESERVED_CONTEXT_WORKLOAD = "workload";

/** Every reserved context key, so one refusal covers them all. */
export const RESERVED_CONTEXT_KEYS = [
  RESERVED_CONTEXT_BOUNDARY,
  RESERVED_CONTEXT_WORKLOAD,
] as const;

/**
 * Where the boundary sits, as the operator configured it. Only stable
 * placement belongs here: it survives a restart, it is what a policy means by
 * "production in eu", and it is safe to sign. A container id, a pod name or a
 * node name is none of those things, so the instance an effect passed through
 * is reported locally and never bound into evidence.
 */
export const BoundaryPlacementSchema = z
  .object({
    cluster_id: token.optional(),
    namespace: token.optional(),
    region: token.optional(),
    workload_id: token.optional(),
  })
  .strict();

/**
 * Which enforcement boundary admitted this intent. A dossier carrying it can
 * answer which of an estate's gateways stood in front of the effect.
 */
export const EnforcementBoundarySignalSchema = z
  .object({
    boundary_id: token,
    agentsafe_version: bounded(80),
    protocol_version: z.literal("agent-safe.intent/1"),
    deployment_type: token,
    environment: token.optional(),
    conformance_version: bounded(120).optional(),
    placement: BoundaryPlacementSchema.optional(),
  })
  .strict();

/** How far the runtime that reported a workload can be trusted about it. */
export const WORKLOAD_TRUST_LEVELS = ["unverified", "supplied", "observed", "verified"] as const;

export const WorkloadProvenanceSchema = z
  .object({
    source: token,
    trust_level: z.enum(WORKLOAD_TRUST_LEVELS),
  })
  .strict();

/**
 * What software proposed the action, as the runtime reported it. AgentSafe is
 * not the authority for any of it: the fields are carried, never established,
 * and `provenance` says who said so and how far that goes.
 */
export const WorkloadSignalSchema = z
  .object({
    runtime: token.optional(),
    artifact_type: token.optional(),
    image: bounded(500).optional(),
    digest: z
      .string()
      .regex(/^sha256:[0-9a-f]{64}$/)
      .optional(),
    publisher: bounded(200).optional(),
    provenance: WorkloadProvenanceSchema,
  })
  .strict();

export const ExecutionSignalsSchema = z
  .object({
    boundary: EnforcementBoundarySignalSchema.optional(),
    workload: WorkloadSignalSchema.optional(),
  })
  .strict();

export type BoundaryPlacement = z.infer<typeof BoundaryPlacementSchema>;
export type EnforcementBoundarySignal = z.infer<typeof EnforcementBoundarySignalSchema>;
export type WorkloadTrustLevel = (typeof WORKLOAD_TRUST_LEVELS)[number];
export type WorkloadProvenance = z.infer<typeof WorkloadProvenanceSchema>;
export type WorkloadSignal = z.infer<typeof WorkloadSignalSchema>;
export type ExecutionSignals = z.infer<typeof ExecutionSignalsSchema>;

/**
 * The reserved entries a set of signals contributes to a context. Absent
 * signals contribute nothing at all: an intent without provenance carries no
 * `workload` key rather than one claiming there is none, so a policy that
 * requires provenance refuses on the signal's absence instead of matching a
 * placeholder.
 */
export function signalContext(signals: ExecutionSignals): JsonObject {
  const parsed = ExecutionSignalsSchema.parse(signals);
  return {
    ...(parsed.boundary === undefined ? {} : { [RESERVED_CONTEXT_BOUNDARY]: parsed.boundary }),
    ...(parsed.workload === undefined ? {} : { [RESERVED_CONTEXT_WORKLOAD]: parsed.workload }),
  } as JsonObject;
}

/**
 * The boundary an intent was captured through, read back from its context.
 * Anything that does not parse is no boundary rather than a partial one, so a
 * tampered context cannot satisfy a boundary check by resembling it.
 */
export function boundaryOf(context: JsonObject): EnforcementBoundarySignal | null {
  const candidate = EnforcementBoundarySignalSchema.safeParse(context[RESERVED_CONTEXT_BOUNDARY]);
  return candidate.success ? candidate.data : null;
}

/** The workload an intent was captured for, read back from its context. */
export function workloadOf(context: JsonObject): WorkloadSignal | null {
  const candidate = WorkloadSignalSchema.safeParse(context[RESERVED_CONTEXT_WORKLOAD]);
  return candidate.success ? candidate.data : null;
}
