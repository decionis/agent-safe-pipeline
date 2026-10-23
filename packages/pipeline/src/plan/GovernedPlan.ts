import { createHash } from "node:crypto";
import { z } from "zod";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { AgentProposal } from "../intent/ExecutionIntent.js";
import { JsonObjectSchema, type JsonObject, type JsonValue } from "../intent/JsonValue.js";
import { PlanIdSchema, PlanStepIdSchema, type PlanStepReference } from "./PlanStepReference.js";

/**
 * A governed plan: one change carried out as several governed operations,
 * each proposed, decided, granted, claimed and finalized on its own.
 *
 * The plan is a governance object, not an orchestrator. It names the steps,
 * which step depends on which and how (the coupling), and what stays
 * admissible once a step has failed. Registering it with the authority
 * authorizes no step: the authority derives each step's plan facts from its
 * own finalization records, and policy decides each step with those facts in
 * front of it. ADR 0008 is the design.
 */
export const GOVERNED_PLAN_VERSION = "agent-safe.plan/1";

/** What a predecessor's outcome means for the step that depends on it. */
export const PLAN_COUPLINGS = ["independent", "ordered", "all_or_escalate"] as const;

export const MAX_PLAN_STEPS = 32;
export const MAX_PLAN_EDGES = 64;
const MAX_COMPENSATED_STEPS = 8;

const actionName = z
  .string()
  .min(1)
  .max(120)
  .regex(/^[a-z][a-z0-9._:-]*$/);
/** An exact target, or a prefix followed by one trailing `*`. */
const targetScope = z
  .string()
  .min(1)
  .max(500)
  .refine((value) => !value.slice(0, -1).includes("*") && value !== "*", {
    message: "PLAN_TARGET_SCOPE_INVALID",
  });

export const PlanStepSchema = z
  .object({
    step_id: PlanStepIdSchema,
    action: actionName,
    target: targetScope,
    /** Parameters the step pins: each must equal the proposal's, canonically. */
    parameters: JsonObjectSchema.optional(),
    /** Present only on a compensation step: the steps whose failure it may follow. */
    compensates: z.array(PlanStepIdSchema).min(1).max(MAX_COMPENSATED_STEPS).optional(),
  })
  .strict();

export const PlanEdgeSchema = z
  .object({
    from: PlanStepIdSchema,
    to: PlanStepIdSchema,
    coupling: z.enum(PLAN_COUPLINGS),
  })
  .strict();

/** What stays admissible once a step has FAILED. */
export const PartialCommitRuleSchema = z
  .object({
    admissible: z.array(PlanStepIdSchema).max(MAX_PLAN_STEPS),
    otherwise: z.enum(["ESCALATE", "BLOCK"]),
  })
  .strict();

export const GovernedPlanSchema = z
  .object({
    version: z.literal(GOVERNED_PLAN_VERSION),
    plan_id: PlanIdSchema,
    tenant_id: z.string().uuid(),
    steps: z.array(PlanStepSchema).min(1).max(MAX_PLAN_STEPS),
    edges: z.array(PlanEdgeSchema).max(MAX_PLAN_EDGES),
    partial_commit: PartialCommitRuleSchema,
  })
  .strict()
  .superRefine((plan, issues) => {
    const problem = planStructureProblem(plan);
    if (problem !== null) issues.addIssue({ code: "custom", message: problem });
  });

export type PlanCoupling = (typeof PLAN_COUPLINGS)[number];
export type PlanStep = z.infer<typeof PlanStepSchema>;
export type PlanEdge = z.infer<typeof PlanEdgeSchema>;
export type PartialCommitRule = z.infer<typeof PartialCommitRuleSchema>;
export type GovernedPlan = z.infer<typeof GovernedPlanSchema>;

/**
 * The first structural problem with a plan, or null. The checks are the ones
 * a dependency graph needs to mean anything: every edge joins two known,
 * distinct steps once; there is no cycle; and a compensation step stands
 * outside the graph, compensating ordinary steps only.
 */
function planStructureProblem(plan: {
  readonly steps: readonly PlanStep[];
  readonly edges: readonly PlanEdge[];
  readonly partial_commit: PartialCommitRule;
}): string | null {
  const steps = new Map<string, PlanStep>();
  for (const step of plan.steps) {
    if (steps.has(step.step_id)) return "PLAN_STEP_DUPLICATE";
    steps.set(step.step_id, step);
  }
  const isCompensation = (id: string): boolean => steps.get(id)?.compensates !== undefined;
  for (const step of plan.steps) {
    for (const compensated of step.compensates ?? []) {
      if (!steps.has(compensated) || isCompensation(compensated)) {
        return "PLAN_COMPENSATION_INVALID";
      }
    }
  }
  const seen = new Set<string>();
  const successors = new Map<string, string[]>();
  for (const edge of plan.edges) {
    if (!steps.has(edge.from) || !steps.has(edge.to)) return "PLAN_EDGE_UNKNOWN_STEP";
    if (edge.from === edge.to) return "PLAN_EDGE_SELF";
    if (isCompensation(edge.from) || isCompensation(edge.to)) return "PLAN_COMPENSATION_INVALID";
    const key = `${edge.from}\n${edge.to}`;
    if (seen.has(key)) return "PLAN_EDGE_DUPLICATE";
    seen.add(key);
    successors.set(edge.from, [...(successors.get(edge.from) ?? []), edge.to]);
  }
  for (const id of plan.partial_commit.admissible) {
    if (!steps.has(id) || isCompensation(id)) return "PLAN_PARTIAL_UNKNOWN_STEP";
  }
  // Kahn's algorithm: a graph with a cycle leaves steps no order can reach.
  const indegree = new Map([...steps.keys()].map((id) => [id, 0]));
  for (const edge of plan.edges) indegree.set(edge.to, (indegree.get(edge.to) ?? 0) + 1);
  const ready = [...indegree].filter(([, count]) => count === 0).map(([id]) => id);
  let ordered = 0;
  while (ready.length > 0) {
    const id = ready.pop() as string;
    ordered += 1;
    for (const next of successors.get(id) ?? []) {
      const remaining = (indegree.get(next) ?? 0) - 1;
      indegree.set(next, remaining);
      if (remaining === 0) ready.push(next);
    }
  }
  return ordered === steps.size ? null : "PLAN_CYCLE";
}

/**
 * The plan's digest: SHA-256 over its canonical JSON (sorted keys), the form
 * every digest in the intent contract uses. The plan is parsed first, so two
 * spellings of one plan that the schema accepts differ only where the plan
 * itself differs.
 */
export function planDigest(plan: GovernedPlan): `sha256:${string}` {
  const parsed = GovernedPlanSchema.parse(plan);
  const canonical = CanonicalIntentHasher.stringify(parsed as unknown as JsonValue);
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

export type PlanStepMismatch =
  | "PLAN_STEP_UNKNOWN"
  | "PLAN_STEP_ACTION_MISMATCH"
  | "PLAN_STEP_TARGET_OUT_OF_SCOPE"
  | "PLAN_STEP_PARAMETER_MISMATCH";

export type PlanStepMatch =
  | { readonly ok: true; readonly reference: PlanStepReference }
  | { readonly ok: false; readonly code: PlanStepMismatch };

/** Whether a target is inside a step's scope: exact, or under a trailing-`*` prefix. */
export function planTargetInScope(scope: string, target: string): boolean {
  return scope.endsWith("*") ? target.startsWith(scope.slice(0, -1)) : target === scope;
}

/**
 * Matches a proposal to one step of a plan and, when it fits, returns the
 * reference the trusted executor stamps into the intent. A different action,
 * a target outside the step's scope, or a parameter that differs from one the
 * step pins is refused here, before anything is captured. The authority makes
 * the same match itself; this one only fails fast.
 */
export function matchPlanStep(
  plan: GovernedPlan,
  stepId: string,
  proposal: AgentProposal,
): PlanStepMatch {
  const step = plan.steps.find((candidate) => candidate.step_id === stepId);
  if (step === undefined) return { ok: false, code: "PLAN_STEP_UNKNOWN" };
  const mismatch = planStepMismatch(step, {
    action: proposal.action,
    target: proposal.target,
    parameters: proposal.parameters,
  });
  if (mismatch !== null) return { ok: false, code: mismatch };
  return {
    ok: true,
    reference: { plan_id: plan.plan_id, plan_digest: planDigest(plan), step_id: step.step_id },
  };
}

/** The reason an action is outside a step, or null when it fits. */
export function planStepMismatch(
  step: PlanStep,
  action: { readonly action: string; readonly target: string; readonly parameters: JsonObject },
): Exclude<PlanStepMismatch, "PLAN_STEP_UNKNOWN"> | null {
  if (action.action !== step.action) return "PLAN_STEP_ACTION_MISMATCH";
  if (!planTargetInScope(step.target, action.target)) return "PLAN_STEP_TARGET_OUT_OF_SCOPE";
  for (const [name, pinned] of Object.entries(step.parameters ?? {})) {
    const proposed = action.parameters[name];
    if (
      proposed === undefined ||
      CanonicalIntentHasher.stringify(proposed) !== CanonicalIntentHasher.stringify(pinned)
    ) {
      return "PLAN_STEP_PARAMETER_MISMATCH";
    }
  }
  return null;
}
