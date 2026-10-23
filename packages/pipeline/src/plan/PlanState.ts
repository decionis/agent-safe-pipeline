import { createHash } from "node:crypto";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { JsonObject, JsonValue } from "../intent/JsonValue.js";
import {
  planDigest,
  planStepMismatch,
  type GovernedPlan,
  type PlanCoupling,
  type PlanStep,
} from "./GovernedPlan.js";
import type { PlanStepReference } from "./PlanStepReference.js";

/**
 * The facts an authority derives for one step of a governed plan, from its
 * own finalization records and nothing a caller says. This is the reference
 * derivation: Decionis mirrors it, and the two are held to the same cases.
 *
 * Every fact is a function of the plan and the records, so a decision and the
 * claim that follows it can be compared: the claim re-derives the step's view
 * and refuses when it is not the one the decision rested on (ADR 0008).
 */

/** One attempt at a step, as a finalization record reads: claimed, then settled. */
export interface PlanStepAttempt {
  readonly step_id: string;
  /** Null while the claim is open. */
  readonly outcome: "COMMITTED" | "FAILED" | "INDETERMINATE" | null;
  /** The effect evidence's status at finalization; null when none was recorded. */
  readonly effect: "CONFIRMED" | "UNCONFIRMED" | null;
  /** When the record last changed: the claim, or its settlement. */
  readonly recorded_at: string;
}

export const PLAN_STEP_STATUSES = [
  "PENDING",
  "IN_FLIGHT",
  "COMMITTED",
  "UNCONFIRMED",
  "INDETERMINATE",
  "FAILED",
] as const;
export const PLAN_STATES = ["ACTIVE", "PARTIAL", "SUSPENDED", "COMPLETE"] as const;
export const PLAN_ADMISSIBILITY = [
  "ADMISSIBLE",
  "COMPENSATION",
  "ESCALATE",
  "WAITING",
  "INADMISSIBLE",
] as const;
export const PLAN_REASON_CODES = [
  "PLAN_UNKNOWN",
  "PLAN_DIGEST_MISMATCH",
  "STEP_UNKNOWN",
  "STEP_MISMATCH",
  "PLAN_SUSPENDED",
  "PLAN_COMPLETE",
  "STEP_ALREADY_ATTEMPTED",
  "NOTHING_TO_COMPENSATE",
  "COMPENSATION_ADMISSIBLE",
  "PREDECESSOR_FAILED",
  "PREDECESSOR_NOT_COMMITTED",
  "PREDECESSOR_UNCONFIRMED",
  "PREDECESSOR_FAILED_ESCALATE",
  "PLAN_PARTIAL_ADMISSIBLE",
  "PLAN_PARTIAL_ESCALATE",
  "PLAN_PARTIAL_BLOCK",
  "STEP_ADMISSIBLE",
] as const;

export type PlanStepStatus = (typeof PLAN_STEP_STATUSES)[number];
export type PlanState = (typeof PLAN_STATES)[number];
export type PlanAdmissibility = (typeof PLAN_ADMISSIBILITY)[number];
export type PlanReasonCode = (typeof PLAN_REASON_CODES)[number];

/** The prefix of every plan-step signal id; reserved, so no caller can bind one. */
export const PLAN_STEP_SIGNAL_PREFIX = "agent_safe.plan:";

/** A material signal reference, in the authority's binding shape. */
export interface PlanStepSignal {
  readonly signal_id: string;
  /** The digest of the step's view: what the decision rested on. */
  readonly version: `sha256:${string}`;
  readonly observed_at: string;
  readonly value_digest: `sha256:${string}`;
  readonly evidence_digest: null;
}

/** What policy reads under `agent_safe.plan`. */
export interface PlanStepFacts {
  readonly schema_version: "1.0";
  readonly plan_id: string;
  readonly plan_digest: string;
  readonly step_id: string;
  readonly state: PlanState | null;
  readonly admissibility: PlanAdmissibility;
  readonly reason: PlanReasonCode;
  readonly status: PlanStepStatus | null;
  readonly predecessors: readonly {
    readonly step_id: string;
    readonly coupling: PlanCoupling;
    readonly status: PlanStepStatus;
  }[];
  readonly compensates: readonly { readonly step_id: string; readonly status: PlanStepStatus }[];
  readonly signal: PlanStepSignal | null;
}

/** An action as the authority sees it, to be matched against the step it claims to be. */
export interface PlanStepAction {
  readonly action: string;
  readonly target: string;
  readonly parameters: JsonObject;
}

/**
 * Precedence when a step has several attempts: a commit outranks anything
 * still open, and anything open outranks a settled failure. In v1 a failed
 * step is not attempted again, so the order only matters for grants that
 * raced to the same step.
 */
const STATUS_PRECEDENCE: readonly PlanStepStatus[] = [
  "COMMITTED",
  "UNCONFIRMED",
  "IN_FLIGHT",
  "INDETERMINATE",
  "FAILED",
  "PENDING",
];

function attemptStatus(attempt: PlanStepAttempt): PlanStepStatus {
  if (attempt.outcome === null) return "IN_FLIGHT";
  if (attempt.outcome === "COMMITTED") {
    return attempt.effect === "CONFIRMED" ? "COMMITTED" : "UNCONFIRMED";
  }
  return attempt.outcome;
}

/** Each step's status, from every attempt the records hold. */
export function planStepStatuses(
  plan: GovernedPlan,
  attempts: readonly PlanStepAttempt[],
): ReadonlyMap<string, PlanStepStatus> {
  const statuses = new Map<string, PlanStepStatus>(
    plan.steps.map((step) => [step.step_id, "PENDING"]),
  );
  for (const attempt of attempts) {
    const current = statuses.get(attempt.step_id);
    if (current === undefined) continue;
    const next = attemptStatus(attempt);
    if (STATUS_PRECEDENCE.indexOf(next) < STATUS_PRECEDENCE.indexOf(current)) {
      statuses.set(attempt.step_id, next);
    }
  }
  return statuses;
}

/**
 * The plan's state. An unknown outcome suspends everything until it is
 * reconciled; a failure makes the plan PARTIAL for good (it did not complete
 * as approved, and compensating does not make it so); a plan whose every
 * ordinary step committed is COMPLETE.
 */
export function planState(
  plan: GovernedPlan,
  statuses: ReadonlyMap<string, PlanStepStatus>,
): PlanState {
  const all = [...statuses.values()];
  if (all.includes("INDETERMINATE")) return "SUSPENDED";
  if (all.includes("FAILED")) return "PARTIAL";
  const ordinary = plan.steps.filter((step) => step.compensates === undefined);
  return ordinary.every((step) => statuses.get(step.step_id) === "COMMITTED")
    ? "COMPLETE"
    : "ACTIVE";
}

type EdgeResult = { readonly admissibility: PlanAdmissibility; readonly reason: PlanReasonCode };

function edgeResult(coupling: PlanCoupling, status: PlanStepStatus): EdgeResult | null {
  if (coupling === "independent" || status === "COMMITTED") return null;
  if (status === "FAILED") {
    return coupling === "ordered"
      ? { admissibility: "INADMISSIBLE", reason: "PREDECESSOR_FAILED" }
      : { admissibility: "ESCALATE", reason: "PREDECESSOR_FAILED_ESCALATE" };
  }
  if (status === "UNCONFIRMED") {
    return { admissibility: "ESCALATE", reason: "PREDECESSOR_UNCONFIRMED" };
  }
  return { admissibility: "WAITING", reason: "PREDECESSOR_NOT_COMMITTED" };
}

/** Refusals outrank waiting, and waiting outranks a person's decision. */
const EDGE_PRECEDENCE: readonly PlanAdmissibility[] = ["INADMISSIBLE", "WAITING", "ESCALATE"];

function sha256(value: JsonValue): `sha256:${string}` {
  const canonical = CanonicalIntentHasher.stringify(value);
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

/**
 * Derives one step's facts. `plan` is the registered plan, or null when the
 * organisation registered none under the stamped id; `action`, when given, is
 * matched against the step. Nothing here throws on a caller's input: every
 * way a stamp can be wrong is an `INADMISSIBLE` fact with its reason.
 */
export function derivePlanStepFacts(input: {
  readonly reference: PlanStepReference;
  readonly plan: GovernedPlan | null;
  readonly attempts: readonly PlanStepAttempt[];
  readonly action?: PlanStepAction;
  /** When the plan was registered: the view's time when no record is newer. */
  readonly registered_at?: string;
}): PlanStepFacts {
  const { reference, plan } = input;
  const refused = (reason: PlanReasonCode): PlanStepFacts => ({
    schema_version: "1.0",
    plan_id: reference.plan_id,
    plan_digest: reference.plan_digest,
    step_id: reference.step_id,
    state: null,
    admissibility: "INADMISSIBLE",
    reason,
    status: null,
    predecessors: [],
    compensates: [],
    signal: null,
  });
  if (plan === null || plan.plan_id !== reference.plan_id) return refused("PLAN_UNKNOWN");
  if (planDigest(plan) !== reference.plan_digest) return refused("PLAN_DIGEST_MISMATCH");
  const step = plan.steps.find((candidate) => candidate.step_id === reference.step_id);
  if (step === undefined) return refused("STEP_UNKNOWN");
  if (input.action !== undefined && planStepMismatch(step, input.action) !== null) {
    return refused("STEP_MISMATCH");
  }

  const statuses = planStepStatuses(plan, input.attempts);
  const state = planState(plan, statuses);
  const status = statuses.get(step.step_id) ?? "PENDING";
  const predecessors = plan.edges
    .filter((edge) => edge.to === step.step_id)
    .map((edge) => ({
      step_id: edge.from,
      coupling: edge.coupling,
      status: statuses.get(edge.from) ?? "PENDING",
    }))
    .sort((left, right) => (left.step_id < right.step_id ? -1 : 1));
  const compensates = [...(step.compensates ?? [])]
    .sort()
    .map((id) => ({ step_id: id, status: statuses.get(id) ?? "PENDING" }));
  const { admissibility, reason } = stepAdmissibility(
    plan,
    step,
    state,
    status,
    predecessors,
    compensates,
  );

  // The view: everything this step's admissibility reads, and nothing else,
  // so a change elsewhere in the plan that cannot change this step does not
  // make its grant stale. Plan state is in every view.
  const view = {
    plan_id: plan.plan_id,
    plan_digest: reference.plan_digest,
    step_id: step.step_id,
    state,
    status,
    predecessors: predecessors.map((entry) => ({ ...entry })),
    compensates: compensates.map((entry) => ({ ...entry })),
  };
  const viewSteps = new Set([
    step.step_id,
    ...predecessors.map((entry) => entry.step_id),
    ...compensates.map((entry) => entry.step_id),
  ]);
  // The view's time is its newest record, so it is as stable as the view: a
  // record elsewhere in the plan cannot move it, and one that changes the
  // plan state changes the version instead.
  const times = input.attempts
    .filter((attempt) => viewSteps.has(attempt.step_id))
    .map((attempt) => attempt.recorded_at)
    .sort();
  const observedAt = times.at(-1) ?? input.registered_at ?? new Date(0).toISOString();
  const digest = sha256(view as unknown as JsonValue);
  return {
    schema_version: "1.0",
    plan_id: plan.plan_id,
    plan_digest: reference.plan_digest,
    step_id: step.step_id,
    state,
    admissibility,
    reason,
    status,
    predecessors,
    compensates,
    signal: {
      signal_id: planStepSignalId(plan.plan_id, step.step_id),
      version: digest,
      observed_at: observedAt,
      value_digest: digest,
      evidence_digest: null,
    },
  };
}

/** The signal id a step's view is bound under. */
export function planStepSignalId(planId: string, stepId: string): string {
  return `${PLAN_STEP_SIGNAL_PREFIX}${planId}:${stepId}`;
}

function stepAdmissibility(
  plan: GovernedPlan,
  step: PlanStep,
  state: PlanState,
  status: PlanStepStatus,
  predecessors: readonly { readonly coupling: PlanCoupling; readonly status: PlanStepStatus }[],
  compensates: readonly { readonly status: PlanStepStatus }[],
): EdgeResult {
  if (state === "SUSPENDED") return { admissibility: "INADMISSIBLE", reason: "PLAN_SUSPENDED" };
  if (state === "COMPLETE") return { admissibility: "INADMISSIBLE", reason: "PLAN_COMPLETE" };
  if (status !== "PENDING") {
    return { admissibility: "INADMISSIBLE", reason: "STEP_ALREADY_ATTEMPTED" };
  }
  if (step.compensates !== undefined) {
    return compensates.some((entry) => entry.status === "FAILED")
      ? { admissibility: "COMPENSATION", reason: "COMPENSATION_ADMISSIBLE" }
      : { admissibility: "INADMISSIBLE", reason: "NOTHING_TO_COMPENSATE" };
  }
  const results = predecessors
    .map((entry) => edgeResult(entry.coupling, entry.status))
    .filter((result): result is EdgeResult => result !== null);
  for (const admissibility of EDGE_PRECEDENCE) {
    const found = results.find((result) => result.admissibility === admissibility);
    if (found !== undefined) return found;
  }
  if (state === "PARTIAL") {
    if (plan.partial_commit.admissible.includes(step.step_id)) {
      return { admissibility: "ADMISSIBLE", reason: "PLAN_PARTIAL_ADMISSIBLE" };
    }
    return plan.partial_commit.otherwise === "ESCALATE"
      ? { admissibility: "ESCALATE", reason: "PLAN_PARTIAL_ESCALATE" }
      : { admissibility: "INADMISSIBLE", reason: "PLAN_PARTIAL_BLOCK" };
  }
  return { admissibility: "ADMISSIBLE", reason: "STEP_ADMISSIBLE" };
}
