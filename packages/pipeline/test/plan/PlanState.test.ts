import { describe, expect, it } from "vitest";
import { planDigest, type GovernedPlan } from "../../src/plan/GovernedPlan.js";
import {
  derivePlanStepFacts,
  planState,
  planStepSignalId,
  planStepStatuses,
  type PlanStepAttempt,
} from "../../src/plan/PlanState.js";
import { STAGED_CHANGE, STAGED_CHANGE_DIGEST } from "./StagedChangePlan.js";

const REGISTERED_AT = "2026-10-23T09:00:00.000Z";

type Outcome = PlanStepAttempt["outcome"];

let tick = 0;
function attempt(
  stepId: string,
  outcome: Outcome,
  effect: PlanStepAttempt["effect"] = outcome === "COMMITTED" ? "CONFIRMED" : null,
): PlanStepAttempt {
  tick += 1;
  return {
    step_id: stepId,
    outcome,
    effect,
    recorded_at: `2026-10-23T09:${String(tick).padStart(2, "0")}:00.000Z`,
  };
}

function facts(
  stepId: string,
  attempts: readonly PlanStepAttempt[],
  plan: GovernedPlan = STAGED_CHANGE,
): ReturnType<typeof derivePlanStepFacts> {
  return derivePlanStepFacts({
    reference: { plan_id: plan.plan_id, plan_digest: planDigest(plan), step_id: stepId },
    plan,
    attempts,
    registered_at: REGISTERED_AT,
  });
}

function verdictOf(stepId: string, attempts: readonly PlanStepAttempt[]): string {
  const derived = facts(stepId, attempts);
  return `${derived.admissibility}/${derived.reason}`;
}

const committed = (...steps: string[]): PlanStepAttempt[] =>
  steps.map((step) => attempt(step, "COMMITTED"));

/** The staged change with an independent notification beside the deploy. */
const WITH_NOTIFY: GovernedPlan = {
  ...STAGED_CHANGE,
  plan_id: "chg-1043",
  steps: [
    ...STAGED_CHANGE.steps,
    { step_id: "notify", action: "status.post", target: "status:web" },
  ],
  edges: [...STAGED_CHANGE.edges, { from: "deploy", to: "notify", coupling: "independent" }],
};

describe("plan facts", () => {
  it("waits for each ordered predecessor to commit with a confirmed effect", () => {
    expect(verdictOf("open-change", [])).toBe("ADMISSIBLE/STEP_ADMISSIBLE");
    expect(verdictOf("drain", [])).toBe("WAITING/PREDECESSOR_NOT_COMMITTED");
    expect(verdictOf("drain", [attempt("open-change", null)])).toBe(
      "WAITING/PREDECESSOR_NOT_COMMITTED",
    );
    expect(verdictOf("drain", committed("open-change"))).toBe("ADMISSIBLE/STEP_ADMISSIBLE");
    // A commit nobody confirmed is a person's call, not an assumption.
    expect(verdictOf("drain", [attempt("open-change", "COMMITTED", "UNCONFIRMED")])).toBe(
      "ESCALATE/PREDECESSOR_UNCONFIRMED",
    );
    expect(verdictOf("deploy", committed("open-change"))).toBe("WAITING/PREDECESSOR_NOT_COMMITTED");
    expect(verdictOf("deploy", committed("open-change", "drain"))).toBe(
      "ADMISSIBLE/STEP_ADMISSIBLE",
    );
  });

  it("makes a failed deploy's dependants a person's decision and opens its compensation", () => {
    const failed = [...committed("open-change", "drain"), attempt("deploy", "FAILED")];
    expect(facts("re-enable", failed).state).toBe("PARTIAL");
    expect(verdictOf("re-enable", failed)).toBe("ESCALATE/PREDECESSOR_FAILED_ESCALATE");
    expect(verdictOf("rollback", failed)).toBe("COMPENSATION/COMPENSATION_ADMISSIBLE");
    expect(verdictOf("rollback", committed("open-change", "drain"))).toBe(
      "INADMISSIBLE/NOTHING_TO_COMPENSATE",
    );
    expect(verdictOf("deploy", failed)).toBe("INADMISSIBLE/STEP_ALREADY_ATTEMPTED");
    expect(verdictOf("drain", failed)).toBe("INADMISSIBLE/STEP_ALREADY_ATTEMPTED");
  });

  it("refuses an ordered step after its predecessor failed", () => {
    const failed = [...committed("open-change"), attempt("drain", "FAILED")];
    expect(verdictOf("deploy", failed)).toBe("INADMISSIBLE/PREDECESSOR_FAILED");
  });

  it("applies the partial-commit rule to steps no failed edge reaches", () => {
    const failed = [...committed("open-change", "drain"), attempt("deploy", "FAILED")];
    const notify = (plan: GovernedPlan): string => {
      const derived = facts("notify", failed, plan);
      return `${derived.admissibility}/${derived.reason}`;
    };
    expect(notify(WITH_NOTIFY)).toBe("ESCALATE/PLAN_PARTIAL_ESCALATE");
    expect(
      notify({ ...WITH_NOTIFY, partial_commit: { admissible: ["notify"], otherwise: "ESCALATE" } }),
    ).toBe("ADMISSIBLE/PLAN_PARTIAL_ADMISSIBLE");
    expect(notify({ ...WITH_NOTIFY, partial_commit: { admissible: [], otherwise: "BLOCK" } })).toBe(
      "INADMISSIBLE/PLAN_PARTIAL_BLOCK",
    );
    // Independent of a deploy still running: the edge orders nothing.
    const running = [...committed("open-change", "drain"), attempt("deploy", null)];
    expect(facts("notify", running, WITH_NOTIFY).admissibility).toBe("ADMISSIBLE");
  });

  it("suspends the plan on an unknown outcome and closes it when complete", () => {
    const unknown = [...committed("open-change"), attempt("drain", "INDETERMINATE")];
    expect(facts("rollback", unknown).state).toBe("SUSPENDED");
    expect(verdictOf("deploy", unknown)).toBe("INADMISSIBLE/PLAN_SUSPENDED");
    const done = committed("open-change", "drain", "deploy", "re-enable");
    expect(facts("rollback", done).state).toBe("COMPLETE");
    expect(verdictOf("rollback", done)).toBe("INADMISSIBLE/PLAN_COMPLETE");
  });

  it("refuses a stamp that names no registered plan, another digest, or another step", () => {
    const reference = { plan_id: "chg-1042", plan_digest: STAGED_CHANGE_DIGEST, step_id: "drain" };
    const refused = (input: Partial<Parameters<typeof derivePlanStepFacts>[0]>): string => {
      const derived = derivePlanStepFacts({
        reference,
        plan: STAGED_CHANGE,
        attempts: [],
        ...input,
      });
      expect(derived.signal).toBeNull();
      return `${derived.admissibility}/${derived.reason}`;
    };
    expect(refused({ plan: null })).toBe("INADMISSIBLE/PLAN_UNKNOWN");
    expect(refused({ plan: WITH_NOTIFY })).toBe("INADMISSIBLE/PLAN_UNKNOWN");
    expect(refused({ reference: { ...reference, plan_digest: `sha256:${"0".repeat(64)}` } })).toBe(
      "INADMISSIBLE/PLAN_DIGEST_MISMATCH",
    );
    expect(refused({ reference: { ...reference, step_id: "verify" } })).toBe(
      "INADMISSIBLE/STEP_UNKNOWN",
    );
    expect(
      refused({ action: { action: "traffic.drain", target: "lb:prod-us/web", parameters: {} } }),
    ).toBe("INADMISSIBLE/STEP_MISMATCH");
    const fits = derivePlanStepFacts({
      reference,
      plan: STAGED_CHANGE,
      attempts: [],
      action: { action: "traffic.drain", target: "lb:prod-eu/web", parameters: {} },
    });
    expect(fits.reason).toBe("PREDECESSOR_NOT_COMMITTED");
  });

  it("counts the strongest attempt at a step", () => {
    const statuses = planStepStatuses(STAGED_CHANGE, [
      attempt("drain", "FAILED"),
      attempt("drain", "COMMITTED"),
      attempt("deploy", "INDETERMINATE"),
      attempt("deploy", null),
      attempt("verify", "COMMITTED"),
    ]);
    expect(Object.fromEntries(statuses)).toEqual({
      "open-change": "PENDING",
      drain: "COMMITTED",
      deploy: "IN_FLIGHT",
      "re-enable": "PENDING",
      rollback: "PENDING",
    });
    expect(planState(STAGED_CHANGE, statuses)).toBe("ACTIVE");
  });
});

describe("the plan-step signal", () => {
  it("names the step and versions its view", () => {
    const base = committed("open-change", "drain");
    const derived = facts("deploy", base);
    expect(derived.signal).toEqual({
      signal_id: planStepSignalId("chg-1042", "deploy"),
      version: derived.signal?.value_digest,
      observed_at: base[1]?.recorded_at,
      value_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      evidence_digest: null,
    });
    expect(derived.signal?.signal_id).toBe("agent_safe.plan:chg-1042:deploy");
    expect(facts("open-change", []).signal?.observed_at).toBe(REGISTERED_AT);
  });

  it("changes when the step's view changes, and only then", () => {
    const base = committed("open-change", "drain");
    const deploy = facts("deploy", base, WITH_NOTIFY).signal;
    // Another grant of the same step claimed: this grant's view is stale.
    expect(
      facts("deploy", [...base, attempt("deploy", null)], WITH_NOTIFY).signal?.version,
    ).not.toBe(deploy?.version);
    // A step outside the view moving inside an unchanged plan state: the same view.
    const reEnable = facts("re-enable", base, WITH_NOTIFY).signal;
    const withNotify = [...base, attempt("notify", "COMMITTED")];
    expect(facts("re-enable", withNotify, WITH_NOTIFY).signal).toEqual(reEnable);
    // The plan state is in every view: a failure anywhere moves them all.
    const failedNotify = [...base, attempt("notify", "FAILED")];
    expect(facts("re-enable", failedNotify, WITH_NOTIFY).signal?.version).not.toBe(
      reEnable?.version,
    );
  });
});
