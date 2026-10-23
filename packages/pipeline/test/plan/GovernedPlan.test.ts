import { describe, expect, it } from "vitest";
import {
  GovernedPlanSchema,
  matchPlanStep,
  planDigest,
  planTargetInScope,
  type GovernedPlan,
} from "../../src/plan/GovernedPlan.js";
import { STAGED_CHANGE, STAGED_CHANGE_DIGEST } from "./StagedChangePlan.js";

function variant(change: (plan: GovernedPlan) => GovernedPlan): unknown {
  return change(structuredClone(STAGED_CHANGE));
}

describe("agent-safe.plan/1", () => {
  it("accepts the staged change and digests it canonically", () => {
    expect(GovernedPlanSchema.parse(STAGED_CHANGE)).toEqual(STAGED_CHANGE);
    expect(planDigest(STAGED_CHANGE)).toBe(STAGED_CHANGE_DIGEST);
    // Key order is not the plan: the same plan spelled differently digests the same.
    const reordered = Object.fromEntries(
      Object.entries(STAGED_CHANGE).reverse(),
    ) as unknown as GovernedPlan;
    expect(planDigest(reordered)).toBe(STAGED_CHANGE_DIGEST);
    // Anything that is the plan is in the digest.
    expect(
      planDigest(
        variant((plan) => ({
          ...plan,
          edges: plan.edges.map((edge) =>
            edge.to === "re-enable" ? { ...edge, coupling: "ordered" } : edge,
          ),
        })) as GovernedPlan,
      ),
    ).not.toBe(STAGED_CHANGE_DIGEST);
  });

  it.each([
    [
      "PLAN_STEP_DUPLICATE",
      (plan: GovernedPlan) => ({ ...plan, steps: [...plan.steps, plan.steps[0]!] }),
    ],
    [
      "PLAN_EDGE_UNKNOWN_STEP",
      (plan: GovernedPlan) => ({
        ...plan,
        edges: [...plan.edges, { from: "drain", to: "verify", coupling: "ordered" as const }],
      }),
    ],
    [
      "PLAN_EDGE_SELF",
      (plan: GovernedPlan) => ({
        ...plan,
        edges: [...plan.edges, { from: "drain", to: "drain", coupling: "ordered" as const }],
      }),
    ],
    [
      "PLAN_EDGE_DUPLICATE",
      (plan: GovernedPlan) => ({ ...plan, edges: [...plan.edges, plan.edges[0]!] }),
    ],
    [
      "PLAN_CYCLE",
      (plan: GovernedPlan) => ({
        ...plan,
        edges: [
          ...plan.edges,
          { from: "re-enable", to: "open-change", coupling: "ordered" as const },
        ],
      }),
    ],
    [
      "PLAN_COMPENSATION_INVALID",
      (plan: GovernedPlan) => ({
        ...plan,
        edges: [...plan.edges, { from: "deploy", to: "rollback", coupling: "ordered" as const }],
      }),
    ],
    [
      "PLAN_COMPENSATION_INVALID",
      (plan: GovernedPlan) => ({
        ...plan,
        steps: plan.steps.map((step) =>
          step.step_id === "rollback" ? { ...step, compensates: ["rollback"] } : step,
        ),
      }),
    ],
    [
      "PLAN_COMPENSATION_INVALID",
      (plan: GovernedPlan) => ({
        ...plan,
        steps: plan.steps.map((step) =>
          step.step_id === "rollback" ? { ...step, compensates: ["canary"] } : step,
        ),
      }),
    ],
    [
      "PLAN_PARTIAL_UNKNOWN_STEP",
      (plan: GovernedPlan) => ({
        ...plan,
        partial_commit: { admissible: ["rollback"], otherwise: "BLOCK" as const },
      }),
    ],
  ])("refuses a plan with %s", (code, change) => {
    const result = GovernedPlanSchema.safeParse(variant(change));
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((issue) => issue.message)).toContain(code);
  });

  it("refuses an unknown field, a misplaced wildcard and a malformed id", () => {
    expect(GovernedPlanSchema.safeParse({ ...STAGED_CHANGE, approved: true }).success).toBe(false);
    for (const target of ["*", "deployment:*/web", "lb:*:web*"]) {
      expect(
        GovernedPlanSchema.safeParse(
          variant((plan) => ({
            ...plan,
            steps: plan.steps.map((step) =>
              step.step_id === "drain" ? { ...step, target } : step,
            ),
          })),
        ).success,
      ).toBe(false);
    }
    expect(GovernedPlanSchema.safeParse({ ...STAGED_CHANGE, plan_id: "../chg" }).success).toBe(
      false,
    );
  });

  it("scopes a target exactly, or by a trailing-wildcard prefix", () => {
    expect(planTargetInScope("lb:prod-eu/web", "lb:prod-eu/web")).toBe(true);
    expect(planTargetInScope("lb:prod-eu/web", "lb:prod-eu/web2")).toBe(false);
    expect(planTargetInScope("deployment:prod-eu/*", "deployment:prod-eu/web")).toBe(true);
    expect(planTargetInScope("deployment:prod-eu/*", "deployment:prod-us/web")).toBe(false);
  });

  it("matches a proposal to its step and refuses one outside it", () => {
    const deploy = {
      action: "deployment.deploy",
      target: "deployment:prod-eu/web",
      parameters: { image: "registry.example/web:2.4.1", strategy: "rolling" },
    };
    expect(matchPlanStep(STAGED_CHANGE, "deploy", deploy)).toEqual({
      ok: true,
      reference: { plan_id: "chg-1042", plan_digest: STAGED_CHANGE_DIGEST, step_id: "deploy" },
    });
    expect(matchPlanStep(STAGED_CHANGE, "verify", deploy)).toEqual({
      ok: false,
      code: "PLAN_STEP_UNKNOWN",
    });
    expect(matchPlanStep(STAGED_CHANGE, "drain", deploy)).toEqual({
      ok: false,
      code: "PLAN_STEP_ACTION_MISMATCH",
    });
    expect(
      matchPlanStep(STAGED_CHANGE, "deploy", { ...deploy, target: "deployment:prod-us/web" }),
    ).toEqual({ ok: false, code: "PLAN_STEP_TARGET_OUT_OF_SCOPE" });
    for (const parameters of [{ image: "registry.example/web:2.5.0" }, { strategy: "rolling" }]) {
      expect(matchPlanStep(STAGED_CHANGE, "deploy", { ...deploy, parameters })).toEqual({
        ok: false,
        code: "PLAN_STEP_PARAMETER_MISMATCH",
      });
    }
  });
});
