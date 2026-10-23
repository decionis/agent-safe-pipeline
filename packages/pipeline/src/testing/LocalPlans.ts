import { GovernedPlanSchema, planDigest, type GovernedPlan } from "../plan/GovernedPlan.js";
import { PlanStepReferenceSchema } from "../plan/PlanStepReference.js";
import {
  derivePlanStepFacts,
  planState,
  planStepStatuses,
  type PlanState,
  type PlanStepAttempt,
  type PlanStepFacts,
  type PlanStepStatus,
} from "../plan/PlanState.js";
import type { JsonObject } from "../intent/JsonValue.js";
import type { LocalAuthority, LocalAuthorityPolicyInput } from "./LocalAuthority.js";

/**
 * The authority's half of governed plans, beside the loopback double: a
 * registry of plans, and the facts of a plan step derived from the double's
 * own records of what was claimed and how each claim was finalized, as hosted
 * Decionis derives them from its finalization records (ADR 0008).
 *
 * A policy hook reads `facts(request)` the way a hosted rule reads
 * `agent_safe.plan`. The facts never come from the request: the request only
 * says which step it claims to be, and the double's grants say what happened.
 * The double does not re-derive them at the claim; the hosted claim does.
 */
export class LocalPlans {
  private readonly plans = new Map<
    string,
    { readonly plan: GovernedPlan; readonly digest: string; readonly registeredAt: string }
  >();

  public constructor(
    private readonly authority: LocalAuthority,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  /**
   * Registers a plan for the organisation, as `POST /v1/authority/plans`
   * does. A plan is immutable: the same id under another digest is refused.
   * Registering authorizes nothing.
   */
  public register(input: GovernedPlan): {
    readonly plan_id: string;
    readonly plan_digest: string;
  } {
    const plan = GovernedPlanSchema.parse(input);
    const digest = planDigest(plan);
    const existing = this.plans.get(plan.plan_id);
    if (existing !== undefined && existing.digest !== digest) {
      throw new Error("PLAN_DIGEST_CONFLICT");
    }
    if (existing === undefined) {
      this.plans.set(plan.plan_id, { plan, digest, registeredAt: this.clock().toISOString() });
    }
    return { plan_id: plan.plan_id, plan_digest: digest };
  }

  /** The facts of the step a request is stamped as, or null for an intent outside any plan. */
  public facts(request: LocalAuthorityPolicyInput): PlanStepFacts | null {
    const stamp = PlanStepReferenceSchema.safeParse(
      (request.context["agent_safe"] as { plan?: unknown } | undefined)?.plan,
    );
    if (!stamp.success) return null;
    const registered = this.plans.get(stamp.data.plan_id);
    return derivePlanStepFacts({
      reference: stamp.data,
      plan: registered?.plan ?? null,
      attempts: this.attempts(stamp.data.plan_id),
      action: {
        action: request.action.type,
        target: request.action.resource,
        parameters: request.action.parameters as JsonObject,
      },
      ...(registered === undefined ? {} : { registered_at: registered.registeredAt }),
    });
  }

  /** A registered plan's state and each step's status, as `GET /v1/authority/plans/{id}` reads them. */
  public state(planId: string): {
    readonly state: PlanState;
    readonly steps: Readonly<Record<string, PlanStepStatus>>;
  } | null {
    const registered = this.plans.get(planId);
    if (registered === undefined) return null;
    const statuses = planStepStatuses(registered.plan, this.attempts(planId));
    return {
      state: planState(registered.plan, statuses),
      steps: Object.fromEntries(statuses),
    };
  }

  /**
   * Every claimed grant whose decision was stamped as a step of this plan,
   * with its finalization: the outcome the double recorded, and whether the
   * effect evidence it accepted confirmed the effect.
   */
  public attempts(planId: string): readonly PlanStepAttempt[] {
    const stepByIntent = new Map<string, string>();
    const claimedAt = new Map<string, string>();
    const finalizedAt = new Map<string, { readonly at: string; readonly confirmed: boolean }>();
    for (const record of this.authority.requests) {
      const body = record.body as Record<string, unknown> | null;
      if (body === null || typeof body !== "object") continue;
      const stamp = PlanStepReferenceSchema.safeParse(
        (
          (body["context"] as Record<string, unknown> | undefined)?.["agent_safe"] as
            { plan?: unknown } | undefined
        )?.plan,
      );
      if (
        stamp.success &&
        stamp.data.plan_id === planId &&
        typeof body["intent_hash"] === "string"
      ) {
        stepByIntent.set(body["intent_hash"], stamp.data.step_id);
      }
      const response = record.response?.body as Record<string, unknown> | undefined;
      if (
        typeof body["execution_token"] === "string" &&
        body["outcome"] === undefined &&
        record.response?.status === 200
      ) {
        claimedAt.set(body["execution_token"], record.at);
      }
      if (
        typeof body["execution_token"] === "string" &&
        typeof body["outcome"] === "string" &&
        record.response?.status === 200 &&
        response?.["finalized"] === true
      ) {
        finalizedAt.set(body["execution_token"], {
          at: record.at,
          confirmed: response["effect_confirmation"] === "CONFIRMED",
        });
      }
    }
    const attempts: PlanStepAttempt[] = [];
    for (const [token, grant] of this.authority.grants) {
      const stepId = stepByIntent.get(grant.intentHash);
      if (stepId === undefined || !grant.claimed) continue;
      const settled = finalizedAt.get(token);
      attempts.push({
        step_id: stepId,
        outcome: grant.finalized,
        effect:
          grant.finalized === null
            ? null
            : settled?.confirmed === true
              ? "CONFIRMED"
              : "UNCONFIRMED",
        recorded_at: settled?.at ?? claimedAt.get(token) ?? this.clock().toISOString(),
      });
    }
    return attempts;
  }
}
