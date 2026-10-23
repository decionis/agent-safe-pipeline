/**
 * Staged change demo: one production change carried out as a governed plan.
 *
 * The change is four steps against three systems: open the change ticket,
 * drain the pool, deploy, and re-enable traffic, with a rollback the plan
 * allows only after a failed deploy. The plan is a governance object: it is
 * registered with the authority and authorizes nothing. Each step is
 * proposed, decided by policy, granted, claimed and finalized on its own, and
 * policy decides it with the plan facts the authority derives from its own
 * finalization records, never from what the caller says (ADR 0008).
 *
 * Every expectation is asserted, so the run is a self-checking proof: it
 * exits 0 only when every out-of-plan step was refused, every admitted step
 * ran exactly once with a confirmed effect, and the rollback ran under a
 * grant of its own. Offline: the loopback authority, in-process systems and
 * synthetic identities throughout.
 */
import { createHash } from "node:crypto";
import process from "node:process";
import {
  CanonicalIntentHasher,
  DecionisGate,
  DecionisGrantVerifier,
  GovernedExecutionRunner,
  IntentCapture,
  matchPlanStep,
  type AgentProposal,
  type AuthorityEffectEvidence,
  type CapturedIntent,
  type ClaimedExecution,
  type DecisionGate,
  type EffectObservation,
  type ExecutionCapability,
  type ExecutionEffect,
  type GovernedPlan,
  type JsonObject,
  type JsonValue,
  type NativeExecutor,
  type PlanStepFacts,
  type PlanStepReference,
  type PreparedAction,
  type ReconcileResult,
  type SafeExecutionResult,
} from "@decionis/agent-safe-pipeline";
import {
  LOCAL_AUTHORITY_API_KEY,
  LocalAuthority,
  LocalPlans,
} from "@decionis/agent-safe-pipeline/testing";

const TENANT_ID = "00000000-0000-4000-8000-000000000010";
const AGENT = { id: "synthetic-change-agent", type: "AI_AGENT" };
const RELEASE = "registry.example/web:2.4.1";
const OBSERVER = { id: LOCAL_AUTHORITY_API_KEY, version: "staged-change-demo/1" };

const out = (line: string): void => {
  process.stdout.write(`${line}\n`);
};

function sha256(value: JsonValue): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(CanonicalIntentHasher.stringify(value), "utf8").digest("hex")}`;
}

// ---------------------------------------------------------------------------
// The plan, as the change advisory board approved it. Approving it grants no
// step; it states the order, what a failure means for each later step, and
// the one compensation that may be proposed.
const PLAN: GovernedPlan = {
  version: "agent-safe.plan/1",
  plan_id: "chg-1042",
  tenant_id: TENANT_ID,
  steps: [
    { step_id: "open-change", action: "change.open", target: "change:CHG-1042" },
    { step_id: "drain", action: "traffic.drain", target: "lb:prod-eu/web" },
    {
      step_id: "deploy",
      action: "deployment.deploy",
      target: "deployment:prod-eu/web",
      parameters: { image: RELEASE },
    },
    { step_id: "re-enable", action: "traffic.enable", target: "lb:prod-eu/web" },
    {
      step_id: "rollback",
      action: "deployment.rollback",
      target: "deployment:prod-eu/*",
      compensates: ["deploy"],
    },
  ],
  edges: [
    { from: "open-change", to: "drain", coupling: "ordered" },
    { from: "drain", to: "deploy", coupling: "ordered" },
    { from: "deploy", to: "re-enable", coupling: "all_or_escalate" },
  ],
  partial_commit: { admissible: [], otherwise: "ESCALATE" },
};

// ---------------------------------------------------------------------------
// The three systems the change touches, in process. Each keeps the state an
// observer reads back after a write, and counts what was applied to it.
class Infrastructure {
  public readonly tickets = new Map<string, "OPEN">();
  public readonly pools = new Map<string, "SERVING" | "DRAINED">([["lb:prod-eu/web", "SERVING"]]);
  public readonly deployments = new Map<string, { image: string; healthy: boolean }>([
    ["deployment:prod-eu/web", { image: "registry.example/web:2.4.0", healthy: true }],
  ]);
  public readonly applied: string[] = [];
  /** The canary of this release fails its health check, so the rollout is aborted. */
  public readonly failingReleases = new Set([RELEASE]);

  public apply(proposal: AgentProposal): { readonly status: "APPLIED" | "ABORTED" } {
    this.applied.push(`${proposal.action} ${proposal.target}`);
    switch (proposal.action) {
      case "change.open":
        this.tickets.set(proposal.target, "OPEN");
        return { status: "APPLIED" };
      case "traffic.drain":
        this.pools.set(proposal.target, "DRAINED");
        return { status: "APPLIED" };
      case "traffic.enable":
        this.pools.set(proposal.target, "SERVING");
        return { status: "APPLIED" };
      case "deployment.deploy": {
        const image = String(proposal.parameters["image"]);
        if (this.failingReleases.has(image)) {
          // The platform aborts the rollout: the release does not serve, and
          // the deployment is left on a failed revision until it is undone.
          const current = this.deployments.get(proposal.target);
          if (current !== undefined) current.healthy = false;
          return { status: "ABORTED" };
        }
        this.deployments.set(proposal.target, { image, healthy: true });
        return { status: "APPLIED" };
      }
      case "deployment.rollback":
        this.deployments.set(proposal.target, {
          image: "registry.example/web:2.4.0",
          healthy: true,
        });
        return { status: "APPLIED" };
      default:
        return { status: "ABORTED" };
    }
  }

  /** What an observer reads back for the resource an action targets. */
  public read(proposal: AgentProposal): JsonObject {
    if (proposal.action === "change.open") {
      return { ticket: proposal.target, state: this.tickets.get(proposal.target) ?? "NONE" };
    }
    if (proposal.action.startsWith("traffic.")) {
      return { pool: proposal.target, state: this.pools.get(proposal.target) ?? "NONE" };
    }
    const deployment = this.deployments.get(proposal.target);
    return {
      deployment: proposal.target,
      image: deployment?.image ?? "NONE",
      healthy: deployment?.healthy ?? false,
    };
  }
}

/** The state each action leaves behind when it worked, as the observer will read it. */
function expectedEffect(proposal: AgentProposal): JsonObject {
  switch (proposal.action) {
    case "change.open":
      return { ticket: proposal.target, state: "OPEN" };
    case "traffic.drain":
      return { pool: proposal.target, state: "DRAINED" };
    case "traffic.enable":
      return { pool: proposal.target, state: "SERVING" };
    case "deployment.deploy":
      return {
        deployment: proposal.target,
        image: proposal.parameters["image"] ?? "",
        healthy: true,
      };
    default:
      return { deployment: proposal.target, image: "registry.example/web:2.4.0", healthy: true };
  }
}

/**
 * The executor's half: it writes to the systems once, inside the dispatch
 * the runner opened after the claim, and reads each write back. A read that
 * matches the expected effect is a CONFIRMED observation; the authority
 * counts a step as committed only with one.
 */
class StagedChangeExecutor implements NativeExecutor<AgentProposal, JsonObject, JsonObject> {
  public readonly platform = "synthetic-infrastructure";
  public readonly version = "1.0.0";
  public readonly style = "dispatch" as const;
  public readonly actionTypes = PLAN.steps.map((step) => step.action);

  public constructor(private readonly infrastructure: Infrastructure) {}

  public async capabilities(): Promise<readonly ExecutionCapability[]> {
    return this.actionTypes.map((actionType) => ({
      platform: this.platform,
      actionType,
      enabled: true,
      scopeGranted: true,
      connected: true,
      requirement: "",
    }));
  }

  public async prepare(proposal: AgentProposal): Promise<PreparedAction> {
    const request = proposal as unknown as JsonValue;
    return {
      actionType: proposal.action,
      proposal,
      downstreamTarget: {
        system: proposal.target.split(":")[0] ?? "infra",
        operation: proposal.action,
      },
      idempotencyKey: `chg-1042:${sha256(request).slice(7, 31)}`,
      expectedEffectDigest: sha256(expectedEffect(proposal)),
      requestDigest: sha256(request),
      facts: {},
    };
  }

  public async execute(run: ClaimedExecution<AgentProposal>): Promise<ExecutionEffect<JsonObject>> {
    return await run.dispatch.run(async () => {
      const answer = this.infrastructure.apply(run.action);
      return {
        kind: "DISPATCHED" as const,
        receipt: {
          status: answer.status,
          correlation: run.intent.intent.intentId,
          observed: this.infrastructure.read(run.action),
        },
      };
    });
  }

  public async observe(
    effect: ExecutionEffect<JsonObject>,
    prepared: PreparedAction,
  ): Promise<EffectObservation<JsonObject>> {
    if (effect.kind !== "DISPATCHED" || effect.receipt === null) {
      return { status: "INDETERMINATE", reason: "NO_RECEIPT", result: null };
    }
    const { status, correlation, observed } = effect.receipt as {
      status: string;
      correlation: string;
      observed: JsonObject;
    };
    if (status !== "APPLIED") {
      return { status: "FAILED", reason: "ROLLOUT_ABORTED", result: null };
    }
    const observedDigest = sha256(observed);
    const evidence: AuthorityEffectEvidence = {
      version: "1.0",
      status: observedDigest === prepared.expectedEffectDigest ? "CONFIRMED" : "UNCONFIRMED",
      observation_method: "READ_AFTER_WRITE",
      observer: OBSERVER,
      expected_effect_digest: prepared.expectedEffectDigest as string,
      observed_effect_digest: observedDigest,
      observed_at: new Date().toISOString(),
      evidence_digest: observedDigest,
      evidence_reference: null,
      execution_correlation_id: correlation,
    };
    return { status: "COMMITTED", reason: null, result: observed, evidence };
  }

  public async reconcile(): Promise<ReconcileResult<JsonObject>> {
    return { status: "UNKNOWN" };
  }
}

// ---------------------------------------------------------------------------
// The authority: the loopback double, its plan registry, and a policy over the
// plan facts. The starter rules: a step still waiting for its predecessors,
// or not admissible at all, is a BLOCK; one a person must decide is an
// ESCALATE; an admissible step and a compensation are allowed, each with its
// own grant.
let plans: LocalPlans | null = null;
const factsByIntent = new Map<string, PlanStepFacts>();
const authority = new LocalAuthority({
  trustedEffectObserverIds: [LOCAL_AUTHORITY_API_KEY],
  policy: (request) => {
    const facts = plans?.facts(request) ?? null;
    if (facts === null) return "BLOCK";
    factsByIntent.set(request.intent_hash, facts);
    if (facts.admissibility === "WAITING" || facts.admissibility === "INADMISSIBLE") {
      return "BLOCK";
    }
    return facts.admissibility === "ESCALATE" ? "ESCALATE" : "ALLOW";
  },
});
await authority.start();
plans = new LocalPlans(authority);

const gate = new DecionisGate({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});
const verifier = new DecionisGrantVerifier({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});
const infrastructure = new Infrastructure();
const executor = new StagedChangeExecutor(infrastructure);
const runner = new GovernedExecutionRunner({ verifier });
const capture = new IntentCapture();

/** The trusted executor's capture of one proposal, stamped as the plan step it was matched to. */
async function captureStep(
  proposal: AgentProposal,
  step: PlanStepReference,
): Promise<CapturedIntent> {
  const prepared = await executor.prepare(proposal);
  return capture.capture(proposal, {
    tenantId: TENANT_ID,
    actor: AGENT,
    downstreamTarget: prepared.downstreamTarget,
    context: prepared.facts,
    idempotencyKey: prepared.idempotencyKey,
    expectedEffectDigest: prepared.expectedEffectDigest as `sha256:${string}`,
    plan: step,
  });
}

interface StepRun {
  readonly decision: DecisionGate | null;
  readonly result: SafeExecutionResult<JsonObject> | null;
  readonly facts: PlanStepFacts | null;
  readonly refusedLocally: string | null;
  readonly captured: CapturedIntent | null;
}

/** Match, stamp, decide, run: what the trusted executor does for every step the agent proposes. */
async function runStep(stepId: string, proposal: AgentProposal): Promise<StepRun> {
  const match = matchPlanStep(PLAN, stepId, proposal);
  if (!match.ok) {
    return {
      decision: null,
      result: null,
      facts: null,
      refusedLocally: match.code,
      captured: null,
    };
  }
  const captured = await captureStep(proposal, match.reference);
  const decision = await gate.evaluate(captured);
  const result = await runner.dispatch(executor, { captured, decision, action: proposal });
  return {
    decision,
    result: result as SafeExecutionResult<JsonObject>,
    facts: factsByIntent.get(captured.intentHash) ?? null,
    refusedLocally: null,
    captured,
  };
}

const describe = (run: StepRun): string => {
  if (run.refusedLocally !== null) return `refused by the executor: ${run.refusedLocally}`;
  const plan = run.facts === null ? "" : ` (${run.facts.admissibility} ${run.facts.reason})`;
  const outcome =
    run.result === null
      ? "nothing ran"
      : run.result.outcome === "BLOCKED"
        ? `BLOCKED ${run.result.reason}`
        : run.result.outcome;
  return `authority ${run.decision?.verdict ?? "none"}${plan}; executor ${outcome}`;
};

const legs: { readonly title: string; readonly ok: boolean; readonly refusal: boolean }[] = [];
function leg(title: string, run: StepRun, expected: (run: StepRun) => boolean): void {
  const ok = expected(run);
  // A refusal is a step that never reached the systems: refused by the
  // executor's match, or blocked before the claim.
  const refusal =
    run.refusedLocally !== null || run.result === null || run.result.outcome === "BLOCKED";
  legs.push({ title, ok, refusal });
  out(`  ${ok ? "PASS" : "FAIL"}  ${title}\n        ${describe(run)}`);
}
const refused = (run: StepRun): boolean => run.result === null || run.result.outcome === "BLOCKED";
const committed = (run: StepRun): boolean =>
  run.decision?.verdict === "ALLOW" && run.result?.outcome === "COMPLETED";

const propose = (action: string, target: string, parameters: JsonObject = {}): AgentProposal => ({
  action,
  target,
  parameters,
});
const OPEN = propose("change.open", "change:CHG-1042");
const DRAIN = propose("traffic.drain", "lb:prod-eu/web");
const DEPLOY = propose("deployment.deploy", "deployment:prod-eu/web", { image: RELEASE });
const ENABLE = propose("traffic.enable", "lb:prod-eu/web");
const ROLLBACK = propose("deployment.rollback", "deployment:prod-eu/web");

// ---------------------------------------------------------------------------
out(
  "Staged change CHG-1042: open, drain, deploy, re-enable; rollback only after a failed deploy\n",
);
const registered = plans.register(PLAN);
out(`Plan ${registered.plan_id} registered: ${registered.plan_digest}`);
const grantsAfterRegistration = authority.grants.size;
legs.push({
  title: "Registering the plan issues no grant",
  ok: grantsAfterRegistration === 0,
  refusal: false,
});
out(
  `  ${grantsAfterRegistration === 0 ? "PASS" : "FAIL"}  Registering the plan issues no grant\n        grants held by the authority: ${grantsAfterRegistration}\n`,
);

leg(
  "The agent proposes the deploy first",
  await runStep("deploy", DEPLOY),
  (run) => refused(run) && run.facts?.reason === "PREDECESSOR_NOT_COMMITTED",
);
leg(
  "A rollback with nothing to compensate",
  await runStep("rollback", ROLLBACK),
  (run) => refused(run) && run.facts?.reason === "NOTHING_TO_COMPENSATE",
);
leg("Step 1: open the change", await runStep("open-change", OPEN), committed);
leg(
  "The deploy again, before the drain committed",
  await runStep("deploy", DEPLOY),
  (run) => refused(run) && run.facts?.reason === "PREDECESSOR_NOT_COMMITTED",
);
leg("Step 2: drain the pool", await runStep("drain", DRAIN), committed);
leg(
  "The deploy with another image than the plan pins",
  await runStep(
    "deploy",
    propose("deployment.deploy", "deployment:prod-eu/web", {
      image: "registry.example/web:2.5.0-rc1",
    }),
  ),
  (run) => run.refusedLocally === "PLAN_STEP_PARAMETER_MISMATCH",
);
// An executor that skipped its own match: the authority makes the same one.
{
  const proposal = propose("deployment.deploy", "deployment:prod-eu/web", {
    image: "registry.example/web:2.5.0-rc1",
  });
  const captured = await captureStep(proposal, {
    plan_id: PLAN.plan_id,
    plan_digest: registered.plan_digest,
    step_id: "deploy",
  });
  const decision = await gate.evaluate(captured);
  const result = await runner.dispatch(executor, { captured, decision, action: proposal });
  leg(
    "The same image stamped as the deploy step anyway",
    {
      decision,
      result: result as SafeExecutionResult<JsonObject>,
      facts: factsByIntent.get(captured.intentHash) ?? null,
      refusedLocally: null,
      captured,
    },
    (run) => refused(run) && run.facts?.reason === "STEP_MISMATCH",
  );
}
leg(
  "A drained pool drained again",
  await runStep("drain", DRAIN),
  (run) => refused(run) && run.facts?.reason === "STEP_ALREADY_ATTEMPTED",
);
const deploy = await runStep("deploy", DEPLOY);
leg(
  "Step 3: deploy (the canary fails its health check)",
  deploy,
  (run) => run.decision?.verdict === "ALLOW" && run.result?.outcome === "DEFINITELY_NOT_EXECUTED",
);
leg(
  "Step 4: re-enable after the failed deploy",
  await runStep("re-enable", ENABLE),
  (run) =>
    run.decision?.verdict === "ESCALATE" &&
    run.facts?.reason === "PREDECESSOR_FAILED_ESCALATE" &&
    refused(run),
);
// The plan allows the rollback; only its own grant lets it run. The deploy's
// decision is for the deploy's intent, so presenting it fails the binding.
{
  const rollback = await captureStep(ROLLBACK, {
    plan_id: PLAN.plan_id,
    plan_digest: registered.plan_digest,
    step_id: "rollback",
  });
  const borrowed = await runner.dispatch(executor, {
    captured: rollback,
    decision: deploy.decision as DecisionGate,
    action: ROLLBACK,
  });
  leg(
    "The rollback presented with the deploy's decision",
    {
      decision: deploy.decision,
      result: borrowed as SafeExecutionResult<JsonObject>,
      facts: null,
      refusedLocally: null,
      captured: rollback,
    },
    (run) => run.result?.outcome === "BLOCKED" && run.result.reason === "INTENT_BINDING_MISMATCH",
  );
}
const rollback = await runStep("rollback", ROLLBACK);
leg(
  "The rollback, decided on its own",
  rollback,
  (run) => committed(run) && run.facts?.admissibility === "COMPENSATION",
);

// ---------------------------------------------------------------------------
const final = plans.state(PLAN.plan_id);
const attempts = new Map(plans.attempts(PLAN.plan_id).map((attempt) => [attempt.step_id, attempt]));
out("\nWhat the authority's records say");
for (const step of PLAN.steps) {
  const attempt = attempts.get(step.step_id);
  const status =
    attempt === undefined
      ? "never claimed"
      : `finalized ${attempt.outcome ?? "not yet"}${attempt.outcome === "COMMITTED" ? `, effect ${attempt.effect}` : ""}`;
  out(`    ${step.step_id.padEnd(12)} ${(final?.steps[step.step_id] ?? "").padEnd(10)} ${status}`);
}
out(
  `    plan state   ${final?.state ?? "unknown"}: the change did not complete as approved (SCITT partially_completed)`,
);
out(
  `    systems      pool ${infrastructure.pools.get("lb:prod-eu/web")}, deployment ${JSON.stringify(infrastructure.deployments.get("deployment:prod-eu/web"))}`,
);

const grantIds = [deploy, rollback].map((run) =>
  run.decision?.authorization === null || run.decision === null
    ? null
    : run.decision.authorization.token,
);
const ranOnce = (prefix: string): boolean =>
  infrastructure.applied.filter((entry) => entry.startsWith(prefix)).length === 1;
const allOk =
  legs.every((entry) => entry.ok) &&
  final?.state === "PARTIAL" &&
  infrastructure.applied.length === 4 &&
  ranOnce("change.open") &&
  ranOnce("traffic.drain") &&
  ranOnce("deployment.deploy") &&
  ranOnce("deployment.rollback") &&
  !infrastructure.applied.some((entry) => entry.startsWith("traffic.enable")) &&
  grantIds[0] !== null &&
  grantIds[1] !== null &&
  grantIds[0] !== grantIds[1];
const refusals = legs.filter((entry) => entry.refusal).length;
const executedOutOfPlan = infrastructure.applied.length - 4;
out(
  `\n${allOk ? "PROVEN" : "NOT PROVEN"}: ${refusals} steps the plan or their grants did not admit, ${executedOutOfPlan} executed; the change opened and the pool drained with a confirmed effect and the deploy failed, each once; the rollback ran once under its own grant; the plan ends PARTIAL.`,
);
await authority.stop();
process.exitCode = allOk ? 0 : 1;
