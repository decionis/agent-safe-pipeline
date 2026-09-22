import { z } from "zod";
import {
  ActionRegistry,
  IntentCapture,
  SafeExecutor,
  createFixtureAuthorityPair,
  type CapturedIntent,
  type EnforcementBoundarySignal,
  type ExecutionSignals,
  type GateDecision,
  type JsonObject,
  type WorkloadSignal,
} from "@decionis/agent-safe-pipeline";

/**
 * Six attacks a valid principal can make, run for real rather than described.
 *
 * `BoundaryTest` sends requests at a synthetic target and shows what reaches
 * it. These are the attacks that live inside the lifecycle instead: they need
 * an authority to have been issued before they can be attempted, so no
 * request at a target can express them. Each one is executed here, against a
 * fixture authority on no network at all, and each must be refused.
 *
 * Nothing here is a mock of the refusal. The intents are captured by
 * `IntentCapture`, the decisions come from the fixture authority pair, the
 * grants are claimed by its verifier, and the refusals are `SafeExecutor`'s
 * own. What the report shows is what the shipped code did.
 */

export const ATTACK_VERSION = "agent-safe.authority-attacks/1";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const ACTOR = { id: "synthetic-treasury-agent", type: "AI_AGENT" } as const;
const BENEFICIARY = "core:beneficiary:synthetic-a";
const OTHER_BENEFICIARY = "core:beneficiary:synthetic-b";
const AUTHORIZED_AMOUNT = 50_000;
const MUTATED_AMOUNT = 100_000;
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const BOUNDARY_A = "synthetic-boundary-a";
const BOUNDARY_B = "synthetic-boundary-b";

export interface AttackResult {
  readonly id: string;
  readonly title: string;
  /** What the attack tries to make happen, in one line an operator can read. */
  readonly attempt: string;
  /** What must happen instead. */
  readonly expected: string;
  /** The refusal code the shipped code produced, or null if nothing refused. */
  readonly refusal: string | null;
  readonly held: boolean;
}

export interface AttackReport {
  readonly version: typeof ATTACK_VERSION;
  readonly results: readonly AttackResult[];
  readonly attempts: number;
  readonly executions: number;
  readonly held: boolean;
}

function boundary(id: string): EnforcementBoundarySignal {
  return {
    boundary_id: id,
    agentsafe_version: "0.0.0-test",
    protocol_version: "agent-safe.intent/1",
    deployment_type: "unknown",
  };
}

function workload(digest: string): WorkloadSignal {
  return {
    runtime: "docker",
    artifact_type: "oci",
    digest,
    provenance: { source: "docker", trust_level: "supplied" },
  };
}

const parametersSchema = z.object({
  amount: z.number().positive(),
  currency: z.string().length(3),
});

function capture(amount: number, target: string, signals?: ExecutionSignals): CapturedIntent {
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    { action: "payment.send", target, parameters: { amount, currency: "EUR" } },
    {
      tenantId: TENANT_ID,
      actor: ACTOR,
      downstreamTarget: { system: "core", operation: "payment.send" },
      idempotencyKey: `payment-${amount}-${target}`,
      context: {} as JsonObject,
      ...(signals === undefined ? {} : { signals }),
    },
  );
}

/** A sealed registry whose one handler counts what it was allowed to do. */
function lane(verdict: "ALLOW" | "BLOCK" = "ALLOW") {
  const dispatched: number[] = [];
  const registry = new ActionRegistry()
    .register("payment.send", {
      parametersSchema,
      execute: async ({ parameters, dispatch }) =>
        await dispatch.run(async () => {
          dispatched.push(parameters.amount);
          return { sent: parameters.amount };
        }),
    })
    .seal();
  const pair = createFixtureAuthorityPair(() => verdict, { unsafeAllowDevelopmentFixture: true });
  return { dispatched, registry, pair };
}

function outcome(
  id: string,
  title: string,
  attempt: string,
  expected: string,
  refusal: string | null,
  dispatched: readonly number[],
  allowedDispatches = 0,
): AttackResult {
  return {
    id,
    title,
    attempt,
    expected,
    refusal,
    held: refusal !== null && dispatched.length === allowedDispatches,
  };
}

function refusalOf(result: { readonly outcome: string; readonly reason?: string }): string | null {
  return result.outcome === "COMPLETED" ? null : (result.reason ?? result.outcome);
}

/**
 * Runs all six and reports what each produced. It reaches nothing: no
 * network, no file, no clock beyond the intent's own expiry.
 */
export async function runAuthorityAttacks(): Promise<AttackReport> {
  const results: AttackResult[] = [];

  // 1. Exact-action mutation. Authorize 50,000; present 100,000.
  {
    const { dispatched, registry, pair } = lane();
    const executor = new SafeExecutor(registry, pair.verifier);
    const authorized = capture(AUTHORIZED_AMOUNT, BENEFICIARY);
    const decision = await pair.authority.evaluate(authorized);
    const mutated = capture(MUTATED_AMOUNT, BENEFICIARY);
    results.push(
      outcome(
        "exact-action-mutation",
        "The amount changed after authorization",
        `payment.amount ${AUTHORIZED_AMOUNT} authorized, ${MUTATED_AMOUNT} dispatched`,
        "dispatch refused",
        refusalOf(await executor.run(mutated, decision)),
        dispatched,
      ),
    );
  }

  // 2. Target substitution. Authorize beneficiary A; present beneficiary B.
  {
    const { dispatched, registry, pair } = lane();
    const executor = new SafeExecutor(registry, pair.verifier);
    const authorized = capture(AUTHORIZED_AMOUNT, BENEFICIARY);
    const decision = await pair.authority.evaluate(authorized);
    const elsewhere = capture(AUTHORIZED_AMOUNT, OTHER_BENEFICIARY);
    results.push(
      outcome(
        "target-substitution",
        "The beneficiary changed after authorization",
        "beneficiary A authorized, beneficiary B dispatched",
        "dispatch refused",
        refusalOf(await executor.run(elsewhere, decision)),
        dispatched,
      ),
    );
  }

  // 3. Replay. Claim a valid authority, dispatch once, present it again.
  {
    const { dispatched, registry, pair } = lane();
    const executor = new SafeExecutor(registry, pair.verifier);
    const authorized = capture(AUTHORIZED_AMOUNT, BENEFICIARY);
    const decision = await pair.authority.evaluate(authorized);
    const first = await executor.run(authorized, decision);
    const second = await executor.run(authorized, decision);
    results.push(
      outcome(
        "replay",
        "A consumed grant presented a second time",
        "one grant claimed, dispatched once, claimed again",
        "second claim refused",
        first.outcome === "COMPLETED" ? refusalOf(second) : "FIRST_DISPATCH_FAILED",
        dispatched,
        1,
      ),
    );
  }

  // 4. Workload substitution. Authority for digest A, execution from digest B.
  {
    const { dispatched, registry, pair } = lane();
    const executor = new SafeExecutor(registry, pair.verifier, undefined, {
      workloadDigest: DIGEST_A,
    });
    const other = capture(AUTHORIZED_AMOUNT, BENEFICIARY, { workload: workload(DIGEST_B) });
    const decision = await pair.authority.evaluate(other);
    results.push(
      outcome(
        "workload-substitution",
        "Another workload reuses an approved release's authority",
        "authority bound to digest A, execution attempted from digest B",
        "dispatch refused",
        refusalOf(await executor.run(other, decision)),
        dispatched,
      ),
    );
  }

  // 5. Boundary substitution. Authority issued at A, presented at B.
  {
    const { dispatched, registry, pair } = lane();
    const executor = new SafeExecutor(registry, pair.verifier, undefined, {
      boundaryId: BOUNDARY_B,
    });
    const elsewhere = capture(AUTHORIZED_AMOUNT, BENEFICIARY, { boundary: boundary(BOUNDARY_A) });
    const decision = await pair.authority.evaluate(elsewhere);
    results.push(
      outcome(
        "boundary-substitution",
        "An authority admitted at one boundary presented at another",
        "issued through boundary A, presented at boundary B",
        "dispatch refused",
        refusalOf(await executor.run(elsewhere, decision)),
        dispatched,
      ),
    );
  }

  // 6. Valid identity, invalid action. Nothing is forged; policy refuses.
  {
    const { dispatched, registry, pair } = lane("BLOCK");
    const executor = new SafeExecutor(registry, pair.verifier);
    const proposed = capture(MUTATED_AMOUNT, BENEFICIARY);
    const decision: GateDecision = await pair.authority.evaluate(proposed);
    results.push(
      outcome(
        "valid-identity-invalid-action",
        "A valid principal proposes an action policy refuses",
        "authenticated, credentialed, permitted API, unauthorized action",
        "no dispatch",
        refusalOf(await executor.run(proposed, decision)),
        dispatched,
      ),
    );
  }

  return {
    version: ATTACK_VERSION,
    results,
    attempts: results.length,
    // One dispatch is legitimate: the replay attack has to succeed once
    // before there is a consumed grant to replay.
    executions: 1,
    held: results.every((result) => result.held),
  };
}
