/**
 * Willis's race over a real HTTP stack: two rollouts, each fitting the last
 * unit of a shared limit that no producer publishes. The authority holds the
 * limit as an allowance, reserves it with the grant, and settles it with the
 * outcome, so only one rollout commits, a top-up lets the other complete, and
 * the moment after a commit is no window. What reached the target is counted
 * by the action itself, independently of anything the authority says.
 *
 * All tenants, actors, grants and rollouts are synthetic.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import { ActionRegistry, ProviderRefusal } from "../../src/execution/ActionRegistry.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "../../src/testing/Index.js";

const CAPACITY = "deploy-capacity";
const authority = new LocalAuthority({
  policy: () => "ALLOW",
  // The approving rule's `then.allowance`: `{ key, amount_pointer: "/replicas" }`.
  allowanceDraws: (request) =>
    request.action.type === "deployment.rollout"
      ? [
          {
            allowance_key: CAPACITY,
            amount: Number.isSafeInteger(request.action.parameters.replicas)
              ? (request.action.parameters.replicas as number)
              : null,
          },
        ]
      : [],
});
let sequence = 0;

beforeAll(async () => {
  await authority.start();
});

afterAll(async () => {
  await authority.stop();
});

function rollout(service: string, replicas: number | string = 1) {
  sequence += 1;
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "deployment.rollout",
      target: `cluster:synthetic:${service}`,
      parameters: { service, replicas },
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000005",
      actor: { id: "synthetic-rollout-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "synthetic-deployer", operation: "rollout" },
      idempotencyKey: `rollout-${sequence}`,
      context: {},
    },
  );
}

function gate() {
  return new DecionisGate({
    baseUrl: authority.baseUrl,
    apiKey: LOCAL_AUTHORITY_API_KEY,
    allowInsecureLoopback: true,
  });
}

/** The target: it counts every rollout that reached it, and can be told to fail one. */
function target() {
  const applied: string[] = [];
  let failNext = false;
  const registry = new ActionRegistry()
    .register("deployment.rollout", {
      parametersSchema: z.object({ service: z.string(), replicas: z.unknown() }).strict(),
      execute: async ({ parameters, dispatch }) =>
        await dispatch.run(async () => {
          if (failNext) {
            failNext = false;
            // The deployer's own deterministic refusal: nothing was effected.
            throw new ProviderRefusal("SYNTHETIC_ROLLOUT_REFUSED");
          }
          applied.push(parameters.service);
          return { rolled_out: parameters.service };
        }),
    })
    .seal();
  const verifier = new DecionisGrantVerifier({
    baseUrl: authority.baseUrl,
    apiKey: LOCAL_AUTHORITY_API_KEY,
    allowInsecureLoopback: true,
  });
  return {
    applied,
    failOnce: () => {
      failNext = true;
    },
    executor: new SafeExecutor(registry, verifier),
  };
}

describe("held allowances against the local authority", () => {
  it("lets one of two rollouts racing for the last unit commit, and the other after a top-up", async () => {
    authority.setAllowance(CAPACITY, 1);
    const { applied, executor } = target();
    const first = rollout("checkout");
    const second = rollout("search");

    // Both proposed before either commits, as two agents would.
    const [firstDecision, secondDecision] = await Promise.all([
      gate().evaluate(first),
      gate().evaluate(second),
    ]);
    expect(firstDecision.verdict).toBe("ALLOW");
    expect(secondDecision.verdict).toBe("BLOCK");
    expect(secondDecision.authorization).toBeNull();
    expect(secondDecision.reasonCodes).toContain("ALLOWANCE_EXHAUSTED");
    expect(authority.allowanceUsage(CAPACITY)).toEqual({
      reserved: 1,
      held: 0,
      consumed: 0,
      available: 0,
    });

    expect((await executor.run(first, firstDecision)).outcome).toBe("COMPLETED");
    expect((await executor.run(second, secondDecision)).outcome).toBe("BLOCKED");
    expect(authority.allowanceUsage(CAPACITY)).toMatchObject({ consumed: 1, available: 0 });

    // The window case: nobody publishes the counter after the commit, and
    // the next proposal is still refused, because the authority counted it.
    const again = rollout("search");
    const refused = await gate().evaluate(again);
    expect(refused.verdict).toBe("BLOCK");
    expect(refused.reasonCodes).toContain("ALLOWANCE_EXHAUSTED");

    // The legitimate counterpart: a top-up, then the second rollout completes.
    authority.setAllowance(CAPACITY, 2);
    const retried = rollout("search");
    const retriedDecision = await gate().evaluate(retried);
    expect(retriedDecision.verdict).toBe("ALLOW");
    expect((await executor.run(retried, retriedDecision)).outcome).toBe("COMPLETED");

    expect(applied).toEqual(["checkout", "search"]);
    expect(authority.allowanceUsage(CAPACITY)).toEqual({
      reserved: 0,
      held: 0,
      consumed: 2,
      available: 0,
    });
  });

  it("gives capacity back when a rollout fails, so a retry needs no top-up", async () => {
    authority.setAllowance(CAPACITY, authority.allowanceUsage(CAPACITY)!.consumed + 1);
    const { applied, executor, failOnce } = target();
    const failing = rollout("billing");
    const failingDecision = await gate().evaluate(failing);
    expect(failingDecision.verdict).toBe("ALLOW");
    failOnce();
    expect((await executor.run(failing, failingDecision)).outcome).toBe("DEFINITELY_NOT_EXECUTED");
    expect(authority.allowanceUsage(CAPACITY)!.available).toBe(1);

    const retry = rollout("billing");
    const retryDecision = await gate().evaluate(retry);
    expect(retryDecision.verdict).toBe("ALLOW");
    expect((await executor.run(retry, retryDecision)).outcome).toBe("COMPLETED");
    expect(applied).toEqual(["billing"]);
    expect(authority.allowanceUsage(CAPACITY)!.available).toBe(0);
  });

  it("refuses a draw on an undefined allowance or with no amount, and never escalates it", async () => {
    const undefinedAuthority = new LocalAuthority({
      policy: () => "ALLOW",
      allowanceDraws: () => [{ allowance_key: "undefined-capacity", amount: 1 }],
    });
    await undefinedAuthority.start();
    try {
      const decision = await new DecionisGate({
        baseUrl: undefinedAuthority.baseUrl,
        apiKey: LOCAL_AUTHORITY_API_KEY,
        allowInsecureLoopback: true,
      }).evaluate(rollout("orders"));
      expect(decision.verdict).toBe("BLOCK");
      expect(decision.reasonCodes).toContain("ALLOWANCE_UNDEFINED");
    } finally {
      await undefinedAuthority.stop();
    }

    authority.setAllowance(CAPACITY, 1_000);
    const decision = await gate().evaluate(rollout("orders", "three"));
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reasonCodes).toContain("ALLOWANCE_AMOUNT_INVALID");
  });
});
