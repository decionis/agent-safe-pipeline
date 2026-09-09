import { z } from "zod";
import { describe, expect, it } from "vitest";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { ActionRegistry, type ActionExecutionContext } from "../../src/execution/ActionRegistry.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

function captured(amount: number) {
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    { action: "refund_order", target: "shopify:order:synthetic-ledger", parameters: { amount } },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-refund-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: `refund-ledger-${amount}`,
      context: {},
    },
  );
}

type Execute = (context: ActionExecutionContext<{ amount: number }>) => Promise<unknown>;

function registryWith(execute: Execute) {
  return new ActionRegistry()
    .register("refund_order", {
      parametersSchema: z.object({ amount: z.number() }).strict(),
      execute,
    })
    .seal();
}

describe("FixtureAuthorizationVerifier commit ledger", () => {
  it("records each attempt outcome exactly once and reports it as RECORDED", async () => {
    const scenarios: Array<{
      readonly execute: Execute;
      readonly outcome: "COMPLETED" | "FAILED_BEFORE_DISPATCH" | "UNKNOWN_AFTER_DISPATCH";
      readonly commit: "COMMITTED" | "FAILED" | "INDETERMINATE";
    }> = [
      {
        execute: async ({ dispatch }) => await dispatch.run(async () => "done"),
        outcome: "COMPLETED",
        commit: "COMMITTED",
      },
      {
        execute: async () => {
          throw new Error("before dispatch");
        },
        outcome: "FAILED_BEFORE_DISPATCH",
        commit: "FAILED",
      },
      {
        execute: async ({ dispatch }) =>
          await dispatch.run(async () => {
            throw new Error("after dispatch");
          }),
        outcome: "UNKNOWN_AFTER_DISPATCH",
        commit: "INDETERMINATE",
      },
    ];

    for (const [index, scenario] of scenarios.entries()) {
      const pair = createFixtureAuthorityPair(() => "ALLOW", {
        unsafeAllowDevelopmentFixture: true,
      });
      const intent = captured(100 + index);
      const decision = await pair.authority.evaluate(intent);
      expect(pair.verifier.ledger()).toHaveLength(0);

      const result = await new SafeExecutor(registryWith(scenario.execute), pair.verifier).run(
        intent,
        decision,
      );

      expect(result.outcome).toBe(scenario.outcome);
      if (result.outcome === "BLOCKED") throw new Error("TEST_EXPECTED_CONSUMED_GRANT");
      expect(result.finalization).toBe("RECORDED");
      const entry = pair.verifier.commitOf(result.authorization.grantId);
      expect(entry).toMatchObject({
        grantId: result.authorization.grantId,
        decisionId: decision.decisionId,
        dossierId: decision.dossierId,
        intentHash: intent.intentHash,
        outcome: scenario.commit,
      });
      expect(entry?.finalizedAt).not.toBeNull();
      expect(Object.isFrozen(entry)).toBe(true);
      expect(pair.verifier.ledger()).toEqual([entry]);
    }
  });

  it("keeps PENDING for a repeated report, a foreign authorization, and an unknown grant", async () => {
    const pair = createFixtureAuthorityPair(() => "ALLOW", { unsafeAllowDevelopmentFixture: true });
    const intent = captured(1);
    const decision = await pair.authority.evaluate(intent);
    const authorization = await pair.verifier.verifyAndConsume(intent, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    expect(pair.verifier.commitOf(authorization.grantId)).toMatchObject({
      outcome: null,
      finalizedAt: null,
    });

    const report = (
      candidate: typeof authorization,
      outcome: "COMMITTED" | "FAILED" | "INDETERMINATE",
    ) => pair.verifier.finalize({ captured: intent, decision, authorization: candidate, outcome });

    expect(await report(authorization, "COMMITTED")).toBe("RECORDED");
    expect(await report(authorization, "FAILED")).toBe("PENDING");
    expect(pair.verifier.commitOf(authorization.grantId)?.outcome).toBe("COMMITTED");

    const other = createFixtureAuthorityPair(() => "ALLOW", {
      unsafeAllowDevelopmentFixture: true,
    });
    const otherIntent = captured(2);
    const otherDecision = await other.authority.evaluate(otherIntent);
    const otherAuthorization = await other.verifier.verifyAndConsume(otherIntent, otherDecision);
    if (otherAuthorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    expect(await report(otherAuthorization, "COMMITTED")).toBe("PENDING");
    expect(
      await report({ ...authorization, decisionId: "synthetic-other-decision" }, "COMMITTED"),
    ).toBe("PENDING");
    expect(
      await report({ ...authorization, grantId: "synthetic-unknown-grant" }, "COMMITTED"),
    ).toBe("PENDING");
    expect(pair.verifier.ledger()).toHaveLength(1);
    expect(other.verifier.commitOf(otherAuthorization.grantId)?.outcome).toBeNull();
  });
});
