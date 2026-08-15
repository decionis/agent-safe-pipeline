import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

function captured(amount = 350) {
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "refund_order",
      target: "shopify:order:58291",
      parameters: { amount, currency: "USD" },
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-refund-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: `refund-${amount}`,
      context: {},
    },
  );
}

function setup(verdict: "ALLOW" | "BLOCK" | "ESCALATE" = "ALLOW") {
  const execute = vi.fn(({ parameters }: { parameters: { amount: number; currency: string } }) => ({
    refundId: `refund-${parameters.amount}`,
  }));
  const registry = new ActionRegistry()
    .register("refund_order", {
      parametersSchema: z.object({ amount: z.number().positive(), currency: z.string().length(3) }),
      execute,
    })
    .seal();
  const pair = createFixtureAuthorityPair(() => verdict, {
    unsafeAllowDevelopmentFixture: true,
  });
  return { execute, pair, executor: new SafeExecutor(registry, pair.verifier) };
}

describe("SafeExecutor", () => {
  it("executes a trusted registered handler only after consuming a bound ALLOW", async () => {
    const { execute, pair, executor } = setup();
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);

    const result = await executor.run<{ refundId: string }>(intent, decision);

    expect(result.executed).toBe(true);
    expect(execute).toHaveBeenCalledTimes(1);
    if (result.executed) expect(result.result.refundId).toBe("refund-350");
  });

  it("does not execute BLOCK or ESCALATE decisions", async () => {
    for (const verdict of ["BLOCK", "ESCALATE"] as const) {
      const { execute, pair, executor } = setup(verdict);
      const intent = captured();
      const result = await executor.run(intent, await pair.authority.evaluate(intent));
      expect(result).toMatchObject({ executed: false, reason: "DECISION_NOT_ALLOW" });
      expect(execute).not.toHaveBeenCalled();
    }
  });

  it("rejects approval swapping and altered action parameters", async () => {
    const { execute, pair, executor } = setup();
    const approved = captured(350);
    const altered = captured(351);
    const result = await executor.run(altered, await pair.authority.evaluate(approved));

    expect(result).toMatchObject({ executed: false, reason: "INTENT_BINDING_MISMATCH" });
    expect(execute).not.toHaveBeenCalled();
  });

  it("does not execute an ALLOW response that is missing its authorization grant", async () => {
    const { execute, pair, executor } = setup();
    const intent = captured();
    const decision = { ...(await pair.authority.evaluate(intent)), authorization: null };

    expect(await executor.run(intent, decision)).toMatchObject({
      executed: false,
      reason: "AUTHORIZATION_MISSING",
    });
    expect(execute).not.toHaveBeenCalled();
  });

  it("allows exactly one execution under one grant across 100 concurrent claims", async () => {
    const { execute, pair, executor } = setup();
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);

    const results = await Promise.all(
      Array.from({ length: 100 }, async () => executor.run(intent, decision)),
    );

    expect(results.filter((result) => result.executed)).toHaveLength(1);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(
      results.filter((result) => !result.executed && result.reason === "AUTHORIZATION_INVALID"),
    ).toHaveLength(99);
  });

  it("does not consume a grant before action parameters pass the trusted schema", async () => {
    const { execute, pair, executor } = setup();
    const invalid = captured(-1);
    const decision = await pair.authority.evaluate(invalid);

    await expect(executor.run(invalid, decision)).rejects.toThrow();
    expect(execute).not.toHaveBeenCalled();
    expect(await pair.verifier.verifyAndConsume(invalid, decision)).not.toBeNull();
  });

  it("forbids the fixture authority in production even with explicit development opt-in", () => {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      expect(() =>
        createFixtureAuthorityPair(() => "ALLOW", {
          unsafeAllowDevelopmentFixture: true,
        }),
      ).toThrow("FIXTURE_AUTHORITY_FORBIDDEN");
    } finally {
      if (previous === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previous;
    }
  });
});
