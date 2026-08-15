import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import type { VerifiedAuthorization } from "../../src/execution/AuthorizationVerifier.js";
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
  return { execute, pair, registry, executor: new SafeExecutor(registry, pair.verifier) };
}

function authorizationFor(
  decision: GateDecision,
  intentHash: string,
  overrides: Partial<VerifiedAuthorization> = {},
): VerifiedAuthorization {
  if (decision.dossierId === null || decision.authorization === null) {
    throw new Error("TEST_DECISION_MISSING_AUTHORIZATION");
  }
  return {
    decisionId: decision.decisionId,
    dossierId: decision.dossierId,
    grantId: "grant-1",
    intentHash,
    expiresAt: decision.authorization.expiresAt,
    ...overrides,
  };
}

describe("SafeExecutor", () => {
  it("executes a trusted registered handler only after consuming a bound ALLOW", async () => {
    const { execute, pair, executor } = setup();
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);

    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.reasonCodes)).toBe(true);
    expect(Object.isFrozen(decision.authorization)).toBe(true);

    const result = await executor.run<{ refundId: string }>(intent, decision);

    expect(result.executed).toBe(true);
    expect(execute).toHaveBeenCalledTimes(1);
    if (result.executed) {
      expect(result.result.refundId).toBe("refund-350");
      expect(Object.isFrozen(result.authorization)).toBe(true);
    }
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

  it("recomputes conformance before consuming a grant", async () => {
    const { execute, pair, registry } = setup();
    const approved = captured();
    const forged = {
      ...approved,
      intent: { ...approved.intent, target: "shopify:order:other" },
    };
    const verifyAndConsume = vi.fn(pair.verifier.verifyAndConsume.bind(pair.verifier));

    const result = await new SafeExecutor(registry, { verifyAndConsume }).run(
      forged,
      await pair.authority.evaluate(approved),
    );

    expect(result).toMatchObject({ executed: false, reason: "INTENT_CONFORMANCE_FAILED" });
    expect(verifyAndConsume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects every captured-intent envelope mismatch and malformed intent", async () => {
    const { execute, pair, registry } = setup();
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);
    const differentHash = `sha256:${"0".repeat(64)}` as const;
    const cyclicContext: Record<string, unknown> = {};
    cyclicContext.self = cyclicContext;
    const cases = [
      {
        captured: { ...intent, intentHash: differentHash },
        decision: { ...decision, intentHash: differentHash },
      },
      { captured: { ...intent, canonicalIntent: "{}" }, decision },
      { captured: { ...intent, byteLength: intent.byteLength + 1 }, decision },
      {
        captured: {
          ...intent,
          intent: { ...intent.intent, context: cyclicContext as never },
        },
        decision,
      },
    ];

    for (const candidate of cases) {
      const verifyAndConsume = vi.fn();
      await expect(
        new SafeExecutor(registry, { verifyAndConsume }).run(
          candidate.captured,
          candidate.decision,
        ),
      ).resolves.toMatchObject({ executed: false, reason: "INTENT_CONFORMANCE_FAILED" });
      expect(verifyAndConsume).not.toHaveBeenCalled();
    }
    expect(execute).not.toHaveBeenCalled();
  });

  it("rechecks conformance after authorization consumption", async () => {
    const { execute, pair, registry } = setup();
    const intent = { ...captured() };
    const decision = await pair.authority.evaluate(intent);
    const verifier = {
      verifyAndConsume: vi.fn(async () => {
        intent.canonicalIntent = "{}";
        return authorizationFor(decision, intent.intentHash);
      }),
    };

    await expect(new SafeExecutor(registry, verifier).run(intent, decision)).resolves.toMatchObject(
      {
        executed: false,
        reason: "INTENT_CONFORMANCE_FAILED",
      },
    );
    expect(verifier.verifyAndConsume).toHaveBeenCalledOnce();
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

    await expect(executor.run(invalid, decision)).rejects.toThrow("ACTION_PARAMETERS_INVALID");
    expect(execute).not.toHaveBeenCalled();
    expect(await pair.verifier.verifyAndConsume(invalid, decision)).not.toBeNull();
  });

  it("blocks verifier failures and mismatched authorization evidence", async () => {
    const { execute, pair, registry } = setup();
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);
    const mismatch = new SafeExecutor(registry, {
      verifyAndConsume: async () => ({
        decisionId: "other-decision",
        dossierId: decision.dossierId ?? "missing",
        grantId: "grant-1",
        intentHash: intent.intentHash,
        expiresAt: decision.authorization?.expiresAt ?? intent.intent.expiresAt,
      }),
    });
    const unavailable = new SafeExecutor(registry, {
      verifyAndConsume: async () => {
        throw new Error("replay store unavailable");
      },
    });

    await expect(mismatch.run(intent, decision)).resolves.toMatchObject({
      executed: false,
      reason: "AUTHORIZATION_INVALID",
    });
    await expect(unavailable.run(intent, decision)).resolves.toMatchObject({
      executed: false,
      reason: "AUTHORIZATION_INVALID",
    });
    expect(execute).not.toHaveBeenCalled();
  });

  it("checks every authorization-evidence binding independently", async () => {
    const { execute, pair, registry } = setup();
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);
    const valid = authorizationFor(decision, intent.intentHash);
    const intentExpiry = Date.parse(intent.intent.expiresAt);
    const cases: Array<{ decision: GateDecision; authorization: VerifiedAuthorization }> = [
      { decision, authorization: { ...valid, decisionId: "other-decision" } },
      { decision, authorization: { ...valid, dossierId: "other-dossier" } },
      { decision, authorization: { ...valid, grantId: "" } },
      {
        decision,
        authorization: { ...valid, intentHash: `sha256:${"0".repeat(64)}` },
      },
      {
        decision,
        authorization: {
          ...valid,
          expiresAt: new Date(Date.parse(valid.expiresAt) + 1_000).toISOString(),
        },
      },
      {
        decision: {
          ...decision,
          authorization: { ...decision.authorization!, expiresAt: "2000-01-01T00:00:00.000Z" },
        },
        authorization: { ...valid, expiresAt: "2000-01-01T00:00:00.000Z" },
      },
      {
        decision: {
          ...decision,
          authorization: {
            ...decision.authorization!,
            expiresAt: new Date(intentExpiry + 1_000).toISOString(),
          },
        },
        authorization: { ...valid, expiresAt: new Date(intentExpiry + 1_000).toISOString() },
      },
    ];

    for (const candidate of cases) {
      const executor = new SafeExecutor(registry, {
        verifyAndConsume: async () => candidate.authorization,
      });
      await expect(executor.run(intent, candidate.decision)).resolves.toMatchObject({
        executed: false,
        reason: "AUTHORIZATION_INVALID",
      });
    }
    expect(execute).not.toHaveBeenCalled();
  });

  it("allows authorization evidence expiring exactly with its intent", async () => {
    const { execute, pair, registry } = setup();
    const intent = captured();
    const original = await pair.authority.evaluate(intent);
    const expiresAt = intent.intent.expiresAt;
    const decision = {
      ...original,
      authorization: { ...original.authorization!, expiresAt },
    };
    const verifier = {
      verifyAndConsume: async () => authorizationFor(decision, intent.intentHash, { expiresAt }),
    };

    await expect(new SafeExecutor(registry, verifier).run(intent, decision)).resolves.toMatchObject(
      {
        executed: true,
      },
    );
    expect(execute).toHaveBeenCalledOnce();
  });

  it("rejects authorization evidence expiring at the current instant", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-16T00:00:00.000Z"));
    try {
      const { execute, pair, registry } = setup();
      const intent = captured();
      const original = await pair.authority.evaluate(intent);
      const expiresAt = new Date().toISOString();
      const decision = {
        ...original,
        authorization: { ...original.authorization!, expiresAt },
      };
      const verifier = {
        verifyAndConsume: async () => authorizationFor(decision, intent.intentHash, { expiresAt }),
      };

      await expect(
        new SafeExecutor(registry, verifier).run(intent, decision),
      ).resolves.toMatchObject({ executed: false, reason: "AUTHORIZATION_INVALID" });
      expect(execute).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not expose raw handler failures", async () => {
    const registry = new ActionRegistry()
      .register("refund_order", {
        parametersSchema: z.object({ amount: z.number(), currency: z.string() }),
        execute: () => {
          throw new Error("provider response containing sensitive data");
        },
      })
      .seal();
    const pair = createFixtureAuthorityPair(() => "ALLOW", {
      unsafeAllowDevelopmentFixture: true,
    });
    const intent = captured();

    await expect(
      new SafeExecutor(registry, pair.verifier).run(intent, await pair.authority.evaluate(intent)),
    ).rejects.toThrow("ACTION_EXECUTION_FAILED");
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
