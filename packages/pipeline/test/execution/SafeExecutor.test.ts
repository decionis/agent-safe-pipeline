import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import { AuditRecorder, type AuditEventV1 } from "../../src/audit/AuditRecorder.js";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { ActionRegistry, type ActionExecutionContext } from "../../src/execution/ActionRegistry.js";
import type {
  AuthorizationVerifier,
  VerifiedAuthorization,
} from "../../src/execution/AuthorizationVerifier.js";
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
  const execute = vi.fn(
    async ({
      parameters,
      dispatch,
    }: ActionExecutionContext<{ amount: number; currency: string }>) =>
      await dispatch.run(async (idempotencyKey) => ({
        refundId: `refund-${parameters.amount}`,
        idempotencyKey,
      })),
  );
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
    expect(result).toMatchObject({ outcome: "COMPLETED", recovered: false });
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

  it("rejects observational artifacts and malformed authorization before verification", async () => {
    const { execute, pair, registry } = setup();
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);
    const permissiveVerifier = {
      verifyAndConsume: vi.fn(async () => authorizationFor(decision, intent.intentHash)),
    };
    const executor = new SafeExecutor(registry, permissiveVerifier);
    const observational = [
      { ...decision, authority: "OBSERVATIONAL" },
      { ...decision, mode: "SHADOW" },
    ] as unknown as GateDecision[];

    for (const candidate of observational) {
      expect(await executor.run(intent, candidate)).toMatchObject({
        outcome: "BLOCKED",
        reason: "DECISION_NOT_AUTHORITATIVE",
      });
    }
    for (const authorization of [undefined, "token"]) {
      expect(
        await executor.run(intent, { ...decision, authorization } as unknown as GateDecision),
      ).toMatchObject({ outcome: "BLOCKED", reason: "AUTHORIZATION_MISSING" });
    }
    expect(permissiveVerifier.verifyAndConsume).not.toHaveBeenCalled();
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

  it("classifies and redacts a handler failure before provider dispatch", async () => {
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
    ).resolves.toEqual(
      expect.objectContaining({
        outcome: "FAILED_BEFORE_DISPATCH",
        executed: false,
        reason: "HANDLER_FAILED_BEFORE_DISPATCH",
        result: null,
      }),
    );
  });

  it("finalizes every consumed grant with the attempt outcome without changing the result", async () => {
    const scenarios: Array<{
      readonly execute: (context: ActionExecutionContext<{ amount: number }>) => Promise<unknown>;
      readonly outcome: "COMPLETED" | "FAILED_BEFORE_DISPATCH" | "UNKNOWN_AFTER_DISPATCH";
      readonly commit: "COMMITTED" | "FAILED" | "INDETERMINATE";
      readonly eventType: string;
      readonly reasonCodes: readonly string[];
    }> = [
      {
        execute: async ({ dispatch }) => await dispatch.run(async () => "done"),
        outcome: "COMPLETED",
        commit: "COMMITTED",
        eventType: "EXECUTION_COMPLETED",
        reasonCodes: ["COMMIT_FINALIZATION_RECORDED"],
      },
      {
        execute: async () => {
          throw new Error("before dispatch");
        },
        outcome: "FAILED_BEFORE_DISPATCH",
        commit: "FAILED",
        eventType: "EXECUTION_FAILED_BEFORE_DISPATCH",
        reasonCodes: ["HANDLER_FAILED_BEFORE_DISPATCH", "COMMIT_FINALIZATION_RECORDED"],
      },
      {
        execute: async ({ dispatch }) =>
          await dispatch.run(async () => {
            throw new Error("after dispatch");
          }),
        outcome: "UNKNOWN_AFTER_DISPATCH",
        commit: "INDETERMINATE",
        eventType: "EXECUTION_OUTCOME_UNKNOWN",
        reasonCodes: ["PROVIDER_OUTCOME_UNKNOWN", "COMMIT_FINALIZATION_RECORDED"],
      },
    ];

    for (const scenario of scenarios) {
      const pair = createFixtureAuthorityPair(() => "ALLOW", {
        unsafeAllowDevelopmentFixture: true,
      });
      const finalize = vi.fn(async () => "RECORDED" as const);
      const verifier: AuthorizationVerifier = {
        verifyAndConsume: (c, d) => pair.verifier.verifyAndConsume(c, d),
        finalize,
      };
      const registry = new ActionRegistry()
        .register("refund_order", {
          parametersSchema: z.object({ amount: z.number(), currency: z.string() }),
          execute: scenario.execute as never,
        })
        .seal();
      const events: AuditEventV1[] = [];
      const audit = new AuditRecorder({
        sink: {
          write: (event) => {
            events.push(event);
          },
        },
      });
      const intent = captured();
      const decision = await pair.authority.evaluate(intent);

      const result = await new SafeExecutor(registry, verifier, audit).run(intent, decision);

      expect(result, scenario.outcome).toMatchObject({
        outcome: scenario.outcome,
        finalization: "RECORDED",
      });
      if (result.outcome === "BLOCKED") throw new Error("TEST_EXPECTED_CONSUMED_GRANT");
      expect(finalize).toHaveBeenCalledTimes(1);
      expect(finalize).toHaveBeenCalledWith({
        captured: intent,
        decision,
        authorization: result.authorization,
        outcome: scenario.commit,
      });
      const terminal = events.at(-1);
      expect(terminal?.eventType).toBe(scenario.eventType);
      expect(terminal?.reasonCodes).toEqual(scenario.reasonCodes);
    }
  });

  it("reports PENDING or UNSUPPORTED finalization and never lets it alter execution", async () => {
    const finalizers: Array<[AuthorizationVerifier["finalize"], string]> = [
      [undefined, "UNSUPPORTED"],
      [async () => "PENDING", "PENDING"],
      [async () => "bogus" as unknown as "PENDING", "PENDING"],
      [
        async () => {
          throw new Error("finalize offline");
        },
        "PENDING",
      ],
    ];

    for (const [finalize, expected] of finalizers) {
      const { execute, pair, registry } = setup();
      const verifier: AuthorizationVerifier = {
        verifyAndConsume: (c, d) => pair.verifier.verifyAndConsume(c, d),
        ...(finalize === undefined ? {} : { finalize }),
      };
      const events: AuditEventV1[] = [];
      const audit = new AuditRecorder({
        sink: {
          write: (event) => {
            events.push(event);
          },
        },
      });
      const intent = captured();
      const decision = await pair.authority.evaluate(intent);

      const result = await new SafeExecutor(registry, verifier, audit).run(intent, decision);

      expect(result, expected).toMatchObject({
        outcome: "COMPLETED",
        executed: true,
        finalization: expected,
      });
      expect(execute).toHaveBeenCalledTimes(1);
      expect(events.at(-1)?.reasonCodes).toEqual([`COMMIT_FINALIZATION_${expected}`]);
    }
  });

  it.each(["provider timeout", "connection reset"])(
    "returns an unknown outcome after %s and never invokes the handler twice for one grant",
    async (failure) => {
      const execute = vi.fn(
        async ({ dispatch }: ActionExecutionContext<{ amount: number; currency: string }>) =>
          await dispatch.run(async () => {
            throw new Error(failure);
          }),
      );
      const registry = new ActionRegistry()
        .register("refund_order", {
          parametersSchema: z.object({ amount: z.number(), currency: z.string() }),
          execute,
        })
        .seal();
      const pair = createFixtureAuthorityPair(() => "ALLOW", {
        unsafeAllowDevelopmentFixture: true,
      });
      const intent = captured();
      const decision = await pair.authority.evaluate(intent);
      const executor = new SafeExecutor(registry, pair.verifier);

      const first = await executor.run(intent, decision);
      expect(first).toMatchObject({
        outcome: "UNKNOWN_AFTER_DISPATCH",
        executed: null,
        reason: "PROVIDER_OUTCOME_UNKNOWN",
        recovery: {
          version: "agent-safe.recovery/1",
          intentHash: intent.intentHash,
          idempotencyKey: intent.intent.idempotencyKey,
        },
      });
      await expect(executor.run(intent, decision)).resolves.toMatchObject({
        outcome: "BLOCKED",
        reason: "AUTHORIZATION_INVALID",
      });
      expect(execute).toHaveBeenCalledTimes(1);
    },
  );

  it("reconciles concurrent recovery attempts once and returns the provider's original result", async () => {
    let release: (() => void) | undefined;
    const reconcile = vi.fn(
      async () =>
        await new Promise<{ status: "COMPLETED"; result: { refundId: string } }>((resolve) => {
          release = () => resolve({ status: "COMPLETED", result: { refundId: "provider-123" } });
        }),
    );
    const registry = new ActionRegistry()
      .register("refund_order", {
        parametersSchema: z.object({ amount: z.number(), currency: z.string() }),
        execute: async ({ dispatch }) =>
          await dispatch.run(async () => {
            throw new Error("response lost");
          }),
        reconcile,
      })
      .seal();
    const pair = createFixtureAuthorityPair(() => "ALLOW", {
      unsafeAllowDevelopmentFixture: true,
    });
    const intent = captured();
    const executor = new SafeExecutor(registry, pair.verifier);
    const attempt = await executor.run(intent, await pair.authority.evaluate(intent));
    if (attempt.outcome !== "UNKNOWN_AFTER_DISPATCH") throw new Error("TEST_EXPECTED_UNKNOWN");

    const first = executor.reconcile<{ refundId: string }>(intent, attempt.recovery);
    const second = executor.reconcile<{ refundId: string }>(intent, attempt.recovery);
    await vi.waitFor(() => expect(reconcile).toHaveBeenCalledTimes(1));
    release?.();

    await expect(first).resolves.toMatchObject({
      outcome: "COMPLETED",
      executed: true,
      recovered: true,
      result: { refundId: "provider-123" },
      authorization: {
        decisionId: attempt.recovery.decisionId,
        dossierId: attempt.recovery.dossierId,
        grantId: attempt.recovery.grantId,
        intentHash: attempt.recovery.intentHash,
        expiresAt: attempt.recovery.expiresAt,
      },
    });
    await expect(second).resolves.toMatchObject({
      outcome: "COMPLETED",
      executed: true,
      recovered: true,
    });
    expect(reconcile).toHaveBeenCalledWith(
      expect.objectContaining({ idempotencyKey: intent.intent.idempotencyKey }),
    );
  });

  it("preserves unknown recovery state and accepts a provider proof that no action occurred", async () => {
    const reconciliation = vi
      .fn()
      .mockRejectedValueOnce(new Error("lookup unavailable"))
      .mockResolvedValueOnce({ status: "NOT_EXECUTED" as const });
    const registry = new ActionRegistry()
      .register("refund_order", {
        parametersSchema: z.object({ amount: z.number(), currency: z.string() }),
        execute: async ({ dispatch }) =>
          await dispatch.run(async () => {
            throw new Error("response lost");
          }),
        reconcile: reconciliation,
      })
      .seal();
    const pair = createFixtureAuthorityPair(() => "ALLOW", {
      unsafeAllowDevelopmentFixture: true,
    });
    const intent = captured();
    const executor = new SafeExecutor(registry, pair.verifier);
    const attempt = await executor.run(intent, await pair.authority.evaluate(intent));
    if (attempt.outcome !== "UNKNOWN_AFTER_DISPATCH") throw new Error("TEST_EXPECTED_UNKNOWN");

    await expect(executor.reconcile(intent, attempt.recovery)).resolves.toMatchObject({
      outcome: "UNKNOWN_AFTER_DISPATCH",
      executed: null,
      reason: "PROVIDER_OUTCOME_UNKNOWN",
      recovery: attempt.recovery,
    });
    await expect(executor.reconcile(intent, attempt.recovery)).resolves.toMatchObject({
      outcome: "DEFINITELY_NOT_EXECUTED",
      executed: false,
      recovered: true,
      reason: "PROVIDER_CONFIRMED_NOT_EXECUTED",
    });
  });

  it("rejects every altered recovery binding independently", async () => {
    const { pair, executor } = setup();
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);
    const recovery = {
      version: "agent-safe.recovery/1" as const,
      ...authorizationFor(decision, intent.intentHash),
      idempotencyKey: intent.intent.idempotencyKey,
    };
    const malformedIntent = { ...intent, canonicalIntent: "{}" };
    const cases = [
      { captured: intent, recovery: { ...recovery, version: "agent-safe.recovery/2" } },
      {
        captured: intent,
        recovery: { ...recovery, intentHash: `sha256:${"0".repeat(64)}` },
      },
      { captured: intent, recovery: { ...recovery, idempotencyKey: "other-operation" } },
      { captured: malformedIntent, recovery },
    ];

    for (const candidate of cases) {
      await expect(
        executor.reconcile(candidate.captured, candidate.recovery as never),
      ).resolves.toMatchObject({
        outcome: "BLOCKED",
        reason: "RECOVERY_BINDING_MISMATCH",
      });
    }
  });

  it("emits the ordered, redacted authorization and execution lifecycle", async () => {
    const { execute, pair, registry } = setup();
    const events: AuditEventV1[] = [];
    const audit = new AuditRecorder({
      sink: {
        write: (event) => {
          events.push(event);
        },
      },
    });
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);

    await expect(
      new SafeExecutor(registry, pair.verifier, audit).run(intent, decision),
    ).resolves.toMatchObject({
      outcome: "COMPLETED",
    });

    expect(events.map((event) => event.eventType)).toEqual([
      "INTENT_CAPTURED",
      "AUTHORITY_DECISION",
      "GRANT_CONSUMED",
      "EXECUTION_STARTED",
      "EXECUTION_COMPLETED",
    ]);
    expect(events[2]?.correlation).toMatchObject({
      intentId: intent.intent.intentId,
      intentHash: intent.intentHash,
      decisionId: decision.decisionId,
      dossierId: decision.dossierId,
    });
    expect(JSON.stringify(events)).not.toContain("fixture-token");
    expect(JSON.stringify(events)).not.toContain("refundId");
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("fails before provider dispatch when required audit delivery fails after grant consumption", async () => {
    const { execute, pair, registry } = setup();
    const write = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("audit unavailable"))
      .mockResolvedValue(undefined);
    const audit = new AuditRecorder({
      sink: { write },
      failurePolicy: "REQUIRE_BEFORE_EXECUTION",
    });
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);
    const verifyAndConsume = vi.fn(pair.verifier.verifyAndConsume.bind(pair.verifier));

    await expect(
      new SafeExecutor(registry, { verifyAndConsume }, audit).run(intent, decision),
    ).resolves.toMatchObject({
      outcome: "FAILED_BEFORE_DISPATCH",
      executed: false,
      reason: "AUDIT_UNAVAILABLE",
    });
    expect(verifyAndConsume).toHaveBeenCalledTimes(1);
    expect(execute).not.toHaveBeenCalled();
  });

  it("fails before provider dispatch when required execution-start evidence is unavailable", async () => {
    const { execute, pair, registry } = setup();
    const write = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("audit unavailable"))
      .mockResolvedValue(undefined);
    const audit = new AuditRecorder({
      sink: { write },
      failurePolicy: "REQUIRE_BEFORE_EXECUTION",
    });
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);
    const verifyAndConsume = vi.fn(pair.verifier.verifyAndConsume.bind(pair.verifier));

    await expect(
      new SafeExecutor(registry, { verifyAndConsume }, audit).run(intent, decision),
    ).resolves.toMatchObject({
      outcome: "FAILED_BEFORE_DISPATCH",
      executed: false,
      reason: "AUDIT_UNAVAILABLE",
    });
    expect(verifyAndConsume).toHaveBeenCalledTimes(1);
    expect(execute).not.toHaveBeenCalled();
  });

  it("does not consume a grant when required initial audit evidence is unavailable", async () => {
    const { execute, pair, registry } = setup();
    const audit = new AuditRecorder({
      sink: {
        write: async () => {
          throw new Error("audit unavailable");
        },
      },
      failurePolicy: "REQUIRE_BEFORE_EXECUTION",
    });
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);
    const verifyAndConsume = vi.fn(pair.verifier.verifyAndConsume.bind(pair.verifier));

    await expect(
      new SafeExecutor(registry, { verifyAndConsume }, audit).run(intent, decision),
    ).resolves.toMatchObject({
      outcome: "BLOCKED",
      executed: false,
      reason: "AUDIT_UNAVAILABLE",
    });
    expect(verifyAndConsume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("requires both initial audit events under the strict delivery policy", async () => {
    const { execute, pair, registry } = setup();
    const write = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("decision audit unavailable"))
      .mockResolvedValue(undefined);
    const audit = new AuditRecorder({
      sink: { write },
      failurePolicy: "REQUIRE_BEFORE_EXECUTION",
    });
    const intent = captured();
    const decision = await pair.authority.evaluate(intent);
    const verifyAndConsume = vi.fn(pair.verifier.verifyAndConsume.bind(pair.verifier));

    await expect(
      new SafeExecutor(registry, { verifyAndConsume }, audit).run(intent, decision),
    ).resolves.toMatchObject({ outcome: "BLOCKED", reason: "AUDIT_UNAVAILABLE" });
    expect(verifyAndConsume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });

  it("keeps best-effort audit failure from changing successful execution", async () => {
    const { execute, pair, registry } = setup();
    const audit = new AuditRecorder({
      sink: {
        write: async () => {
          throw new Error("audit unavailable");
        },
      },
      failurePolicy: "BEST_EFFORT",
    });
    const intent = captured();

    await expect(
      new SafeExecutor(registry, pair.verifier, audit).run(
        intent,
        await pair.authority.evaluate(intent),
      ),
    ).resolves.toMatchObject({ outcome: "COMPLETED", executed: true, recovered: false });
    expect(execute).toHaveBeenCalledTimes(1);
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
