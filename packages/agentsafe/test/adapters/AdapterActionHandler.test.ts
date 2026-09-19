import {
  CanonicalIntentHasher,
  ProviderRefusal,
  type CapturedIntent,
} from "@decionis/agent-safe-pipeline";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { adapterActionHandler, effectBlock } from "../../src/adapters/AdapterActionHandler.js";
import { EffectEvidenceRegister } from "../../src/adapters/EffectEvidenceRegister.js";
import { IndeterminateOutcome } from "../../src/adapters/EffectAdapter.js";
import type {
  AdapterExecution,
  EffectAdapter,
  PreparedAction,
  ProviderReconciliationResult,
  ProviderResult,
} from "../../src/adapters/EffectAdapter.js";
import { jcsDigest } from "../../src/adapters/JcsDigest.js";

interface FakeAction {
  readonly amount: string;
}

const expectedEffect = { effect_type: "TESTED", amount: "10.00" };

const prepared: PreparedAction = {
  expectedEffect,
  expectedEffectDigest: jcsDigest(expectedEffect),
  intentDigest: jcsDigest({ amount: "10.00" }),
  requestDigest: jcsDigest({ amount: "10.00" }),
  resourceRef: "fixture_resource_1",
  effectType: "TESTED",
  domain: "TEST_DOMAIN",
  actionType: "TEST_ACTION",
};

const answer = (overrides: Partial<ProviderResult> = {}): ProviderResult => ({
  status: "COMMITTED",
  providerStatus: "POSTED",
  providerReference: "fixture_provider_ref_9",
  responseDigest: jcsDigest({ status: "POSTED" }),
  failureReason: null,
  observed: { ...expectedEffect },
  observationMethod: "READ_AFTER_WRITE",
  providerGenerated: true,
  source: "FAKE",
  ...overrides,
});

/** An adapter that says what it is told to say, and counts what it was asked. */
function fakeAdapter(
  script: {
    readonly execute?: (execution: AdapterExecution<FakeAction>) => Promise<ProviderResult>;
    readonly reconcile?: () => Promise<ProviderReconciliationResult>;
  } = {},
): EffectAdapter<FakeAction> & { readonly calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    id: "synthetic-fake-adapter",
    version: "0.1.0",
    actionTypes: ["fake.test.action"],
    prepare: () => {
      calls.push("prepare");
      return prepared;
    },
    execute: async (execution) => {
      calls.push("execute");
      return await (script.execute?.(execution) ?? Promise.resolve(answer()));
    },
    observeEffect: (result) => {
      calls.push("observe");
      return result.observed;
    },
    reconcile: async () => {
      calls.push("reconcile");
      return await (script.reconcile?.() ?? Promise.resolve({ status: "UNKNOWN" }));
    },
  };
}

const authorization = Object.freeze({
  decisionId: "synthetic-decision-1",
  dossierId: "synthetic-dossier-1",
  grantId: "synthetic-grant-1",
  intentHash: "sha256:".padEnd(71, "a"),
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
});

function captured(): CapturedIntent {
  const hasher = new CanonicalIntentHasher();
  return hasher.capture({
    version: "agent-safe.intent/1",
    intentId: "11111111-1111-4111-8111-111111111111",
    tenantId: "00000000-0000-4000-8000-000000000007",
    capturedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    actor: { id: "synthetic-treasury-agent", type: "AI_AGENT" },
    action: "fake.test.action",
    target: "fixture_resource_1",
    parameters: { amount: "10.00" },
    downstreamTarget: { system: "fake", operation: "test", environment: "local" },
    context: {},
    idempotencyKey: "synthetic-key-7",
  });
}

function handlerFor(
  adapter: EffectAdapter<FakeAction>,
  register = new EffectEvidenceRegister(),
  onMismatch?: (fields: readonly string[]) => void,
) {
  return {
    register,
    handler: adapterActionHandler<FakeAction>({
      adapter,
      schema: z.strictObject({ amount: z.string() }),
      register,
      timeoutMs: 2_000,
      ...(onMismatch === undefined ? {} : { onMismatch }),
    }),
  };
}

const dispatch = (run: { count: number }) => ({
  idempotencyKey: "synthetic-key-7",
  run: async <T>(operation: (key: string) => Promise<T> | T): Promise<T> => {
    run.count += 1;
    return await operation("synthetic-key-7");
  },
  receipt: (): void => {},
});

async function execute(
  adapter: EffectAdapter<FakeAction>,
  register?: EffectEvidenceRegister,
  onMismatch?: (fields: readonly string[]) => void,
): Promise<{
  readonly result: unknown;
  readonly runs: number;
  readonly register: EffectEvidenceRegister;
  readonly error: unknown;
}> {
  const wired = handlerFor(adapter, register, onMismatch);
  const runs = { count: 0 };
  let result: unknown = null;
  let error: unknown = null;
  try {
    result = await wired.handler.execute({
      intent: captured(),
      parameters: { amount: "10.00" },
      authorization,
      dispatch: dispatch(runs),
    });
  } catch (thrown) {
    error = thrown;
  }
  return { result, runs: runs.count, register: wired.register, error };
}

describe("adapterActionHandler", () => {
  it("dispatches once, observes, and registers the evidence against this authorization", async () => {
    const adapter = fakeAdapter();
    const { result, runs, register } = await execute(adapter);
    expect(runs).toBe(1);
    expect(adapter.calls).toEqual(["prepare", "execute", "observe"]);
    expect(result).toMatchObject({
      outcome: "COMMITTED",
      confirmation: "CONFIRMED",
      comparison: "MATCH",
      observationMethod: "READ_AFTER_WRITE",
      providerReference: "fixture_provider_ref_9",
    });
    const registered = register.take(authorization);
    expect(registered?.comparison).toBe("MATCH");
    expect(register.take(authorization)).toBeNull();
  });

  it("cannot confirm an acknowledgement, whatever the provider called it", async () => {
    const adapter = fakeAdapter({
      execute: async () =>
        await Promise.resolve(
          answer({
            observed: null,
            observationMethod: "DOWNSTREAM_ACK",
            providerStatus: "ACCEPTED",
          }),
        ),
    });
    const { result } = await execute(adapter);
    expect(result).toMatchObject({ outcome: "COMMITTED", confirmation: "PENDING" });
    expect((result as { readonly observedEffectDigest: unknown }).observedEffectDigest).toBeNull();
  });

  it("throws a provider's own refusal, after registering what it observed", async () => {
    // A provider that was reached and said no is a fact. Returning here
    // would tell the pipeline the side effect happened, so the refusal is
    // thrown — and the evidence is registered first, because the authority
    // still has to learn what was observed.
    const adapter = fakeAdapter({
      execute: async () =>
        await Promise.resolve(
          answer({ status: "FAILED", observed: null, failureReason: "POLICY_STATE_CHANGED" }),
        ),
    });
    const { result, register, error } = await execute(adapter);
    expect(result).toBeNull();
    expect(error).toBeInstanceOf(ProviderRefusal);
    expect((error as ProviderRefusal).reason).toBe("POLICY_STATE_CHANGED");
    const registered = register.take(authorization);
    expect(registered?.outcome).toBe("FAILED");
    expect(registered?.confirmation).toBe("NOT_EFFECTED");
  });

  it("names the refusal PROVIDER_REFUSED when the provider gave no reason of its own", async () => {
    const adapter = fakeAdapter({
      execute: async () =>
        await Promise.resolve(answer({ status: "FAILED", observed: null, failureReason: null })),
    });
    const { error } = await execute(adapter);
    expect((error as ProviderRefusal).reason).toBe("PROVIDER_REFUSED");
  });

  it("names a mismatch, tells the watcher its fields, and never confirms it", async () => {
    const seen: string[][] = [];
    const adapter = fakeAdapter({
      execute: async () =>
        await Promise.resolve(answer({ observed: { ...expectedEffect, amount: "99.00" } })),
    });
    const { result } = await execute(adapter, undefined, (fields) => seen.push([...fields]));
    expect(seen).toEqual([["amount"]]);
    expect(result).toMatchObject({ comparison: "MISMATCH", confirmation: "UNKNOWN" });
    expect((result as { readonly reasonCodes: string[] }).reasonCodes).toContain("EFFECT_MISMATCH");
  });

  it("re-raises an indeterminate outcome after registering what it knows", async () => {
    const adapter = fakeAdapter({
      execute: () => Promise.reject(new IndeterminateOutcome("PROVIDER_UNREACHABLE", "504")),
    });
    const { error, register, runs } = await execute(adapter);
    expect(runs).toBe(1);
    expect(error).toBeInstanceOf(IndeterminateOutcome);
    expect((error as IndeterminateOutcome).providerStatus).toBe("504");
    expect(register.take(authorization)?.outcome).toBe("INDETERMINATE");
  });

  it("lets an error that is not an indeterminate outcome through untouched", async () => {
    const adapter = fakeAdapter({ execute: () => Promise.reject(new Error("BOOM")) });
    const { error, register } = await execute(adapter);
    expect((error as Error).message).toBe("BOOM");
    expect(register.take(authorization)).toBeNull();
  });

  it("reconciles only into a matching read-back, and never dispatches", async () => {
    const matching = fakeAdapter({
      reconcile: async () => await Promise.resolve({ status: "COMPLETED", result: answer() }),
    });
    const wired = handlerFor(matching);
    const completed = await wired.handler.reconcile?.({
      intent: captured(),
      parameters: { amount: "10.00" },
      idempotencyKey: "synthetic-key-7",
    });
    expect(completed?.status).toBe("COMPLETED");
    expect(matching.calls).not.toContain("execute");

    const differing = fakeAdapter({
      reconcile: async () =>
        await Promise.resolve({
          status: "COMPLETED",
          result: answer({ observed: { ...expectedEffect, amount: "1.00" } }),
        }),
    });
    const second = handlerFor(differing).handler;
    expect(
      (
        await second.reconcile?.({
          intent: captured(),
          parameters: { amount: "10.00" },
          idempotencyKey: "synthetic-key-7",
        })
      )?.status,
    ).toBe("UNKNOWN");

    const missing = fakeAdapter({
      reconcile: async () => await Promise.resolve({ status: "NOT_EXECUTED" }),
    });
    expect(
      (
        await handlerFor(missing).handler.reconcile?.({
          intent: captured(),
          parameters: { amount: "10.00" },
          idempotencyKey: "synthetic-key-7",
        })
      )?.status,
    ).toBe("NOT_EXECUTED");
  });

  it("bounds the dispatch by the grant when the grant expires first", async () => {
    const budgets: number[] = [];
    const adapter = fakeAdapter({
      execute: async (execution) => {
        budgets.push(execution.deadline.remainingMs);
        return await Promise.resolve(answer());
      },
    });
    const wired = handlerFor(adapter);
    const runs = { count: 0 };
    await wired.handler.execute({
      intent: captured(),
      parameters: { amount: "10.00" },
      authorization: { ...authorization, expiresAt: new Date(Date.now() + 300).toISOString() },
      dispatch: dispatch(runs),
    });
    expect(budgets[0]).toBeLessThanOrEqual(300);
  });

  it("passes the adapter's own clock through to the record", async () => {
    const register = new EffectEvidenceRegister();
    const clock = vi.fn(() => new Date("2026-03-02T10:00:00.000Z"));
    const handler = adapterActionHandler<FakeAction>({
      adapter: fakeAdapter(),
      schema: z.strictObject({ amount: z.string() }),
      register,
      timeoutMs: 1_000,
      clock,
    });
    await handler.execute({
      intent: captured(),
      parameters: { amount: "10.00" },
      authorization,
      dispatch: dispatch({ count: 0 }),
    });
    expect(register.take(authorization)?.evidence["observed_at"]).toBe("2026-03-02T10:00:00.000Z");
  });
});

describe("effectBlock", () => {
  it("is the wire shape of an adapter result, and null for anything else", () => {
    expect(effectBlock(null)).toBeNull();
    expect(effectBlock(42)).toBeNull();
    expect(effectBlock({ outcome: "COMMITTED" })).toBeNull();
    const block = effectBlock({
      outcome: "COMMITTED",
      confirmation: "CONFIRMED",
      comparison: "MATCH",
      mismatchedFields: [],
      observationMethod: "READ_AFTER_WRITE",
      expectedEffectDigest: "sha256:a",
      observedEffectDigest: "sha256:a",
      responseDigest: "sha256:b",
      providerReference: "fixture_provider_ref_9",
      evidenceDigest: "sha256:c",
      reasonCodes: ["EFFECT_MISMATCH"],
    });
    expect(block).toEqual({
      outcome: "COMMITTED",
      confirmation: "CONFIRMED",
      comparison: "MATCH",
      mismatched_fields: [],
      observation_method: "READ_AFTER_WRITE",
      expected_effect_digest: "sha256:a",
      observed_effect_digest: "sha256:a",
      response_digest: "sha256:b",
      provider_reference: "fixture_provider_ref_9",
      evidence_digest: "sha256:c",
      reason_codes: ["EFFECT_MISMATCH"],
    });
  });

  it("fills the shape even when a result carries only its digest", () => {
    expect(effectBlock({ evidenceDigest: "sha256:c" })).toEqual({
      outcome: null,
      confirmation: null,
      comparison: null,
      mismatched_fields: [],
      observation_method: null,
      expected_effect_digest: null,
      observed_effect_digest: null,
      response_digest: null,
      provider_reference: null,
      evidence_digest: "sha256:c",
      reason_codes: [],
    });
  });
});
