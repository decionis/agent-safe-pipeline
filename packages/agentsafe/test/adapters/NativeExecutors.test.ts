import {
  createFixtureAuthorityPair,
  GovernedExecutionRunner,
  IndeterminateOutcome,
  type AuthorizationVerifier,
  type ExecutorScope,
  type PreparedAction,
} from "@decionis/agent-safe-pipeline";
import { describe, expect, it, vi } from "vitest";
import { describeByEffect } from "../../src/adapters/AdapterActionHandler.js";
import type { ProviderResult } from "../../src/adapters/EffectAdapter.js";
import { EffectAdapterExecutor } from "../../src/adapters/EffectAdapterExecutor.js";
import {
  BankingAdapter,
  type BankingTransport,
} from "../../src/adapters/banking/BankingAdapter.js";
import {
  BankingExecutor,
  CORE_BANKING_PLATFORM,
  describeBankingAction,
} from "../../src/adapters/banking/BankingExecutor.js";
import {
  CARD_ISSUER_PLATFORM,
  CardAuthorizationExecutor,
} from "../../src/adapters/cards/CardAuthorizationExecutor.js";
import { prepareCardPurchase } from "../../src/adapters/cards/CardEffect.js";
import { bankingAction, observedEffect } from "../support/BankingFixtures.js";
import { TENANT_ID } from "../support/Environment.js";

const SCOPE: ExecutorScope = {
  orgId: TENANT_ID,
  workspaceId: "fixture-workspace",
  connectionId: "fixture-connection",
  connectionRevision: "1",
  environment: "sandbox",
};
const ACTOR = { id: "synthetic-treasury-agent", type: "AGENT" };

function committed(observed: Record<string, unknown> | null): ProviderResult {
  return {
    status: "COMMITTED",
    providerStatus: "201",
    providerReference: "fixture_txn_1",
    responseDigest: null,
    failureReason: null,
    observed: observed as ProviderResult["observed"],
    observationMethod: "READ_AFTER_WRITE",
    providerGenerated: true,
    source: "CORE_BANKING_RESPONSE",
  };
}

function runnerWith(finalize?: AuthorizationVerifier["finalize"]) {
  const pair = createFixtureAuthorityPair(() => "ALLOW", { unsafeAllowDevelopmentFixture: true });
  const verifier: AuthorizationVerifier = {
    verifyAndConsume: async (captured, decision) =>
      await pair.verifier.verifyAndConsume(captured, decision),
    finalize: finalize ?? (async (input) => await pair.verifier.finalize(input)),
  };
  return {
    runner: new GovernedExecutionRunner({ verifier, authority: pair.authority }),
    ledger: pair.verifier,
  };
}

function bankingExecutor(transport: Partial<BankingTransport>): BankingExecutor {
  return new BankingExecutor({
    adapter: new BankingAdapter({
      id: "synthetic-core-banking",
      version: "0.1.0",
      transport: {
        execute: transport.execute ?? (() => Promise.reject(new Error("unused"))),
        reconcile: transport.reconcile ?? (() => Promise.resolve({ status: "UNKNOWN" })),
      },
    }),
  });
}

describe("the banking family as a dispatch-style native executor", () => {
  it("describes a BEAP action as an intent the runner can capture and decide", async () => {
    const executor = bankingExecutor({});
    expect(executor).toMatchObject({ platform: CORE_BANKING_PLATFORM, style: "dispatch" });
    expect(executor.actionTypes).toContain("beap.loan_disbursement.disburse_loan");
    const prepared = await executor.prepare(bankingAction());
    expect(prepared).toMatchObject({
      actionType: "beap.loan_disbursement.disburse_loan",
      proposal: {
        action: "beap.loan_disbursement.disburse_loan",
        target: "loan:fixture_loan_84721",
      },
      downstreamTarget: {
        system: "SYNTHETIC_CORE",
        operation: "LOAN_DISBURSEMENT",
        environment: "LOCAL",
      },
      idempotencyKey: "synthetic-req-0001",
      facts: {
        beap: {
          domain: "LOAN_DISBURSEMENT",
          action_type: "DISBURSE_LOAN",
          effect_type: "LOAN_DISBURSEMENT",
        },
      },
    });
    const long = bankingAction({
      action: { type: "DISBURSE_LOAN", request_id: `synthetic-${"r".repeat(400)}` },
    });
    const adapter = new BankingAdapter({
      id: "x",
      version: "1",
      transport: {} as BankingTransport,
    });
    expect(describeBankingAction(long, adapter.prepare(long)).idempotencyKey).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    const noEnvironment = bankingAction({
      downstream: { provider: "SYNTHETIC_CORE", operation: "LOAN_DISBURSEMENT" },
    });
    expect(
      describeBankingAction(noEnvironment, adapter.prepare(noEnvironment)).downstreamTarget,
    ).toEqual({ system: "SYNTHETIC_CORE", operation: "LOAN_DISBURSEMENT" });
    expect(await executor.capabilities(SCOPE)).toHaveLength(executor.actionTypes.length);
  });

  it("commits through the runner, and hands the authority the observation it made", async () => {
    const finalize = vi.fn(async () => "RECORDED" as const);
    const { runner } = runnerWith(finalize);
    const executor = bankingExecutor({
      execute: async (execution) => committed(observedEffect(execution.prepared)),
    });
    const { result } = await runner.submit(executor, {
      action: bankingAction(),
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(result).toMatchObject({ outcome: "COMPLETED", executed: true });
    if (result.outcome !== "COMPLETED") throw new Error("unreachable");
    expect(result.result).toMatchObject({ record: { comparison: "MATCH", outcome: "COMMITTED" } });
    expect(finalize).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "COMMITTED",
        effectEvidence: expect.objectContaining({
          version: "1.0",
          observation_method: "READ_AFTER_WRITE",
        }),
      }),
    );
  });

  it("reports a refusal as a refusal, and a lost answer as unknown until a matching read-back", async () => {
    const refused = runnerWith();
    const refusing = bankingExecutor({
      execute: async () => ({
        ...committed(null),
        status: "FAILED",
        failureReason: "INSUFFICIENT_FUNDS",
      }),
    });
    expect(
      (
        await refused.runner.submit(refusing, {
          action: bankingAction(),
          scope: SCOPE,
          actor: ACTOR,
        })
      ).result,
    ).toMatchObject({ outcome: "DEFINITELY_NOT_EXECUTED", reason: "INSUFFICIENT_FUNDS" });

    const lost = runnerWith();
    let readBack: Record<string, unknown> = {};
    const executor = bankingExecutor({
      execute: async (execution) => {
        readBack = observedEffect(execution.prepared);
        throw new IndeterminateOutcome("UPSTREAM_TIMEOUT", null, "h.p.s");
      },
      reconcile: async () => ({ status: "COMPLETED", result: committed(readBack) }),
    });
    const { captured, result } = await lost.runner.submit(executor, {
      action: bankingAction(),
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(result.outcome).toBe("UNKNOWN_AFTER_DISPATCH");
    if (result.outcome !== "UNKNOWN_AFTER_DISPATCH") throw new Error("unreachable");
    expect(
      await lost.runner.reconcile(executor, {
        captured,
        recovery: result.recovery,
        action: bankingAction(),
      }),
    ).toMatchObject({ outcome: "COMPLETED", executed: true });
    readBack = { amount: "1.00" };
    expect(
      await lost.runner.reconcile(executor, {
        captured,
        recovery: result.recovery,
        action: bankingAction(),
      }),
    ).toMatchObject({ outcome: "UNKNOWN_AFTER_DISPATCH" });
  });
});

describe("an effect adapter with no description of its own", () => {
  it("reads as its effect, and prepares again for an action it did not prepare", async () => {
    const adapter = new BankingAdapter({
      id: "synthetic-core-banking",
      version: "0.1.0",
      transport: {
        execute: () => Promise.reject(new Error("unused")),
        reconcile: () => Promise.resolve({ status: "NOT_EXECUTED" }),
      },
    });
    const executor = new EffectAdapterExecutor({
      adapter,
      platform: "custom",
      describe: describeByEffect,
      capabilities: async () => [],
    });
    const action = bankingAction();
    const prepared = await executor.prepare(action);
    expect(prepared.proposal.action).toBe("disburse_loan");
    expect(prepared.downstreamTarget).toEqual({
      system: "loan_disbursement",
      operation: "LOAN_DISBURSEMENT",
    });
    expect(await executor.capabilities(SCOPE)).toEqual([]);
    expect(await executor.observe({ kind: "NOT_DISPATCHED" })).toMatchObject({
      status: "INDETERMINATE",
    });
    const foreign: PreparedAction = { ...prepared };
    const answer = await executor.reconcile({
      intent: { intentHash: `sha256:${"0".repeat(64)}`, intent: { intentId: "i" } } as never,
      prepared: foreign,
      idempotencyKey: "synthetic-req-0001",
      scope: null,
      providerReference: null,
    });
    expect(answer).toEqual({ status: "NOT_EXECUTED" });
  });
});

describe("the cards family as a permit-style native executor", () => {
  const purchase = {
    cardTokenRef: "fixture_card_ref_0042",
    amountMinor: 4_250,
    currency: "EUR",
    merchantId: "fixture_merchant_17",
  };
  const request = {
    authorization_id: "fixture_auth_1",
    card_token_ref: "fixture_card_ref_0042",
    amount_minor: 4_000,
    currency: "EUR",
    merchant_id: "fixture_merchant_17",
  };
  const executor = new CardAuthorizationExecutor({
    observer: { id: "synthetic-core-banking", version: "0.1.0" },
  });

  it("holds the grant with a permit, claims it once the issuer asks, and settles from its result", async () => {
    const { runner, ledger } = runnerWith();
    expect(executor).toMatchObject({ platform: CARD_ISSUER_PLATFORM, style: "permit" });
    expect(await executor.capabilities()).toEqual([
      expect.objectContaining({ actionType: "card.purchase", enabled: true }),
    ]);
    const { captured, result } = await runner.submit(executor, {
      action: purchase,
      scope: SCOPE,
      actor: ACTOR,
    });
    if (result.outcome !== "HELD" || !("permit" in result)) throw new Error("not held");
    expect(captured.intent.idempotencyKey).toMatch(/^card-purchase:sha256:/);
    const presented = await runner.present(result.held);
    expect(presented).toMatchObject({
      outcome: "CLAIMED",
      permit: { permitId: result.permit.permitId, intentHash: captured.intentHash },
    });
    const receipt = (status: "APPROVED" | "DECLINED", leaseExpired = false) => ({
      receipt: {
        purchase,
        prepared: prepareCardPurchase(purchase),
        request,
        result: { status },
        leaseExpired,
        correlationId: captured.intent.intentId,
        idempotencyKey: captured.intent.idempotencyKey,
      },
    });
    const settled = await runner.settle(result.held, receipt("APPROVED"));
    expect(settled).toMatchObject({ status: "SETTLED", outcome: "COMPLETED" });
    expect(ledger.ledger()[0]?.outcome).toBe("COMMITTED");

    const declined = await executor.observe({ kind: "RECEIPT", ...receipt("DECLINED") });
    expect(declined).toMatchObject({ status: "FAILED", reason: "ISSUER_DECLINED" });
    const late = await executor.observe({ kind: "RECEIPT", ...receipt("APPROVED", true) });
    expect(late.status).toBe("INDETERMINATE");
    expect(await executor.observe({ kind: "NOT_DISPATCHED" })).toMatchObject({
      status: "INDETERMINATE",
    });
    expect(await executor.reconcile()).toEqual({ status: "UNKNOWN" });
  });
});
