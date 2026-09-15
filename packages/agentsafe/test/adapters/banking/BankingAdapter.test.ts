import { describe, expect, it } from "vitest";
import { MonotonicDeadline } from "../../../src/time/MonotonicClock.js";
import { jcsDigest } from "../../../src/adapters/JcsDigest.js";
import type { ProviderResult } from "../../../src/adapters/EffectAdapter.js";
import {
  BankingActionError,
  BankingAdapter,
  registeredActionNames,
  type BankingTransport,
} from "../../../src/adapters/banking/BankingAdapter.js";
import { expectedEffect } from "../../../src/adapters/banking/EffectProjections.js";
import { bankingAction, paymentAction } from "../../support/BankingFixtures.js";

const refusing: BankingTransport = {
  execute: () => Promise.reject(new Error("the transport is not used by these tests")),
  reconcile: () => Promise.reject(new Error("the transport is not used by these tests")),
};

const adapter = new BankingAdapter({
  id: "synthetic-core-banking",
  version: "0.1.0",
  transport: refusing,
});

const code = (work: () => unknown): string => {
  try {
    work();
  } catch (error) {
    return error instanceof BankingActionError ? error.code : `unexpected ${String(error)}`;
  }
  return "no refusal";
};

describe("BankingAdapter.prepare", () => {
  it("is pure, and produces the digests the authority binds a grant to", () => {
    const action = bankingAction();
    const prepared = adapter.prepare(action);
    expect(prepared.expectedEffect).toEqual(expectedEffect(action));
    expect(prepared.expectedEffectDigest).toBe(jcsDigest(expectedEffect(action)));
    expect(prepared.intentDigest).toBe(BankingAdapter.intentDigest(action));
    expect(prepared.requestDigest).toBe(jcsDigest(action.requested_effect as never));
    expect(prepared.effectType).toBe("LOAN_DISBURSEMENT");
    expect(prepared.resourceRef).toBe("fixture_loan_84721");
    expect(prepared.domain).toBe("LOAN_DISBURSEMENT");
    expect(prepared.actionType).toBe("DISBURSE_LOAN");
  });

  it("keeps the intent digest and the expected-effect digest distinct", () => {
    const prepared = adapter.prepare(paymentAction());
    expect(prepared.intentDigest).not.toBe(prepared.expectedEffectDigest);
    expect(prepared.intentDigest).not.toBe(prepared.requestDigest);
  });

  it("reads the amount through Money, so a wrong scale is refused before anything is hashed", () => {
    expect(
      code(() =>
        adapter.prepare(
          bankingAction({ financial_context: { amount: "250000.0", currency: "CHF" } }),
        ),
      ),
    ).toBe("unexpected MoneyError: AMOUNT_SCALE_INVALID");
    expect(
      code(() =>
        adapter.prepare(
          bankingAction({ financial_context: { amount: "250000.00", currency: "XXX" } }),
        ),
      ),
    ).toBe("unexpected CurrencyError: CURRENCY_UNSUPPORTED");
  });

  it("refuses a foreign profile, an unregistered action, and a bad IBAN reference", () => {
    expect(code(() => adapter.prepare(bankingAction({ profile: "other/v9" as never })))).toBe(
      "BANKING_PROFILE_UNKNOWN",
    );
    expect(
      code(() =>
        adapter.prepare(
          bankingAction({ action: { type: "FORGIVE_LOAN", request_id: "synthetic-req-0009" } }),
        ),
      ),
    ).toBe(
      "unexpected ProjectionError: ACTION_NOT_REGISTERED_IN_PROFILE: LOAN_DISBURSEMENT/FORGIVE_LOAN",
    );
    expect(
      code(() =>
        adapter.prepare(
          bankingAction({
            requested_effect: {
              operation: "DISBURSE",
              destination_ref: "iban:GB82WEST12345698765433",
            },
          }),
        ),
      ),
    ).toBe("BANKING_REFERENCE_INVALID");
    expect(
      code(() =>
        adapter.prepare(
          bankingAction({ target: { type: "LOAN", ref: "iban:GB82WEST12345698765433" } }),
        ),
      ),
    ).toBe("BANKING_REFERENCE_INVALID");
  });

  it("accepts a valid IBAN reference wherever the profile allows one", () => {
    const prepared = adapter.prepare(
      bankingAction({
        requested_effect: { operation: "DISBURSE", destination_ref: "iban:GB82WEST12345698765432" },
      }),
    );
    expect(prepared.expectedEffect["destination_ref"]).toBe("iban:GB82WEST12345698765432");
  });
});

describe("BankingAdapter.observeEffect", () => {
  const prepared = adapter.prepare(bankingAction());

  const answer = (observed: Record<string, unknown> | null): ProviderResult => ({
    status: "COMMITTED",
    providerStatus: "POSTED",
    providerReference: "fixture_provider_ref_1",
    responseDigest: jcsDigest({ status: "POSTED" }),
    failureReason: null,
    observed: observed as never,
    observationMethod: "READ_AFTER_WRITE",
    providerGenerated: true,
    source: "CORE_BANKING_RESPONSE",
  });

  it("invents nothing for an acknowledgement", () => {
    expect(adapter.observeEffect(answer(null), prepared)).toBeNull();
  });

  it("keeps only the projection's own fields, so a provider cannot add one", () => {
    const observed = adapter.observeEffect(
      answer({ ...prepared.expectedEffect, settled_at: "later", amount: "250000.00" }),
      prepared,
    );
    expect(observed).toEqual(prepared.expectedEffect);
    expect(observed).not.toHaveProperty("settled_at");
  });

  it("leaves a field the provider did not return absent, so the comparison can see it", () => {
    const partial = { ...prepared.expectedEffect };
    delete partial["amount"];
    expect(adapter.observeEffect(answer(partial), prepared)).not.toHaveProperty("amount");
  });
});

describe("the adapter's registered names", () => {
  it("are the transport names of every action this build mirrors", () => {
    expect(adapter.actionTypes).toEqual(registeredActionNames());
    expect(adapter.actionTypes).toContain("beap.loan_disbursement.disburse_loan");
    expect(adapter.actionTypes).toContain("beap.corporate_payments.send_payment");
    expect(adapter.id).toBe("synthetic-core-banking");
    expect(adapter.version).toBe("0.1.0");
    for (const name of adapter.actionTypes) expect(name).toBe(name.toLowerCase());
  });
});

describe("the adapter's transport seam", () => {
  it("delegates execution and reconciliation without interpreting either", async () => {
    const calls: string[] = [];
    const delegating = new BankingAdapter({
      id: "synthetic-core-banking",
      version: "0.1.0",
      transport: {
        execute: async () => {
          calls.push("execute");
          return await Promise.resolve({
            status: "COMMITTED",
            providerStatus: "ACCEPTED",
            providerReference: null,
            responseDigest: null,
            failureReason: null,
            observed: null,
            observationMethod: "DOWNSTREAM_ACK",
            providerGenerated: true,
            source: "CORE_BANKING_RESPONSE",
          } satisfies ProviderResult);
        },
        reconcile: async () => {
          calls.push("reconcile");
          return await Promise.resolve({ status: "NOT_EXECUTED" as const });
        },
      },
    });
    const prepared = delegating.prepare(bankingAction());
    const result = await delegating.execute({
      action: bankingAction(),
      prepared,
      authorization: {
        decisionId: "synthetic-decision-1",
        dossierId: "synthetic-dossier-1",
        grantId: "synthetic-grant-1",
        intentHash: `sha256:${"a".repeat(64)}`,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
      idempotencyKey: "synthetic-key-1",
      deadline: MonotonicDeadline.after(1_000),
    });
    expect(result.providerStatus).toBe("ACCEPTED");
    expect(
      await delegating.reconcile({
        idempotencyKey: "synthetic-key-1",
        providerReference: null,
        intentHash: `sha256:${"a".repeat(64)}`,
        prepared,
      }),
    ).toEqual({ status: "NOT_EXECUTED" });
    expect(calls).toEqual(["execute", "reconcile"]);
  });
});
