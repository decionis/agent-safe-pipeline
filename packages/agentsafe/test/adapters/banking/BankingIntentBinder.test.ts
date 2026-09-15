import { describe, expect, it } from "vitest";
import type { DownstreamConfig } from "../../../src/config/ExecutorConfig.js";
import { BankingAdapter } from "../../../src/adapters/banking/BankingAdapter.js";
import {
  bindBankingAction,
  BindingError,
  type BindingInput,
} from "../../../src/adapters/banking/BankingIntentBinder.js";
import {
  transportActionName,
  transportTarget,
  type BankingAction,
} from "../../../src/adapters/banking/BankingAction.js";
import { bankingAction, FIXTURE_ACTOR_ID } from "../../support/BankingFixtures.js";

const downstream = {
  system: "synthetic_core",
  operation: "loan_disbursement",
  environment: "local",
} as DownstreamConfig;

const adapter = new BankingAdapter({
  id: "synthetic-core-banking",
  version: "0.1.0",
  transport: {
    execute: () => Promise.reject(new Error("prepare only")),
    reconcile: () => Promise.reject(new Error("prepare only")),
  },
});

const digests = (action: BankingAction) => {
  const prepared = adapter.prepare(action);
  return {
    intentDigest: prepared.intentDigest,
    expectedEffectDigest: prepared.expectedEffectDigest,
  };
};

/** The binding input for an action, with the transport fields derived from it. */
function forAction(action: BankingAction, overrides: Partial<BindingInput> = {}): BindingInput {
  return {
    action: transportActionName(action),
    target: transportTarget(action),
    parameters: action as never,
    idempotencyKey: action.action.request_id,
    downstream,
    actor: { id: FIXTURE_ACTOR_ID, type: "AI_AGENT" },
    ...overrides,
  };
}

function input(overrides: Partial<BindingInput> = {}): BindingInput {
  return forAction(bankingAction(), overrides);
}

const code = (work: () => unknown): string => {
  try {
    work();
  } catch (error) {
    return error instanceof BindingError ? error.code : `unexpected ${String(error)}`;
  }
  return "no refusal";
};

describe("bindBankingAction", () => {
  it("computes the trusted context from the action, not from the caller", () => {
    const bound = bindBankingAction(input(), digests);
    expect(bound.context).toEqual({
      beap_profile: "decionis.beap/v1.0",
      beap_intent_digest: bound.intentDigest,
      beap_expected_effect_digest: bound.expectedEffectDigest,
    });
    expect(bound.intentDigest).toBe(BankingAdapter.intentDigest(bankingAction()));
    expect(bound.action.action.type).toBe("DISBURSE_LOAN");
  });

  it("carries a batch manifest digest only when the action has one", () => {
    const release = bankingAction({
      batch: {
        manifest_digest: `sha256:${"a".repeat(64)}`,
        item_count: 4,
        source_file_digest: `sha256:${"b".repeat(64)}`,
      },
    });
    const bound = bindBankingAction(forAction(release), digests);
    expect(bound.context["beap_batch_manifest_digest"]).toBe(`sha256:${"a".repeat(64)}`);
  });

  it("refuses a transport name or target that disagrees with the action", () => {
    expect(code(() => bindBankingAction(input({ action: "beap.other.thing" }), digests))).toBe(
      "BANKING_ACTION_NAME_MISMATCH",
    );
    expect(code(() => bindBankingAction(input({ target: "loan:fixture_loan_1" }), digests))).toBe(
      "BANKING_TARGET_MISMATCH",
    );
  });

  it("refuses a request id that is not the key the attempt is bound to", () => {
    expect(
      code(() => bindBankingAction(input({ idempotencyKey: "synthetic-other" }), digests)),
    ).toBe("BANKING_REQUEST_ID_MISMATCH");
  });

  it("refuses a downstream the caller named rather than the one this process serves", () => {
    for (const provider of ["OTHER_CORE", "SYNTHETIC_CORE_2"]) {
      const action = bankingAction({
        downstream: { provider, product: "LENDING", operation: "LOAN_DISBURSEMENT" },
      });
      expect(code(() => bindBankingAction(forAction(action), digests))).toBe(
        "BANKING_DOWNSTREAM_MISMATCH",
      );
    }
    const wrongOperation = bankingAction({
      downstream: { provider: "SYNTHETIC_CORE", operation: "CARD_ISSUANCE" },
    });
    expect(code(() => bindBankingAction(forAction(wrongOperation), digests))).toBe(
      "BANKING_DOWNSTREAM_MISMATCH",
    );
    const wrongEnvironment = bankingAction({
      downstream: {
        provider: "SYNTHETIC_CORE",
        operation: "LOAN_DISBURSEMENT",
        environment: "PRODUCTION",
      },
    });
    expect(code(() => bindBankingAction(forAction(wrongEnvironment), digests))).toBe(
      "BANKING_DOWNSTREAM_MISMATCH",
    );
  });

  it("accepts an action that names no environment at all", () => {
    const action = bankingAction({
      downstream: { provider: "SYNTHETIC_CORE", operation: "LOAN_DISBURSEMENT" },
    });
    expect(
      bindBankingAction(forAction(action), digests).action.downstream.environment,
    ).toBeUndefined();
  });

  it("refuses an actor that is not the principal the door authenticated", () => {
    expect(
      code(() =>
        bindBankingAction(
          input({ actor: { id: "synthetic-someone-else", type: "AI_AGENT" } }),
          digests,
        ),
      ),
    ).toBe("BANKING_ACTOR_MISMATCH");
  });

  it("refuses parameters that are not a canonical action at all", () => {
    for (const parameters of [{ amountMinor: 1 }, {}, { profile: "decionis.beap/v1.0" }]) {
      expect(code(() => bindBankingAction(input({ parameters }), digests))).toBe(
        "BANKING_ACTION_INVALID",
      );
    }
  });

  it("names its refusal, so a caller can tell it from another kind", () => {
    try {
      bindBankingAction(input({ action: "beap.other.thing" }), digests);
      throw new Error("expected a refusal");
    } catch (error) {
      expect(error).toBeInstanceOf(BindingError);
      expect((error as BindingError).name).toBe("BindingError");
      expect((error as BindingError).message).toBe("BANKING_ACTION_NAME_MISMATCH");
    }
  });

  it("asks for the digests only after every refusal has passed", () => {
    let asked = 0;
    const counting = (action: BankingAction) => {
      asked += 1;
      return digests(action);
    };
    expect(code(() => bindBankingAction(input({ action: "beap.other.thing" }), counting))).toBe(
      "BANKING_ACTION_NAME_MISMATCH",
    );
    expect(asked).toBe(0);
    bindBankingAction(input(), counting);
    expect(asked).toBe(1);
  });
});
