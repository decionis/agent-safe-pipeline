import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  BankingActionSchema,
  BankingActionWireSchema,
  BEAP_PROFILE,
  isBankingActionName,
  transportActionName,
  transportTarget,
} from "../../../src/adapters/banking/BankingAction.js";
import { bankingAction, paymentAction } from "../../support/BankingFixtures.js";
import { repositoryPath } from "../../support/RepositoryRoot.js";

const example = (name: string): unknown =>
  JSON.parse(readFileSync(repositoryPath("profiles", "beap", "v1.0", "examples", name), "utf8"));

describe("BankingActionSchema", () => {
  it("parses the profile's own action examples unchanged", () => {
    for (const name of [
      "banking-action.loan-disbursement.json",
      "banking-action.payment-batch-release.json",
    ]) {
      const parsed = BankingActionWireSchema.safeParse(example(name));
      expect(parsed.success, `${name}: ${JSON.stringify(parsed.error?.issues ?? [])}`).toBe(true);
      expect(parsed.data?.profile).toBe(BEAP_PROFILE);
    }
  });

  it("refuses a key the profile does not define", () => {
    const extra = { ...bankingAction(), surprise: true };
    expect(BankingActionWireSchema.safeParse(extra).success).toBe(false);
  });

  it("refuses a JSON number as an amount, so no float reaches the canonicaliser", () => {
    const numeric = bankingAction({
      financial_context: { amount: 250_000 as unknown as string, currency: "CHF" },
    });
    expect(BankingActionSchema.safeParse(numeric).success).toBe(false);
    for (const amount of ["1e3", "-1.00", "-0", "01.00", "1,00", ".50"]) {
      const action = bankingAction({ financial_context: { amount, currency: "CHF" } });
      expect(BankingActionSchema.safeParse(action).success, amount).toBe(false);
    }
  });

  it("refuses a non-scalar effect parameter and a parameter name the profile does not allow", () => {
    const nested = paymentAction({
      requested_effect: {
        operation: "TRANSFER",
        source_ref: "fixture_account_5150",
        destination_ref: "fixture_account_7788",
        parameters: { rail: { deep: true } as unknown as string },
      },
    });
    expect(BankingActionSchema.safeParse(nested).success).toBe(false);
    const shouting = paymentAction({
      requested_effect: {
        operation: "TRANSFER",
        parameters: { RAIL: "SEPA_CT" },
      },
    });
    expect(BankingActionSchema.safeParse(shouting).success).toBe(false);
  });

  it("refuses an identifier that is not the profile's shape, and a foreign profile", () => {
    expect(BankingActionSchema.safeParse(bankingAction({ domain: "lower_case" })).success).toBe(
      false,
    );
    expect(
      BankingActionSchema.safeParse(bankingAction({ profile: "other/v9" as never })).success,
    ).toBe(false);
    expect(
      BankingActionSchema.safeParse(
        bankingAction({ action: { type: "DISBURSE_LOAN", request_id: "" } }),
      ).success,
    ).toBe(false);
  });

  it("applies the profile's conditional rule for a batch release", () => {
    const release = bankingAction({
      domain: "CORPORATE_PAYMENTS",
      action: { type: "RELEASE_PAYMENT_BATCH", request_id: "synthetic-req-0003" },
      subject: undefined,
      financial_context: undefined,
      requested_effect: { operation: "RELEASE" },
    });
    const issues = BankingActionWireSchema.safeParse(release).error?.issues ?? [];
    expect(issues.map((issue) => issue.path.join("."))).toEqual(["batch", "financial_context"]);
  });

  it("derives the transport name and target from the action, per Appendix B.5", () => {
    const action = bankingAction();
    expect(transportActionName(action)).toBe("beap.loan_disbursement.disburse_loan");
    expect(transportTarget(action)).toBe("loan:fixture_loan_84721");
    expect(transportActionName(paymentAction())).toBe("beap.corporate_payments.send_payment");
    expect(isBankingActionName("beap.loan_disbursement.disburse_loan")).toBe(true);
    expect(isBankingActionName("forward_request")).toBe(false);
    // The prefix includes the dot, so a name that merely starts with the
    // letters is not in the family.
    expect(isBankingActionName("beapish.thing")).toBe(false);
    expect(isBankingActionName("beap.")).toBe(true);
  });
});
