import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { jcsDigest } from "../../../src/adapters/JcsDigest.js";
import {
  BASE_PROJECTION,
  expectedEffect,
  ProjectionError,
  projectionValue,
  PROJECTION_PROFILE,
  registeredAction,
  REGISTERED_ACTIONS,
} from "../../../src/adapters/banking/EffectProjections.js";
import {
  EFFECT_REASON_CODES,
  EXECUTION_REASON_CODES,
  isBankingReasonCode,
  REASON_CODE_CATEGORIES,
} from "../../../src/adapters/banking/ReasonCodes.js";
import {
  confirmationFor,
  EFFECT_EVIDENCE_PROFILE,
} from "../../../src/adapters/EffectEvidenceBuilder.js";
import { BEAP_PROFILE } from "../../../src/adapters/banking/BankingAction.js";
import { bankingAction, paymentAction } from "../../support/BankingFixtures.js";
import { repositoryPath } from "../../support/RepositoryRoot.js";

/** The same object with every key order reversed, at every depth. */
function reverseKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseKeys);
  if (typeof value !== "object" || value === null) return value;
  const reversed: Record<string, unknown> = {};
  for (const key of Object.keys(value).reverse()) {
    reversed[key] = reverseKeys((value as Record<string, unknown>)[key]);
  }
  return reversed;
}

const registryPath = (name: string): string =>
  repositoryPath("profiles", "beap", "v1.0", "registries", name);

const code = (work: () => unknown): string => {
  try {
    work();
  } catch (error) {
    return error instanceof ProjectionError ? error.code : `unexpected ${String(error)}`;
  }
  return "no refusal";
};

function registry(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(registryPath(name), "utf8")) as Record<string, unknown>;
}

describe("the profile identifier this build emits", () => {
  it("is one value, named by the family and by the generic evidence builder alike, and is the mirrored version", () => {
    expect(BEAP_PROFILE).toBe("decionis.beap/v1.0");
    expect(EFFECT_EVIDENCE_PROFILE).toBe(BEAP_PROFILE);
    expect(PROJECTION_PROFILE).toBe(BEAP_PROFILE);
    expect(existsSync(repositoryPath("profiles", "beap", "v1.0", "beap-v1.0.md"))).toBe(true);
  });
});

describe("the profile registries this build mirrors", () => {
  it("are the files the profile's own manifest attests", () => {
    const manifest = readFileSync(registryPath("MANIFEST.sha256"), "utf8")
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => line.trim().split(/\s+/) as [string, string]);
    expect(manifest.length).toBeGreaterThanOrEqual(6);
    for (const [digest, name] of manifest) {
      const actual = createHash("sha256")
        .update(readFileSync(registryPath(name)))
        .digest("hex");
      expect(actual, name).toBe(digest);
    }
  });

  it("agree with every action type this build claims to implement", () => {
    const actionTypes = registry("action-types.json");
    expect(actionTypes["profile"]).toBe(PROJECTION_PROFILE);
    expect(actionTypes["base_projection"]).toEqual([...BASE_PROJECTION]);
    const entries = actionTypes["entries"] as {
      readonly domain: string;
      readonly type: string;
      readonly effect_type: string;
      readonly projection: readonly string[];
    }[];
    for (const mirrored of REGISTERED_ACTIONS) {
      const entry = entries.find(
        (candidate) => candidate.domain === mirrored.domain && candidate.type === mirrored.type,
      );
      expect(entry, `${mirrored.domain}/${mirrored.type}`).toBeDefined();
      expect(entry?.effect_type).toBe(mirrored.effectType);
      expect(entry?.projection).toEqual([...mirrored.projection]);
    }
  });

  it("agree with every reason code this build names", () => {
    const entries = registry("reason-codes.json")["entries"] as {
      readonly id: string;
      readonly category: string;
    }[];
    for (const reason of [...EXECUTION_REASON_CODES, ...EFFECT_REASON_CODES]) {
      const entry = entries.find((candidate) => candidate.id === reason);
      expect(entry, reason).toBeDefined();
      expect(entry?.category).toBe(REASON_CODE_CATEGORIES.get(reason));
    }
    expect(isBankingReasonCode("POLICY_STATE_CHANGED")).toBe(true);
    expect(isBankingReasonCode("PROVIDER_WAS_RUDE")).toBe(false);
  });

  it("decide which observation method may confirm, and this build agrees with them", () => {
    const methods = registry("observation-methods.json")["entries"] as {
      readonly id: string;
      readonly sufficient_for_confirmed: boolean;
    }[];
    for (const method of ["DOWNSTREAM_ACK", "READ_AFTER_WRITE", "STATE_RECONCILIATION"]) {
      expect(
        methods.map((entry) => entry.id),
        method,
      ).toContain(method);
    }
    // The registry's own flag is the rule `confirmationFor` implements: a
    // matching observation confirms only through a method the profile says
    // is sufficient for it.
    for (const method of methods) {
      expect(confirmationFor("COMMITTED", "MATCH", method.id), method.id).toBe(
        method.sufficient_for_confirmed ? "CONFIRMED" : "PENDING",
      );
    }
  });

  it("name every confirmation state the evidence can carry", () => {
    const states = (
      registry("confirmation-states.json")["entries"] as { readonly id: string }[]
    ).map((entry) => entry.id);
    for (const state of ["PENDING", "CONFIRMED", "NOT_EFFECTED", "REVERSED", "UNKNOWN"]) {
      expect(states, state).toContain(state);
    }
  });
});

describe("expectedEffect", () => {
  it("is the registry's fields, read from the action, in the registry's order", () => {
    expect(expectedEffect(bankingAction())).toEqual({
      effect_type: "LOAN_DISBURSEMENT",
      domain: "LOAN_DISBURSEMENT",
      action: "DISBURSE_LOAN",
      target: "LOAN:fixture_loan_84721",
      subject: "CUSTOMER:fixture_customer_28491",
      amount: "250000.00",
      currency: "CHF",
      destination_ref: "fixture_account_1921",
    });
    expect(Object.keys(expectedEffect(paymentAction()))).toEqual([
      "effect_type",
      "domain",
      "action",
      "target",
      "amount",
      "currency",
      "source_ref",
      "destination_ref",
      "parameters.value_date",
      "parameters.rail",
    ]);
  });

  it("digests the same whatever order the action's keys arrived in", () => {
    const action = paymentAction();
    expect(jcsDigest(expectedEffect(reverseKeys(action) as typeof action))).toBe(
      jcsDigest(expectedEffect(action)),
    );
  });

  it("changes when the amount, the destination, or the rail changes", () => {
    const base = jcsDigest(expectedEffect(paymentAction()));
    const louder = paymentAction({ financial_context: { amount: "1250.01", currency: "EUR" } });
    expect(jcsDigest(expectedEffect(louder))).not.toBe(base);
    const elsewhere = paymentAction({
      requested_effect: {
        operation: "TRANSFER",
        source_ref: "fixture_account_5150",
        destination_ref: "fixture_account_9999",
        parameters: { value_date: "2026-03-02", rail: "SEPA_CT" },
      },
    });
    expect(jcsDigest(expectedEffect(elsewhere))).not.toBe(base);
    const faster = paymentAction({
      requested_effect: {
        operation: "TRANSFER",
        source_ref: "fixture_account_5150",
        destination_ref: "fixture_account_7788",
        parameters: { value_date: "2026-03-02", rail: "SEPA_INST" },
      },
    });
    expect(jcsDigest(expectedEffect(faster))).not.toBe(base);
  });

  it("refuses an action the profile does not register, and a projection with a hole in it", () => {
    expect(code(() => registeredAction("LOAN_DISBURSEMENT", "FORGIVE_LOAN"))).toBe(
      "ACTION_NOT_REGISTERED_IN_PROFILE",
    );
    expect(code(() => expectedEffect(bankingAction({ domain: "NOT_A_DOMAIN" })))).toBe(
      "ACTION_NOT_REGISTERED_IN_PROFILE",
    );
    expect(code(() => expectedEffect(bankingAction({ financial_context: undefined })))).toBe(
      "PROJECTION_FIELD_MISSING",
    );
    expect(code(() => expectedEffect(bankingAction({ subject: undefined })))).toBe(
      "PROJECTION_FIELD_MISSING",
    );
    expect(
      code(() => expectedEffect(bankingAction({ requested_effect: { operation: "DISBURSE" } }))),
    ).toBe("PROJECTION_FIELD_MISSING");
    expect(code(() => projectionValue(paymentAction(), "parameters.absent"))).toBe(
      "PROJECTION_FIELD_MISSING",
    );
    expect(code(() => projectionValue(paymentAction(), "batch.item_count"))).toBe(
      "PROJECTION_FIELD_MISSING",
    );
    expect(code(() => projectionValue(paymentAction(), "invented"))).toBe(
      "PROJECTION_FIELD_MISSING",
    );
  });

  it("reads a batch field from the batch block when there is one", () => {
    const release = paymentAction({
      batch: {
        manifest_digest: `sha256:${"a".repeat(64)}`,
        item_count: 3,
        source_file_digest: `sha256:${"b".repeat(64)}`,
      },
    });
    expect(projectionValue(release, "batch.item_count")).toBe(3);
    expect(projectionValue(release, "batch.manifest_digest")).toBe(`sha256:${"a".repeat(64)}`);
  });
});
