import { describe, expect, it } from "vitest";
import {
  compareEffect,
  compareReceipt,
  receiptStatement,
} from "../../src/adapters/EffectComparison.js";

const expected = {
  effect_type: "LOAN_DISBURSEMENT",
  amount: "250000.00",
  currency: "CHF",
  destination_ref: "fixture_account_1921",
};

describe("compareEffect", () => {
  it("is PENDING when there is nothing to compare, which is not a match", () => {
    expect(compareEffect(expected, null)).toEqual({ comparison: "PENDING", mismatched: [] });
  });

  it("matches only when every projected field is the same value", () => {
    expect(compareEffect(expected, { ...expected })).toEqual({
      comparison: "MATCH",
      mismatched: [],
    });
    expect(compareEffect(expected, { ...expected, amount: "250000.01" })).toEqual({
      comparison: "MISMATCH",
      mismatched: ["amount"],
    });
    expect(
      compareEffect(expected, { ...expected, amount: "1.00", currency: "EUR" }).mismatched,
    ).toEqual(["amount", "currency"]);
  });

  it("cannot be matched by a provider that returned more, or hidden by one that returned less", () => {
    expect(compareEffect(expected, { ...expected, settled_at: "later" }).comparison).toBe("MATCH");
    const without = { ...expected };
    delete (without as Partial<typeof expected>).destination_ref;
    expect(compareEffect(expected, without).mismatched).toEqual(["destination_ref"]);
  });

  it("holds an array equal only to an array of the same values in the same order", () => {
    expect(compareEffect({ a: [1, 2] }, { a: [1, 2] }).comparison).toBe("MATCH");
    expect(compareEffect({ a: [1, 2] }, { a: [2, 1] }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: [1, 2] }, { a: [1, 9] }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: [1] }, { a: [1, 2] }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: [1, 2] }, { a: [1] }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: [] }, { a: [] }).comparison).toBe("MATCH");
  });

  it("does not let a provider's body pass by resembling the shape it is not", () => {
    // An object with the same indices is not the array, in either direction,
    // and neither is one that carries a `length`.
    expect(compareEffect({ a: [1] }, { a: { 0: 1 } }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: { 0: 1 } }, { a: [1] }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: [1] }, { a: { 0: 1, length: 1 } }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: { 0: 1, length: 1 } }, { a: [1] }).comparison).toBe("MISMATCH");
    // Nor is a string the object of its own characters.
    expect(compareEffect({ a: "x" }, { a: { 0: "x" } }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: { 0: "x" } }, { a: "x" }).comparison).toBe("MISMATCH");
  });

  it("holds null equal to null and to nothing else", () => {
    expect(compareEffect({ a: null }, { a: null }).comparison).toBe("MATCH");
    expect(compareEffect({ a: null }, { a: 0 }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: null }, { a: {} }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: {} }, { a: null }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: null }, { a: [] }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: [] }, { a: null }).comparison).toBe("MISMATCH");
  });

  it("compares values structurally, never by reference or by coercion", () => {
    expect(compareEffect({ a: [1, 2] }, { a: [1, 2] }).comparison).toBe("MATCH");
    expect(compareEffect({ a: [1, 2] }, { a: [2, 1] }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: [1, 2] }, { a: [1] }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: { b: 1 } }, { a: { b: 1 } }).comparison).toBe("MATCH");
    expect(compareEffect({ a: { b: 1 } }, { a: { b: 1, c: 2 } }).comparison).toBe("MISMATCH");
    // Same keys, one differing value: every key has to agree, not just one.
    expect(compareEffect({ a: { b: 1, c: 2 } }, { a: { b: 1, c: 9 } }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: { b: 1, c: 2 } }, { a: { b: 1, c: 2 } }).comparison).toBe("MATCH");
    expect(compareEffect({ a: { b: 1 } }, { a: [1] }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: 1 }, { a: "1" }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: 0 }, { a: false }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: null }, { a: null }).comparison).toBe("MATCH");
    expect(compareEffect({ a: null }, { a: 0 }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: 1 }, { a: null }).comparison).toBe("MISMATCH");
    expect(compareEffect({ a: { b: 1 } }, { a: null }).comparison).toBe("MISMATCH");
    expect(compareEffect({}, {}).comparison).toBe("MATCH");
  });
});

/** A receipt's shape with the payload given: three segments, the middle one base64url JSON. */
const receiptWith = (payload: unknown, header = '{"alg":"EdDSA"}', signature = "c2ln"): string =>
  `${Buffer.from(header).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${signature}`;
const DIGEST = `sha256:${"1".repeat(64)}`;
const OTHER = `sha256:${"2".repeat(64)}`;

describe("receiptStatement", () => {
  it("reads the effect's status and digest from a receipt, and nothing else", () => {
    expect(
      receiptStatement(receiptWith({ sub: "g", effect: { status: "EFFECTED", digest: DIGEST } })),
    ).toEqual({ status: "EFFECTED", digest: DIGEST });
    expect(receiptStatement(receiptWith({ effect: { status: "REFUSED" } }))).toEqual({
      status: "REFUSED",
      digest: null,
    });
    expect(receiptStatement(receiptWith({ effect: { status: "INDETERMINATE" } }))).toEqual({
      status: "INDETERMINATE",
      digest: null,
    });
    // A digest given as null is no digest, as the authority reads it.
    expect(receiptStatement(receiptWith({ effect: { status: "EFFECTED", digest: null } }))).toEqual(
      { status: "EFFECTED", digest: null },
    );
  });

  it("reads nothing from what is not a receipt with a statement the profile defines", () => {
    for (const notAStatement of [
      undefined,
      null,
      "",
      "two.parts",
      "a.b.c.d",
      // A statement in a value that is not a compact JWS is not read either.
      `x.${Buffer.from('{"effect":{"status":"EFFECTED"}}').toString("base64url")}`,
      `x.${Buffer.from('{"effect":{"status":"EFFECTED"}}').toString("base64url")}.c.d`,
      `${"a".repeat(19_990)}.${Buffer.from('{"effect":{"status":"EFFECTED"}}').toString("base64url")}.c2ln`,
      `x.${Buffer.from("not json").toString("base64url")}.c2ln`,
      `x.${Buffer.from("[]").toString("base64url")}.c2ln`,
      `x.${Buffer.from("null").toString("base64url")}.c2ln`,
      receiptWith({}),
      receiptWith({ effect: null }),
      receiptWith({ effect: [] }),
      receiptWith({ effect: "EFFECTED" }),
      receiptWith({ effect: { status: "DONE" } }),
      receiptWith({ effect: { digest: DIGEST } }),
      receiptWith({ effect: { status: "EFFECTED", digest: 5 } }),
      receiptWith({ effect: { status: "EFFECTED", digest: [DIGEST] } }),
      receiptWith({ effect: { status: "EFFECTED", digest: "sha256:zz" } }),
      receiptWith({ effect: { status: "EFFECTED", digest: `x${DIGEST}` } }),
      receiptWith({ effect: { status: "EFFECTED", digest: `${DIGEST}x` } }),
      receiptWith({ effect: { status: "EFFECTED", digest: DIGEST.toUpperCase() } }),
    ]) {
      expect(
        receiptStatement(notAStatement),
        JSON.stringify(notAStatement)?.slice(0, 60),
      ).toBeNull();
    }
    // The bound is the contract's: one character over is not read.
    const longest = receiptWith({ effect: { status: "EFFECTED" } }).padEnd(20_000, "a");
    expect(receiptStatement(longest)).toEqual({ status: "EFFECTED", digest: null });
    expect(receiptStatement(`${longest}a`)).toBeNull();
  });
});

describe("compareReceipt", () => {
  it("is ABSENT with no statement, whatever the account", () => {
    expect(compareReceipt("COMMITTED", DIGEST, DIGEST, null)).toBe("ABSENT");
    expect(compareReceipt("FAILED", DIGEST, null, null)).toBe("ABSENT");
  });

  it("is a mismatch when the receipt's status contradicts the outcome, whatever the digest says", () => {
    expect(compareReceipt("COMMITTED", DIGEST, DIGEST, { status: "REFUSED", digest: DIGEST })).toBe(
      "MISMATCH",
    );
    expect(
      compareReceipt("COMMITTED", DIGEST, DIGEST, { status: "INDETERMINATE", digest: null }),
    ).toBe("MISMATCH");
    expect(compareReceipt("FAILED", DIGEST, null, { status: "EFFECTED", digest: null })).toBe(
      "MISMATCH",
    );
    expect(compareReceipt("FAILED", DIGEST, null, { status: "INDETERMINATE", digest: null })).toBe(
      "MISMATCH",
    );
    expect(
      compareReceipt("INDETERMINATE", DIGEST, null, { status: "EFFECTED", digest: DIGEST }),
    ).toBe("MISMATCH");
    expect(compareReceipt("INDETERMINATE", DIGEST, null, { status: "REFUSED", digest: null })).toBe(
      "MISMATCH",
    );
  });

  it("is SILENT when the statuses agree and the receipt names no digest", () => {
    expect(compareReceipt("COMMITTED", DIGEST, DIGEST, { status: "EFFECTED", digest: null })).toBe(
      "SILENT",
    );
    expect(compareReceipt("FAILED", DIGEST, null, { status: "REFUSED", digest: null })).toBe(
      "SILENT",
    );
    expect(
      compareReceipt("INDETERMINATE", DIGEST, null, { status: "INDETERMINATE", digest: null }),
    ).toBe("SILENT");
  });

  it("compares the digest with the authorised effect, then with the observation when there is one", () => {
    expect(compareReceipt("COMMITTED", DIGEST, null, { status: "EFFECTED", digest: DIGEST })).toBe(
      "MATCH",
    );
    expect(
      compareReceipt("COMMITTED", DIGEST, DIGEST, { status: "EFFECTED", digest: DIGEST }),
    ).toBe("MATCH");
    expect(compareReceipt("COMMITTED", DIGEST, DIGEST, { status: "EFFECTED", digest: OTHER })).toBe(
      "MISMATCH",
    );
    expect(compareReceipt("COMMITTED", DIGEST, null, { status: "EFFECTED", digest: OTHER })).toBe(
      "MISMATCH",
    );
    // The receipt agrees with the grant and disagrees with what was observed:
    // two witnesses differ, and that is a mismatch too.
    expect(compareReceipt("COMMITTED", DIGEST, OTHER, { status: "EFFECTED", digest: DIGEST })).toBe(
      "MISMATCH",
    );
    // A refusal that carries a digest is compared like any other statement.
    expect(compareReceipt("FAILED", DIGEST, null, { status: "REFUSED", digest: DIGEST })).toBe(
      "MATCH",
    );
    expect(compareReceipt("FAILED", DIGEST, null, { status: "REFUSED", digest: OTHER })).toBe(
      "MISMATCH",
    );
  });
});
