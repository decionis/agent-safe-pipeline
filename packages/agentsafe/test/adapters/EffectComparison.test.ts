import { describe, expect, it } from "vitest";
import { compareEffect } from "../../src/adapters/EffectComparison.js";

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
