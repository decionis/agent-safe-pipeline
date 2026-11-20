import { describe, expect, it } from "vitest";
import {
  exposureDeclaration,
  RouteExposureSchema,
} from "../../src/exposure/ExposureDeclaration.js";
import {
  currencyExponent,
  minorUnits,
  readExposureFacts,
  readSettledAmount,
  walkPointer,
} from "../../src/exposure/ExposureFacts.js";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";

/** A declaration as the file states it, through the loader's own schema. */
const declare = (raw: unknown) => exposureDeclaration(RouteExposureSchema.parse(raw));

function request(body: unknown, overrides: Partial<InterceptedRequest> = {}): InterceptedRequest {
  return {
    method: "POST",
    path: "/vendors/v-9/payments",
    search: "?currency=eur&ref=a&ref=b",
    headers: { "content-type": "application/json", "x-agent-id": "agent-1" },
    body: Buffer.from(JSON.stringify(body), "utf8"),
    remoteAddress: null,
    encrypted: false,
    ...overrides,
  };
}

const declaration = declare({
  amount: "/body/payment/amount",
  currency: "/body/payment/currency",
  subjects: { vendor: "/path/vendor" },
});

describe("reading what a payment states", () => {
  it("reads the amount, currency and subjects by pointer, and defaults the agent to the actor", () => {
    const result = readExposureFacts(
      declaration,
      request({ payment: { amount: 1250, currency: "gbp" } }),
      "/vendors/:vendor/payments",
      "actor-from-config",
    );
    expect(result).toEqual({
      ok: true,
      facts: {
        actionType: "PAYMENT_RELEASE",
        amount: 1250,
        currency: "GBP",
        subjects: { vendor: "v-9", agent: "actor-from-config" },
      },
    });
  });

  it("reads headers and query values, and a fixed currency", () => {
    const fixed = declare({
      actionType: "vendor_bank_change",
      amount: "/body/amount",
      amountUnit: "major",
      currency: "jpy",
      subjects: { agent: "/headers/x-agent-id", customer: "/query/currency" },
    });
    expect(
      readExposureFacts(fixed, request({ amount: "1500" }), "/vendors/*/payments", "a"),
    ).toEqual({
      ok: true,
      facts: {
        actionType: "VENDOR_BANK_CHANGE",
        amount: 1500,
        currency: "JPY",
        subjects: { agent: "agent-1", customer: "eur" },
      },
    });
  });

  it.each([
    [{ payment: { amount: -1, currency: "USD" } }, "EXPOSURE_AMOUNT_UNREADABLE"],
    [{ payment: { amount: 1.5, currency: "USD" } }, "EXPOSURE_AMOUNT_UNREADABLE"],
    [{ payment: { amount: "1e3", currency: "USD" } }, "EXPOSURE_AMOUNT_UNREADABLE"],
    [{ payment: { amount: "9007199254740993", currency: "USD" } }, "EXPOSURE_AMOUNT_UNREADABLE"],
    [{ payment: { currency: "USD" } }, "EXPOSURE_AMOUNT_UNREADABLE"],
    [{ payment: { amount: 10, currency: "US" } }, "EXPOSURE_CURRENCY_UNREADABLE"],
    [{ payment: { amount: 10, currency: { code: "USD" } } }, "EXPOSURE_CURRENCY_UNREADABLE"],
  ])("refuses %j as %s rather than guess", (body, code) => {
    expect(readExposureFacts(declaration, request(body), "/vendors/:vendor/payments", "a")).toEqual(
      { ok: false, code },
    );
  });

  it("refuses a declared subject the request does not state, or states as a payload", () => {
    const vendor = declare({
      amount: "/body/amount",
      currency: "USD",
      subjects: { vendor: "/body/vendor" },
    });
    for (const body of [
      { amount: 1 },
      { amount: 1, vendor: "  " },
      { amount: 1, vendor: "x".repeat(201) },
      { amount: 1, vendor: ["a"] },
    ]) {
      expect(readExposureFacts(vendor, request(body), "/p", "a")).toEqual({
        ok: false,
        code: "EXPOSURE_SUBJECT_UNREADABLE",
      });
    }
  });

  it("reads no body that is not JSON", () => {
    const result = readExposureFacts(
      declaration,
      request(
        { payment: { amount: 1, currency: "USD" } },
        { headers: { "content-type": "text/plain" } },
      ),
      "/vendors/:vendor/payments",
      "a",
    );
    expect(result).toEqual({ ok: false, code: "EXPOSURE_CURRENCY_UNREADABLE" });
  });
});

describe("a step that moves no money: a change of a vendor's bank details", () => {
  const change = declare({
    actionType: "vendor_bank_change",
    subjects: { vendor: "/path/vendor" },
  });

  it("states no amount and no currency, and reads its subjects", () => {
    expect(change).toMatchObject({
      actionType: "VENDOR_BANK_CHANGE",
      amount: null,
      currency: null,
    });
    const result = readExposureFacts(
      change,
      request({ iban: "GB00 0000" }, { path: "/vendors/v-9/bank-account" }),
      "/vendors/:vendor/bank-account",
      "configured-actor",
    );
    expect(result).toEqual({
      ok: true,
      facts: {
        actionType: "VENDOR_BANK_CHANGE",
        amount: 0,
        currency: "XXX",
        subjects: { vendor: "v-9", agent: "configured-actor" },
      },
    });
  });

  it("still refuses a vendor the request does not state", () => {
    expect(
      readExposureFacts(
        declare({ actionType: "VENDOR_BANK_CHANGE", subjects: { vendor: "/body/vendor" } }),
        request({}),
        "/vendors/:vendor/payments",
        "actor",
      ),
    ).toEqual({ ok: false, code: "EXPOSURE_SUBJECT_UNREADABLE" });
  });

  it("is the only kind that may omit them: a payment states both, a step both or neither", () => {
    for (const raw of [
      { subjects: { vendor: "/path/vendor" } },
      { amount: "/body/amount" },
      { currency: "USD", actionType: "REFUND_REQUEST" },
      { actionType: "VENDOR_BANK_CHANGE", amount: "/body/amount" },
      { actionType: "VENDOR_BANK_CHANGE", settledAmount: "/body/settled" },
    ])
      expect(RouteExposureSchema.safeParse(raw).success, JSON.stringify(raw)).toBe(false);
    // A bank change that does state an amount reads it as before.
    expect(
      declare({ actionType: "VENDOR_BANK_CHANGE", amount: "/body/amount", currency: "USD" }),
    ).toMatchObject({ amount: "/body/amount", currency: "USD" });
  });
});

describe("pointers and amounts", () => {
  it("follows own keys and decimal indexes only, never a prototype", () => {
    const root = { body: { list: [{ "a/b": 1, "c~d": 2 }] } };
    expect(walkPointer(root, "/body/list/0/a~1b")).toBe(1);
    expect(walkPointer(root, "/body/list/0/c~0d")).toBe(2);
    expect(walkPointer(root, "/body/list/00")).toBeUndefined();
    expect(walkPointer(root, "/body/list/length")).toBeUndefined();
    expect(walkPointer(root, "/body/__proto__")).toBeUndefined();
    expect(walkPointer(root, "/body/constructor")).toBeUndefined();
    expect(walkPointer(root, "/body/list/0/a~1b/deeper")).toBeUndefined();
  });

  it("converts a major amount exactly, by the currency's exponent", () => {
    expect(currencyExponent("USD")).toBe(2);
    expect(currencyExponent("JPY")).toBe(0);
    expect(currencyExponent("KWD")).toBe(3);
    expect(minorUnits("12.5", "MAJOR", "USD")).toBe(1250);
    expect(minorUnits(12.34, "MAJOR", "USD")).toBe(1234);
    expect(minorUnits("1.234", "MAJOR", "KWD")).toBe(1234);
    expect(minorUnits("1.234", "MAJOR", "USD")).toBeNull();
    expect(minorUnits("1.5", "MAJOR", "JPY")).toBeNull();
    expect(minorUnits("0", "MINOR", "USD")).toBe(0);
    expect(minorUnits(" 42 ", "MINOR", "USD")).toBe(42);
    expect(minorUnits(true, "MINOR", "USD")).toBeNull();
  });

  it("settles what the answer says moved, only when it is no more than was reserved", () => {
    const settled = declare({
      amount: "/body/amount",
      currency: "USD",
      settledAmount: "/body/captured",
    });
    const facts = {
      actionType: "PAYMENT_RELEASE" as const,
      amount: 500,
      currency: "USD",
      subjects: {},
    };
    const answer = (body: unknown, type = "application/json") => ({
      headers: [["content-type", type]] as const,
      body: Buffer.from(JSON.stringify(body)),
    });
    expect(readSettledAmount(settled, facts, answer({ captured: 400 }))).toBe(400);
    expect(readSettledAmount(settled, facts, answer({ captured: 600 }))).toBeNull();
    expect(readSettledAmount(settled, facts, answer({ captured: 400 }, "text/plain"))).toBeNull();
    expect(readSettledAmount(settled, facts, { headers: [], body: Buffer.from("{") })).toBeNull();
    expect(
      readSettledAmount(declare({ amount: "/body/a", currency: "USD" }), facts, answer({})),
    ).toBeNull();
  });
});
