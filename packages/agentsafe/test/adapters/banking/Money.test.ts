import { describe, expect, it } from "vitest";
import {
  CurrencyError,
  isSupportedCurrency,
  minorUnitExponent,
  supportedCurrencies,
} from "../../../src/adapters/banking/Currency.js";
import { Money, MoneyError } from "../../../src/adapters/banking/Money.js";

const code = (work: () => unknown): string => {
  try {
    work();
  } catch (error) {
    if (error instanceof MoneyError || error instanceof CurrencyError) return error.code;
    return `unexpected ${String(error)}`;
  }
  return "no refusal";
};

describe("minorUnitExponent", () => {
  it("knows the currencies whose exponent is not two, and refuses one it does not know", () => {
    expect(minorUnitExponent("CHF")).toBe(2);
    expect(minorUnitExponent("JPY")).toBe(0);
    expect(minorUnitExponent("KWD")).toBe(3);
    expect(minorUnitExponent("CLF")).toBe(4);
    expect(code(() => minorUnitExponent("XXX"))).toBe("CURRENCY_UNSUPPORTED");
    expect(code(() => minorUnitExponent("chf"))).toBe("CURRENCY_UNSUPPORTED");
    expect(isSupportedCurrency("CHF")).toBe(true);
    expect(isSupportedCurrency("XXX")).toBe(false);
    expect(supportedCurrencies()).toContain("EUR");
    expect(supportedCurrencies().length).toBeGreaterThan(40);
  });
});

describe("the errors these refusals carry", () => {
  it("name themselves, so a caller can tell one from another", () => {
    for (const [work, name, message] of [
      [(): unknown => Money.fromDecimal("x", "CHF"), "MoneyError", "AMOUNT_NOT_A_DECIMAL_STRING"],
      [(): unknown => minorUnitExponent("XXX"), "CurrencyError", "CURRENCY_UNSUPPORTED"],
    ] as const) {
      try {
        work();
        throw new Error("expected a refusal");
      } catch (error) {
        expect((error as Error).name).toBe(name);
        expect((error as Error).message).toBe(message);
      }
    }
  });
});

describe("Money", () => {
  it("reads the wire form at exactly the currency's scale", () => {
    expect(Money.fromDecimal("250000.00", "CHF").minor).toBe(25_000_000n);
    expect(Money.fromDecimal("0.01", "CHF").minor).toBe(1n);
    expect(Money.fromDecimal("100", "JPY").minor).toBe(100n);
    expect(Money.fromDecimal("1.234", "KWD").minor).toBe(1_234n);
    expect(Money.fromDecimal("1.2345", "CLF").minor).toBe(12_345n);
  });

  it("refuses a scale the currency does not have, rather than padding or rounding it", () => {
    expect(code(() => Money.fromDecimal("250000.0", "CHF"))).toBe("AMOUNT_SCALE_INVALID");
    expect(code(() => Money.fromDecimal("250000", "CHF"))).toBe("AMOUNT_SCALE_INVALID");
    expect(code(() => Money.fromDecimal("250000.000", "CHF"))).toBe("AMOUNT_SCALE_INVALID");
    expect(code(() => Money.fromDecimal("100.00", "JPY"))).toBe("AMOUNT_SCALE_INVALID");
  });

  it("refuses everything a JSON number would have let through", () => {
    expect(code(() => Money.fromDecimal("1e3", "CHF"))).toBe("AMOUNT_NOT_A_DECIMAL_STRING");
    expect(code(() => Money.fromDecimal("-0.00", "CHF"))).toBe("AMOUNT_NOT_A_DECIMAL_STRING");
    expect(code(() => Money.fromDecimal("-1.00", "CHF"))).toBe("AMOUNT_NOT_A_DECIMAL_STRING");
    expect(code(() => Money.fromDecimal("01.00", "CHF"))).toBe("AMOUNT_NOT_A_DECIMAL_STRING");
    expect(code(() => Money.fromDecimal(" 1.00", "CHF"))).toBe("AMOUNT_NOT_A_DECIMAL_STRING");
    expect(code(() => Money.fromDecimal("", "CHF"))).toBe("AMOUNT_NOT_A_DECIMAL_STRING");
    expect(code(() => Money.fromDecimal("1,00", "CHF"))).toBe("AMOUNT_NOT_A_DECIMAL_STRING");
  });

  it("refuses an amount past the boundary, from either form", () => {
    // The wire form bounds the whole part at 28 digits, so for a two-place
    // currency the string shape is the binding limit and the minor-unit
    // ceiling is reached only by a currency with more places.
    expect(Money.fromDecimal(`${"9".repeat(28)}.00`, "CHF").minor).toBe(
      BigInt(`${"9".repeat(28)}00`),
    );
    expect(code(() => Money.fromDecimal(`${"9".repeat(29)}.00`, "CHF"))).toBe(
      "AMOUNT_NOT_A_DECIMAL_STRING",
    );
    expect(code(() => Money.fromDecimal(`${"9".repeat(28)}.0000`, "CLF"))).toBe("AMOUNT_TOO_LARGE");
    expect(code(() => Money.fromMinor(10n ** 30n, "CHF"))).toBe("AMOUNT_TOO_LARGE");
    expect(code(() => Money.fromMinor(10n ** 30n - 1n, "CHF"))).toBe("no refusal");
    expect(code(() => Money.fromMinor(-1n, "CHF"))).toBe("AMOUNT_TOO_LARGE");
    // Zero is an amount, not a refusal: the boundary is below it, not at it.
    expect(Money.fromMinor(0n, "CHF").toDecimal()).toBe("0.00");
    expect(code(() => Money.fromMinor(1n, "XXX"))).toBe("CURRENCY_UNSUPPORTED");
    // The ceiling is reached exactly, from the wire form of a four-place currency.
    expect(code(() => Money.fromDecimal(`1${"0".repeat(26)}.0000`, "CLF"))).toBe(
      "AMOUNT_TOO_LARGE",
    );
    expect(code(() => Money.fromDecimal(`9${"9".repeat(25)}.9999`, "CLF"))).toBe("no refusal");
  });

  it("round-trips the wire form, so a digest taken over it still matches", () => {
    for (const [amount, currency] of [
      ["250000.00", "CHF"],
      ["0.00", "CHF"],
      ["0.01", "EUR"],
      ["7", "JPY"],
      ["0.001", "BHD"],
      ["12.3456", "UYW"],
    ] as const) {
      expect(Money.fromDecimal(amount, currency).toDecimal()).toBe(amount);
    }
    expect(Money.fromMinor(5n, "CHF").toDecimal()).toBe("0.05");
    expect(String(Money.fromDecimal("1.00", "EUR"))).toBe("1.00 EUR");
  });

  it("adds within a currency and refuses to mix two", () => {
    const one = Money.fromDecimal("1.00", "CHF");
    const two = Money.fromDecimal("2.50", "CHF");
    expect(one.add(two).toDecimal()).toBe("3.50");
    expect(Money.sum([one, two, one]).toDecimal()).toBe("4.50");
    expect(Money.sum([two]).equals(two)).toBe(true);
    expect(one.equals(Money.fromDecimal("1.00", "CHF"))).toBe(true);
    expect(one.equals(Money.fromDecimal("1.00", "EUR"))).toBe(false);
    expect(one.equals(two)).toBe(false);
    expect(code(() => one.add(Money.fromDecimal("1.00", "EUR")))).toBe("CURRENCY_MISMATCH");
    expect(code(() => Money.sum([]))).toBe("CURRENCY_MISMATCH");
    expect(code(() => Money.sum([one, Money.fromDecimal("1.00", "EUR")]))).toBe(
      "CURRENCY_MISMATCH",
    );
  });
});
