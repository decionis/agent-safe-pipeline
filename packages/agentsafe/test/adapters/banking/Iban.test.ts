import { describe, expect, it } from "vitest";
import {
  ibanFromReference,
  isValidIban,
  referenceIsValid,
} from "../../../src/adapters/banking/Iban.js";

describe("Iban", () => {
  it("accepts the published check-digit examples and refuses a single altered digit", () => {
    expect(isValidIban("GB82WEST12345698765432")).toBe(true);
    expect(isValidIban("DE89370400440532013000")).toBe(true);
    expect(isValidIban("CH9300762011623852957")).toBe(true);
    expect(isValidIban("gb82 west 1234 5698 7654 32")).toBe(true);
    expect(isValidIban("GB82WEST12345698765433")).toBe(false);
    expect(isValidIban("GB83WEST12345698765432")).toBe(false);
  });

  it("refuses anything that is not shaped like an IBAN at all", () => {
    expect(isValidIban("")).toBe(false);
    expect(isValidIban("GB82")).toBe(false);
    expect(isValidIban("1B82WEST12345698765432")).toBe(false);
    expect(isValidIban("GBX2WEST12345698765432")).toBe(false);
    expect(isValidIban(`GB82${"W".repeat(31)}`)).toBe(false);
  });

  it("reads an IBAN only out of an iban: reference", () => {
    expect(ibanFromReference("iban:GB82WEST12345698765432")).toBe("GB82WEST12345698765432");
    expect(ibanFromReference(" iban:GB82WEST12345698765432 ")).toBe("GB82WEST12345698765432");
    expect(ibanFromReference("fixture_account_1921")).toBeNull();
    expect(ibanFromReference("iban:gb82west12345698765432")).toBeNull();
  });

  it("lets an opaque reference through and checks a transparent one", () => {
    expect(referenceIsValid("fixture_account_1921")).toBe(true);
    expect(referenceIsValid("iban:GB82WEST12345698765432")).toBe(true);
    expect(referenceIsValid("iban:GB82WEST12345698765433")).toBe(false);
  });
});
