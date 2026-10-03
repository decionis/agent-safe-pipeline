import { describe, expect, it } from "vitest";
import { containsPan } from "../../../src/adapters/cards/Pan.js";

// Published test card numbers only: every one is a network's documented test
// value, Luhn-valid by construction, and none can be charged.
describe("containsPan", () => {
  it.each([
    ["a sixteen-digit number", "4111111111111111"],
    ["another network's", "5555555555554444"],
    ["a fifteen-digit one", "378282246310005"],
    ["one with zeros in it", "4000000000000002"],
    ["thirteen digits, the shortest", "4911111111112"],
    ["nineteen digits, the longest", "4911111111111111113"],
    ["a number after a prefix", "tok_4111111111111111"],
    ["a number between letters", "tok4111111111111111x"],
    ["a number grouped by spaces", "4111 1111 1111 1111"],
    ["a number grouped by hyphens", "4111-1111-1111-1111"],
    ["a number grouped by dots", "4111.1111.1111.1111"],
    ["a grouped number before a lowercase letter", "4111-1111-1111-1111a1"],
    ["a grouped number after a prefix", "tok_4111-1111-1111-1111"],
    ["a grouped number after a digit and a letter", "1a4111-1111-1111-1111"],
    ["a grouped number before an uppercase letter", "4111-1111-1111-1111Z1"],
    ["a number followed by another group", "4111111111111111-0042"],
    ["a number before a short group", "4111111111111111 22"],
    ["a number after a short group", "1234 4111111111111111"],
    ["thirteen zeros, which pass Luhn", "0000000000000"],
  ])("finds %s", (_name, value) => {
    expect(containsPan(value)).toBe(true);
  });

  it.each([
    ["nothing", ""],
    ["a reference with no digits", "tok_abcdef"],
    ["twelve Luhn-valid digits", "491111111119"],
    ["twenty Luhn-valid digits", "49111111111111111117"],
    ["sixteen digits that fail Luhn", "4111111111111112"],
    ["seventeen digits that fail Luhn", "41111111111111111"],
    ["two runs a letter keeps apart", "41111111a11111111"],
    ["two runs an uppercase letter keeps apart", "41111111Q11111111"],
    ["a short reference", "fixture_card_ref_0042"],
  ])("does not find one in %s", (_name, value) => {
    expect(containsPan(value)).toBe(false);
  });
});
