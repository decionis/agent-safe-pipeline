import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CardHoldSeal } from "../../../src/adapters/cards/CardHoldSeal.js";

const KEY = randomBytes(32);

describe("the hold seal", () => {
  it("opens what it sealed, under the same key and the same row identity only", () => {
    const seal = CardHoldSeal.fromKey(KEY);
    const sealed = seal.seal('{"grant":"token"}', "hold|org|card|merchant|intent");
    expect(sealed.startsWith("v1.")).toBe(true);
    expect(sealed).not.toContain("token");
    expect(seal.open(sealed, "hold|org|card|merchant|intent")).toBe('{"grant":"token"}');
    // Moved to another row, or read under another key, it does not open.
    expect(seal.open(sealed, "hold|org|card|merchant|other")).toBeNull();
    expect(
      CardHoldSeal.fromKey(randomBytes(32)).open(sealed, "hold|org|card|merchant|intent"),
    ).toBeNull();
    // Two seals of the same value differ: a fresh nonce each time.
    expect(seal.seal("x", "a")).not.toBe(seal.seal("x", "a"));
  });

  it("refuses a damaged value rather than guessing", () => {
    const seal = CardHoldSeal.fromKey(KEY);
    const sealed = seal.seal("plain", "a");
    const [version, nonce, body, tag] = sealed.split(".") as [string, string, string, string];
    expect(seal.open(`${version}.${nonce}.${body}.${tag.slice(0, -2)}AA`, "a")).toBeNull();
    expect(seal.open(`v2.${nonce}.${body}.${tag}`, "a")).toBeNull();
    expect(seal.open(`${version}.${nonce}.${body}`, "a")).toBeNull();
    expect(seal.open(`${version}.AAAA.${body}.${tag}`, "a")).toBeNull();
    expect(seal.open("", "a")).toBeNull();
  });

  it("reads a key as hex or base64 text of exactly 32 bytes, and nothing else", () => {
    const hex = KEY.toString("hex");
    const base64 = KEY.toString("base64");
    const base64url = KEY.toString("base64url");
    const sealed = CardHoldSeal.fromText(`${hex}\n`).seal("v", "id");
    expect(CardHoldSeal.fromText(base64).open(sealed, "id")).toBe("v");
    expect(CardHoldSeal.fromText(` ${base64url} `).open(sealed, "id")).toBe("v");
    for (const bad of [
      "",
      "abc",
      hex.slice(0, 62),
      randomBytes(16).toString("base64"),
      randomBytes(48).toString("hex"),
    ]) {
      expect(() => CardHoldSeal.fromText(bad)).toThrow("CARD_HOLDS_KEY_INVALID");
    }
    expect(() => CardHoldSeal.fromKey(randomBytes(31))).toThrow("CARD_HOLDS_KEY_INVALID");
  });
});
