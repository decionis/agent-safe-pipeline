import { readFileSync } from "node:fs";
import { CanonicalIntentHasher } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import {
  assertIJson,
  isWellFormedUtf16,
  jcsCanonical,
  jcsDigest,
  JcsError,
} from "../../src/adapters/JcsDigest.js";
import { repositoryPath } from "../support/RepositoryRoot.js";

const code = (work: () => unknown): string => {
  try {
    work();
  } catch (error) {
    return error instanceof JcsError ? error.code : `unexpected ${String(error)}`;
  }
  return "no refusal";
};

describe("jcsDigest", () => {
  it("is the digest of the pipeline's own canonical form", () => {
    const value = { b: 1, a: [true, null, "x"] };
    expect(jcsCanonical(value)).toBe(CanonicalIntentHasher.stringify(value));
    expect(jcsDigest(value)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("is stable under key order and changes with any value", () => {
    expect(jcsDigest({ a: 1, b: 2 })).toBe(jcsDigest({ b: 2, a: 1 }));
    expect(jcsDigest({ a: 1, b: 2 })).not.toBe(jcsDigest({ a: 1, b: 3 }));
    expect(jcsDigest({ a: 1 })).not.toBe(jcsDigest({ a: "1" }));
  });

  it("refuses input no other implementation would canonicalise the same way", () => {
    expect(code(() => jcsDigest("\ud800"))).toBe("JCS_NOT_I_JSON");
    expect(code(() => jcsDigest("\udc00x"))).toBe("JCS_NOT_I_JSON");
    expect(code(() => jcsDigest({ ["\ud800"]: 1 }))).toBe("JCS_NOT_I_JSON");
    expect(code(() => jcsDigest([{ nested: "\ud83d" }]))).toBe("JCS_NOT_I_JSON");
    expect(code(() => jcsDigest(["\ud800"]))).toBe("JCS_NOT_I_JSON");
    expect(code(() => jcsDigest({ deep: { deeper: [1, "\udfff"] } }))).toBe("JCS_NOT_I_JSON");
    expect(code(() => jcsDigest(Number.POSITIVE_INFINITY))).toBe("JCS_NUMBER_NOT_FINITE");
    expect(code(() => jcsDigest(Number.NaN))).toBe("JCS_NUMBER_NOT_FINITE");
    expect(code(() => jcsCanonical("\ud800"))).toBe("JCS_NOT_I_JSON");
  });

  it("accepts every well-formed shape, surrogate pairs included", () => {
    expect(isWellFormedUtf16("a😀b")).toBe(true);
    expect(isWellFormedUtf16("\ud83d")).toBe(false);
    expect(isWellFormedUtf16("\ud83d\ud83d")).toBe(false);
    expect(isWellFormedUtf16("")).toBe(true);
    // The first and the last code point a surrogate pair can encode.
    expect(isWellFormedUtf16("\ud800\udc00")).toBe(true);
    expect(isWellFormedUtf16("\udbff\udfff")).toBe(true);
    // A character just outside the surrogate range is an ordinary character.
    expect(isWellFormedUtf16("\ue000")).toBe(true);
    expect(isWellFormedUtf16("\ud7ff")).toBe(true);
    // Every unpaired surrogate, at both boundaries, in both roles.
    expect(isWellFormedUtf16("\ud800")).toBe(false);
    expect(isWellFormedUtf16("\udbff")).toBe(false);
    expect(isWellFormedUtf16("\udc00")).toBe(false);
    expect(isWellFormedUtf16("\udfff")).toBe(false);
    expect(isWellFormedUtf16("\udc00\udc00")).toBe(false);
    expect(isWellFormedUtf16("\ud800\ue000")).toBe(false);
    expect(isWellFormedUtf16("a\udfffb")).toBe(false);
    expect(code(() => assertIJson({ emoji: "😀", n: -0, list: [1, 2] }))).toBe("no refusal");
    expect(code(() => assertIJson(true))).toBe("no refusal");
    expect(code(() => assertIJson(false))).toBe("no refusal");
    expect(code(() => assertIJson(null))).toBe("no refusal");
    expect(code(() => assertIJson({ a: null, b: [null] }))).toBe("no refusal");
    // A key the canonical form drops has nothing under it to check.
    expect(code(() => assertIJson({ a: undefined } as never))).toBe("no refusal");
    expect(jcsDigest({ a: undefined } as never)).toBe(jcsDigest({}));
  });

  it("names itself, so a caller can tell one refusal from another", () => {
    try {
      jcsDigest("\ud800");
      throw new Error("expected a refusal");
    } catch (error) {
      expect(error).toBeInstanceOf(JcsError);
      expect((error as JcsError).name).toBe("JcsError");
      expect((error as JcsError).message).toBe("JCS_NOT_I_JSON");
    }
  });

  it("agrees with the repository's own conformance vector", () => {
    const vector = JSON.parse(
      readFileSync(repositoryPath("conformance", "agent-safe-intent-v1.json"), "utf8"),
    ) as { readonly canonical_json: string; readonly binding: Record<string, unknown> };
    expect(jcsCanonical(vector.binding as never)).toBe(vector.canonical_json);
  });
});
