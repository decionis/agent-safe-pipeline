import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { CanonicalIntentHasher } from "../../src/intent/CanonicalIntentHasher.js";
import type { JsonValue } from "../../src/intent/JsonValue.js";

interface ConformanceVector {
  description?: string;
  binding: JsonValue;
  canonical_json?: string;
  intent_hash: string;
}

const VECTORS_DIR = new URL("../../../../conformance/vectors/", import.meta.url);

describe("agent-safe.intent/1 conformance", () => {
  it("matches the public cross-implementation SHA-256 vector", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL("../../../../conformance/agent-safe-intent-v1.json", import.meta.url),
        "utf8",
      ),
    ) as { binding: JsonValue; intent_hash: string };
    const canonical = CanonicalIntentHasher.stringify(fixture.binding);
    const actual = `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;

    expect(actual).toBe(fixture.intent_hash);
  });

  it("discovers and validates every vector in conformance/vectors/", async () => {
    const files = (await readdir(VECTORS_DIR)).filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThanOrEqual(6);

    for (const file of files) {
      const vector = JSON.parse(
        await readFile(new URL(file, VECTORS_DIR), "utf8"),
      ) as ConformanceVector;

      // 1. the hasher's canonicalization must equal the published bytes
      const canonical = CanonicalIntentHasher.stringify(vector.binding);
      expect(canonical, `${file}: canonical JSON mismatch`).toBe(vector.canonical_json);

      // 2. the published SHA-256 must match those bytes
      const actual = `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
      expect(actual, `${file}: hash mismatch`).toBe(vector.intent_hash);
    }
  });

  it("keeps composed and decomposed text intentionally distinct (no NFC)", async () => {
    const nfc = CanonicalIntentHasher.stringify({ text: "caf\u00e9" });
    const nfd = CanonicalIntentHasher.stringify({ text: "cafe\u0301" });
    expect(nfc).not.toBe(nfd);
  });

  it("canonicalizes negative zero to 0 (JS JSON encoding)", async () => {
    expect(CanonicalIntentHasher.stringify({ amount: -0 })).toBe('{"amount":0}');
  });
});
