import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { CanonicalIntentHasher } from "../../src/intent/CanonicalIntentHasher.js";
import type { JsonValue } from "../../src/intent/JsonValue.js";

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
});
