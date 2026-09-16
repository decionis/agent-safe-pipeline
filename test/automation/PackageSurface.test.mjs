import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

/**
 * The packed-tarball workflow's consumer pins the package's runtime exports
 * by name and fails on any difference. This holds the built package to that
 * same list locally, so a new export is declared in the consumer in the same
 * change that adds it, and never first discovered by CI.
 */
const consumerUrl = new URL("../../tests/integration/npm-pack/consumer.mjs", import.meta.url);
const packageUrl = new URL("../../packages/pipeline/dist/Index.js", import.meta.url);

function pinnedRuntimeExports(source) {
  const match = /const EXPECTED_RUNTIME = \[([^\]]*)\];/.exec(source);
  assert.ok(match, "consumer.mjs declares EXPECTED_RUNTIME as one array literal of strings");
  const names = [...match[1].matchAll(/"([^"]+)"/g)].map(([, name]) => name);
  assert.ok(names.length > 0, "EXPECTED_RUNTIME names at least one export");
  return names;
}

describe("package surface", () => {
  it("exports at runtime exactly what the packed-tarball consumer expects", async () => {
    const pinned = pinnedRuntimeExports(await readFile(consumerUrl, "utf8"));
    const built = Object.keys(await import(packageUrl)).sort();
    assert.deepEqual(pinned, [...pinned].sort(), "the pinned list is kept sorted");
    assert.deepEqual(
      built,
      pinned,
      "runtime exports of packages/pipeline/dist/Index.js differ from tests/integration/npm-pack/consumer.mjs",
    );
  });
});
