import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { URL } from "node:url";

const workflow = await readFile(
  new URL("../../.github/workflows/zenodo-release.yml", import.meta.url),
  "utf8",
);

describe("Zenodo release workflow", () => {
  it("runs after stable releases and supports an explicit bounded retry", () => {
    assert.match(workflow, /release:\n\s+types: \[published\]/);
    assert.match(workflow, /workflow_dispatch:/);
    assert.match(workflow, /github\.event\.release\.prerelease == false/);
    assert.match(workflow, /--attempts 20/);
    assert.match(workflow, /--delay-ms 10000/);
    assert.match(workflow, /--request-timeout-ms 5000/);
    assert.match(workflow, /timeout-minutes: 10/);
  });

  it("has read-only repository permissions and never publishes or edits metadata", () => {
    assert.match(workflow, /permissions:\n {2}contents: read/);
    assert.doesNotMatch(workflow, /contents: write/);
    assert.doesNotMatch(workflow, /id-token: write/);
    assert.doesNotMatch(workflow, /gh release create|npm publish|zenodo.*token/i);
    assert.match(workflow, /pnpm metadata:check/);
  });

  it("retains machine-readable evidence without repository credentials", () => {
    assert.match(workflow, /persist-credentials: false/);
    assert.match(workflow, /--output zenodo-release-evidence\.json/);
    assert.match(workflow, /actions\/upload-artifact@/);
    assert.match(workflow, /retention-days: 90/);
  });
});
