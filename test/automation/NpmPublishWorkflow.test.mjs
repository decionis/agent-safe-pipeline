import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { URL } from "node:url";

const workflow = await readFile(
  new URL("../../.github/workflows/deploy.yml", import.meta.url),
  "utf8",
);
const stepStart = workflow.indexOf(
  "      - name: Publish package to npm through trusted publishing\n",
);
const stepEnd = workflow.indexOf("      - name: Create verified GitHub release\n", stepStart);
const runMarker = "        run: |\n";
const runStart = workflow.indexOf(runMarker, stepStart) + runMarker.length;

assert.notEqual(stepStart, -1, "npm publish step is missing");
assert.notEqual(stepEnd, -1, "step following npm publish is missing");
assert.ok(runStart >= runMarker.length, "npm publish script is missing");

const publishScript = workflow
  .slice(runStart, stepEnd)
  .replace(/^ {10}/gm, "")
  .trim();

async function runPublish({ publicAfter, version }) {
  const directory = await mkdtemp(join(tmpdir(), "agent-safe-npm-publish-"));
  const npmPath = join(directory, "npm");
  const sleepPath = join(directory, "sleep");
  await writeFile(
    npmPath,
    `#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$TEST_STATE/calls"
if [ "$1" = "view" ]; then
  count=0
  if [ -f "$TEST_STATE/count" ]; then read -r count < "$TEST_STATE/count"; fi
  count=$((count + 1))
  printf '%s\\n' "$count" > "$TEST_STATE/count"
  if [ "$TEST_PUBLIC_AFTER" -gt 0 ] && [ "$count" -ge "$TEST_PUBLIC_AFTER" ]; then
    printf '%s\\n' "$RELEASE_VERSION"
    exit 0
  fi
  exit 1
fi
if [ "$1" = "publish" ]; then
  : > "$TEST_STATE/published"
  exit 0
fi
exit 2
`,
  );
  await writeFile(sleepPath, '#!/bin/sh\nprintf \'%s\\n\' "$1" >> "$TEST_STATE/sleeps"\n');
  await Promise.all([chmod(npmPath, 0o700), chmod(sleepPath, 0o700)]);

  try {
    const result = spawnSync("bash", ["-c", publishScript], {
      encoding: "utf8",
      env: {
        ...process.env,
        NPM_PACKAGE: "@decionis/agent-safe-pipeline",
        PATH: `${directory}:/usr/bin:/bin`,
        RELEASE_TARBALL: "package.tgz",
        RELEASE_VERSION: version,
        TEST_PUBLIC_AFTER: String(publicAfter),
        TEST_STATE: directory,
      },
    });
    const calls = (await readFile(join(directory, "calls"), "utf8")).trim().split("\n");
    const count = Number(await readFile(join(directory, "count"), "utf8"));
    return { calls, count, result };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("npm trusted publish workflow", () => {
  it("skips an idempotent publication when the version is already public", async () => {
    const { calls, count, result } = await runPublish({ publicAfter: 1, version: "0.1.2" });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(count, 1);
    assert.equal(
      calls.some((call) => call.startsWith("publish ")),
      false,
    );
  });

  it("publishes prereleases under next and tolerates registry propagation", async () => {
    const { calls, count, result } = await runPublish({
      publicAfter: 4,
      version: "0.1.3-rc.1",
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(count, 4);
    assert.ok(calls.includes("publish ./release/package.tgz --access public --tag next"));
    assert.match(result.stdout, /became public after 3 verification attempt\(s\)/);
  });

  it("keeps stable releases on npm's default latest tag", async () => {
    const { calls, result } = await runPublish({ publicAfter: 2, version: "0.1.3" });

    assert.equal(result.status, 0, result.stderr);
    assert.ok(calls.includes("publish ./release/package.tgz --access public"));
    assert.equal(
      calls.some((call) => call.includes("--tag next")),
      false,
    );
  });

  it("fails after the bounded propagation window", async () => {
    const { count, result } = await runPublish({ publicAfter: 0, version: "0.1.3-rc.1" });

    assert.equal(result.status, 1);
    assert.equal(count, 37);
    assert.match(result.stderr, /did not become public within 180 seconds/);
  });
});
