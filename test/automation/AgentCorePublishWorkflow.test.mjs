import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { parse } from "yaml";

const workflow = parse(
  await readFile(
    new URL("../../.github/workflows/commerce-mcp-agentcore.yml", import.meta.url),
    "utf8",
  ),
);
const steps = workflow.jobs.image.steps;
const publish = steps.find((step) => step.id === "publish");
const repository = "709825985650.dkr.ecr.us-east-1.amazonaws.com/decionis/test-agent";
const digest = `sha256:${"a".repeat(64)}`;

async function runPublish(target, existingDigest = "", returnedDigest = digest) {
  const directory = await mkdtemp(join(tmpdir(), "agentcore-publish-test-"));
  const callsPath = join(directory, "calls");
  const outputPath = join(directory, "output");
  const inspectionsPath = join(directory, "inspections");
  try {
    await writeFile(callsPath, "");
    await writeFile(outputPath, "");
    await writeFile(inspectionsPath, "0");
    await writeFile(
      join(directory, "aws"),
      '#!/bin/sh\nprintf "aws %s\\n" "$*" >> "$TEST_CALLS"\nprintf "synthetic-password\\n"\n',
      { mode: 0o700 },
    );
    await writeFile(
      join(directory, "docker"),
      [
        "#!/bin/sh",
        'printf "docker %s\\n" "$*" >> "$TEST_CALLS"',
        'case "$1" in',
        "  login) cat >/dev/null ;;",
        '  buildx) if [ "$2" = imagetools ]; then',
        '    count=$(cat "$TEST_INSPECTIONS")',
        '    if [ "$count" -eq 0 ]; then value="$TEST_EXISTING_DIGEST"; else value="$TEST_DIGEST"; fi',
        '    printf \'"%s"\\n\' "$value"',
        '    echo $((count + 1)) > "$TEST_INSPECTIONS"',
        "  fi ;;",
        "esac",
        "",
      ].join("\n"),
      { mode: 0o700 },
    );
    const result = spawnSync("bash", ["-c", publish.run], {
      encoding: "utf8",
      env: {
        PATH: `${directory}:/usr/bin:/bin`,
        AWS_REGION: "us-east-1",
        GITHUB_OUTPUT: outputPath,
        GITHUB_SHA: "synthetic-sha",
        REPOSITORY: target,
        TEST_CALLS: callsPath,
        TEST_EXISTING_DIGEST: existingDigest,
        TEST_DIGEST: returnedDigest,
        TEST_INSPECTIONS: inspectionsPath,
        VERSION: "0.1.4",
      },
    });
    return {
      result,
      calls: await readFile(callsPath, "utf8"),
      output: await readFile(outputPath, "utf8"),
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("AgentCore Marketplace image publication", () => {
  it("restricts publication to master and places the shadow gate before the push", () => {
    assert.equal(
      workflow.jobs.image.if,
      "${{ inputs.mode != 'publish' || github.ref == 'refs/heads/master' }}",
    );
    const gateIndex = steps.findIndex((step) => step.name === "Decionis Action Gate (shadow)");
    assert.ok(gateIndex >= 0 && gateIndex < steps.indexOf(publish));
    assert.equal(steps[gateIndex].with.mode, "shadow");
    assert.equal(steps[gateIndex]["continue-on-error"], true);
  });

  it("refuses repositories outside the exact Marketplace registry and seller prefix", async () => {
    for (const target of [
      "",
      "709825985650.dkr.ecr.us-west-2.amazonaws.com/decionis/test-agent",
      "123456789012.dkr.ecr.us-east-1.amazonaws.com/decionis/test-agent",
      "709825985650.dkr.ecr.us-east-1.amazonaws.com/other/test-agent",
      `${repository};echo unexpected`,
    ]) {
      const { result, calls, output } = await runPublish(target);
      assert.notEqual(result.status, 0, target);
      assert.equal(calls, "", target);
      assert.equal(output, "", target);
    }
  });

  it("publishes an arm64 immutable version tag and exposes its exact digest for attestation", async () => {
    const { result, calls, output } = await runPublish(repository);
    assert.equal(result.status, 0, result.stderr);
    assert.match(calls, /--platform linux\/arm64 --provenance=false --push/);
    assert.ok(calls.includes(`-t ${repository}:0.1.4 .`));
    assert.ok(!calls.includes(":latest"));
    assert.equal(output, `name=${repository}\ndigest=${digest}\n`);
  });

  it("refuses an invalid registry digest instead of attesting it", async () => {
    const { result, output } = await runPublish(repository, "", "not-a-digest");
    assert.notEqual(result.status, 0);
    assert.equal(output, "");
  });

  it("reuses an existing immutable version tag without retagging it", async () => {
    const { result, calls, output } = await runPublish(repository, digest);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(calls.includes(`imagetools inspect ${repository}:0.1.4`));
    assert.ok(!calls.includes("buildx build"));
    assert.ok(!calls.includes(":latest"));
    assert.equal(output, `name=${repository}\ndigest=${digest}\n`);
  });
});
