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

async function runPublish(target, returnedDigest = digest) {
  const directory = await mkdtemp(join(tmpdir(), "agentcore-publish-test-"));
  const callsPath = join(directory, "calls");
  const outputPath = join(directory, "output");
  try {
    await writeFile(callsPath, "");
    await writeFile(outputPath, "");
    await writeFile(
      join(directory, "aws"),
      '#!/bin/sh\nprintf "aws %s\\n" "$*" >> "$TEST_CALLS"\nprintf "synthetic-password\\n"\n',
      { mode: 0o700 },
    );
    await writeFile(
      join(directory, "docker"),
      '#!/bin/sh\nprintf "docker %s\\n" "$*" >> "$TEST_CALLS"\ncase "$1" in login) cat >/dev/null;; buildx) if [ "$2" = imagetools ]; then printf \'"%s"\\n\' "$TEST_DIGEST"; fi;; esac\n',
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
        TEST_DIGEST: returnedDigest,
        VERSION: "0.1.3",
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

  it("publishes arm64 and exposes the exact digest for attestation", async () => {
    const { result, calls, output } = await runPublish(repository);
    assert.equal(result.status, 0, result.stderr);
    assert.match(calls, /--platform linux\/arm64 --provenance=false --push/);
    assert.ok(calls.includes(`-t ${repository}:0.1.3 .`));
    assert.equal(output, `name=${repository}\ndigest=${digest}\n`);
  });

  it("refuses an invalid registry digest instead of attesting it", async () => {
    const { result, output } = await runPublish(repository, "not-a-digest");
    assert.notEqual(result.status, 0);
    assert.equal(output, "");
  });
});
