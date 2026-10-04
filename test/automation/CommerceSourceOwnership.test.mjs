import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const root = fileURLToPath(new URL("../../", import.meta.url));
const read = (path) => readFile(join(root, path), "utf8");
const sourceCommit = "087b591a19464ecfe0f8b33cac113cc6757944e6";
const indexes = ["packages/commerce-mcp", "packages/commerce-mcp-claude-extension"];
const publisherPath = ".github/workflows/commerce-mcp-npm-publish.yml";

describe("Commerce source ownership", () => {
  it("keeps only indexes to the released source, licenses and unchanged installer", async () => {
    for (const directory of indexes) {
      assert.deepEqual(await readdir(join(root, directory)), ["README.md"], directory);
      const document = await read(`${directory}/README.md`);
      assert.ok(
        document.includes(
          `https://github.com/decionis/agent-safe-pipeline/tree/${sourceCommit}/${directory}`,
        ),
        `${directory} must link the published source commit`,
      );
      assert.ok(
        document.includes(
          `https://github.com/decionis/agent-safe-pipeline/blob/${sourceCommit}/${directory}/LICENSE`,
        ),
        `${directory} must retain access to the released license`,
      );
      assert.match(document, /npx -y @decionis\/commerce@0\.1\.6/);
      assert.match(document, /unpublished candidate/);
      assert.match(document, /Commerce owns ongoing (?:MCP )?development/);
      assert.match(document, /https:\/\/github\.com\/mcp\/com\.decionis\/commerce-gate/);
      assert.doesNotMatch(document, /github\.com\/decionis\/Commerce\//i);
    }
  });

  it("excludes the indexes from workspace dependencies and the published-package inventory", async () => {
    const lockfile = parse(await read("pnpm-lock.yaml"));
    for (const directory of indexes) assert.equal(lockfile.importers[directory], undefined);
    const full = await read("llms-full.txt");
    const inventory = [...full.matchAll(/^- Package: (.+)$/gm)].map((match) => match[1]);
    assert.deepEqual(inventory.sort(), ["@decionis/agent-safe-pipeline", "@decionis/agentsafe"]);
    assert.ok(full.startsWith(`${(await read("llms.txt")).trim()}\n`));
    for (const [directory, name] of [
      ["packages/pipeline", "@decionis/agent-safe-pipeline"],
      ["packages/agentsafe", "@decionis/agentsafe"],
    ]) {
      assert.equal(JSON.parse(await read(`${directory}/package.json`)).name, name);
    }
    assert.doesNotMatch(await read("packages/agentsafe/Dockerfile"), /packages\/commerce-mcp/);
  });

  it("leaves no active Commerce package release or AgentCore workflow", async () => {
    const names = await readdir(join(root, ".github/workflows"));
    for (const name of [
      "commerce-mcp-agentcore.yml",
      "commerce-mcp-mcpb.yml",
      "commerce-mcp-registry-publish.yml",
    ]) {
      assert.ok(!names.includes(name), `${name} must move with Commerce's source`);
    }
    assert.ok(names.includes("deploy.yml"), "AgentSafe's release workflow must remain");
    assert.ok(names.includes("commerce-mcp-npm-publish.yml"), "publisher identity must remain");
    for (const name of names.filter((entry) => entry.endsWith(".yml"))) {
      const workflow = await read(`.github/workflows/${name}`);
      assert.doesNotMatch(
        workflow,
        /packages\/commerce-mcp|@decionis\/commerce(?:["'\s@]|$)/,
        name,
      );
    }
  });

  it("preserves AgentSafe's manual publishing safeguards at the existing workflow path", async () => {
    const workflow = parse(await read(publisherPath));
    assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
    const inputs = workflow.on.workflow_dispatch.inputs;
    assert.deepEqual(inputs.npm_package.options, ["agentsafe"]);
    assert.equal(inputs.npm_package.default, "agentsafe");
    assert.equal(inputs.mode.default, "verify");
    assert.deepEqual(inputs.mode.options, ["verify", "publish"]);
    assert.equal(inputs.npm_tag.default, "latest");
    const job = workflow.jobs.npm;
    assert.equal(job.environment, "package-publish");
    assert.match(
      job.if,
      /github\.ref == format\('refs\/heads\/\{0\}', github\.event\.repository\.default_branch\)/,
    );
    const gate = job.steps.findIndex((step) => step.name === "Decionis Action Gate (shadow)");
    const publish = job.steps.findIndex((step) => step.name === "Publish selected package");
    assert.ok(gate >= 0 && publish > gate);
    assert.equal(job.steps[gate].if, "${{ inputs.mode == 'publish' }}");
    assert.equal(job.steps[gate].with.mode, "shadow");
    assert.equal(job.steps[gate]["continue-on-error"], true);
    assert.equal(job.steps[publish].if, "${{ inputs.mode == 'publish' }}");
    assert.equal(job.steps[publish].env.NODE_AUTH_TOKEN, "${{ secrets.NPM_TOKEN }}");
    assert.match(job.steps[publish].run, /Refusing to skip or mutate the tag/);
    assert.match(
      job.steps[publish].run,
      /npm publish \\\n\s+--access public \\\n\s+--tag "\$\{NPM_TAG\}"/,
    );
    for (const step of job.steps.filter((entry) => entry.uses)) {
      assert.match(step.uses, /@[a-f0-9]{40}$/);
    }
  });

  it("resolves AgentSafe and rejects the removed Commerce selector without publishing", async () => {
    const workflow = parse(await read(publisherPath));
    const resolver = workflow.jobs.npm.steps.find((step) => step.id === "package");
    const directory = await mkdtemp(join(tmpdir(), "agentsafe-publisher-selection-"));
    try {
      const output = join(directory, "output");
      const run = (selection) =>
        spawnSync("bash", ["-c", resolver.run], {
          cwd: root,
          encoding: "utf8",
          env: { ...process.env, SELECTED_PACKAGE: selection, GITHUB_OUTPUT: output },
        });
      const selected = run("agentsafe");
      assert.equal(selected.status, 0, selected.stderr);
      const manifest = JSON.parse(await read("packages/agentsafe/package.json"));
      const result = await readFile(output, "utf8");
      assert.equal(
        result,
        `directory=packages/agentsafe\nname=@decionis/agentsafe\nversion=${manifest.version}\ngate_action=npm-publish-decionis-agentsafe\n`,
      );
      for (const selection of ["commerce-mcp", "", "agentsafe; echo unsupported"]) {
        const rejected = run(selection);
        assert.equal(rejected.status, 1, selection);
        assert.match(rejected.stdout, /Unsupported npm package selector/);
        assert.equal(
          await readFile(output, "utf8"),
          result,
          "rejection must produce no output bindings",
        );
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
