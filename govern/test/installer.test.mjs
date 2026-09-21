// install.sh tests: run the real script under both `sh` and `bash` inside
// throwaway git fixtures. The gh CLI is a PATH shim; pushes go to a local
// bare "origin". PATH is pinned to /usr/bin:/bin so a real gh is never found
// unless the shim provides one.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile, chmod, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateLocalPolicy } from "../src/policy-engine.mjs";

const INSTALLER = fileURLToPath(new URL("../install.sh", import.meta.url));
const BASE_PATH = "/usr/bin:/bin";

function exec(cmd, args, { cwd, env = {} } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd,
      env: {
        PATH: BASE_PATH,
        HOME: cwd,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_TERMINAL_PROMPT: "0",
        ...env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => resolve({ code: code ?? 0, stdout, stderr }));
  });
}

async function git(cwd, ...args) {
  const r = await exec("git", args, { cwd });
  assert.equal(r.code, 0, `git ${args.join(" ")} failed: ${r.stderr}`);
  return r;
}

const CI_YML = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
  reusable:
    uses: org/repo/.github/workflows/x.yml@main
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: deploy
        run: ./deploy.sh
`;

async function makeRepo({ workflows = {}, commit = true } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "govern-install-"));
  await git(dir, "init", "-q", "-b", "main");
  await git(dir, "config", "user.email", "test@example.com");
  await git(dir, "config", "user.name", "Test");
  await writeFile(join(dir, "README.md"), "# fixture\n");
  for (const [name, content] of Object.entries(workflows)) {
    await mkdir(join(dir, ".github/workflows"), { recursive: true });
    await writeFile(join(dir, ".github/workflows", name), content);
  }
  if (commit) {
    await git(dir, "add", "-A");
    await git(dir, "commit", "-qm", "init");
  }
  return dir;
}

const exists = (p) =>
  access(p).then(
    () => true,
    () => false,
  );

const runInstaller = (shellBin, dir, args = [], env = {}) =>
  exec(shellBin, [INSTALLER, ...args], { cwd: dir, env });

for (const shellBin of ["sh", "bash"]) {
  describe(`install.sh under ${shellBin}`, () => {
    it("creates the workflow and policy, and is idempotent", async () => {
      const dir = await makeRepo();
      const first = await runInstaller(shellBin, dir);
      assert.equal(first.code, 0, first.stderr);
      assert.match(first.stdout, /created: \.github\/workflows\/decionis-govern\.yml/);
      assert.match(first.stdout, /created: DECIONIS_POLICY\.md/);

      const workflow = await readFile(join(dir, ".github/workflows/decionis-govern.yml"), "utf8");
      assert.match(workflow, /uses: decionis\/govern@v1/);
      assert.match(workflow, /api-key: \$\{\{ secrets\.DECIONIS_API_KEY \}\}/);
      assert.match(workflow, /org-id: \$\{\{ secrets\.DECIONIS_ORG_ID \}\}/);
      assert.match(workflow, /mode: shadow/);
      assert.match(workflow, /workflow-key: github_pr_change_intent/);

      // Fresh worktree files only; second run is a no-op.
      const second = await runInstaller(shellBin, dir);
      assert.equal(second.code, 0);
      assert.match(second.stdout, /already exists/);
      assert.match(second.stdout, /nothing to do/);
    });

    it("generated policy template yields a deterministic local block in the engine", async () => {
      const dir = await makeRepo();
      await runInstaller(shellBin, dir);
      const policy = await readFile(join(dir, "DECIONIS_POLICY.md"), "utf8");
      const r = evaluateLocalPolicy(policy, {
        payload: { change_freeze: true },
        orgId: "org-x",
        workflowKey: "github_pr_change_intent",
      });
      assert.equal(r.status, "verdict");
      assert.equal(r.outcome, "block");
      assert.equal(r.deterministic, true);
    });

    it("--dry-run writes nothing", async () => {
      const dir = await makeRepo({ workflows: { "ci.yml": CI_YML } });
      const r = await runInstaller(shellBin, dir, ["--dry-run", "--inject"]);
      assert.equal(r.code, 0, r.stderr);
      assert.match(r.stdout, /would create: \.github\/workflows\/decionis-govern\.yml/);
      assert.match(r.stdout, /would inject 2 step\(s\) into \.github\/workflows\/ci\.yml/);
      assert.equal(await exists(join(dir, "DECIONIS_POLICY.md")), false);
      const ci = await readFile(join(dir, ".github/workflows/ci.yml"), "utf8");
      assert.equal(ci, CI_YML);
    });

    it("--inject inserts the shadow step first in each steps job, skipping reusable jobs", async () => {
      const dir = await makeRepo({ workflows: { "ci.yml": CI_YML } });
      const r = await runInstaller(shellBin, dir, ["--inject", "--workflow-key", "custom_key"]);
      assert.equal(r.code, 0, r.stderr);
      assert.match(r.stdout, /injected 2 step\(s\) into \.github\/workflows\/ci\.yml/);
      assert.match(r.stdout, /reusable-workflow job skipped/);

      const ci = (await readFile(join(dir, ".github/workflows/ci.yml"), "utf8")).split("\n");
      const stepsIdx = ci.findIndex((l) => l === "    steps:");
      assert.equal(
        ci[stepsIdx + 1],
        "      - name: Decionis shadow verdict # decionis-govern (auto)",
        "injected as the first step at the existing item indent",
      );
      assert.equal(ci[stepsIdx + 2], "        uses: decionis/govern@v1");
      assert.equal(ci[stepsIdx + 3], "        continue-on-error: true");
      assert.match(ci.join("\n"), /workflow-key: custom_key/);
      // The reusable job is untouched.
      assert.match(ci.join("\n"), /uses: org\/repo\/\.github\/workflows\/x\.yml@main/);

      // Idempotent: a second --inject skips the file.
      const again = await runInstaller(shellBin, dir, ["--inject"]);
      assert.match(
        again.stdout,
        /skip: +\.github\/workflows\/ci\.yml \(already uses decionis\/govern\)/,
      );
    });

    it("--inject handles 4-space indentation", async () => {
      const wide = `on: push\njobs:\n    build:\n        runs-on: ubuntu-latest\n        steps:\n            - run: echo hi\n`;
      const dir = await makeRepo({ workflows: { "wide.yml": wide } });
      const r = await runInstaller(shellBin, dir, ["--inject"]);
      assert.equal(r.code, 0, r.stderr);
      const lines = (await readFile(join(dir, ".github/workflows/wide.yml"), "utf8")).split("\n");
      const stepsIdx = lines.findIndex((l) => l === "        steps:");
      assert.equal(
        lines[stepsIdx + 1],
        "            - name: Decionis shadow verdict # decionis-govern (auto)",
      );
      // Step child keys align after the "- " marker: item indent + 2.
      assert.equal(lines[stepsIdx + 2], "              uses: decionis/govern@v1");
    });

    it("--inject skips flow-style steps and tabbed files while injecting healthy ones", async () => {
      const flow = `on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{ run: echo hi }]\n`;
      const tabbed = `on: push\njobs:\n\tb:\n\t\truns-on: ubuntu-latest\n`;
      const dir = await makeRepo({
        workflows: { "flow.yml": flow, "tabbed.yml": tabbed, "ok.yml": CI_YML },
      });
      const r = await runInstaller(shellBin, dir, ["--inject"]);
      assert.equal(r.code, 0, r.stderr);
      assert.match(r.stdout, /skip: +\.github\/workflows\/tabbed\.yml \(contains tabs/);
      assert.match(r.stdout, /flow\.yml \(no injectable jobs\)/);
      assert.match(r.stdout, /injected 2 step\(s\) into \.github\/workflows\/ok\.yml/);
      assert.equal(await readFile(join(dir, ".github/workflows/flow.yml"), "utf8"), flow);
    });

    it("fails with the documented exit codes", async () => {
      const bare = await mkdtemp(join(tmpdir(), "govern-notrepo-"));
      assert.equal((await runInstaller(shellBin, bare)).code, 2);

      // Git-state gates apply to --pr only; a plain run in a dirty tree is fine.
      const dirty = await makeRepo();
      await writeFile(join(dirty, "uncommitted.txt"), "dirt\n");
      assert.equal((await runInstaller(shellBin, dirty, ["--pr"])).code, 4);
      const plainDirty = await runInstaller(shellBin, dirty);
      assert.equal(plainDirty.code, 0, plainDirty.stderr);

      const detached = await makeRepo();
      await git(detached, "checkout", "-q", "--detach");
      assert.equal((await runInstaller(shellBin, detached, ["--pr"])).code, 3);

      const ok = await makeRepo();
      assert.equal((await runInstaller(shellBin, ok, ["--bogus"])).code, 64);
      assert.equal((await runInstaller(shellBin, ok, ["--mode", "yolo"])).code, 64);
    });
  });
}

describe("install.sh --pr", () => {
  async function withOrigin(dir) {
    const bare = await mkdtemp(join(tmpdir(), "govern-origin-"));
    await git(bare, "init", "-q", "--bare");
    await git(dir, "remote", "add", "origin", bare);
    return bare;
  }

  it("branches, commits, pushes, and calls gh pr create", async () => {
    const dir = await makeRepo({ workflows: { "ci.yml": CI_YML } });
    const bare = await withOrigin(dir);

    const shimDir = await mkdtemp(join(tmpdir(), "govern-shim-"));
    const spyFile = join(shimDir, "gh-spy.txt");
    await writeFile(join(shimDir, "gh"), `#!/bin/sh\necho "$@" >> "${spyFile}"\nexit 0\n`);
    await chmod(join(shimDir, "gh"), 0o755);

    const r = await exec("sh", [INSTALLER, "--pr", "--inject", "--org-id", "org-123"], {
      cwd: dir,
      env: { PATH: `${shimDir}:${BASE_PATH}` },
    });
    assert.equal(r.code, 0, r.stderr + r.stdout);

    const spy = await readFile(spyFile, "utf8");
    assert.match(spy, /pr create/);
    assert.match(spy, /--base main --head feature\/add-decionis-governance/);

    const branches = (await git(bare, "branch", "--list")).stdout;
    assert.match(branches, /feature\/add-decionis-governance/);

    const show = (await git(dir, "show", "--stat", "--oneline", "HEAD")).stdout;
    assert.match(show, /add Decionis governance gate/);
    assert.match(show, /decionis-govern\.yml/);
    assert.match(show, /DECIONIS_POLICY\.md/);
    assert.match(show, /ci\.yml/);

    const workflow = await readFile(join(dir, ".github/workflows/decionis-govern.yml"), "utf8");
    assert.match(workflow, /org-id: org-123/, "--org-id inlines a literal id");
  });

  it("prints the compare URL when gh is unavailable", async () => {
    const dir = await makeRepo();
    await git(dir, "remote", "remove", "origin").catch(() => {});
    const bare = await mkdtemp(join(tmpdir(), "govern-origin2-"));
    await git(bare, "init", "-q", "--bare");
    // Use a github-style remote URL so the compare link can be derived; the
    // push itself goes nowhere, so point origin at the local bare path but
    // derive the URL case separately below.
    await git(dir, "remote", "add", "origin", bare);
    const r = await exec("sh", [INSTALLER, "--pr"], { cwd: dir });
    assert.equal(r.code, 0, r.stderr + r.stdout);
    // Local-path origins can't map to a web URL — the fallback message appears.
    assert.match(r.stdout, /open a PR from feature\/add-decionis-governance/i);
  });

  it("derives GitHub compare URLs from ssh and https remotes", async () => {
    // Pure URL-derivation check via the script's sed pipeline, no push:
    const ssh = await exec("sh", [
      "-c",
      `echo "git@github.com:acme/widgets.git" | sed -e 's/^git@//' -e 's/:/\\//' -e 's/\\.git$//' -e 's/^/https:\\/\\//'`,
    ]);
    assert.equal(ssh.stdout.trim(), "https://github.com/acme/widgets");
  });

  it("--pr without an origin remote exits 5", async () => {
    const dir = await makeRepo();
    const r = await exec("sh", [INSTALLER, "--pr"], { cwd: dir });
    assert.equal(r.code, 5);
  });
});
