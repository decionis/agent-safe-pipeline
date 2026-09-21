import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { LocalAuthority, LOCAL_AUTHORITY_API_KEY } from "@decionis/agent-safe-pipeline/testing";

/**
 * The Go binary against the pipeline's own loopback Decionis: the fixture
 * re-hashes every binding with its own canonicalizer, validates every request
 * against the contract's strict shapes, issues the grant one claim consumes,
 * and records the finalization. What passes here is a client another
 * implementation of the contract accepts, not one that agrees with itself.
 */
const TENANT = "00000000-0000-4000-8000-000000000002";
const moduleRoot = fileURLToPath(new URL("..", import.meta.url));
let work;
let binary;
let authority;

before(async () => {
  work = await mkdtemp(join(tmpdir(), "govern-contract-"));
  binary = join(work, "govern");
  const build = spawnSync("go", ["build", "-o", binary, "./cmd/govern"], {
    cwd: moduleRoot,
    encoding: "utf8",
  });
  assert.equal(build.status, 0, build.stderr);
  authority = new LocalAuthority({ verificationLinks: true });
  await authority.start();
});

after(async () => {
  await authority?.stop();
  if (work) await rm(work, { recursive: true, force: true });
});

/** Runs `govern run` as a GitHub Actions step would, against the loopback authority. */
async function govern(args, { mode = "enforce", amountMinor = 100, extraEnv = {} } = {}) {
  const dir = await mkdtemp(join(work, "step-"));
  const outputs = join(dir, "outputs");
  const summary = join(dir, "summary.md");
  await writeFile(outputs, "");
  // The authority lives in this process, so the step is awaited, never
  // spawned synchronously: a blocked event loop would be an unreachable authority.
  const result = await exec(binary, ["run", "--report", join(dir, "report.json"), ...args], {
    cwd: dir,
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "synthetic-org/synthetic-repo",
      GITHUB_REF: "refs/heads/main",
      GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567",
      GITHUB_RUN_ID: "1",
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_JOB: "deploy",
      GITHUB_WORKFLOW_REF:
        "synthetic-org/synthetic-repo/.github/workflows/deploy.yml@refs/heads/main",
      GITHUB_SERVER_URL: "https://github.example",
      GITHUB_OUTPUT: outputs,
      GITHUB_STEP_SUMMARY: summary,
      GITHUB_WORKSPACE: dir,
      GOVERN_MODE: mode,
      GOVERN_ACTION: "production-deploy",
      GOVERN_PAYLOAD: JSON.stringify({ amountMinor }),
      DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
      DECIONIS_TENANT_ID: TENANT,
      DECIONIS_API_URL: authority.baseUrl,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      ...extraEnv,
    },
  });
  const report = JSON.parse(await readFile(join(dir, "report.json"), "utf8"));
  return {
    ...result,
    outputs: parseOutputs(await readFile(outputs, "utf8")),
    summary: await readFile(summary, "utf8"),
    report,
  };
}

function exec(file, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, options);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

function parseOutputs(text) {
  const outputs = {};
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const [name, delimiter] = lines[i].split("<<");
    if (delimiter === undefined) continue;
    const value = [];
    for (i += 1; i < lines.length && lines[i] !== delimiter; i += 1) value.push(lines[i]);
    outputs[name] = value.join("\n");
  }
  return outputs;
}

const since = (mark) => authority.requests.slice(mark);

describe("govern against the loopback Decionis", () => {
  it("in enforcement, an ALLOW is claimed before the command runs and finalized after it", async () => {
    const mark = authority.requests.length;
    const run = await govern([
      "--",
      "sh",
      "-c",
      "echo attested:${DECIONIS_CLAIM_ATTESTATION%%.*} decision:$DECIONIS_DECISION_ID",
    ]);
    assert.equal(run.status, 0, run.stdout + run.stderr);
    const paths = since(mark).map((request) => `${request.method} ${request.path}`);
    assert.deepEqual(paths.slice(0, 3), [
      "POST /v1/authority/enforce-and-bind",
      "POST /v1/execution/claim-token",
      "POST /v1/execution/finalize-token",
    ]);
    assert.match(paths[3], /^GET \/v1\/protocol\/dossiers\//);
    const enforce = since(mark)[0];
    assert.equal(
      enforce.recomputedHash,
      enforce.body.intent_hash,
      "the fixture's own hash of the binding agrees",
    );
    assert.equal(enforce.headers["idempotency-key"], enforce.body.intent_id);
    assert.equal(enforce.body.mode, "ENFORCEMENT");
    assert.equal(enforce.body.downstream_target.system, "github_actions");
    assert.equal(enforce.body.actor.type, "WORKFLOW");
    assert.match(run.stdout, /attested:eyJ/, "the claim attestation reached the command");
    assert.match(run.stdout, /decision:synthetic-decision-/);
    const [grant] = authority.grants.values();
    assert.equal(grant.claimed, true);
    assert.equal(grant.finalized, "COMMITTED");
    assert.equal(run.outputs.decision, "ALLOW");
    assert.equal(run.outputs.executed, "true");
    assert.equal(run.outputs.claimed, "true");
    assert.equal(run.outputs.finalization, "RECORDED");
    assert.ok(
      run.outputs["verify-url"].startsWith(`${authority.baseUrl}/verify/`),
      run.outputs["verify-url"],
    );
    assert.equal(run.report.dossier.fetched, true);
    assert.equal(run.report.dossier.issuer_tier, "synthetic_loopback");
    assert.match(run.summary, /Allowed/);
  });

  it("in enforcement, a BLOCK never runs the command and claims nothing", async () => {
    const mark = authority.requests.length;
    const grants = authority.grants.size;
    const run = await govern(["--", "sh", "-c", "echo ran-$((1+1))"], { amountMinor: 500_000 });
    assert.equal(run.status, 1);
    assert.doesNotMatch(run.stdout, /ran-2/);
    assert.equal(
      since(mark).filter((request) => request.path === "/v1/execution/claim-token").length,
      0,
    );
    assert.equal(authority.grants.size, grants);
    assert.equal(run.outputs.decision, "BLOCK");
    assert.equal(run.outputs.executed, "false");
    assert.match(run.stdout, /::error::Decionis BLOCKED execution/);
  });

  it("in enforcement, a managed ESCALATE holds the step until the approval, then runs", async () => {
    authority.scriptNextManagedLifecycle(["AWAITING_APPROVER", "PRESENCE_VERIFIED", "GRANT_READY"]);
    const mark = authority.requests.length;
    const run = await govern(["--", "sh", "-c", "exit 3"], {
      amountMinor: 50_000,
      extraEnv: { GOVERN_ESCALATION: "managed", GOVERN_APPROVER_ROLE: "RELEASE_MANAGER" },
    });
    assert.equal(run.status, 3, run.stdout);
    const paths = since(mark).map(
      (request) =>
        `${request.method} ${request.path.replace(/synthetic-escalation-[^/]+/, "<id>")}`,
    );
    assert.equal(paths[0], "POST /v1/authority/enforce-and-bind");
    assert.equal(paths.filter((path) => path === "GET /v1/authority/escalations/<id>").length, 3);
    assert.ok(paths.includes("POST /v1/execution/claim-token"));
    assert.ok(paths.includes("POST /v1/execution/finalize-token"));
    assert.equal(since(mark)[0].body.escalation.mode, "MANAGED");
    assert.equal(since(mark)[0].body.escalation.approver.role_id, "RELEASE_MANAGER");
    assert.equal(run.outputs.decision, "ALLOW");
    assert.equal(run.outputs.outcome, "FAILED");
    assert.equal(run.report.escalation.final_status, "GRANT_READY");
  });

  it("in shadow, the command runs first and the verdict is recorded without a grant", async () => {
    const mark = authority.requests.length;
    const grants = authority.grants.size;
    const run = await govern(["--", "sh", "-c", "exit 4"], {
      mode: "shadow",
      amountMinor: 500_000,
    });
    assert.equal(run.status, 4);
    const enforce = since(mark).find(
      (request) => request.path === "/v1/authority/enforce-and-bind",
    );
    assert.equal(enforce.body.mode, "SHADOW");
    assert.equal(enforce.recomputedHash, enforce.body.intent_hash);
    assert.equal(authority.grants.size, grants);
    assert.equal(run.outputs.decision, "BLOCK");
    assert.equal(run.outputs.executed, "true");
    assert.equal(run.outputs["exit-code"], "4");
    assert.match(run.summary, /Shadow/);
  });

  it("a verdict-only step follows fail-on", async () => {
    const held = await govern(["--fail-on", "block_or_escalate"], { amountMinor: 50_000 });
    assert.equal(held.status, 1);
    assert.equal(held.outputs.decision, "ESCALATE");
    const passed = await govern(["--fail-on", "never"], { amountMinor: 500_000 });
    assert.equal(passed.status, 0);
    assert.equal(passed.outputs.decision, "BLOCK");
  });

  it("carries the repository policy file's hash in the intent", async () => {
    const mark = authority.requests.length;
    const dir = await mkdtemp(join(work, "policy-"));
    await writeFile(join(dir, "DECIONIS_POLICY.md"), "# Synthetic policy\n");
    const run = await govern([], { mode: "shadow", extraEnv: { GOVERN_WORKSPACE: dir } });
    assert.equal(run.status, 0);
    const described = since(mark)[0].body.context.decionis_policy;
    assert.equal(described.path, "DECIONIS_POLICY.md");
    assert.equal(described.sha256, run.outputs["policy-sha256"]);
    assert.equal(run.report.policy.bytes, 19);
  });
});
