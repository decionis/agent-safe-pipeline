// @ts-check
// Decionis GitHub Action — Node 20 entrypoint.
// Zero deps: uses built-in fetch + node:fs.
// Resolves a Decionis Decision Dossier for the current workflow step and
// fails the step on a `block` (or `escalate`, configurable) verdict.

import { spawn } from "node:child_process";
import { appendFile, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { isAbsolute, join } from "node:path";

import { evaluateDecision, fetchExecutionGrant, parseDecisionResponse } from "./api-client.mjs";
import { evaluateLocalPolicy } from "./policy-engine.mjs";

/** Max policy-file bytes carried inline with a decision (content over this is
 *  referenced by hash only, never silently dropped). */
const POLICY_FILE_INLINE_LIMIT = 131072; // 128 KiB

const FAIL_MODES = new Set(["block", "escalate", "block_or_escalate", "never"]);
const RUN_MODES = new Set(["enforce", "shadow"]);
const LOCAL_EVAL_MODES = new Set(["auto", "off", "strict"]);

/** Default for the `local-eval` input — the one-line switch for fast-path semantics. */
export const DEFAULT_LOCAL_EVAL = "auto";
/** Longest we wait for the background pipeline after the command exits. */
export const SHADOW_GRACE_CAP_MS = 10_000;
/** Small allowance past the request-timeout budget for parsing/publishing. */
export const SHADOW_GRACE_EXTRA_MS = 2_500;
/** Bound on the best-effort dossier-recording call after a local block. */
export const BLOCK_RECORD_CAP_MS = 5_000;

/** Read an Action input (GitHub maps inputs to env vars). */
function getInput(name, { required = false } = {}) {
  const envKey = `INPUT_${name.toUpperCase().replace(/-/g, "_")}`;
  const value = process.env[envKey];
  if (value === undefined || value === "") {
    if (required) throw new Error(`Decionis: missing required input '${name}'`);
    return "";
  }
  return value;
}

function getBooleanInput(name, fallback = false) {
  const raw = getInput(name).trim().toLowerCase();
  if (raw === "") return fallback;
  return raw === "true" || raw === "1" || raw === "yes";
}

/** GitHub log commands — these render nicely in the Action log. */
function logGroup(title, body) {
  console.log(`::group::${title}`);
  console.log(body);
  console.log("::endgroup::");
}
function logError(message) {
  console.log(`::error::${message}`);
}
function logWarning(message) {
  console.log(`::warning::${message}`);
}
function logNotice(message) {
  console.log(`::notice::${message}`);
}

/** Set a GitHub Action output (file-based, the v2 mechanism). */
async function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (!outputFile) return; // running locally, just no-op
  const safe = value === null || value === undefined ? "" : String(value);
  // Use heredoc syntax so multiline values are safe.
  const delim = `__DECIONIS_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  await appendFile(outputFile, `${name}<<${delim}\n${safe}\n${delim}\n`);
}

/** Write to the run summary (markdown rendered on the run page). */
async function writeSummary(markdown) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryFile) return;
  await appendFile(summaryFile, markdown + "\n");
}

/**
 * Build a minimal payload from the GitHub workflow context when the consumer
 * didn't pass one. Honest — only includes fields actually present on the run.
 */
function buildPayloadFromContext() {
  const env = process.env;
  return {
    source: "github_actions",
    github: {
      repository: env.GITHUB_REPOSITORY ?? null,
      ref: env.GITHUB_REF ?? null,
      sha: env.GITHUB_SHA ?? null,
      event_name: env.GITHUB_EVENT_NAME ?? null,
      actor: env.GITHUB_ACTOR ?? null,
      run_id: env.GITHUB_RUN_ID ?? null,
      run_attempt: env.GITHUB_RUN_ATTEMPT ?? null,
      workflow: env.GITHUB_WORKFLOW ?? null,
      job: env.GITHUB_JOB ?? null,
      server_url: env.GITHUB_SERVER_URL ?? "https://github.com",
    },
  };
}

/**
 * Parse the consumer-provided payload string. Accepts JSON object or JSON
 * object inside a heredoc-style string. Falls back to context-derived payload
 * if the input is blank.
 */
export function resolvePayload(rawInput, contextBuilder = buildPayloadFromContext) {
  const trimmed = (rawInput ?? "").trim();
  if (trimmed === "") return contextBuilder();
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
    throw new Error("payload JSON must be an object");
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`Decionis: input 'payload' is not valid JSON object: ${reason}`);
  }
}

/**
 * Build the DECIONIS_POLICY.md descriptor that rides along with a decision.
 * Pure + testable: the content hash is the version handle — a changed file
 * yields a new sha256, so each policy revision is distinct and recorded.
 * Content over POLICY_FILE_INLINE_LIMIT is referenced by hash only (with
 * `truncated: true`) — never silently dropped.
 */
export function buildPolicySource(content, { path, ref = null } = {}) {
  const text = typeof content === "string" ? content : "";
  const bytes = Buffer.byteLength(text, "utf8");
  const sha256 = createHash("sha256").update(text, "utf8").digest("hex");
  const inline = bytes <= POLICY_FILE_INLINE_LIMIT;
  return {
    type: "decionis_policy_md",
    path: path ?? null,
    ref: ref ?? null,
    sha256,
    bytes,
    truncated: !inline,
    ...(inline ? { content: text } : {}),
  };
}

/**
 * Read the repo-local policy file (default DECIONIS_POLICY.md at the workspace
 * root) and return its descriptor, or null if absent/unreadable. Never throws:
 * a missing or broken policy file must not fail the gate.
 */
export async function loadPolicyFile(relPath, { workspace, ref } = {}) {
  const rel = (relPath ?? "").trim();
  if (!rel) return null;
  const root = workspace ?? process.env.GITHUB_WORKSPACE ?? process.cwd();
  const full = isAbsolute(rel) ? rel : join(root, rel);
  try {
    const content = await readFile(full, "utf8");
    return buildPolicySource(content, { path: rel, ref: ref ?? null });
  } catch {
    return null;
  }
}

/**
 * Fold the friendly `action` label into the payload without clobbering an
 * explicit `action` field the caller already set. Returns a new object.
 */
export function applyActionLabel(payload, action) {
  const label = (action ?? "").trim();
  if (!label) return payload;
  if (payload && typeof payload === "object" && "action" in payload) return payload;
  return { ...payload, action: label };
}

/**
 * Decide whether the wrapped `run` command may execute.
 *
 * This is the enforcing path — Decionis runs the command itself, so it cannot
 * execute without an authorizing verdict (no skippable `if:`). In `shadow`
 * mode the command always runs: shadow observes, it must never change behavior.
 * In `enforce` mode only an `allow` verdict permits execution.
 */
export function shouldExecute(decision, runMode) {
  if (runMode === "shadow") return true;
  return (decision ?? "").toLowerCase() === "allow";
}

/**
 * Start the gated command through the chosen shell, streaming its output.
 * Returns immediately with the child and an `exited` promise so callers can
 * run evaluation work concurrently (speculative shadow / async notarization).
 */
function startCommand(command, shell, extraEnv = {}) {
  const sh = (shell || "bash").trim() === "sh" ? "sh" : "bash";
  const args = ["-e", "-c", command];
  const child = spawn(sh, args, { stdio: "inherit", env: { ...process.env, ...extraEnv } });
  const exited = new Promise((resolve) => {
    child.on("close", (code) => resolve(code ?? 0));
    child.on("error", (err) => {
      logError(`Decionis could not run the gated command: ${err.message}`);
      resolve(1);
    });
  });
  return { child, exited };
}

/** Run the gated command to completion (enforcing path convenience). */
function executeCommand(command, shell, extraEnv = {}) {
  return startCommand(command, shell, extraEnv).exited;
}

/** Sleep helper for bounded grace waits. */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Wrap background/observe-only work: any failure becomes a `::notice::` and
 * resolves to null. Shadow mode and async notarization must never be able to
 * change the step's exit code.
 */
async function swallow(label, promise) {
  try {
    return await promise;
  } catch (err) {
    logNotice(`Decionis (non-fatal) ${label}: ${err instanceof Error ? err.message : err}`);
    return null;
  }
}

/**
 * The single decision table for how a run reaches its verdict — the branch
 * point for the `local-eval` input. Pure + testable.
 *
 * act:  "local" = a deterministic committed rule verdict gates the run;
 *       "api"   = the blocking evaluate-decision call gates it (v1.8 path).
 * api:  what happens to the network call when act=local —
 *       "none" (strict: fully offline), "background" (notarize while the
 *       command runs), "bounded" (notarize with a capped wait), or
 *       "blocking" when act=api.
 *
 * `request-grant: true` always forces the blocking path: the signed grant
 * must exist before the command's environment is built.
 */
export function planEvaluation({ localOutcome, localEval, requestGrant, hasRunCommand }) {
  const deterministic = Boolean(localOutcome?.deterministic);
  if (!deterministic || localEval === "off" || requestGrant) {
    return { act: "api", api: "blocking" };
  }
  if (localEval === "strict") return { act: "local", api: "none" };
  if (localOutcome.outcome === "block") return { act: "local", api: "bounded" };
  return { act: "local", api: hasRunCommand ? "background" : "bounded" };
}

/**
 * Grace budget for the background pipeline after the command exits: whatever
 * remains of the request-timeout budget plus a small parsing allowance,
 * capped so a fast command never waits long on a slow API.
 */
export function computeGraceMs(pipelineStartMs, nowMs, timeoutMs) {
  const remaining = Math.max(timeoutMs - (nowMs - pipelineStartMs), 0);
  return Math.min(remaining + SHADOW_GRACE_EXTRA_MS, SHADOW_GRACE_CAP_MS);
}

/**
 * Timing instrumentation: the speedups from local evaluation and speculative
 * execution must be visible in the log, not just real.
 */
export function createTimeline(t0 = performance.now()) {
  const events = [];
  const fmt = (ms) => (ms >= 10_000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms)}ms`);
  return {
    events,
    mark(label, detail) {
      events.push({ label, detail: detail ?? null, at: performance.now() - t0 });
    },
    render() {
      if (events.length === 0) return "Decionis timing — no events recorded";
      const parts = events.map((e) => `${e.label}${e.detail ? ` ${e.detail}` : ""} +${fmt(e.at)}`);
      return `Decionis timing — ${parts.join(" · ")}`;
    },
  };
}

/**
 * Build the execution-grant issue request body. Pure + testable. The grant
 * binds the authorization to this org, dossier, action, and the repo@sha that
 * triggered the run, so a target can verify exactly what was authorized.
 */
export function buildGrantRequestBody({ orgId, dossierId, decision, action, audience }) {
  const repo = process.env.GITHUB_REPOSITORY ?? null;
  const sha = process.env.GITHUB_SHA ?? null;
  const subject = repo && sha ? `${repo}@${sha}` : (repo ?? undefined);
  return {
    org_id: orgId,
    dossier_id: dossierId,
    outcome: decision,
    ...(action ? { action } : {}),
    ...(audience ? { audience } : {}),
    ...(subject ? { subject } : {}),
  };
}

/** Decide whether a given verdict should fail the step under the configured mode. */
export function shouldFail(decision, failOn, runMode) {
  if (runMode === "shadow") return false;
  const d = (decision ?? "").toLowerCase();
  if (failOn === "never") return false;
  if (failOn === "block") return d === "block" || d === "deny" || d === "denied";
  if (failOn === "escalate") return d === "escalate" || d === "review";
  if (failOn === "block_or_escalate") {
    return d === "block" || d === "deny" || d === "denied" || d === "escalate" || d === "review";
  }
  // Unknown fail-on values are treated as the default (block).
  return d === "block" || d === "deny" || d === "denied";
}

/**
 * Build the canonical public verify URL (with `?sig=` for the OG card).
 * When a policy sha256 is provided, the link additionally pins the exact
 * repo-policy revision the decision was made under (`&policy=sha256:<hash>`)
 * — an additive query parameter the server is free to ignore.
 */
export function buildVerifyUrl(siteBase, dossierId, signature, { policySha256 } = {}) {
  const base = siteBase.replace(/\/$/, "");
  const id = encodeURIComponent(dossierId);
  const params = [];
  if (signature) params.push(`sig=${encodeURIComponent(signature)}`);
  params.push("source=github_actions");
  if (policySha256) params.push(`policy=${encodeURIComponent(`sha256:${policySha256}`)}`);
  return `${base}/verify/decision-dossiers/${id}?${params.join("&")}`;
}

// ───────────────────────── Growth / virality surface ─────────────────────────
// The PR comment, the run summary, and the embeddable badge are the surfaces
// every reviewer and downstream repo sees. They carry a signed verify link plus
// soft attribution back to the action so adoption compounds (each governed repo
// becomes a billboard). Attribution is on by default but a single input turns
// it off for teams that want a bare comment.

const ACTION_URL = "https://github.com/decionis/govern";
const BRAND_URL = "https://decionis.com";
const COMMENT_MARKER = "<!-- decionis-govern -->";

/** Map a raw verdict to display theme + shields.io color (no leading #). */
export function verdictTheme(decision) {
  const d = (decision ?? "").toLowerCase();
  if (d === "allow") return { emoji: "✅", label: "Allowed", color: "2ea043" };
  if (d === "block" || d === "deny" || d === "denied")
    return { emoji: "🛑", label: "Blocked", color: "d1242f" };
  if (d === "escalate" || d === "review")
    return { emoji: "⚠️", label: "Escalate", color: "bf8700" };
  if (d === "restrain" || d === "restrained")
    return { emoji: "✋", label: "Restrained", color: "9a6700" };
  return { emoji: "🛡️", label: decision || "Unknown", color: "6D28D9" };
}

/** Verdict shield image URL — rendered at the top of the PR comment + summary. */
export function verdictBadgeUrl(decision) {
  const t = verdictTheme(decision);
  return `https://img.shields.io/badge/Decionis-${encodeURIComponent(
    t.label,
  )}-${t.color}?style=for-the-badge&logo=shield&logoColor=white`;
}

/**
 * The embeddable "Governed by Decionis" badge — the viral artifact. Devs drop
 * it into their own README; every adopting repo links back to the action.
 * When a verify URL is available it links to the live signed proof.
 */
export function governedByBadgeMarkdown(linkUrl = ACTION_URL) {
  const img =
    "https://img.shields.io/badge/Governed%20by-Decionis-6D28D9?logo=shield&logoColor=white";
  return `[![Governed by Decionis](${img})](${linkUrl})`;
}

/**
 * Build the PR comment body. Pure + testable. Carries a hidden marker so the
 * comment is updated in place (no comment spam across pushes).
 */
export function buildPrCommentBody({
  decision,
  dossierId,
  verifyUrl,
  policyVersion,
  reasonCode,
  runMode,
  failOn,
  actionLabel = "",
  showAttribution = true,
}) {
  const t = verdictTheme(decision);
  const heading = actionLabel
    ? `### ${t.emoji} Action gate · \`${actionLabel}\` — ${t.label}`
    : `### ${t.emoji} Governed step — ${t.label}`;
  const rows = [
    `| **Verdict** | \`${decision || "unknown"}\` |`,
    policyVersion ? `| **Policy** | \`${policyVersion}\` |` : "",
    reasonCode ? `| **Reason** | \`${reasonCode}\` |` : "",
    dossierId ? `| **Dossier** | \`${dossierId}\` |` : "",
  ]
    .filter(Boolean)
    .join("\n");

  const modeNote =
    runMode === "shadow"
      ? "> 🟣 **Shadow mode** — recorded for review only. This check never fails your build."
      : `> Enforcing — this check fails the run on \`${failOn}\`.`;

  const lines = [
    COMMENT_MARKER,
    `<img alt="Decionis verdict: ${t.label}" src="${verdictBadgeUrl(decision)}" />`,
    "",
    heading,
    "",
    "| | |",
    "| --- | --- |",
    rows,
    "",
    verifyUrl
      ? `**[🔎 Verify this decision →](${verifyUrl})** — signed, tamper-evident proof.`
      : "",
    "",
    modeNote,
  ];

  if (showAttribution) {
    lines.push(
      "",
      "---",
      `<sub>🛡️ Governed by <a href="${BRAND_URL}/?source=gha_pr_comment">Decionis</a> — ` +
        `a runtime guardrail for autonomous AI agents &amp; CI/CD: gate deploys, migrations &amp; ` +
        `infra changes before they execute. ` +
        `<a href="${BRAND_URL}/quickstart?source=gha_pr_comment">Start in shadow mode in 30s →</a> ` +
        `(<a href="${ACTION_URL}"><code>decionis/govern</code></a>)</sub>`,
    );
  }

  return lines.join("\n");
}

const GH_HEADERS = (token) => ({
  Authorization: `Bearer ${token}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
});

/** Find a previously-posted Decionis comment on the PR (by hidden marker). */
async function findDecionisCommentId(repoFullName, prNumber, githubToken) {
  try {
    const res = await fetch(
      `https://api.github.com/repos/${repoFullName}/issues/${prNumber}/comments?per_page=100`,
      { headers: GH_HEADERS(githubToken) },
    );
    if (!res.ok) return null;
    const comments = await res.json();
    if (!Array.isArray(comments)) return null;
    const existing = comments.find(
      (c) => typeof c?.body === "string" && c.body.includes(COMMENT_MARKER),
    );
    return existing?.id ?? null;
  } catch {
    return null;
  }
}

/**
 * Upsert the PR comment: update our existing comment in place if present,
 * otherwise create one. Sticky-by-marker so re-runs never spam the thread —
 * a noisy bot is an uninstalled bot.
 */
async function upsertPrComment(repoFullName, prNumber, githubToken, body) {
  if (!repoFullName || !prNumber || !githubToken) return false;
  try {
    const existingId = await findDecionisCommentId(repoFullName, prNumber, githubToken);
    const url = existingId
      ? `https://api.github.com/repos/${repoFullName}/issues/comments/${existingId}`
      : `https://api.github.com/repos/${repoFullName}/issues/${prNumber}/comments`;
    const res = await fetch(url, {
      method: existingId ? "PATCH" : "POST",
      headers: GH_HEADERS(githubToken),
      body: JSON.stringify({ body }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function maybeCommentPr({
  enabled,
  decision,
  dossierId,
  verifyUrl,
  policyVersion,
  reasonCode,
  runMode,
  failOn,
  actionLabel,
  showAttribution,
}) {
  if (!enabled) return;
  if (process.env.GITHUB_EVENT_NAME !== "pull_request") return;
  const repoFullName = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  const githubToken = process.env.GITHUB_TOKEN;
  if (!repoFullName || !eventPath || !githubToken) return;
  let prNumber = null;
  try {
    const event = JSON.parse(await readFile(eventPath, "utf8"));
    prNumber = event?.pull_request?.number ?? event?.number ?? null;
  } catch {
    return;
  }
  if (!prNumber) return;
  const body = buildPrCommentBody({
    decision,
    dossierId,
    verifyUrl,
    policyVersion,
    reasonCode,
    runMode,
    failOn,
    actionLabel,
    showAttribution,
  });
  await upsertPrComment(repoFullName, prNumber, githubToken, body);
}

async function main() {
  const timeline = createTimeline();
  const actionLabel = getInput("action").trim();
  const failOnRaw = (getInput("fail-on") || "block").trim().toLowerCase();
  const failOn = FAIL_MODES.has(failOnRaw) ? failOnRaw : "block";
  const runModeRaw = (getInput("mode") || "enforce").trim().toLowerCase();
  const runMode = RUN_MODES.has(runModeRaw) ? runModeRaw : "enforce";
  const localEvalRaw = (getInput("local-eval") || DEFAULT_LOCAL_EVAL).trim().toLowerCase();
  const localEval = LOCAL_EVAL_MODES.has(localEvalRaw) ? localEvalRaw : DEFAULT_LOCAL_EVAL;
  const commentPr = getBooleanInput("comment-pr", false);
  const showAttribution = getBooleanInput("show-attribution", true);
  const runCommand = getInput("run");
  const shell = getInput("shell") || "bash";
  const requestGrant = getBooleanInput("request-grant", false);
  const grantAudience = getInput("grant-audience").trim();
  const apiBaseUrl = (getInput("api-base-url") || "https://api.decionis.com").replace(/\/$/, "");
  const siteBaseUrl = (getInput("site-base-url") || "https://decionis.com").replace(/\/$/, "");
  const timeoutMs = Number(getInput("request-timeout-ms") || "20000") || 20000;

  // ── Shadow credential grace ─────────────────────────────────────────────
  // In shadow mode a missing api-key/org-id/workflow-key must not fail the
  // step: installer-injected shadow steps stay inert until secrets exist.
  let apiKey = "";
  let orgId = "";
  let workflowKey = "";
  try {
    apiKey = getInput("api-key", { required: true });
    orgId = getInput("org-id", { required: true });
    workflowKey = getInput("workflow-key", { required: true });
  } catch (err) {
    if (runMode !== "shadow") throw err;
    logNotice(
      `Decionis shadow mode — ${err instanceof Error ? err.message : err}. ` +
        "The gate is not configured yet; nothing is recorded and shadow never fails the step.",
    );
    if (runCommand) {
      await setOutput("executed", "true");
      process.exit(await executeCommand(runCommand, shell));
    }
    process.exit(0);
  }

  const payload = applyActionLabel(resolvePayload(getInput("payload")), actionLabel);

  // DECIONIS_POLICY.md convention: read the repo-local policy file (default
  // `DECIONIS_POLICY.md` at the workspace root) and inject it into the decision
  // so the gate evaluates with — and the dossier records — your repo's policy.
  // A YAML file is also accepted: with the default path, `.yaml`/`.yml`
  // siblings are tried too. Set `policy-file: ""` to disable. Missing/unreadable
  // file never fails the gate.
  const policyFilePath = getInput("policy-file").trim();
  const policyEnforce = getBooleanInput("policy-enforce", false);
  const policyCandidates =
    policyFilePath === "DECIONIS_POLICY.md"
      ? ["DECIONIS_POLICY.md", "DECIONIS_POLICY.yaml", "DECIONIS_POLICY.yml"]
      : policyFilePath
        ? [policyFilePath]
        : [];
  let policySource = null;
  for (const candidate of policyCandidates) {
    policySource = await loadPolicyFile(candidate, { ref: process.env.GITHUB_SHA ?? null });
    if (policySource) break;
  }
  if (policySource) {
    // Opt-in GitOps enforcement: compiles the file's structured `decionis`
    // rules block into an ACTIVE enforced policy bundle server-side.
    if (policyEnforce) policySource.enforce = true;
    payload.decionis_policy = policySource;
    await setOutput("policy-sha256", policySource.sha256);
    await setOutput("policy-path", policySource.path ?? "");
    await setOutput("policy-enforced", policyEnforce ? "true" : "false");
    logGroup(
      "Decionis policy file",
      `path=${policySource.path} sha256=${policySource.sha256} bytes=${policySource.bytes}${policySource.truncated ? " (referenced by hash; over inline limit)" : ""}`,
    );
  }

  // ── Local policy engine ─────────────────────────────────────────────────
  // Evaluate the committed ```decionis rules block in-process (microseconds).
  // The engine mirrors the server evaluator and yields a deterministic
  // verdict only for an explicitly matched allow/block rule; everything else
  // reports a fallback reason and defers to the API.
  let localOutcome = null;
  if (localEval !== "off" && policySource) {
    if (policySource.truncated) {
      logNotice("Decionis local engine skipped — the policy file exceeds the inline size limit.");
    } else if (/\.ya?ml$/i.test(policySource.path ?? "")) {
      logNotice("Decionis local engine skipped — YAML policy files are evaluated by the API.");
    } else {
      localOutcome = evaluateLocalPolicy(policySource.content, { payload, orgId, workflowKey });
      timeline.mark(
        "local eval",
        `${localOutcome.status}${localOutcome.outcome ? ` '${localOutcome.outcome}'` : ""} in ${localOutcome.elapsedUs}µs`,
      );
      logGroup(
        "Decionis local policy engine",
        [
          `status=${localOutcome.status} outcome=${localOutcome.outcome ?? "—"} deterministic=${localOutcome.deterministic}`,
          `rules=${localOutcome.ruleCount} elapsed=${localOutcome.elapsedUs}µs local-eval=${localEval}`,
          localOutcome.matchedRule
            ? `rule: #${localOutcome.matchedRule.index + 1} "${localOutcome.matchedRule.name}" → ${localOutcome.matchedRule.action}`
            : "",
          localOutcome.fallbackReason ? `fallback: ${localOutcome.fallbackReason}` : "",
          localOutcome.explanation ? `why: ${localOutcome.explanation}` : "",
        ]
          .filter(Boolean)
          .join("\n"),
      );
    }
  }

  const plan = planEvaluation({
    localOutcome,
    localEval,
    requestGrant,
    hasRunCommand: Boolean(runCommand),
  });
  if (plan.act === "local") {
    logNotice(
      `⚡ Decionis local verdict '${localOutcome.outcome}' via rule "${localOutcome.matchedRule.name}" ` +
        `in ${(localOutcome.elapsedUs / 1000).toFixed(2)}ms — API roundtrip ` +
        `${plan.api === "none" ? "skipped (local-eval: strict)" : "moved off the critical path"}.`,
    );
  }

  const requestBody = {
    org_id: orgId,
    workflow_key: workflowKey,
    payload,
    mode: runMode === "shadow" ? "SHADOW" : "ENFORCE",
    source: "github_actions",
  };

  // ── Reporting state ──────────────────────────────────────────────────────
  // Single-writer discipline: finalizeReport() is the only place that writes
  // decision outputs, the (append-only) step summary, and the PR comment, and
  // it runs exactly once per run — background work only mutates `report`.
  const report = {
    decision: "",
    source: "",
    dossierId: "",
    signature: null,
    policyVersion: null,
    reasonCode: null,
    mismatch: false,
    finalized: false,
  };
  if (plan.act === "local") {
    report.decision = localOutcome.outcome;
    report.source = "local";
  }

  const abortController = new AbortController();

  const callApi = async (boundMs = timeoutMs) => {
    logGroup(
      "Decionis evaluate-decision request",
      JSON.stringify(
        {
          url: `${apiBaseUrl}/v1/protocol/evaluate-decision`,
          org_id: orgId,
          workflow_key: workflowKey,
          mode: requestBody.mode,
          fail_on: failOn,
          local_eval: localEval,
          evaluation_plan: `${plan.act}/${plan.api}`,
          payload_keys: Object.keys(payload),
        },
        null,
        2,
      ),
    );
    const startedAt = performance.now();
    const response = await evaluateDecision({
      apiBaseUrl,
      apiKey,
      body: requestBody,
      timeoutMs: boundMs,
      signal: abortController.signal,
    });
    if (!response.ok) {
      const error = new Error(`Decionis evaluate-decision failed (${response.status})`);
      // @ts-ignore — carried for the enforce-path error log
      error.status = response.status;
      // @ts-ignore
      error.bodyText = response.bodyText;
      throw error;
    }
    const parsed = parseDecisionResponse(response.data);
    timeline.mark(
      "API verdict",
      `'${parsed.decision}' in ${Math.round(performance.now() - startedAt)}ms`,
    );
    return parsed;
  };

  const adoptApiVerdict = (parsed, { authoritative }) => {
    report.dossierId = parsed.dossierId;
    report.signature = parsed.signature;
    report.policyVersion = parsed.policyVersion;
    report.reasonCode = parsed.reasonCode;
    if (authoritative) {
      report.decision = parsed.decision;
      report.source = "api";
    }
    if (
      localOutcome?.deterministic &&
      parsed.decision &&
      parsed.decision !== localOutcome.outcome
    ) {
      report.mismatch = true;
      logWarning(
        `Decionis verdict mismatch — local rule verdict '${localOutcome.outcome}'${authoritative ? "" : " (already acted on)"} ` +
          `vs API verdict '${parsed.decision}'. The signed dossier records the API verdict; ` +
          "review org-level policy or set local-eval: off for this workflow.",
      );
    }
  };

  const finalizeReport = async () => {
    if (report.finalized) return;
    report.finalized = true;
    const verifyUrl = report.dossierId
      ? buildVerifyUrl(siteBaseUrl, report.dossierId, report.signature, {
          policySha256: policySource?.sha256,
        })
      : "";
    const badgeMarkdown = governedByBadgeMarkdown(verifyUrl || ACTION_URL);
    await Promise.all([
      setOutput("decision", report.decision),
      setOutput("decision-source", report.source),
      setOutput("dossier-id", report.dossierId),
      setOutput("verify-url", verifyUrl),
      setOutput("policy-version", report.policyVersion ?? ""),
      setOutput("reason-code", report.reasonCode ?? ""),
      setOutput("badge-markdown", badgeMarkdown),
      setOutput("verdict-mismatch", report.mismatch ? "true" : "false"),
    ]);

    const theme = verdictTheme(report.decision);
    await writeSummary(
      [
        `## ${theme.emoji} Decionis Action Gate${actionLabel ? ` · \`${actionLabel}\`` : ""}: ${theme.label}`,
        "",
        `<img alt="Decionis verdict: ${theme.label}" src="${verdictBadgeUrl(report.decision)}" />`,
        "",
        "| | |",
        "| --- | --- |",
        `| **Verdict** | \`${report.decision || "unknown"}\` |`,
        report.source === "local"
          ? `| **Source** | ⚡ local rule "${localOutcome.matchedRule.name}" in ${localOutcome.elapsedUs}µs |`
          : report.source
            ? `| **Source** | \`${report.source}\` |`
            : "",
        `| **Policy** | \`${report.policyVersion ?? "—"}\` |`,
        report.reasonCode ? `| **Reason** | \`${report.reasonCode}\` |` : "",
        report.dossierId ? `| **Dossier** | \`${report.dossierId}\` |` : "",
        `| **Mode** | \`${runMode}\`${runMode === "shadow" ? " — never fails the build" : ` · fail-on \`${failOn}\``} |`,
        "",
        report.mismatch
          ? "> ⚠️ The API verdict differed from the local rule verdict (`verdict-mismatch=true`) — review org-level policy."
          : "",
        verifyUrl
          ? `**[🔎 Verify this decision →](${verifyUrl})** — signed, tamper-evident proof${policySource ? ", pinned to this repo's policy revision" : ""}.`
          : "",
        "",
        "<details><summary>📌 Add the “Governed by Decionis” badge to your README</summary>",
        "",
        "```markdown",
        governedByBadgeMarkdown(),
        "```",
        "",
        `Gate your own deploys, releases, and infra changes → [**decionis/govern**](${ACTION_URL})`,
        "</details>",
      ]
        .filter(Boolean)
        .join("\n"),
    );

    if (report.decision) {
      logNotice(
        `Decionis verdict: ${report.decision} (${report.source}${report.dossierId ? `, dossier ${report.dossierId}` : ""})`,
      );
    }

    await maybeCommentPr({
      enabled: commentPr,
      decision: report.decision,
      dossierId: report.dossierId,
      verifyUrl,
      policyVersion: report.policyVersion,
      reasonCode: report.reasonCode,
      runMode,
      failOn,
      actionLabel,
      showAttribution,
    });
  };

  // ── Branch A: speculative shadow ─────────────────────────────────────────
  // The verdict can never change behavior in shadow, so the command starts
  // IMMEDIATELY and the whole evaluation pipeline runs in the background.
  // The step's exit code is exactly the command's exit code — evaluation
  // failures are notices, never errors.
  if (runMode === "shadow" && runCommand && !requestGrant) {
    const { exited } = startCommand(runCommand, shell, {});
    timeline.mark("command started");
    logNotice(
      "🟣 Decionis shadow mode — command started immediately; the verdict resolves in the background.",
    );
    await setOutput("executed", "true");
    const pipelineStart = performance.now();
    const pipeline = swallow(
      "shadow evaluation",
      (async () => {
        if (plan.act === "local" && plan.api === "none") return; // strict: fully offline
        adoptApiVerdict(await callApi(), { authoritative: true });
      })(),
    );
    const code = await exited;
    timeline.mark("command exited", `code ${code}`);
    const graceMs = computeGraceMs(pipelineStart, performance.now(), timeoutMs);
    const pending = await Promise.race([
      pipeline.then(() => false),
      sleep(graceMs).then(() => true),
    ]);
    if (pending) {
      abortController.abort();
      logNotice(
        `Decionis shadow verdict still pending after the ${Math.round(graceMs)}ms grace window — completing with the command's exit code.`,
      );
    }
    await finalizeReport();
    logNotice(timeline.render());
    process.exit(code);
  }

  // ── Branch B: shadow, verdict-only ───────────────────────────────────────
  if (runMode === "shadow" && !runCommand && !requestGrant) {
    await swallow(
      "shadow evaluation",
      (async () => {
        if (plan.act === "local" && plan.api === "none") return;
        adoptApiVerdict(await callApi(), { authoritative: true });
      })(),
    );
    await finalizeReport();
    logNotice(timeline.render());
    return; // shadow never fails — not even on API errors
  }

  // ── Branch C/D: enforce, gated by a deterministic local verdict ──────────
  if (plan.act === "local" && runMode === "enforce") {
    if (localOutcome.outcome === "block") {
      // Best-effort dossier recording, tightly bounded: nothing is waiting to
      // run, but the block should still leave a signed audit trail.
      if (plan.api === "bounded") {
        const parsed = await swallow(
          "dossier recording",
          callApi(Math.min(timeoutMs, BLOCK_RECORD_CAP_MS)),
        );
        if (parsed) adoptApiVerdict(parsed, { authoritative: false });
      }
      await finalizeReport();
      logNotice(timeline.render());
      if (runCommand) {
        await setOutput("executed", "false");
        logError(
          `Decionis BLOCKED execution locally (rule "${localOutcome.matchedRule.name}", mode=${runMode}). ` +
            `The gated command was NOT run.${report.dossierId ? ` Dossier: ${report.dossierId}` : ""}`,
        );
        process.exit(1);
      }
      if (shouldFail("block", failOn, runMode)) {
        logError(
          `Decionis blocked this step locally (verdict=block, rule "${localOutcome.matchedRule.name}", fail-on=${failOn}).`,
        );
        process.exit(1);
      }
      return;
    }

    // Local allow.
    if (runCommand) {
      logNotice("Decionis authorized execution locally — running the gated command.");
      if (plan.api === "none") {
        await finalizeReport();
        await setOutput("executed", "true");
        timeline.mark("command started");
        const code = await executeCommand(runCommand, shell, {});
        timeline.mark("command exited", `code ${code}`);
        logNotice(timeline.render());
        process.exit(code);
      }
      // auto: start the command now, notarize while it runs.
      const { exited } = startCommand(runCommand, shell, {});
      timeline.mark("command started");
      await setOutput("executed", "true");
      const pipelineStart = performance.now();
      const pipeline = swallow(
        "notarization",
        (async () => {
          adoptApiVerdict(await callApi(), { authoritative: false });
        })(),
      );
      const code = await exited;
      timeline.mark("command exited", `code ${code}`);
      const graceMs = computeGraceMs(pipelineStart, performance.now(), timeoutMs);
      const pending = await Promise.race([
        pipeline.then(() => false),
        sleep(graceMs).then(() => true),
      ]);
      if (pending) {
        abortController.abort();
        logNotice(
          `Decionis notarization still pending after the ${Math.round(graceMs)}ms grace window — completing with the command's exit code.`,
        );
      }
      await finalizeReport();
      logNotice(timeline.render());
      process.exit(code);
    }

    // Local allow, verdict-only: notarize with a bounded wait, never fail.
    if (plan.api !== "none") {
      const parsed = await swallow("notarization", callApi());
      if (parsed) adoptApiVerdict(parsed, { authoritative: false });
    }
    await finalizeReport();
    logNotice(timeline.render());
    return; // an allow verdict never fails the step
  }

  // ── Branch E: blocking API path (v1.8 semantics) ─────────────────────────
  // Reached on: local-eval off, no/indeterminate local verdict, matched
  // escalate/restrain, request-grant, or YAML/truncated/absent policy files.
  let apiVerdict;
  try {
    apiVerdict = await callApi();
  } catch (err) {
    if (runMode === "shadow") {
      logNotice(
        `Decionis shadow mode — evaluation unavailable (${err instanceof Error ? err.message : err}); shadow never fails the step.`,
      );
      await finalizeReport();
      if (runCommand) {
        await setOutput("executed", "true");
        process.exit(await executeCommand(runCommand, shell));
      }
      return;
    }
    // @ts-ignore — status/bodyText attached by callApi for HTTP failures
    if (err?.status)
      logError(`Decionis API returned ${err.status}: ${String(err.bodyText ?? "").slice(0, 600)}`);
    throw err;
  }
  adoptApiVerdict(apiVerdict, { authoritative: true });
  await finalizeReport();

  // ── Execution Grant (Governor Layer) ────────────────────────────────────
  // On an authorizing verdict, request a short-lived signed grant. Targets
  // verify it before acting, so execution can't proceed without a Decionis
  // verdict even if the workflow gate is bypassed.
  const grantEnv = {};
  if (requestGrant && report.decision === "allow" && report.dossierId) {
    const grant = await fetchExecutionGrant({
      apiBaseUrl,
      apiKey,
      timeoutMs,
      logNotice,
      body: buildGrantRequestBody({
        orgId,
        dossierId: report.dossierId,
        decision: report.decision,
        action: actionLabel,
        audience: grantAudience,
      }),
    });
    if (grant?.execution_grant) {
      await setOutput("execution-grant", grant.execution_grant);
      await setOutput("grant-expires-at", grant.expires_at ?? "");
      grantEnv.DECIONIS_EXECUTION_GRANT = grant.execution_grant;
      grantEnv.DECIONIS_GRANT_VERIFY_URL = `${apiBaseUrl}/v1${grant.jwks_url ?? "/.well-known/decionis-execution-grant-jwks.json"}`;
      logNotice(`Execution grant issued (expires ${grant.expires_at ?? "soon"}).`);
    }
  }

  // ── Enforcing path ──────────────────────────────────────────────────────
  // When a `run` command is supplied, Decionis OWNS the execution: the command
  // runs through this Action, so it cannot execute without an authorizing
  // verdict. There is no skippable `if:` to delete. The grant (if any) is in
  // the command's env as DECIONIS_EXECUTION_GRANT for the target to verify.
  if (runCommand) {
    const authorized = shouldExecute(report.decision, runMode);
    await setOutput("executed", authorized ? "true" : "false");
    if (!authorized) {
      logError(
        `Decionis BLOCKED execution (verdict=${report.decision}, mode=${runMode}). The gated command was NOT run. Dossier: ${report.dossierId}`,
      );
      process.exit(1);
    }
    logNotice(
      runMode === "shadow"
        ? "Decionis shadow mode — running the gated command (observe-only)."
        : "Decionis authorized execution — running the gated command.",
    );
    timeline.mark("command started");
    const code = await executeCommand(runCommand, shell, grantEnv);
    timeline.mark("command exited", `code ${code}`);
    logNotice(timeline.render());
    process.exit(code);
  }

  // ── Advisory path (no `run`) ────────────────────────────────────────────
  // Verdict-only: sets outputs for a downstream `if:`. Note this guard is
  // advisory and can be removed — prefer the `run` wrapper above to enforce.
  if (shouldFail(report.decision, failOn, runMode)) {
    logError(
      `Decionis blocked this step (verdict=${report.decision}, fail-on=${failOn}, mode=${runMode}). Dossier: ${report.dossierId}`,
    );
    process.exit(1);
  }
  logNotice(timeline.render());
}

const isMain = (() => {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === new URL(process.argv[1], "file://").href;
  } catch {
    return false;
  }
})();

if (isMain) {
  main().catch((err) => {
    logError(`Decionis Action failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
