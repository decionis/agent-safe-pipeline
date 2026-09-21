import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  applyActionLabel,
  buildGrantRequestBody,
  buildPolicySource,
  buildPrCommentBody,
  buildVerifyUrl,
  governedByBadgeMarkdown,
  loadPolicyFile,
  resolvePayload,
  shouldExecute,
  shouldFail,
  verdictBadgeUrl,
  verdictTheme,
} from "../src/index.mjs";

describe("buildPolicySource", () => {
  it("hashes content; the sha256 is the version handle", () => {
    const a = buildPolicySource("# Policy\nblock prod on fridays\n", {
      path: "DECIONIS_POLICY.md",
    });
    assert.equal(a.type, "decionis_policy_md");
    assert.equal(a.path, "DECIONIS_POLICY.md");
    assert.match(a.sha256, /^[0-9a-f]{64}$/);
    assert.equal(a.truncated, false);
    assert.equal(a.content, "# Policy\nblock prod on fridays\n");
    const same = buildPolicySource("# Policy\nblock prod on fridays\n", {});
    const changed = buildPolicySource("# Policy\nblock prod always\n", {});
    assert.equal(a.sha256, same.sha256);
    assert.notEqual(a.sha256, changed.sha256);
  });

  it("references oversized content by hash only, never silently drops it", () => {
    const big = "x".repeat(200000);
    const s = buildPolicySource(big, { path: "DECIONIS_POLICY.md" });
    assert.equal(s.truncated, true);
    assert.equal("content" in s, false);
    assert.equal(s.bytes, 200000);
    assert.match(s.sha256, /^[0-9a-f]{64}$/);
  });

  it("carries the git ref when provided", () => {
    const s = buildPolicySource("policy", { path: "p.md", ref: "abc123" });
    assert.equal(s.ref, "abc123");
  });
});

describe("loadPolicyFile", () => {
  it("returns null when the path is empty (disabled)", async () => {
    assert.equal(await loadPolicyFile("", { workspace: "/tmp" }), null);
  });
  it("returns null (never throws) when the file is absent", async () => {
    const r = await loadPolicyFile("DECIONIS_POLICY.md", {
      workspace: "/nonexistent-decionis-workspace-xyz",
    });
    assert.equal(r, null);
  });
});

describe("shouldFail", () => {
  it("fails on block when fail-on=block (default)", () => {
    assert.equal(shouldFail("block", "block", "enforce"), true);
    assert.equal(shouldFail("deny", "block", "enforce"), true);
    assert.equal(shouldFail("denied", "block", "enforce"), true);
  });

  it("does NOT fail on escalate when fail-on=block", () => {
    assert.equal(shouldFail("escalate", "block", "enforce"), false);
    assert.equal(shouldFail("review", "block", "enforce"), false);
  });

  it("fails on escalate / review when fail-on=escalate", () => {
    assert.equal(shouldFail("escalate", "escalate", "enforce"), true);
    assert.equal(shouldFail("review", "escalate", "enforce"), true);
    assert.equal(shouldFail("block", "escalate", "enforce"), false);
  });

  it("fail-on=block_or_escalate covers both", () => {
    assert.equal(shouldFail("block", "block_or_escalate", "enforce"), true);
    assert.equal(shouldFail("escalate", "block_or_escalate", "enforce"), true);
    assert.equal(shouldFail("allow", "block_or_escalate", "enforce"), false);
  });

  it("shadow mode never fails the step regardless of verdict or fail-on", () => {
    for (const decision of ["allow", "block", "escalate", "review", "deny"]) {
      for (const failOn of ["block", "escalate", "block_or_escalate", "never"]) {
        assert.equal(shouldFail(decision, failOn, "shadow"), false, `shadow ${decision}/${failOn}`);
      }
    }
  });

  it("fail-on=never opts out of all failures", () => {
    assert.equal(shouldFail("block", "never", "enforce"), false);
    assert.equal(shouldFail("escalate", "never", "enforce"), false);
  });

  it("never fails on an allow verdict, regardless of fail-on", () => {
    for (const failOn of ["block", "escalate", "block_or_escalate", "never"]) {
      assert.equal(shouldFail("allow", failOn, "enforce"), false);
    }
  });
});

describe("buildGrantRequestBody", () => {
  const prevRepo = process.env.GITHUB_REPOSITORY;
  const prevSha = process.env.GITHUB_SHA;
  afterEach(() => {
    if (prevRepo === undefined) delete process.env.GITHUB_REPOSITORY;
    else process.env.GITHUB_REPOSITORY = prevRepo;
    if (prevSha === undefined) delete process.env.GITHUB_SHA;
    else process.env.GITHUB_SHA = prevSha;
  });
  it("binds org, dossier, outcome, action, audience, and repo@sha subject", () => {
    process.env.GITHUB_REPOSITORY = "octo/repo";
    process.env.GITHUB_SHA = "deadbeef";
    const body = buildGrantRequestBody({
      orgId: "org-1",
      dossierId: "dsr-1",
      decision: "allow",
      action: "production-deploy",
      audience: "prod",
    });
    assert.deepEqual(body, {
      org_id: "org-1",
      dossier_id: "dsr-1",
      outcome: "allow",
      action: "production-deploy",
      audience: "prod",
      subject: "octo/repo@deadbeef",
    });
  });
  it("omits optional fields when absent", () => {
    delete process.env.GITHUB_REPOSITORY;
    delete process.env.GITHUB_SHA;
    const body = buildGrantRequestBody({ orgId: "o", dossierId: "d", decision: "allow" });
    assert.deepEqual(body, { org_id: "o", dossier_id: "d", outcome: "allow" });
  });
});

describe("shouldExecute (wrapped `run` command)", () => {
  it("enforce: only an allow verdict permits execution", () => {
    assert.equal(shouldExecute("allow", "enforce"), true);
    for (const d of ["block", "deny", "escalate", "review", "restrain", ""]) {
      assert.equal(shouldExecute(d, "enforce"), false, `enforce ${d}`);
    }
  });
  it("shadow: always executes (observe-only, never changes behavior)", () => {
    for (const d of ["allow", "block", "escalate", "review", "deny"]) {
      assert.equal(shouldExecute(d, "shadow"), true, `shadow ${d}`);
    }
  });
  it("is case-insensitive on the verdict", () => {
    assert.equal(shouldExecute("ALLOW", "enforce"), true);
    assert.equal(shouldExecute("BLOCK", "enforce"), false);
  });
});

describe("buildVerifyUrl", () => {
  it("includes ?sig= and ?source=github_actions for OG-rich unfurls", () => {
    const url = buildVerifyUrl("https://decionis.com", "dsr-abc", "sha256:0123");
    assert.equal(
      url,
      "https://decionis.com/verify/decision-dossiers/dsr-abc?sig=sha256%3A0123&source=github_actions",
    );
  });

  it("omits ?sig= when no signature is available, still attributes the source", () => {
    const url = buildVerifyUrl("https://decionis.com", "dsr-abc", null);
    assert.equal(
      url,
      "https://decionis.com/verify/decision-dossiers/dsr-abc?source=github_actions",
    );
  });

  it("URL-encodes dossier ids with special chars", () => {
    const url = buildVerifyUrl("https://decionis.com", "dsr/abc#1", null);
    assert.match(url, /dsr%2Fabc%231/);
  });

  it("strips a trailing slash from the site base URL", () => {
    const url = buildVerifyUrl("https://decionis.com/", "dsr-x", null);
    assert.match(url, /^https:\/\/decionis\.com\/verify\/decision-dossiers\/dsr-x/);
  });
});

describe("verdictTheme", () => {
  it("maps verdict synonyms to a stable label + color", () => {
    assert.equal(verdictTheme("allow").label, "Allowed");
    assert.equal(verdictTheme("deny").label, "Blocked");
    assert.equal(verdictTheme("denied").label, "Blocked");
    assert.equal(verdictTheme("review").label, "Escalate");
    assert.equal(verdictTheme("restrained").label, "Restrained");
  });
  it("is case-insensitive and falls back for unknown verdicts", () => {
    assert.equal(verdictTheme("BLOCK").label, "Blocked");
    assert.equal(verdictTheme("weird").label, "weird");
    assert.equal(verdictTheme("").label, "Unknown");
  });
});

describe("verdictBadgeUrl", () => {
  it("is a shields.io URL carrying the verdict label", () => {
    assert.match(verdictBadgeUrl("block"), /^https:\/\/img\.shields\.io\/badge\/Decionis-Blocked-/);
    assert.match(verdictBadgeUrl("allow"), /Decionis-Allowed-2ea043/);
  });
});

describe("governedByBadgeMarkdown", () => {
  it("produces a clickable shields badge linking to the action by default", () => {
    const md = governedByBadgeMarkdown();
    assert.match(md, /^\[!\[Governed by Decionis\]\(https:\/\/img\.shields\.io\/badge\/Governed/);
    assert.match(md, /\(https:\/\/github\.com\/decionis\/govern\)$/);
  });
  it("links to a custom URL (e.g. the live verify URL) when given one", () => {
    assert.match(
      governedByBadgeMarkdown("https://decionis.com/verify/x"),
      /\(https:\/\/decionis\.com\/verify\/x\)$/,
    );
  });
});

describe("buildPrCommentBody", () => {
  const base = {
    decision: "block",
    dossierId: "dsr-123",
    verifyUrl: "https://decionis.com/verify/decision-dossiers/dsr-123?sig=abc",
    policyVersion: "v4.3.0",
    reasonCode: "velocity_ceiling_exceeded",
    runMode: "enforce",
    failOn: "block",
  };
  it("includes the hidden sticky marker so re-runs update in place", () => {
    assert.match(buildPrCommentBody(base), /<!-- decionis-govern -->/);
  });
  it("renders the verdict, verify link, policy, and reason", () => {
    const body = buildPrCommentBody(base);
    assert.match(body, /Governed step — Blocked/);
    assert.match(body, /Verify this decision →/);
    assert.match(body, /v4\.3\.0/);
    assert.match(body, /velocity_ceiling_exceeded/);
  });
  it("shows the shadow-mode note (never fails build) in shadow", () => {
    const body = buildPrCommentBody({ ...base, runMode: "shadow" });
    assert.match(body, /Shadow mode/);
    assert.match(body, /never fails your build/);
  });
  it("includes attribution by default and omits it when disabled", () => {
    assert.match(buildPrCommentBody(base), /Governed by .*Decionis/);
    const bare = buildPrCommentBody({ ...base, showAttribution: false });
    assert.doesNotMatch(bare, /Governed by <a/);
  });
  it("attribution carries the AI-agent guardrail CTA + shadow-mode quickstart", () => {
    const body = buildPrCommentBody(base);
    assert.match(body, /autonomous AI agents/);
    assert.match(body, /shadow mode in 30s/);
    assert.match(body, /quickstart\?source=gha_pr_comment/);
  });
});

describe("applyActionLabel", () => {
  it("folds the action label into the payload", () => {
    assert.deepEqual(applyActionLabel({ env: "prod" }, "production-deploy"), {
      env: "prod",
      action: "production-deploy",
    });
  });
  it("does not clobber an explicit payload.action", () => {
    assert.deepEqual(applyActionLabel({ action: "explicit" }, "production-deploy"), {
      action: "explicit",
    });
  });
  it("returns the payload untouched when no label is given", () => {
    const p = { env: "prod" };
    assert.equal(applyActionLabel(p, ""), p);
    assert.equal(applyActionLabel(p, "   "), p);
  });
});

describe("buildPrCommentBody — action label", () => {
  it("surfaces the action label in the heading when provided", () => {
    const body = buildPrCommentBody({
      decision: "block",
      runMode: "enforce",
      failOn: "block",
      actionLabel: "production-deploy",
    });
    assert.match(body, /Action gate · `production-deploy` — Blocked/);
  });
});

describe("resolvePayload", () => {
  it("falls back to a GitHub-context-derived payload when input is blank", () => {
    const payload = resolvePayload("", () => ({ source: "github_actions_test", repo: "x/y" }));
    assert.equal(payload.source, "github_actions_test");
    assert.equal(payload.repo, "x/y");
  });

  it("parses a JSON object input as-is", () => {
    const payload = resolvePayload('{"environment":"production","blast_radius":"high"}');
    assert.deepEqual(payload, { environment: "production", blast_radius: "high" });
  });

  it("throws on invalid JSON", () => {
    assert.throws(() => resolvePayload("not json"), /not valid JSON/);
  });

  it("throws if payload JSON is an array, not an object", () => {
    assert.throws(() => resolvePayload("[1,2,3]"), /must be an object/);
  });
});
