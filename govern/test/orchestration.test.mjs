import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_LOCAL_EVAL,
  SHADOW_GRACE_CAP_MS,
  SHADOW_GRACE_EXTRA_MS,
  BLOCK_RECORD_CAP_MS,
  planEvaluation,
  computeGraceMs,
  createTimeline,
  buildVerifyUrl,
  shouldFail,
} from "../src/index.mjs";
import { normalizeVerdict, parseDecisionResponse } from "../src/api-client.mjs";

const localAllow = { deterministic: true, outcome: "allow" };
const localBlock = { deterministic: true, outcome: "block" };
const localFallback = { deterministic: false, outcome: null };

describe("planEvaluation (the local-eval decision table)", () => {
  it("defaults to auto", () => {
    assert.equal(DEFAULT_LOCAL_EVAL, "auto");
  });

  it("routes to the blocking API without a deterministic local verdict", () => {
    for (const localEval of ["auto", "strict", "off"]) {
      for (const localOutcome of [null, localFallback]) {
        assert.deepEqual(
          planEvaluation({ localOutcome, localEval, requestGrant: false, hasRunCommand: true }),
          { act: "api", api: "blocking" },
        );
      }
    }
  });

  it("local-eval off ignores even a deterministic verdict", () => {
    assert.deepEqual(
      planEvaluation({
        localOutcome: localAllow,
        localEval: "off",
        requestGrant: false,
        hasRunCommand: true,
      }),
      { act: "api", api: "blocking" },
    );
  });

  it("request-grant always forces the blocking path (grants need a dossier first)", () => {
    assert.deepEqual(
      planEvaluation({
        localOutcome: localAllow,
        localEval: "auto",
        requestGrant: true,
        hasRunCommand: true,
      }),
      { act: "api", api: "blocking" },
    );
    assert.deepEqual(
      planEvaluation({
        localOutcome: localAllow,
        localEval: "strict",
        requestGrant: true,
        hasRunCommand: false,
      }),
      { act: "api", api: "blocking" },
    );
  });

  it("strict: deterministic verdicts act locally with zero network", () => {
    assert.deepEqual(
      planEvaluation({
        localOutcome: localAllow,
        localEval: "strict",
        requestGrant: false,
        hasRunCommand: true,
      }),
      { act: "local", api: "none" },
    );
    assert.deepEqual(
      planEvaluation({
        localOutcome: localBlock,
        localEval: "strict",
        requestGrant: false,
        hasRunCommand: false,
      }),
      { act: "local", api: "none" },
    );
  });

  it("auto: local block records the dossier with a bounded wait", () => {
    assert.deepEqual(
      planEvaluation({
        localOutcome: localBlock,
        localEval: "auto",
        requestGrant: false,
        hasRunCommand: true,
      }),
      { act: "local", api: "bounded" },
    );
  });

  it("auto: local allow notarizes in the background while a command runs, bounded otherwise", () => {
    assert.deepEqual(
      planEvaluation({
        localOutcome: localAllow,
        localEval: "auto",
        requestGrant: false,
        hasRunCommand: true,
      }),
      { act: "local", api: "background" },
    );
    assert.deepEqual(
      planEvaluation({
        localOutcome: localAllow,
        localEval: "auto",
        requestGrant: false,
        hasRunCommand: false,
      }),
      { act: "local", api: "bounded" },
    );
  });
});

describe("computeGraceMs", () => {
  it("grants the remaining timeout budget plus the parsing allowance", () => {
    // Pipeline started 1s ago with a 5s timeout → 4s remaining + extra.
    assert.equal(computeGraceMs(0, 1000, 5000), 4000 + SHADOW_GRACE_EXTRA_MS);
  });

  it("floors at the extra allowance when the budget is exhausted", () => {
    assert.equal(computeGraceMs(0, 60_000, 5000), SHADOW_GRACE_EXTRA_MS);
  });

  it("caps long budgets so fast commands never wait long", () => {
    assert.equal(computeGraceMs(0, 0, 120_000), SHADOW_GRACE_CAP_MS);
    assert.ok(SHADOW_GRACE_CAP_MS <= 10_000);
    assert.ok(BLOCK_RECORD_CAP_MS <= SHADOW_GRACE_CAP_MS);
  });
});

describe("createTimeline", () => {
  it("renders marks with offsets and details", () => {
    const t = createTimeline(0);
    t.mark("local eval", "'allow' in 412µs");
    t.mark("command started");
    const rendered = t.render();
    assert.match(rendered, /^Decionis timing — /);
    assert.match(rendered, /local eval 'allow' in 412µs \+\d+(\.\d+)?m?s/);
    assert.match(rendered, /command started \+/);
    assert.equal(t.events.length, 2);
  });

  it("says so when nothing was recorded", () => {
    assert.match(createTimeline().render(), /no events recorded/);
  });
});

describe("buildVerifyUrl policy pinning", () => {
  it("appends the policy revision pin as an additive query param", () => {
    const url = buildVerifyUrl("https://decionis.com", "dsr-1", "sig-1", {
      policySha256: "abc123",
    });
    assert.equal(
      url,
      "https://decionis.com/verify/decision-dossiers/dsr-1?sig=sig-1&source=github_actions&policy=sha256%3Aabc123",
    );
  });

  it("pins without a signature too", () => {
    const url = buildVerifyUrl("https://decionis.com", "dsr-1", null, { policySha256: "abc" });
    assert.equal(
      url,
      "https://decionis.com/verify/decision-dossiers/dsr-1?source=github_actions&policy=sha256%3Aabc",
    );
  });

  it("three-argument calls stay byte-identical to v1.8", () => {
    assert.equal(
      buildVerifyUrl("https://decionis.com", "dsr-abc", "sha256:0123"),
      "https://decionis.com/verify/decision-dossiers/dsr-abc?sig=sha256%3A0123&source=github_actions",
    );
    assert.equal(
      buildVerifyUrl("https://decionis.com", "dsr-abc", null),
      "https://decionis.com/verify/decision-dossiers/dsr-abc?source=github_actions",
    );
  });
});

describe("verdict normalization (protocol outcome → gate vocabulary)", () => {
  it("maps the protocol outcomes onto allow/block/review", () => {
    assert.equal(normalizeVerdict("APPROVE"), "allow");
    assert.equal(normalizeVerdict("REJECT"), "block");
    assert.equal(normalizeVerdict("REVIEW"), "review");
    assert.equal(normalizeVerdict("ESCALATE"), "escalate");
    assert.equal(normalizeVerdict("AUTO_APPROVE"), "allow");
    assert.equal(normalizeVerdict("AUTO_REJECT"), "block");
    assert.equal(normalizeVerdict("REQUIRE_REVIEW"), "review");
  });

  it("passes through the legacy vocabulary untouched", () => {
    for (const v of ["allow", "block", "deny", "denied", "escalate", "review", "restrain"]) {
      assert.equal(normalizeVerdict(v), v);
    }
  });

  it("parseDecisionResponse normalizes outcome and keeps the wire value", () => {
    const parsed = parseDecisionResponse({
      outcome: "APPROVE",
      dossier_id: "dsr-9",
      reason_codes: ["ok"],
    });
    assert.equal(parsed.decision, "allow");
    assert.equal(parsed.rawDecision, "approve");
    assert.equal(parsed.dossierId, "dsr-9");
    assert.equal(parsed.reasonCode, "ok");
  });

  it("parseDecisionResponse falls back through reason_code and tolerates junk", () => {
    assert.equal(parseDecisionResponse({ reason_code: "rc" }).reasonCode, "rc");
    assert.equal(
      parseDecisionResponse({ reason_codes: "nope", reason_code: "rc" }).reasonCode,
      "rc",
    );
    assert.equal(parseDecisionResponse({}).reasonCode, null);
  });
});

describe("local verdicts obey the same gates as API verdicts", () => {
  it("a local block with fail-on: never or escalate does not fail the step", () => {
    assert.equal(shouldFail("block", "never", "enforce"), false);
    assert.equal(shouldFail("block", "escalate", "enforce"), false);
    assert.equal(shouldFail("block", "block", "enforce"), true);
  });

  it("the normalized API 'review' verdict lands in the escalate family", () => {
    assert.equal(shouldFail("review", "escalate", "enforce"), true);
    assert.equal(shouldFail("review", "block", "enforce"), false);
  });
});
