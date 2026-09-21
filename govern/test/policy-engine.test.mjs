import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
  SUPPORTED_OPS,
  UNKNOWN_FACT,
  extractDecionisBlock,
  parsePolicy,
  buildEvaluationFacts,
  resolveFactValue,
  valuesEqual,
  evaluatePredicate,
  evaluateRuleConditions,
  isDomainCertain,
  evaluatePolicy,
  evaluateLocalPolicy,
} from "../src/policy-engine.mjs";

const examplePath = (name) => fileURLToPath(new URL(`../examples/${name}`, import.meta.url));

/** Wrap a rules document in a policy markdown file. */
const md = (rulesJson, info = "decionis") =>
  `# Policy\n\nProse here.\n\n\`\`\`${info}\n${rulesJson}\n\`\`\`\n`;

const RULES = (rules) => JSON.stringify({ version: 1, rules });

const ALLOW_STAGING = {
  name: "Allow staging",
  all: [{ field: "context.environment", op: "eq", value: "staging" }],
  action: "allow",
  domain: "*",
};
const BLOCK_FREEZE = {
  name: "Block during freeze",
  all: [{ field: "context.change_freeze", op: "eq", value: true }],
  action: "block",
  domain: "*",
};

describe("extractDecionisBlock (mirrors the platform compiler regex)", () => {
  it("extracts the first block's trimmed body", () => {
    const body = extractDecionisBlock(md('{"version":1,"rules":[]}'));
    assert.equal(body, '{"version":1,"rules":[]}');
  });

  it("returns null when there is no block, or input is not a string", () => {
    assert.equal(extractDecionisBlock("# just prose"), null);
    assert.equal(extractDecionisBlock(undefined), null);
    assert.equal(extractDecionisBlock(null), null);
  });

  it("returns null for an empty block body", () => {
    assert.equal(extractDecionisBlock("```decionis\n   \n```"), null);
  });

  it("takes the FIRST of multiple blocks, like the server", () => {
    const text = md('{"first":1}') + "\n" + md('{"second":2}');
    assert.equal(extractDecionisBlock(text), '{"first":1}');
  });

  it("accepts an optional json/yaml info tag and CRLF line endings", () => {
    assert.equal(extractDecionisBlock('```decionis json\r\n{"a":1}\r\n```'), '{"a":1}');
    assert.equal(extractDecionisBlock('```decionis yaml\n{"a":1}\n```'), '{"a":1}');
    assert.equal(extractDecionisBlock('```DECIONIS\n{"a":1}\n```'), '{"a":1}');
  });

  it("returns null for an unterminated fence", () => {
    assert.equal(extractDecionisBlock('```decionis\n{"a":1}\n'), null);
  });
});

describe("parsePolicy (mirrors compileDecionisRules)", () => {
  it("compiles both shipped example policies cleanly (lockstep with examples/)", async () => {
    for (const name of ["DECIONIS_POLICY.md", "DECIONIS_POLICY.devops.md"]) {
      const content = await readFile(examplePath(name), "utf8");
      const block = extractDecionisBlock(content);
      assert.ok(block, `${name} has a decionis block`);
      const compiled = parsePolicy(block, { workflowKey: "github_deploy_approval" });
      assert.equal(compiled.ok, true, `${name} compiles: ${JSON.stringify(compiled)}`);
      assert.ok(compiled.rules.length >= 3, `${name} has rules`);
    }
  });

  it("reports not_json for YAML-style bodies (server would still parse them)", () => {
    const r = parsePolicy("rules:\n  - name: x\n");
    assert.deepEqual(r, { ok: false, reason: "not_json" });
  });

  it("rejects non-object documents and missing/empty rules", () => {
    assert.equal(parsePolicy("[1,2]").ok, false);
    assert.equal(parsePolicy('{"version":1}').ok, false);
    assert.equal(parsePolicy('{"version":1,"rules":[]}').ok, false);
  });

  it("is all-or-nothing: one bad rule rejects the whole block", () => {
    const r = parsePolicy(
      RULES([
        ALLOW_STAGING,
        { name: "bad", all: [{ field: "x", op: "regex", value: "y" }], action: "allow" },
      ]),
    );
    assert.equal(r.ok, false);
    assert.equal(r.reason, "compile_error");
    assert.match(r.errors[0], /unknown operator "regex"/);
  });

  it("requires exactly one non-empty all/any (empty arrays count as absent)", () => {
    const both = parsePolicy(
      RULES([
        {
          name: "x",
          all: [{ field: "a", op: "eq", value: 1 }],
          any: [{ field: "b", op: "eq", value: 2 }],
          action: "allow",
        },
      ]),
    );
    assert.equal(both.ok, false);
    const neither = parsePolicy(RULES([{ name: "x", action: "allow" }]));
    assert.equal(neither.ok, false);
    // all: [] is treated as absent, so a populated any is fine — mirror quirk.
    const emptyAll = parsePolicy(
      RULES([
        {
          name: "x",
          all: [],
          any: [{ field: "b", op: "eq", value: 2 }],
          action: "allow",
          domain: "*",
        },
      ]),
    );
    assert.equal(emptyAll.ok, true);
    assert.equal(emptyAll.rules[0].quantifier, "any");
  });

  it("validates action, name, and per-op value requirements", () => {
    assert.equal(
      parsePolicy(RULES([{ name: "x", all: [{ field: "a", op: "eq", value: 1 }], action: "veto" }]))
        .ok,
      false,
    );
    assert.equal(
      parsePolicy(
        RULES([{ name: "  ", all: [{ field: "a", op: "eq", value: 1 }], action: "allow" }]),
      ).ok,
      false,
    );
    assert.equal(
      parsePolicy(RULES([{ name: "x", all: [{ field: "a", op: "eq" }], action: "allow" }])).ok,
      false,
    );
    assert.equal(
      parsePolicy(
        RULES([{ name: "x", all: [{ field: "a", op: "in", value: [1] }], action: "allow" }]),
      ).ok,
      false,
    );
    const okIn = parsePolicy(
      RULES([{ name: "x", all: [{ field: "a", op: "in", values: [1, 2] }], action: "allow" }]),
    );
    assert.equal(okIn.ok, true);
    assert.deepEqual(okIn.rules[0].predicates[0].values, [1, 2]);
  });

  it("drops any provided value for exists (pure existence, like the compiler)", () => {
    const r = parsePolicy(
      RULES([{ name: "x", all: [{ field: "a", op: "exists", value: false }], action: "allow" }]),
    );
    assert.equal(r.ok, true);
    const predicate = r.rules[0].predicates[0];
    assert.equal(predicate.operator, "EXISTS");
    assert.equal("value" in predicate, false);
  });

  it("ignores unknown keys (top-level and per-rule) and the version field", () => {
    const r = parsePolicy(
      JSON.stringify({
        version: 99,
        comment: "ignored",
        rules: [{ ...ALLOW_STAGING, severity: "high", notes: "ignored" }],
      }),
    );
    assert.equal(r.ok, true);
  });

  it("honors priority (clamped, rounded) and falls back to the rule index", () => {
    const r = parsePolicy(
      RULES([
        { ...ALLOW_STAGING, priority: 2.7 },
        { ...BLOCK_FREEZE, priority: "5" },
        { ...BLOCK_FREEZE, name: "third", priority: 999999 },
      ]),
    );
    assert.equal(r.ok, true);
    assert.equal(r.rules[0].priority, 3);
    assert.equal(r.rules[1].priority, 1); // non-number priority → index
    assert.equal(r.rules[2].priority, 100000); // clamped
  });

  it("defaults rule domain to the workflow key, then github_action", () => {
    const rule = { name: "x", all: [{ field: "a", op: "eq", value: 1 }], action: "allow" };
    assert.equal(
      parsePolicy(RULES([rule]), { workflowKey: "deploy_gate" }).rules[0].domain,
      "deploy_gate",
    );
    assert.equal(parsePolicy(RULES([rule])).rules[0].domain, "github_action");
    assert.equal(parsePolicy(RULES([{ ...rule, domain: " * " }])).rules[0].domain, "*");
  });

  it("keeps op aliases: ne and neq both compile to NEQ", () => {
    const r = parsePolicy(
      RULES([
        { name: "a", all: [{ field: "x", op: "ne", value: 1 }], action: "allow" },
        { name: "b", all: [{ field: "x", op: "NEQ", value: 1 }], action: "allow" },
      ]),
    );
    assert.equal(r.ok, true);
    assert.equal(r.rules[0].predicates[0].operator, "NEQ");
    assert.equal(r.rules[1].predicates[0].operator, "NEQ");
    assert.equal(SUPPORTED_OPS.includes("neq"), true);
  });
});

describe("buildEvaluationFacts (mirrors normalize + handler + facts builder)", () => {
  const facts = buildEvaluationFacts(
    { action: "production-deploy", environment: "prod", amount: 5000, signals: { velocity: 3 } },
    { orgId: "org-1", workflowKey: "deploy_gate" },
  );

  it("merges the payload into context and injects workflow_key", () => {
    assert.equal(facts.context.environment, "prod");
    assert.equal(facts.context.workflow_key, "deploy_gate");
    assert.equal(facts.intake, facts.context);
    assert.equal(facts.signals.velocity, 3);
  });

  it("derives decision_type from payload.action, then workflow_key, then action_gate", () => {
    assert.equal(facts.decision_type, "production-deploy");
    assert.equal(
      buildEvaluationFacts({}, { workflowKey: "deploy_gate" }).decision_type,
      "deploy_gate",
    );
    assert.equal(buildEvaluationFacts({}, {}).decision_type, "action_gate");
    const long = "x".repeat(300);
    assert.equal(buildEvaluationFacts({ action: long }, {}).decision_type.length, 120);
  });

  it("masks request-level fields at the root exactly like the server quirk", () => {
    // payload.amount is visible via context.amount but the root `amount` is the
    // (absent) request field — the explicit key overwrites the context spread.
    assert.equal(facts.amount, undefined);
    assert.equal(Object.prototype.hasOwnProperty.call(facts, "amount"), true);
    assert.equal(facts.context.amount, 5000);
  });

  it("marks server-only facts as UNKNOWN_FACT", () => {
    assert.equal(facts.decision_domain, UNKNOWN_FACT);
    assert.equal(facts.mode, UNKNOWN_FACT);
    assert.equal(facts.policy, UNKNOWN_FACT);
    assert.equal(facts.context.vertical_pack, UNKNOWN_FACT);
  });

  it("collects attachments from context or evidence, with a count", () => {
    const a = buildEvaluationFacts({ attachments: [1, 2] }, {});
    assert.equal(a.attachment_count, 2);
    const b = buildEvaluationFacts({ evidence: { attachments: [1] } }, {});
    assert.equal(b.attachment_count, 1);
    assert.equal(buildEvaluationFacts({}, {}).attachment_count, 0);
  });
});

describe("resolveFactValue (mirrors resolveEvaluateDecisionPolicyFactValue)", () => {
  const facts = buildEvaluationFacts(
    { "dotted.literal": "root-hit", nested: { deep: { value: 7 } }, list: ["a", "b"] },
    { orgId: "org-1", workflowKey: "wf" },
  );

  it("prefers an exact root key, even one containing dots", () => {
    assert.deepEqual(resolveFactValue(facts, "dotted.literal"), {
      kind: "value",
      value: "root-hit",
    });
  });

  it("resolves dot paths and bracket indices", () => {
    assert.deepEqual(resolveFactValue(facts, "context.nested.deep.value"), {
      kind: "value",
      value: 7,
    });
    assert.deepEqual(resolveFactValue(facts, "nested.deep.value"), { kind: "value", value: 7 });
    assert.deepEqual(resolveFactValue(facts, "list[1]"), { kind: "value", value: "b" });
    assert.deepEqual(resolveFactValue(facts, "context.list.0"), { kind: "value", value: "a" });
  });

  it("resolves missing paths to undefined (not unknown)", () => {
    assert.deepEqual(resolveFactValue(facts, "context.absent.leaf"), {
      kind: "value",
      value: undefined,
    });
    assert.deepEqual(resolveFactValue(facts, "list.notanumber"), {
      kind: "value",
      value: undefined,
    });
  });

  it("reports unknown when traversal touches a server-only fact", () => {
    assert.equal(resolveFactValue(facts, "decision_domain").kind, "unknown");
    assert.equal(resolveFactValue(facts, "policy.bundle_id").kind, "unknown");
    assert.equal(resolveFactValue(facts, "context.vertical_pack").kind, "unknown");
    assert.equal(resolveFactValue(facts, "mode").kind, "unknown");
  });
});

describe("valuesEqual (mirrors areEvaluateDecisionPolicyValuesEqual)", () => {
  it("coerces numbers, booleans, and case-insensitive text", () => {
    assert.equal(valuesEqual("1", 1), true);
    assert.equal(valuesEqual(1, true), true);
    assert.equal(valuesEqual("true", true), true);
    assert.equal(valuesEqual("Production", "production"), true);
    assert.equal(valuesEqual("  padded ", "padded"), true);
    assert.equal(valuesEqual("12abc", 12), true); // parseFloat prefix quirk — server mirror
    assert.equal(valuesEqual("1", true), false); // number stage skipped, boolean("1")=null, text differs
  });

  it("matches any element when either side is an array", () => {
    assert.equal(valuesEqual(["a", "b"], "B"), true);
    assert.equal(valuesEqual("a", ["x", "A"]), true);
    assert.equal(valuesEqual(["a"], ["b", ["a"]]), true);
  });

  it("falls back to strict identity", () => {
    assert.equal(valuesEqual(null, null), true);
    assert.equal(valuesEqual(undefined, null), false);
    assert.equal(valuesEqual({ a: 1 }, { a: 1 }), false);
  });
});

describe("evaluatePredicate (server-exact operators, three-valued only for unknowns)", () => {
  const facts = buildEvaluationFacts(
    {
      action: "production-deploy",
      environment: "Production",
      blast_radius: "15000",
      change_freeze: true,
      branch: "release/1.2",
      labels: ["infra", "ai-authored"],
    },
    { orgId: "org-1", workflowKey: "deploy_gate" },
  );
  const p = (field, op, rest = {}) => {
    const parsed = parsePolicy(
      RULES([{ name: "t", all: [{ field, op, ...rest }], action: "allow" }]),
    );
    assert.equal(parsed.ok, true, JSON.stringify(parsed));
    return parsed.rules[0].predicates[0];
  };

  it("eq / neq with coercion", () => {
    assert.equal(
      evaluatePredicate(p("context.environment", "eq", { value: "production" }), facts),
      true,
    );
    assert.equal(
      evaluatePredicate(p("decision_type", "eq", { value: "production-deploy" }), facts),
      true,
    );
    assert.equal(
      evaluatePredicate(p("context.change_freeze", "eq", { value: "true" }), facts),
      true,
    );
    assert.equal(
      evaluatePredicate(p("context.environment", "neq", { value: "staging" }), facts),
      true,
    );
    assert.equal(evaluatePredicate(p("context.missing", "eq", { value: "x" }), facts), false);
  });

  it("numeric comparisons coerce strings and fail closed on non-numbers", () => {
    assert.equal(evaluatePredicate(p("context.blast_radius", "gt", { value: 10000 }), facts), true);
    assert.equal(
      evaluatePredicate(p("context.blast_radius", "lte", { value: "15000" }), facts),
      true,
    );
    assert.equal(evaluatePredicate(p("context.environment", "gt", { value: 1 }), facts), false);
    assert.equal(evaluatePredicate(p("context.missing", "gt", { value: 1 }), facts), false);
  });

  it("in / not_in use the values array with semantic equality", () => {
    assert.equal(
      evaluatePredicate(
        p("context.environment", "in", { values: ["staging", "PRODUCTION"] }),
        facts,
      ),
      true,
    );
    assert.equal(
      evaluatePredicate(p("context.environment", "not_in", { values: ["staging"] }), facts),
      true,
    );
    assert.equal(
      evaluatePredicate(p("context.environment", "not_in", { values: ["production"] }), facts),
      false,
    );
  });

  it("exists is pure existence; null does not exist", () => {
    assert.equal(evaluatePredicate(p("context.change_freeze", "exists"), facts), true);
    assert.equal(evaluatePredicate(p("context.missing", "exists"), facts), false);
    const withNull = buildEvaluationFacts({ maybe: null }, {});
    assert.equal(evaluatePredicate(p("context.maybe", "exists"), withNull), false);
  });

  it("contains: any-element for arrays, case-insensitive substring for text", () => {
    assert.equal(
      evaluatePredicate(p("context.labels", "contains", { value: "INFRA" }), facts),
      true,
    );
    assert.equal(
      evaluatePredicate(p("context.branch", "contains", { value: "RELEASE" }), facts),
      true,
    );
    assert.equal(
      evaluatePredicate(p("context.branch", "contains", { value: "hotfix" }), facts),
      false,
    );
    assert.equal(
      evaluatePredicate(p("context.change_freeze", "contains", { value: "tru" }), facts),
      true,
    );
  });

  it("matches: case-insensitive regex; invalid patterns are false", () => {
    assert.equal(
      evaluatePredicate(p("context.branch", "matches", { value: "^release/" }), facts),
      true,
    );
    assert.equal(evaluatePredicate(p("context.branch", "matches", { value: "(" }), facts), false);
    assert.equal(evaluatePredicate(p("context.missing", "matches", { value: "x" }), facts), false);
  });

  it("returns unknown only when the fact is server-only", () => {
    assert.equal(
      evaluatePredicate(p("decision_domain", "eq", { value: "DEVOPS" }), facts),
      "unknown",
    );
    assert.equal(evaluatePredicate(p("policy.version", "exists"), facts), "unknown");
  });
});

describe("evaluateRuleConditions (Kleene logic)", () => {
  const facts = buildEvaluationFacts({ a: 1 }, { orgId: "o", workflowKey: "wf" });
  const rule = (quantifier, conditions) => {
    const parsed = parsePolicy(RULES([{ name: "t", [quantifier]: conditions, action: "allow" }]));
    assert.equal(parsed.ok, true);
    return parsed.rules[0];
  };
  const T = { field: "context.a", op: "eq", value: 1 };
  const F = { field: "context.a", op: "eq", value: 2 };
  const U = { field: "decision_domain", op: "eq", value: "DEVOPS" };

  it("all: false beats unknown; unknown beats true", () => {
    assert.equal(evaluateRuleConditions(rule("all", [F, U]), facts), false);
    assert.equal(evaluateRuleConditions(rule("all", [T, U]), facts), "unknown");
    assert.equal(evaluateRuleConditions(rule("all", [T, T]), facts), true);
  });

  it("any: true beats unknown; unknown beats false", () => {
    assert.equal(evaluateRuleConditions(rule("any", [T, U]), facts), true);
    assert.equal(evaluateRuleConditions(rule("any", [F, U]), facts), "unknown");
    assert.equal(evaluateRuleConditions(rule("any", [F, F]), facts), false);
  });
});

describe("evaluatePolicy (ordering, domain certainty, halt rule)", () => {
  const facts = buildEvaluationFacts(
    { environment: "staging", change_freeze: true },
    { orgId: "o", workflowKey: "wf" },
  );
  const compile = (rules) => {
    const parsed = parsePolicy(RULES(rules), { workflowKey: "wf" });
    assert.equal(parsed.ok, true, JSON.stringify(parsed));
    return parsed.rules;
  };

  it("default priorities mirror the server quirk: the LATER rule sorts first", () => {
    // The platform compiler defaults priority = rule index and the evaluator
    // sorts priority DESC, so with no explicit priorities the last rule in
    // the file is evaluated first. This engine mirrors that reality so local
    // verdicts predict server verdicts (the ordering fix belongs upstream).
    const r = evaluatePolicy(compile([BLOCK_FREEZE, ALLOW_STAGING]), facts);
    assert.equal(r.outcome, "allow");
    assert.equal(r.matchedRule.name, "Allow staging");
  });

  it("equal explicit priorities restore file order via the index tiebreak", () => {
    const r = evaluatePolicy(
      compile([
        { ...BLOCK_FREEZE, priority: 10 },
        { ...ALLOW_STAGING, priority: 10 },
      ]),
      facts,
    );
    assert.equal(r.outcome, "block");
    assert.equal(r.matchedRule.name, "Block during freeze");
  });

  it("priority reorders ahead of file order; ties break by index", () => {
    const r = evaluatePolicy(compile([BLOCK_FREEZE, { ...ALLOW_STAGING, priority: 50 }]), facts);
    assert.equal(r.outcome, "allow");
  });

  it("non-matching rules are skipped even with uncertain domains", () => {
    const noMatchUncertainDomain = {
      name: "not matching",
      all: [{ field: "context.environment", op: "eq", value: "prod" }],
      action: "block", // no domain → defaults to workflow key → uncertain, but inert
    };
    const r = evaluatePolicy(compile([noMatchUncertainDomain, ALLOW_STAGING]), facts);
    assert.equal(r.outcome, "allow");
  });

  it("a matching rule with a non-wildcard domain is indeterminate", () => {
    const domainBound = { ...BLOCK_FREEZE, domain: "DEVOPS" };
    const r = evaluatePolicy(compile([domainBound]), facts);
    assert.equal(r.outcome, "indeterminate");
    assert.match(r.explanation, /domain "DEVOPS"/);
  });

  it("an unknown-condition rule halts the scan before later-sorted definitive rules", () => {
    const unknownRule = {
      name: "server-only",
      all: [{ field: "decision_domain", op: "eq", value: "DEVOPS" }],
      action: "block",
      domain: "*",
      priority: 100, // sorts first
    };
    const r = evaluatePolicy(compile([unknownRule, ALLOW_STAGING]), facts);
    assert.equal(r.outcome, "indeterminate");
    assert.equal(r.haltedRule.name, "server-only");
  });

  it("a definitive match that sorts ahead of an unknown rule is not halted by it", () => {
    const unknownRule = {
      name: "server-only",
      all: [{ field: "decision_domain", op: "eq", value: "DEVOPS" }],
      action: "block",
      domain: "*", // priority defaults to index 0 — sorts after the allow rule
    };
    const r = evaluatePolicy(compile([unknownRule, { ...ALLOW_STAGING, priority: 100 }]), facts);
    assert.equal(r.outcome, "allow");
  });

  it("no matching rule → no_match", () => {
    const r = evaluatePolicy(
      compile([
        { ...ALLOW_STAGING, all: [{ field: "context.environment", op: "eq", value: "prod" }] },
      ]),
      facts,
    );
    assert.equal(r.outcome, "no_match");
  });

  it("isDomainCertain accepts * and ANY only", () => {
    assert.equal(isDomainCertain({ domain: "*" }), true);
    assert.equal(isDomainCertain({ domain: " any " }), true);
    assert.equal(isDomainCertain({ domain: "DEVOPS" }), false);
    assert.equal(isDomainCertain({ domain: "github_action" }), false);
  });
});

describe("evaluateLocalPolicy (facade)", () => {
  const opts = { payload: { environment: "staging" }, orgId: "org-1", workflowKey: "wf" };

  it("falls back when there is no rules block or no policy text", () => {
    assert.equal(evaluateLocalPolicy("# prose only", opts).fallbackReason, "no_rules_block");
    assert.equal(evaluateLocalPolicy("", opts).fallbackReason, "no_rules_block");
  });

  it("falls back on YAML-ish or malformed blocks without judging them invalid", () => {
    const yaml = evaluateLocalPolicy(md("rules:\n  - name: x"), opts);
    assert.equal(yaml.status, "fallback");
    assert.equal(yaml.fallbackReason, "not_json");
    const bad = evaluateLocalPolicy(md('{"rules":[{"name":"x","action":"allow"}]}'), opts);
    assert.equal(bad.status, "fallback");
    assert.match(bad.fallbackReason, /^compile_error:/);
  });

  it("returns a deterministic allow/block for wildcard-domain matches", () => {
    const allow = evaluateLocalPolicy(md(RULES([ALLOW_STAGING])), opts);
    assert.equal(allow.status, "verdict");
    assert.equal(allow.outcome, "allow");
    assert.equal(allow.deterministic, true);
    assert.equal(allow.matchedRule.name, "Allow staging");
    assert.ok(allow.elapsedUs >= 1);
    assert.equal(allow.ruleCount, 1);

    const block = evaluateLocalPolicy(md(RULES([BLOCK_FREEZE])), {
      ...opts,
      payload: { change_freeze: true },
    });
    assert.equal(block.outcome, "block");
    assert.equal(block.deterministic, true);
  });

  it("reports matched escalate/restrain as non-deterministic predictions", () => {
    const r = evaluateLocalPolicy(
      md(RULES([{ ...BLOCK_FREEZE, name: "Escalate freeze", action: "escalate" }])),
      { ...opts, payload: { change_freeze: true } },
    );
    assert.equal(r.status, "fallback");
    assert.equal(r.outcome, "escalate");
    assert.equal(r.deterministic, false);
    assert.equal(r.fallbackReason, "outcome_not_local:escalate");
    assert.equal(r.matchedRule.name, "Escalate freeze");
  });

  it("shipped example: an infra destroy matches the escalate rule and defers to the API", async () => {
    const content = await readFile(examplePath("DECIONIS_POLICY.devops.md"), "utf8");
    const r = evaluateLocalPolicy(content, {
      payload: { destroys_resources: true },
      orgId: "org-1",
      workflowKey: "infra-destroy",
    });
    assert.equal(r.status, "fallback");
    assert.equal(r.fallbackReason, "outcome_not_local:escalate");
    assert.equal(r.outcome, "escalate");
    assert.equal(r.matchedRule.name, "Escalate infrastructure destroy");
  });

  it("shipped example: a change freeze yields a deterministic local block", async () => {
    const content = await readFile(examplePath("DECIONIS_POLICY.devops.md"), "utf8");
    const r = evaluateLocalPolicy(content, {
      payload: { change_freeze: true },
      orgId: "org-1",
      workflowKey: "deploy",
    });
    assert.equal(r.status, "verdict");
    assert.equal(r.outcome, "block");
    assert.equal(r.deterministic, true);
  });

  it("shipped example: a non-matching payload falls through to no_match", async () => {
    const content = await readFile(examplePath("DECIONIS_POLICY.md"), "utf8");
    const r = evaluateLocalPolicy(content, {
      payload: { environment: "dev" },
      orgId: "org-1",
      workflowKey: "docs_only",
    });
    assert.equal(r.status, "fallback");
    assert.equal(r.fallbackReason, "no_match");
  });
});
