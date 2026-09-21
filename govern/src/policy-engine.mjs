// @ts-check
// Decionis local policy engine — parses the fenced ```decionis rules block of
// a DECIONIS_POLICY.md file and evaluates it against a decision payload
// entirely in-process (microseconds, no network).
//
// HOST-AGNOSTIC BY DESIGN: no process.env, no fs, no network, no node:crypto —
// pure functions over strings and plain objects, so the same module can serve
// the GitHub Action, the platform MCP server, or a future WASM build.
//
// FAITHFUL MIRROR: extraction, validation, fact building, field resolution,
// operator semantics (including value coercion), rule ordering, and
// first-match selection replicate the platform's compiler
// (apps/api/src/services/policyEncoding/decionisRulesBlock.ts), request
// normalizer (apps/api/src/services/protocolAdapter/normalizeEvaluateBody.ts),
// and evaluator (apps/protocol/src/app.ts — buildEvaluateDecisionPolicyFacts /
// resolveEvaluateDecisionPolicyFactValue / evaluateDecisionPolicyPredicate /
// evaluateDecisionPolicyGraph). Divergence here is a bug: when in doubt this
// engine must return a fallback, never a guess.
//
// SAFETY MODEL: a deterministic verdict is returned ONLY when an explicitly
// committed allow/block rule matches using facts that are fully knowable
// client-side. Facts only the server can know (decision domain taxonomy,
// rollout-effective mode, selected bundle metadata) are marked UNKNOWN;
// any rule whose outcome could hinge on them halts the scan and defers to
// the API. Rules that definitively do NOT match are skipped regardless —
// a non-matching rule contributes nothing on either side.

/** Operators accepted by the platform compiler (OP_MAP keys, lowercase). */
export const SUPPORTED_OPS = [
  "eq",
  "ne",
  "neq",
  "gt",
  "gte",
  "lt",
  "lte",
  "in",
  "not_in",
  "exists",
  "contains",
  "matches",
];

/** Sentinel for facts the server derives from state we cannot see client-side. */
export const UNKNOWN_FACT = Object.freeze({ __decionis_unknown_fact__: true });

const OP_MAP = {
  eq: "EQ",
  ne: "NEQ",
  neq: "NEQ",
  gt: "GT",
  gte: "GTE",
  lt: "LT",
  lte: "LTE",
  in: "IN",
  not_in: "NOT_IN",
  exists: "EXISTS",
  contains: "CONTAINS",
  matches: "MATCHES",
};
const VALUELESS_OPS = new Set(["EXISTS"]);
const VALUES_OPS = new Set(["IN", "NOT_IN"]);
const ACTIONS = new Set(["allow", "block", "restrain", "escalate"]);

const isPlainObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
/** Mirror of the server's asRecord: non-objects coerce to an empty record. */
const asRecord = (v) => (isPlainObject(v) ? v : {});

// ───────────────────────────── extraction ─────────────────────────────

/**
 * Extract the raw text inside the first ```decionis fenced block. Mirrors the
 * platform compiler's extractDecionisRulesBlock verbatim (same regex): the
 * FIRST block wins, the info string may carry an optional json/yaml tag, and
 * a missing/empty block means "nothing to enforce".
 *
 * @param {string} markdown
 * @returns {string | null}
 */
export function extractDecionisBlock(markdown) {
  if (typeof markdown !== "string") return null;
  const re = /```decionis(?:\s+(?:json|ya?ml))?[ \t]*\r?\n([\s\S]*?)\r?\n```/i;
  const m = re.exec(markdown);
  return m ? (m[1] ?? "").trim() || null : null;
}

// ───────────────────────────── compilation ─────────────────────────────

/**
 * Parse + validate a rules block exactly like the platform compiler
 * (compileDecionisRules): all-or-nothing, unknown extra keys ignored,
 * `priority` / `domain` / `rationale` honored, `version` ignored entirely.
 * The one client-side difference: the server parses the block with a YAML 1.2
 * reader (JSON superset). We are zero-dependency, so a block that is not
 * valid JSON yields `{ok:false, reason:"not_json"}` — the caller must fall
 * back to the API (which may still compile it as YAML), never reject it.
 *
 * @param {string} blockText
 * @param {{workflowKey?: string | null}} [opts]
 * @returns {{ok: true, rules: Array<CompiledRule>} | {ok: false, reason: string, errors?: string[]}}
 *
 * CompiledRule = { name: string, quantifier: "all"|"any",
 *                  predicates: Array<{field: string, operator: string, value?: any, values?: any[]}>,
 *                  action: "allow"|"block"|"restrain"|"escalate",
 *                  domain: string, priority: number, originalIndex: number }
 */
export function parsePolicy(blockText, opts = {}) {
  let parsed;
  try {
    parsed = JSON.parse(blockText);
  } catch {
    return { ok: false, reason: "not_json" };
  }

  const errors = [];
  if (!isPlainObject(parsed)) {
    return { ok: false, reason: "compile_error", errors: ["decionis block must be a JSON object"] };
  }
  const rawRules = parsed.rules;
  if (!Array.isArray(rawRules) || rawRules.length === 0) {
    return {
      ok: false,
      reason: "compile_error",
      errors: ['decionis block needs a non-empty "rules" array'],
    };
  }

  const domainDefault = (opts.workflowKey ?? "").trim() || "github_action";
  const rules = [];

  rawRules.forEach((raw, i) => {
    const path = `rules[${i}]`;
    if (!isPlainObject(raw)) {
      errors.push(`${path}: must be an object`);
      return;
    }
    const r = raw;
    const name = typeof r.name === "string" && r.name.trim() ? r.name.trim() : "";
    if (!name) errors.push(`${path}: needs a non-empty "name"`);

    const actionRaw = typeof r.action === "string" ? r.action.trim().toLowerCase() : "";
    const action = ACTIONS.has(actionRaw) ? actionRaw : null;
    if (!action) {
      errors.push(
        `${path}: unknown action "${r.action}" (allowed: allow, block, restrain, escalate)`,
      );
    }

    const hasAll = Array.isArray(r.all) && r.all.length > 0;
    const hasAny = Array.isArray(r.any) && r.any.length > 0;
    if (hasAll === hasAny) {
      errors.push(`${path}: provide exactly one of "all" or "any" with at least one condition`);
    }

    const groupKey = hasAll ? "all" : "any";
    const rawPredicates = hasAll ? r.all : r.any;
    const predicates = [];
    (Array.isArray(rawPredicates) ? rawPredicates : []).forEach((pred, j) => {
      const compiled = compilePredicate(pred, `${path}.${groupKey}[${j}]`, errors);
      if (compiled) predicates.push(compiled);
    });

    if (!name || !action || hasAll === hasAny || predicates.length === 0) return;

    const priority =
      typeof r.priority === "number" && Number.isFinite(r.priority)
        ? Math.max(0, Math.min(100000, Math.round(r.priority)))
        : i;

    rules.push({
      name,
      quantifier: groupKey,
      predicates,
      action,
      domain: typeof r.domain === "string" && r.domain.trim() ? r.domain.trim() : domainDefault,
      priority,
      originalIndex: i,
    });
  });

  if (errors.length > 0) return { ok: false, reason: "compile_error", errors };
  return { ok: true, rules };
}

/** Mirror of the compiler's compilePredicate. Errors accumulate; null on failure. */
function compilePredicate(raw, path, errors) {
  if (!isPlainObject(raw)) {
    errors.push(`${path}: predicate must be an object`);
    return null;
  }
  const field = typeof raw.field === "string" ? raw.field.trim() : "";
  if (!field) {
    errors.push(`${path}: predicate needs a non-empty "field"`);
    return null;
  }
  const opRaw = typeof raw.op === "string" ? raw.op.trim().toLowerCase() : "";
  const operator = OP_MAP[opRaw];
  if (!operator) {
    errors.push(
      `${path}: unknown operator "${raw.op}" (allowed: ${Object.keys(OP_MAP).join(", ")})`,
    );
    return null;
  }
  const out = { field, operator };
  if (VALUELESS_OPS.has(operator)) return out; // EXISTS: any provided value is dropped, as on the server
  if (VALUES_OPS.has(operator)) {
    if (!Array.isArray(raw.values) || raw.values.length === 0) {
      errors.push(`${path}: operator "${opRaw}" requires a non-empty "values" array`);
      return null;
    }
    out.values = raw.values;
    return out;
  }
  if (!("value" in raw)) {
    errors.push(`${path}: operator "${opRaw}" requires a "value"`);
    return null;
  }
  out.value = raw.value;
  return out;
}

// ───────────────────────────── facts ─────────────────────────────

/**
 * Reconstruct the facts object the server evaluates rules against, for a
 * decision submitted by this Action. Mirrors normalizeEvaluateDecisionBody
 * (payload merges into context; decision_type derives from context.action →
 * workflow_key → "action_gate"), the handler's context enrichment, and
 * buildEvaluateDecisionPolicyFacts — including its quirk that explicit
 * request-level keys (amount, risk_score, …) OVERWRITE same-named payload
 * keys at the facts root with undefined when the Action didn't send them.
 *
 * Facts only the server can compute are set to UNKNOWN_FACT:
 *  - decision_domain (vertical-pack taxonomy resolution)
 *  - mode (org rollout policy may override the requested mode)
 *  - objective_profile / requested_policy_version (schema & pack defaults)
 *  - context.vertical_pack (resolved pack key)
 *  - policy (selected bundle id/version)
 */
export function buildEvaluationFacts(payload, { orgId, workflowKey } = {}) {
  const p = isPlainObject(payload) ? payload : {};
  const context = { ...p, vertical_pack: UNKNOWN_FACT, workflow_key: workflowKey ?? null };
  const signals = asRecord(context.signals);
  const override = asRecord(context.override);
  const evidence = asRecord(context.evidence);
  const attachments = Array.isArray(context.attachments)
    ? context.attachments
    : Array.isArray(evidence.attachments)
      ? evidence.attachments
      : [];

  // normalizeEvaluateDecisionBody: derive decision_type (Action never sends one).
  const candidates = [
    typeof p.action === "string" ? p.action : null,
    typeof workflowKey === "string" ? workflowKey : null,
  ];
  const derived = candidates.find((c) => typeof c === "string" && c.trim() !== "");
  const decisionType = (derived ?? "action_gate").toString().trim().slice(0, 120);

  return {
    ...context,
    org_id: orgId,
    decision_type: decisionType,
    decision_domain: UNKNOWN_FACT,
    amount: undefined,
    risk_score: undefined,
    channel: undefined,
    objective_profile: UNKNOWN_FACT,
    mode: UNKNOWN_FACT,
    decision_band: undefined,
    transaction_type: undefined,
    workflow_key: workflowKey ?? undefined,
    vertical_pack: undefined,
    requested_policy_version: UNKNOWN_FACT,
    context,
    intake: context,
    signals,
    override,
    evidence,
    attachments,
    attachment_count: attachments.length,
    policy: UNKNOWN_FACT,
  };
}

/**
 * Resolve a field against the facts, mirroring the server's
 * resolveEvaluateDecisionPolicyFactValue (exact root key first, then
 * dot/bracket path traversal; arrays index numerically; non-objects coerce to
 * empty records). Returns {kind:"unknown"} the moment traversal touches an
 * UNKNOWN_FACT — that value exists server-side but is not knowable here.
 *
 * @returns {{kind: "value", value: any} | {kind: "unknown"}}
 */
export function resolveFactValue(facts, field) {
  if (Object.prototype.hasOwnProperty.call(facts, field)) {
    const v = facts[field];
    return v === UNKNOWN_FACT ? { kind: "unknown" } : { kind: "value", value: v };
  }

  const normalizedPath = String(field).replace(/\[(\d+)\]/g, ".$1");
  const segments = normalizedPath
    .split(".")
    .map((segment) => segment.trim())
    .filter(Boolean);
  if (segments.length === 0) return { kind: "value", value: undefined };

  let current = facts;
  for (const segment of segments) {
    if (current === UNKNOWN_FACT) return { kind: "unknown" };
    if (Array.isArray(current)) {
      const index = Number.parseInt(segment, 10);
      if (!Number.isFinite(index)) return { kind: "value", value: undefined };
      current = current[index];
      continue;
    }
    current = asRecord(current)[segment];
  }
  return current === UNKNOWN_FACT ? { kind: "unknown" } : { kind: "value", value: current };
}

// ─────────────────────── value coercion (server-exact) ───────────────────────

/** Mirror of the server's asNumber (parseFloat semantics for strings). */
function asNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number.parseFloat(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

/** Mirror of parseEvaluateDecisionPolicyBoolean. */
function asBooleanish(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  return null;
}

/** Mirror of normalizeEvaluateDecisionPolicyText. */
function asComparableText(value) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed.toLowerCase() : null;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value).toLowerCase();
  }
  return null;
}

/**
 * Semantic equality, mirroring areEvaluateDecisionPolicyValuesEqual: arrays
 * match on any element (both sides, recursively), then numeric coercion, then
 * boolean coercion, then case-insensitive text, then strict identity.
 */
export function valuesEqual(actual, expected) {
  if (Array.isArray(actual)) {
    return actual.some((item) => valuesEqual(item, expected));
  }
  if (Array.isArray(expected)) {
    return expected.some((item) => valuesEqual(actual, item));
  }

  const actualNumber = asNumber(actual);
  const expectedNumber = asNumber(expected);
  if (actualNumber != null && expectedNumber != null) return actualNumber === expectedNumber;

  const actualBoolean = asBooleanish(actual);
  const expectedBoolean = asBooleanish(expected);
  if (actualBoolean != null && expectedBoolean != null) return actualBoolean === expectedBoolean;

  const actualText = asComparableText(actual);
  const expectedText = asComparableText(expected);
  if (actualText != null && expectedText != null) return actualText === expectedText;

  return actual === expected;
}

// ───────────────────────────── evaluation ─────────────────────────────

/**
 * Evaluate one compiled predicate, three-valued: `true` / `false` exactly as
 * the server's evaluateDecisionPolicyPredicate would, or `"unknown"` when the
 * referenced fact is not knowable client-side.
 *
 * @returns {boolean | "unknown"}
 */
export function evaluatePredicate(predicate, facts) {
  const resolved = resolveFactValue(facts, predicate.field);
  if (resolved.kind === "unknown") return "unknown";
  const actual = resolved.value;
  const expectedValues = Array.isArray(predicate.values)
    ? predicate.values
    : Object.prototype.hasOwnProperty.call(predicate, "value")
      ? [predicate.value]
      : [];

  switch (predicate.operator) {
    case "EQ":
      return valuesEqual(actual, predicate.value);
    case "NEQ":
      return !valuesEqual(actual, predicate.value);
    case "GT": {
      const a = asNumber(actual);
      const b = asNumber(predicate.value);
      return a != null && b != null ? a > b : false;
    }
    case "GTE": {
      const a = asNumber(actual);
      const b = asNumber(predicate.value);
      return a != null && b != null ? a >= b : false;
    }
    case "LT": {
      const a = asNumber(actual);
      const b = asNumber(predicate.value);
      return a != null && b != null ? a < b : false;
    }
    case "LTE": {
      const a = asNumber(actual);
      const b = asNumber(predicate.value);
      return a != null && b != null ? a <= b : false;
    }
    case "IN":
      return expectedValues.some((expected) => valuesEqual(actual, expected));
    case "NOT_IN":
      return expectedValues.every((expected) => !valuesEqual(actual, expected));
    case "EXISTS":
      // Compiler drops any provided value for EXISTS, so this is pure existence.
      return actual !== undefined && actual !== null;
    case "CONTAINS": {
      if (Array.isArray(actual)) {
        return expectedValues.some((expected) =>
          actual.some((item) => valuesEqual(item, expected)),
        );
      }
      const actualText = asComparableText(actual);
      if (!actualText) return false;
      return expectedValues.some((expected) => {
        const expectedText = asComparableText(expected);
        return expectedText ? actualText.includes(expectedText) : false;
      });
    }
    case "MATCHES": {
      const actualText = asComparableText(actual);
      const pattern = typeof predicate.value === "string" ? predicate.value : null;
      if (!actualText || !pattern) return false;
      try {
        return new RegExp(pattern, "i").test(actualText);
      } catch {
        return false;
      }
    }
    default:
      return false; // mirrors the server's default arm; unreachable for compiled rules
  }
}

/**
 * Evaluate a rule's condition group under Kleene three-valued logic.
 * `all`: any false → false; any unknown (and no false) → unknown; else true.
 * `any`: any true → true; any unknown (and no true) → unknown; else false.
 *
 * @returns {boolean | "unknown"}
 */
export function evaluateRuleConditions(rule, facts) {
  let sawUnknown = false;
  if (rule.quantifier === "all") {
    for (const predicate of rule.predicates) {
      const r = evaluatePredicate(predicate, facts);
      if (r === false) return false;
      if (r === "unknown") sawUnknown = true;
    }
    return sawUnknown ? "unknown" : true;
  }
  for (const predicate of rule.predicates) {
    const r = evaluatePredicate(predicate, facts);
    if (r === true) return true;
    if (r === "unknown") sawUnknown = true;
  }
  return sawUnknown ? "unknown" : false;
}

/**
 * Is this rule guaranteed to survive the server's decision-domain filter?
 * The server keeps a rule when its domain is "*" / "ANY" or equals the
 * resolved taxonomy domain — which we cannot compute client-side. So only
 * wildcard domains are certain; anything else is uncertain and matters only
 * if the rule would otherwise match.
 */
export function isDomainCertain(rule) {
  const normalized = rule.domain.trim().toUpperCase();
  return normalized === "*" || normalized === "ANY";
}

function describePredicates(rule, facts) {
  const parts = rule.predicates.map((p) => {
    const state = evaluatePredicate(p, facts);
    const rhs = Object.prototype.hasOwnProperty.call(p, "values")
      ? JSON.stringify(p.values)
      : JSON.stringify(p.value);
    return `${p.field} ${p.operator.toLowerCase()} ${rhs ?? ""} → ${state}`;
  });
  return `${rule.quantifier}[ ${parts.join("; ")} ]`;
}

/**
 * First-match scan over the compiled rules in server order (priority DESC,
 * original index ASC — mirroring sortEvaluateDecisionPolicyRules).
 *
 *  - conditions false → skip (a non-matching rule is inert on both sides)
 *  - conditions true + wildcard domain → SELECTED
 *  - conditions true + non-wildcard domain → indeterminate (the server may
 *    domain-filter this rule; we cannot know, and if kept it would win)
 *  - conditions unknown → indeterminate (if it matched server-side it wins)
 *  - exhausted → no_match (server outcome: REVIEW via no_matching_rule)
 *
 * @returns {{outcome: "allow"|"block"|"restrain"|"escalate"|"no_match"|"indeterminate",
 *            matchedRule: object|null, haltedRule: object|null, explanation: string}}
 */
export function evaluatePolicy(rules, facts) {
  const ordered = [...rules].sort((left, right) => {
    if (left.priority !== right.priority) return right.priority - left.priority;
    return left.originalIndex - right.originalIndex;
  });

  for (const rule of ordered) {
    const conditions = evaluateRuleConditions(rule, facts);
    if (conditions === false) continue;
    const label = `rule #${rule.originalIndex + 1} "${rule.name}"`;
    if (conditions === "unknown") {
      return {
        outcome: "indeterminate",
        matchedRule: null,
        haltedRule: rule,
        explanation: `${label} depends on server-side facts: ${describePredicates(rule, facts)}`,
      };
    }
    if (!isDomainCertain(rule)) {
      return {
        outcome: "indeterminate",
        matchedRule: null,
        haltedRule: rule,
        explanation:
          `${label} matches but its domain "${rule.domain}" is not "*" — the server's ` +
          `domain filter may include or exclude it, so the verdict is not locally decidable`,
      };
    }
    return {
      outcome: rule.action,
      matchedRule: rule,
      haltedRule: null,
      explanation: `${label} matched: ${describePredicates(rule, facts)}`,
    };
  }
  return {
    outcome: "no_match",
    matchedRule: null,
    haltedRule: null,
    explanation: "no rule matched (server would resolve no_matching_rule → REVIEW)",
  };
}

// ───────────────────────────── facade ─────────────────────────────

/**
 * One-call facade: policy file content + decision inputs → local evaluation.
 *
 * `deterministic` is true ONLY for an allow/block from an explicitly matched,
 * wildcard-domain committed rule evaluated over fully client-knowable facts.
 * A matched escalate/restrain is reported as a fallback with the outcome
 * attached (a prediction for the API path to confirm).
 *
 * @param {string} content  Raw DECIONIS_POLICY.md text.
 * @param {{payload?: object, orgId?: string, workflowKey?: string}} [options]
 * @returns {{status: "verdict"|"fallback", outcome: string|null, deterministic: boolean,
 *            fallbackReason: string|null, matchedRule: {index: number, name: string, action: string}|null,
 *            explanation: string, ruleCount: number, elapsedUs: number}}
 */
export function evaluateLocalPolicy(content, { payload, orgId, workflowKey } = {}) {
  const t0 = performance.now();
  const done = (partial) => ({
    matchedRule: null,
    explanation: "",
    ruleCount: partial.ruleCount ?? 0,
    ...partial,
    elapsedUs: Math.max(1, Math.round((performance.now() - t0) * 1000)),
  });
  const fallback = (reason, extra = {}) =>
    done({
      status: "fallback",
      outcome: null,
      deterministic: false,
      fallbackReason: reason,
      ...extra,
    });

  const blockText = extractDecionisBlock(content);
  if (blockText === null) return fallback("no_rules_block");
  const compiled = parsePolicy(blockText, { workflowKey });
  if (!compiled.ok) {
    const detail = compiled.errors?.[0] ? `:${compiled.errors[0]}` : "";
    return fallback(`${compiled.reason}${detail}`);
  }
  const facts = buildEvaluationFacts(payload, { orgId, workflowKey });
  const result = evaluatePolicy(compiled.rules, facts);
  const ruleCount = compiled.rules.length;

  if (result.outcome === "indeterminate") {
    return fallback(`rule_indeterminate:${result.haltedRule.name}`, {
      explanation: result.explanation,
      ruleCount,
    });
  }
  if (result.outcome === "no_match") return fallback("no_match", { ruleCount });

  const matchedRule = {
    index: result.matchedRule.originalIndex,
    name: result.matchedRule.name,
    action: result.matchedRule.action,
  };
  if (result.outcome === "escalate" || result.outcome === "restrain") {
    return fallback(`outcome_not_local:${result.outcome}`, {
      outcome: result.outcome,
      matchedRule,
      explanation: result.explanation,
      ruleCount,
    });
  }
  return done({
    status: "verdict",
    outcome: result.outcome,
    deterministic: true,
    fallbackReason: null,
    matchedRule,
    explanation: result.explanation,
    ruleCount,
  });
}
