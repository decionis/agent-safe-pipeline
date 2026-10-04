import { createHash } from "node:crypto";
import type { CommerceAction } from "../CommerceGateClient.js";
import { CommerceGateError } from "../Errors.js";
import {
  COMMERCE_CHECK_IDS,
  type CommercePreflightInput,
  type CommercePreflightResult,
} from "./Contracts.js";
import {
  commercePreflightResultSchema,
  isPlainRecord,
  matchesPreflightSchema,
  parseCommercePreflightInput,
} from "./Schema.js";

const DISPOSITION_RANK = { PROCEED: 0, HOLD: 1, BLOCK: 2 } as const;
const OUTCOME_RANK: Readonly<Record<string, number>> = {
  APPROVE: 0,
  REVIEW: 1,
  ESCALATE: 1,
  REJECT: 2,
};

function invalidResponse(): CommerceGateError {
  return new CommerceGateError(
    "INVALID_UPSTREAM_RESPONSE",
    "The Decionis API did not return a complete, consistent, request-bound commerce-preflight-v1 result. CommerceGate failed closed; no legacy evaluation was substituted.",
  );
}

/** Captures JSON before an asynchronous call so response binding cannot follow caller mutation. */
export class CommercePreflightBinding {
  readonly action: CommerceAction;
  readonly preflight: CommercePreflightInput;
  private readonly actionDigest: string;
  private readonly factsDigest: string;

  constructor(action: CommerceAction, preflight: unknown) {
    this.preflight = parseCommercePreflightInput(preflight);
    try {
      const canonicalAction = canonicalJson(action);
      this.action = JSON.parse(canonicalAction) as CommerceAction;
      this.actionDigest = digest(canonicalAction);
      this.factsDigest = canonicalPreflightDigest(this.preflight.facts);
    } catch {
      throw new CommerceGateError(
        "INVALID_INPUT",
        "The explicit preflight action and facts must be bounded JSON with valid Unicode and finite numbers.",
      );
    }
  }

  validateEvaluation(response: unknown, requestedPolicyVersion?: string): CommercePreflightResult {
    if (
      !isPlainRecord(response) ||
      response.mode !== "SHADOW" ||
      typeof response.outcome !== "string" ||
      !Object.hasOwn(OUTCOME_RANK, response.outcome) ||
      !matchesPreflightSchema(response.commerce_preflight, commercePreflightResultSchema)
    ) {
      throw invalidResponse();
    }
    const result = response.commerce_preflight as CommercePreflightResult;
    if (
      result.action_type !== this.action.action_type ||
      result.idempotency_key !== this.action.idempotency_key ||
      result.action_digest !== this.actionDigest ||
      result.facts_digest !== this.factsDigest ||
      result.policy_version !== response.policy_version ||
      (requestedPolicyVersion !== undefined && result.policy_version !== requestedPolicyVersion)
    ) {
      throw invalidResponse();
    }
    const ids = new Set(result.checks.map((check) => check.id));
    if (ids.size !== COMMERCE_CHECK_IDS.length) throw invalidResponse();
    for (const check of result.checks) {
      const emptyVerdict = check.status === "not_applicable" || check.status === "disabled";
      if (
        emptyVerdict !== (check.verdict === null) ||
        ((check.status === "missing_facts" || check.status === "unsupported") &&
          check.verdict !== "HOLD")
      ) {
        throw invalidResponse();
      }
    }
    // Validate the server's aggregation invariant; this does not evaluate business policy.
    const expected = result.checks.some((check) => check.verdict === "BLOCK")
      ? "BLOCK"
      : result.checks.some((check) => check.verdict === "HOLD")
        ? "HOLD"
        : result.checks.some((check) => check.status === "evaluated")
          ? "PROCEED"
          : "HOLD";
    if (
      result.disposition !== expected ||
      OUTCOME_RANK[response.outcome] < DISPOSITION_RANK[result.disposition]
    )
      throw invalidResponse();
    return result;
  }
}

/** SHA-256 of RFC8785/JCS JSON, matching the server's canonicalPayloadDigest. */
export function canonicalPreflightDigest(value: unknown): `sha256:${string}` {
  return digest(canonicalJson(value));
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function canonicalJson(value: unknown): string {
  let entries = 0;
  const serialize = (item: unknown, depth: number): string => {
    entries += 1;
    if (depth > 20 || entries > 4096) throw new TypeError("PREFLIGHT_JSON_TOO_COMPLEX");
    if (item === null) return "null";
    if (typeof item === "boolean") return item ? "true" : "false";
    if (typeof item === "string") {
      if (item.length > 100 * 1024) throw new TypeError("PREFLIGHT_JSON_TOO_LARGE");
      assertUnicode(item);
      return JSON.stringify(item);
    }
    if (typeof item === "number") {
      if (!Number.isFinite(item)) throw new TypeError("PREFLIGHT_JSON_NUMBER_INVALID");
      return JSON.stringify(item);
    }
    if (Array.isArray(item)) {
      if (item.length > 4096) throw new TypeError("PREFLIGHT_JSON_TOO_COMPLEX");
      return `[${Array.from(item, (child) => serialize(child, depth + 1)).join(",")}]`;
    }
    if (!isPlainRecord(item)) throw new TypeError("PREFLIGHT_JSON_OBJECT_INVALID");
    const keys = Object.keys(item);
    if (keys.length > 4096) throw new TypeError("PREFLIGHT_JSON_TOO_COMPLEX");
    return `{${keys
      .sort()
      .map((key) => {
        assertUnicode(key);
        return `${JSON.stringify(key)}:${serialize(item[key], depth + 1)}`;
      })
      .join(",")}}`;
  };
  const result = serialize(value, 0);
  if (Buffer.byteLength(result, "utf8") > 100 * 1024)
    throw new TypeError("PREFLIGHT_JSON_TOO_LARGE");
  return result;
}

function assertUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff))
        throw new TypeError("PREFLIGHT_JSON_UNICODE_INVALID");
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("PREFLIGHT_JSON_UNICODE_INVALID");
    }
  }
}
