import type { JsonValue } from "@decionis/agent-safe-pipeline";
import { HashChain, type ChainHead } from "../../src/audit/HashChain.js";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";

/** One edge decision's fields, as `EdgeRuntime.record` links them. */
export function decision(
  at: string,
  overrides: Readonly<Record<string, JsonValue>> = {},
): Record<string, JsonValue> {
  return {
    at,
    event: "EDGE_DECISION",
    mode: "ENFORCEMENT",
    intent_id: "intent-synthetic",
    intent_hash: `sha256:${"a".repeat(64)}`,
    decision_id: "edge:synthetic",
    verdict: "ALLOW",
    reason_codes: ["POLICY_ALLOW"],
    policy_version: "policy-2026.10",
    bundle_id: "bundle-1",
    kid: "decionis-policy-bundle-test-v1",
    jti: "jti-1",
    evaluation_digest: `sha256:${"e".repeat(64)}`,
    delegated: false,
    caller_principal: null,
    ...overrides,
  };
}

/** A lifecycle line between decisions, which the count skips. */
export function lifecycle(at: string): Record<string, JsonValue> {
  return { at, event: "EXECUTION_COMPLETED", verdict: "ALLOW", intent_id: "intent-synthetic" };
}

/** A collected log: lines linked on the executor's evidence chain, in order. */
export class EvidenceLog {
  public readonly lines: string[] = [];
  public readonly chain: HashChain;

  public constructor(head: ChainHead | null = null, stream = EVIDENCE_STREAM) {
    this.chain = new HashChain(stream, head);
  }

  public add(...records: readonly Record<string, JsonValue>[]): this {
    for (const fields of records) this.chain.link(fields, (line) => this.lines.push(line));
    return this;
  }

  public get head(): ChainHead {
    return this.chain.head;
  }
}
