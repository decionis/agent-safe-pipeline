import { CanonicalIntentHasher, type JsonValue } from "@decionis/agent-safe-pipeline";
import { HashChain } from "../audit/HashChain.js";
import { emptyUsage, UsageTally, type PeriodUsage } from "./UsageTally.js";
import type { UsagePeriod } from "./UsagePeriod.js";

export type UsageFindingCode =
  | "CHAIN_LINE_INVALID"
  | "CHAIN_HASH_MISMATCH"
  | "CHAIN_HEAD_UNKNOWN"
  | "CHAIN_START_MISSING"
  | "CHAIN_RANGE_BROKEN"
  | "USAGE_MISMATCH";

export interface UsageFinding {
  readonly code: UsageFindingCode;
  /** One-based position in the input, for a finding about one line. */
  readonly line?: number;
}

export interface UsageCount {
  readonly ok: boolean;
  readonly usage: PeriodUsage;
  readonly findings: readonly UsageFinding[];
}

interface Linked {
  readonly seq: number;
  readonly prev_hash: string;
  readonly hash: string;
  readonly record: Readonly<Record<string, JsonValue>>;
}

/**
 * The lines of one stream, each checked against its own hash and indexed by
 * it. A line whose hash does not match its fields is a finding and is left
 * out, so no walk can pass through it. `last` is the last good line in the
 * input: the head the chain reached when the log was collected.
 */
function index(
  lines: Iterable<string>,
  stream: string,
): {
  readonly byHash: ReadonlyMap<string, Linked>;
  readonly last: Linked | undefined;
  readonly findings: UsageFinding[];
} {
  const byHash = new Map<string, Linked>();
  const findings: UsageFinding[] = [];
  let last: Linked | undefined;
  let position = 0;
  for (const text of lines) {
    position += 1;
    let record: Record<string, JsonValue> | null;
    try {
      record = JSON.parse(text) as Record<string, JsonValue> | null;
    } catch {
      if (text.trim() !== "") findings.push({ code: "CHAIN_LINE_INVALID", line: position });
      continue;
    }
    if (record?.["stream"] !== stream) continue;
    const { seq, prev_hash, hash } = record;
    if (!Number.isSafeInteger(seq) || typeof prev_hash !== "string") {
      findings.push({ code: "CHAIN_LINE_INVALID", line: position });
      continue;
    }
    if (HashChain.digest(record) !== hash) {
      findings.push({ code: "CHAIN_HASH_MISMATCH", line: position });
      continue;
    }
    last = { seq: seq as number, prev_hash, hash, record };
    byHash.set(hash, last);
  }
  return { byHash, last, findings };
}

/**
 * The chain ending at `head`, oldest first: each line's `prev_hash` is the
 * line before it and its `seq` one more. The walk stops at the first line,
 * at `stop`, or where the line before is missing. A branch a crash
 * abandoned (lines written after the last persisted head, then written
 * again under the same numbers) is not on this chain and is not walked.
 */
function walk(byHash: ReadonlyMap<string, Linked>, head: Linked, stop?: string): Linked[] {
  const path = [head];
  let current = head;
  while (current.hash !== stop) {
    const previous = byHash.get(current.prev_hash);
    if (previous?.seq !== current.seq - 1) break;
    path.push(previous);
    current = previous;
  }
  return path.reverse();
}

function tally(path: readonly Linked[], period: UsagePeriod): PeriodUsage {
  const usage = new UsageTally();
  for (const line of path) {
    const record = line.record;
    if (record["event"] !== "EDGE_DECISION") continue;
    usage.add(
      {
        at: String(record["at"]),
        mode: record["mode"],
        verdict: record["verdict"],
        delegated: record["delegated"],
        jti: record["jti"],
        seq: line.seq,
        hash: line.hash,
      },
      period,
    );
  }
  return usage.usage(period.period);
}

/**
 * Counts a period's edge decisions from collected log lines: the chain of
 * `stream` that ends at `head` (the last line in the input unless named) is
 * walked back to its start, and the `EDGE_DECISION` lines on it whose `at`
 * falls in the period are counted. A tampered line anywhere in the stream,
 * or a chain that is cut off after the period began, is a finding, and a
 * report is not made from it.
 */
export function countUsage(
  lines: Iterable<string>,
  options: { readonly stream: string; readonly period: UsagePeriod; readonly head?: string },
): UsageCount {
  const indexed = index(lines, options.stream);
  const findings = indexed.findings;
  const head = options.head === undefined ? indexed.last : indexed.byHash.get(options.head);
  if (head === undefined) {
    if (options.head !== undefined) findings.push({ code: "CHAIN_HEAD_UNKNOWN" });
    return { ok: findings.length === 0, usage: emptyUsage(), findings };
  }
  const path = walk(indexed.byHash, head);
  const first = path[0] as Linked;
  if (first.seq !== 1 && Date.parse(String(first.record["at"])) >= options.period.start) {
    findings.push({ code: "CHAIN_START_MISSING" });
  }
  return { ok: findings.length === 0, usage: tally(path, options.period), findings };
}

/** What a usage report claims about its range and counts. */
export interface ClaimedUsage extends PeriodUsage {
  readonly stream: string;
}

/**
 * Recounts a report's period from collected log lines and checks it: the
 * range must be one unbroken chain from `first_hash` back from `last_hash`,
 * and the `EDGE_DECISION` lines on it in the period must count exactly what
 * the report says, with the same first and last line and the same bundles.
 * A report that counted nothing names no range and claims nothing to check
 * beyond its zeros.
 */
export function verifyUsage(
  lines: Iterable<string>,
  claimed: ClaimedUsage,
  period: UsagePeriod,
): UsageCount {
  let usage = emptyUsage();
  if (claimed.last_hash !== null) {
    const indexed = index(lines, claimed.stream);
    const broken: UsageCount = { ok: false, usage, findings: [{ code: "CHAIN_RANGE_BROKEN" }] };
    const head = indexed.byHash.get(claimed.last_hash);
    if (head === undefined) return broken;
    const path = walk(indexed.byHash, head, claimed.first_hash ?? undefined);
    if ((path[0] as Linked).hash !== claimed.first_hash) return broken;
    usage = tally(path, period);
  }
  const same =
    CanonicalIntentHasher.stringify(comparable(usage)) ===
    CanonicalIntentHasher.stringify(comparable(claimed));
  return { ok: same, usage, findings: same ? [] : [{ code: "USAGE_MISMATCH" }] };
}

/** The fields a recount must reproduce, as one value. */
function comparable(usage: PeriodUsage): JsonValue {
  return {
    counts: usage.counts,
    delegated: usage.delegated,
    bundles: [...usage.bundles],
    first_seq: usage.first_seq,
    first_hash: usage.first_hash,
    last_seq: usage.last_seq,
    last_hash: usage.last_hash,
  };
}
