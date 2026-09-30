import type { JsonValue } from "@decionis/agent-safe-pipeline";
import { CHAIN_GENESIS, HashChain, type ChainHead } from "../audit/HashChain.js";

export type ChainFindingCode =
  "CHAIN_LINE_INVALID" | "CHAIN_HASH_MISMATCH" | "CHAIN_SEQ_GAP" | "CHAIN_PREV_MISMATCH";

export interface ChainFinding {
  readonly code: ChainFindingCode;
  /** One-based position in the input. */
  readonly line: number;
  readonly stream: string | null;
  /** The hosted tenant whose chain it is, when the line names one. */
  readonly tenant?: string;
  readonly seq: number | null;
  readonly expected?: string | number;
  readonly found?: string | number;
}

export interface StreamSummary {
  readonly lines: number;
  readonly head: ChainHead;
  /** Lines that began a chain from genesis: one per process start without a checkpoint. */
  readonly starts: number;
}

export interface ChainVerification {
  readonly ok: boolean;
  readonly lines: number;
  /** Lines that belong to no chain, such as the process's own start-up lines. */
  readonly ignored: number;
  /** By stream, or by `tenant/stream` for a hosted tenant's chain. */
  readonly streams: Readonly<Record<string, StreamSummary>>;
  readonly findings: readonly ChainFinding[];
}

interface ChainedLine {
  readonly stream: string;
  readonly tenant: string | null;
  /** Which chain the line belongs to: its stream, within its tenant when it has one. */
  readonly chain: string;
  readonly seq: number;
  readonly prev_hash: string;
  readonly hash: string;
  readonly record: Record<string, JsonValue>;
}

function chained(value: unknown): ChainedLine | "not-chained" | "invalid" {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "not-chained";
  const record = value as Record<string, JsonValue>;
  if (!("stream" in record)) return "not-chained";
  const { stream, seq, prev_hash, hash, tenant } = record;
  if (typeof stream !== "string" || stream === "") return "invalid";
  if (tenant !== undefined && (typeof tenant !== "string" || tenant === "")) return "invalid";
  if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 1) return "invalid";
  if (typeof prev_hash !== "string" || typeof hash !== "string") return "invalid";
  const owner = tenant ?? null;
  return {
    stream,
    tenant: owner,
    chain: owner === null ? stream : `${owner}/${stream}`,
    seq,
    prev_hash,
    hash,
    record,
  };
}

/**
 * Walks the lines of one or more chained streams and reports every break:
 * a line that is not one, a hash that does not match its fields, a sequence
 * that skips or rewinds, a `prev_hash` that is not the previous line's hash.
 * A line that names a `tenant` belongs to that tenant's chain of its stream,
 * so one hosted process's output, holding many tenants' chains, verifies whole.
 * A line with no `stream` field belongs to no chain and is counted as
 * ignored. A fresh start from genesis is a restart, not a break, and is
 * counted, so a reader can compare it with the process's restarts. Anyone
 * holding the lines can run this; it needs no key and no service.
 */
export function verifyAuditChain(lines: Iterable<string>): ChainVerification {
  const findings: ChainFinding[] = [];
  const streams = new Map<string, { lines: number; head: ChainHead; starts: number }>();
  let count = 0;
  let ignored = 0;
  for (const text of lines) {
    count += 1;
    if (text.trim() === "") {
      ignored += 1;
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      findings.push({ code: "CHAIN_LINE_INVALID", line: count, stream: null, seq: null });
      continue;
    }
    const line = chained(parsed);
    if (line === "not-chained") {
      ignored += 1;
      continue;
    }
    if (line === "invalid") {
      findings.push({ code: "CHAIN_LINE_INVALID", line: count, stream: null, seq: null });
      continue;
    }
    const expectedHash = HashChain.digest(line.record);
    if (expectedHash !== line.hash) {
      findings.push({
        code: "CHAIN_HASH_MISMATCH",
        line: count,
        stream: line.stream,
        ...(line.tenant === null ? {} : { tenant: line.tenant }),
        seq: line.seq,
        expected: expectedHash,
        found: line.hash,
      });
    }
    const state = streams.get(line.chain);
    const genesis = line.seq === 1 && line.prev_hash === CHAIN_GENESIS;
    if (state === undefined) {
      streams.set(line.chain, {
        lines: 1,
        head: { seq: line.seq, hash: line.hash },
        starts: genesis ? 1 : 0,
      });
      continue;
    }
    state.lines += 1;
    if (genesis) {
      state.starts += 1;
    } else if (line.seq !== state.head.seq + 1) {
      findings.push({
        code: "CHAIN_SEQ_GAP",
        line: count,
        stream: line.stream,
        ...(line.tenant === null ? {} : { tenant: line.tenant }),
        seq: line.seq,
        expected: state.head.seq + 1,
        found: line.seq,
      });
    } else if (line.prev_hash !== state.head.hash) {
      findings.push({
        code: "CHAIN_PREV_MISMATCH",
        line: count,
        stream: line.stream,
        ...(line.tenant === null ? {} : { tenant: line.tenant }),
        seq: line.seq,
        expected: state.head.hash,
        found: line.prev_hash,
      });
    }
    state.head = { seq: line.seq, hash: line.hash };
  }
  return {
    ok: findings.length === 0,
    lines: count,
    ignored,
    streams: Object.fromEntries(
      [...streams.entries()].map(([name, state]) => [name, { ...state }]),
    ),
    findings,
  };
}
