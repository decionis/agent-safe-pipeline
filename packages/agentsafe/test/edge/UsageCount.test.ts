import { describe, expect, it } from "vitest";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { countUsage, verifyUsage, type ClaimedUsage } from "../../src/edge/UsageCount.js";
import { usagePeriod, type UsagePeriod } from "../../src/edge/UsagePeriod.js";
import { emptyUsage } from "../../src/edge/UsageTally.js";
import { decision, EvidenceLog, lifecycle } from "../support/EvidenceLog.js";

const september = usagePeriod("2026-09") as UsagePeriod;
const stream = EVIDENCE_STREAM;

/** August, three September decisions among lifecycle lines, then October. */
function month(): EvidenceLog {
  return new EvidenceLog().add(
    decision("2026-08-31T23:59:59.999Z"),
    lifecycle("2026-09-01T00:00:00.000Z"),
    decision("2026-09-01T00:00:00.000Z"),
    lifecycle("2026-09-02T00:00:00.000Z"),
    decision("2026-09-15T00:00:00.000Z", {
      verdict: "ESCALATE",
      delegated: true,
      jti: "jti-2",
    }),
    decision("2026-09-30T23:59:59.999Z", { mode: "SHADOW", verdict: "BLOCK" }),
    lifecycle("2026-10-01T00:00:00.000Z"),
    decision("2026-10-01T00:00:00.000Z"),
  );
}

function record(line: string | undefined): Record<string, unknown> {
  return JSON.parse(line ?? "null") as Record<string, unknown>;
}

const claimed = (usage: ReturnType<typeof countUsage>["usage"]): ClaimedUsage => ({
  ...usage,
  stream,
});

describe("countUsage", () => {
  it("counts the period's edge decisions on the chain, with the range they span", () => {
    const log = month();
    const count = countUsage(log.lines, { stream, period: september });
    expect(count.ok).toBe(true);
    expect(count.findings).toEqual([]);
    expect(count.usage).toEqual({
      counts: {
        by_mode: { ENFORCEMENT: 2, SHADOW: 1 },
        by_verdict: { ALLOW: 1, ESCALATE: 1, BLOCK: 1 },
        total: 3,
      },
      delegated: 1,
      first_seq: 3,
      first_hash: record(log.lines[2])["hash"],
      last_seq: 6,
      last_hash: record(log.lines[5])["hash"],
      bundles: ["jti-1", "jti-2"],
    });
  });

  it("counts only lines that are edge decisions", () => {
    const log = new EvidenceLog().add(
      decision("2026-09-02T00:00:00.000Z", { event: "EDGE_DECISION_SIMULATED" }),
      decision("2026-09-03T00:00:00.000Z"),
    );
    expect(countUsage(log.lines, { stream, period: september }).usage).toMatchObject({
      counts: { total: 1 },
      first_seq: 2,
    });
  });

  it("counts nothing, cleanly, from a log with no line of the stream", () => {
    const other = new EvidenceLog(null, "agent-safe.security/1").add(
      decision("2026-09-02T00:00:00Z"),
    );
    const count = countUsage(["", "   ", ...other.lines, "null", "5", '"text"', "[]"], {
      stream,
      period: september,
    });
    expect(count).toEqual({ ok: true, usage: emptyUsage(), findings: [] });
  });

  it("follows the chain a crash resumed, not the branch it abandoned", () => {
    const log = new EvidenceLog().add(
      lifecycle("2026-09-01T00:00:00.000Z"),
      decision("2026-09-02T00:00:00.000Z"),
    );
    const checkpoint = log.head;
    // Written after the last persisted head, then lost with the process.
    log.add(decision("2026-09-03T00:00:00.000Z", { jti: "jti-lost" }));
    const resumed = new EvidenceLog(checkpoint).add(
      decision("2026-09-04T00:00:00.000Z", { jti: "jti-3" }),
    );
    const count = countUsage([...log.lines, ...resumed.lines], { stream, period: september });
    expect(count.ok).toBe(true);
    expect(count.usage.counts.total).toBe(2);
    expect(count.usage.bundles).toEqual(["jti-1", "jti-3"]);
    expect(count.usage).toMatchObject({ first_seq: 2, last_seq: 3, last_hash: resumed.head.hash });
  });

  it("counts the newest chain of a log with several, or the one whose head is named", () => {
    const first = new EvidenceLog().add(decision("2026-09-02T00:00:00.000Z"));
    const second = new EvidenceLog().add(
      decision("2026-09-05T00:00:00.000Z", { jti: "jti-9" }),
      decision("2026-09-06T00:00:00.000Z", { jti: "jti-9" }),
    );
    const lines = [...first.lines, ...second.lines];
    expect(countUsage(lines, { stream, period: september }).usage.counts.total).toBe(2);
    const named = countUsage(lines, { stream, period: september, head: first.head.hash });
    expect(named.usage).toMatchObject({ bundles: ["jti-1"], last_hash: first.head.hash });
    expect(named.ok).toBe(true);
  });

  it("refuses an unknown head", () => {
    const count = countUsage(month().lines, {
      stream,
      period: september,
      head: `sha256:${"f".repeat(64)}`,
    });
    expect(count).toEqual({
      ok: false,
      usage: emptyUsage(),
      findings: [{ code: "CHAIN_HEAD_UNKNOWN" }],
    });
  });

  it("reports a tampered or malformed line by position and does not count through it", () => {
    const lines = [...month().lines];
    const tampered = record(lines[4]);
    tampered["verdict"] = "ALLOW";
    lines[4] = JSON.stringify(tampered);
    lines.splice(1, 0, "{not json");
    const count = countUsage(lines, { stream, period: september });
    expect(count.ok).toBe(false);
    // The chain walked back from the head stops where the tampered line was,
    // which leaves the period's start out of reach.
    expect(count.findings).toEqual([
      { code: "CHAIN_LINE_INVALID", line: 2 },
      { code: "CHAIN_HASH_MISMATCH", line: 6 },
      { code: "CHAIN_START_MISSING" },
    ]);
    expect(count.usage).toMatchObject({ first_seq: 6, last_seq: 6 });
  });

  it("refuses a chained line without a whole-number sequence or a previous hash", () => {
    const line = record(month().lines[0]);
    for (const broken of [
      { ...line, seq: "1" },
      { ...line, seq: 1.5 },
      { ...line, prev_hash: 7 },
    ]) {
      const count = countUsage([JSON.stringify(broken)], { stream, period: september });
      expect(count.findings, JSON.stringify(broken)).toEqual([
        { code: "CHAIN_LINE_INVALID", line: 1 },
      ]);
    }
  });

  it("says when the log does not reach back to the period's start", () => {
    const log = new EvidenceLog().add(
      lifecycle("2026-08-31T22:00:00.000Z"),
      lifecycle("2026-08-31T23:59:59.999Z"),
      lifecycle("2026-09-01T00:00:00.000Z"),
      decision("2026-09-02T00:00:00.000Z"),
    );
    expect(countUsage(log.lines, { stream, period: september }).ok).toBe(true);
    // Cut, but the first line kept is still from before the period.
    expect(countUsage(log.lines.slice(1), { stream, period: september }).ok).toBe(true);
    const cut = countUsage(log.lines.slice(2), { stream, period: september });
    expect(cut.findings).toEqual([{ code: "CHAIN_START_MISSING" }]);
    expect(cut.usage.counts.total).toBe(1);
    // A chain that began inside the period is whole.
    const fresh = new EvidenceLog().add(decision("2026-09-20T00:00:00.000Z"));
    expect(countUsage(fresh.lines, { stream, period: september }).ok).toBe(true);
  });

  it("stops at a line whose predecessor is not the line before it", () => {
    const log = new EvidenceLog().add(
      decision("2026-08-01T00:00:00.000Z"),
      decision("2026-08-02T00:00:00.000Z"),
      decision("2026-08-03T00:00:00.000Z"),
    );
    const second = record(log.lines[1]);
    // A line that names an earlier line's hash but skips sequence numbers.
    const skipping = new EvidenceLog({ seq: 9, hash: String(second["hash"]) }).add(
      decision("2026-09-05T00:00:00.000Z"),
    );
    const count = countUsage([...log.lines, ...skipping.lines], { stream, period: september });
    expect(count.usage).toMatchObject({ first_seq: 10, last_seq: 10 });
    expect(count.findings).toEqual([{ code: "CHAIN_START_MISSING" }]);
  });
});

describe("verifyUsage", () => {
  it("accepts a report whose counts and range the chain reproduces", () => {
    const log = month();
    const usage = countUsage(log.lines, { stream, period: september }).usage;
    const verified = verifyUsage(log.lines, claimed(usage), september);
    expect(verified).toEqual({ ok: true, usage, findings: [] });
  });

  it("does not care how the report ordered its keys", () => {
    const log = month();
    const usage = countUsage(log.lines, { stream, period: september }).usage;
    const reordered: ClaimedUsage = {
      ...claimed(usage),
      counts: {
        total: usage.counts.total,
        by_verdict: {
          BLOCK: usage.counts.by_verdict.BLOCK,
          ESCALATE: usage.counts.by_verdict.ESCALATE,
          ALLOW: usage.counts.by_verdict.ALLOW,
        },
        by_mode: {
          SHADOW: usage.counts.by_mode.SHADOW,
          ENFORCEMENT: usage.counts.by_mode.ENFORCEMENT,
        },
      },
    };
    expect(verifyUsage(log.lines, reordered, september).ok).toBe(true);
  });

  it("accepts a report of nothing without a log, and refuses zeros that are not", () => {
    expect(verifyUsage([], claimed(emptyUsage()), september)).toEqual({
      ok: true,
      usage: emptyUsage(),
      findings: [],
    });
    const inflated = { ...claimed(emptyUsage()), delegated: 1 };
    expect(verifyUsage([], inflated, september).findings).toEqual([{ code: "USAGE_MISMATCH" }]);
  });

  it("refuses a range the chain does not hold whole", () => {
    const log = month();
    const usage = countUsage(log.lines, { stream, period: september }).usage;
    const unknownHead = { ...claimed(usage), last_hash: `sha256:${"f".repeat(64)}` };
    expect(verifyUsage(log.lines, unknownHead, september)).toEqual({
      ok: false,
      usage: emptyUsage(),
      findings: [{ code: "CHAIN_RANGE_BROKEN" }],
    });
    const unknownStart = { ...claimed(usage), first_hash: `sha256:${"f".repeat(64)}` };
    expect(verifyUsage(log.lines, unknownStart, september).findings).toEqual([
      { code: "CHAIN_RANGE_BROKEN" },
    ]);
    const gap = log.lines.filter((_, index) => index !== 3);
    expect(verifyUsage(gap, claimed(usage), september).findings).toEqual([
      { code: "CHAIN_RANGE_BROKEN" },
    ]);
  });

  it("refuses counts, a delegation, bundles or a range the recount does not reproduce", () => {
    const log = month();
    const usage = countUsage(log.lines, { stream, period: september }).usage;
    const before = record(log.lines[1]);
    for (const altered of [
      { ...claimed(usage), counts: { ...usage.counts, total: 4 } },
      {
        ...claimed(usage),
        counts: { ...usage.counts, by_mode: { ENFORCEMENT: 3, SHADOW: 0 } },
      },
      { ...claimed(usage), delegated: 0 },
      { ...claimed(usage), bundles: ["jti-1"] },
      { ...claimed(usage), first_seq: 2 },
      { ...claimed(usage), last_seq: 7 },
      // A range that starts on a line that is not a counted decision.
      { ...claimed(usage), first_seq: 2, first_hash: String(before["hash"]) },
    ] as ClaimedUsage[]) {
      const verified = verifyUsage(log.lines, altered, september);
      expect(verified.findings, JSON.stringify(altered)).toEqual([{ code: "USAGE_MISMATCH" }]);
      expect(verified.ok).toBe(false);
      expect(verified.usage.counts.total).toBeGreaterThan(0);
    }
  });

  it("recounts only the named stream", () => {
    const log = month();
    const usage = countUsage(log.lines, { stream, period: september }).usage;
    const elsewhere = { ...claimed(usage), stream: "agent-safe.security/1" };
    expect(verifyUsage(log.lines, elsewhere, september).findings).toEqual([
      { code: "CHAIN_RANGE_BROKEN" },
    ]);
  });
});
