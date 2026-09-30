import { describe, expect, it } from "vitest";
import { CHAIN_GENESIS, HashChain } from "../../src/audit/HashChain.js";
import { verifyAuditChain } from "../../src/verify/VerifyAuditChain.js";

const STREAM = "agent-safe.test/1";

function lines(count: number, chain = new HashChain(STREAM)): string[] {
  return Array.from(
    { length: count },
    (_, index) => chain.link({ event: "E", n: index }, () => undefined).line,
  );
}

describe("verifyAuditChain", () => {
  it("verifies a long chain, counting its lines and its start", () => {
    const report = verifyAuditChain(lines(1_000));
    expect(report.ok).toBe(true);
    expect(report.findings).toEqual([]);
    expect(report.lines).toBe(1_000);
    expect(report.ignored).toBe(0);
    expect(report.streams[STREAM]).toMatchObject({ lines: 1_000, starts: 1 });
    expect(report.streams[STREAM]?.head.seq).toBe(1_000);
  });

  it("reports a changed byte at its sequence number and nothing else", () => {
    const input = lines(5);
    input[2] = (input[2] ?? "").replace('"n":2', '"n":7');
    const report = verifyAuditChain(input);
    expect(report.ok).toBe(false);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toMatchObject({
      code: "CHAIN_HASH_MISMATCH",
      line: 3,
      stream: STREAM,
      seq: 3,
    });
    expect(String(report.findings[0]?.expected)).toMatch(/^sha256:/);
  });

  it("reports a deleted line as a gap, and a rewound sequence the same way", () => {
    const input = lines(5);
    input.splice(2, 1);
    const deleted = verifyAuditChain(input);
    expect(deleted.findings).toEqual([
      { code: "CHAIN_SEQ_GAP", line: 3, stream: STREAM, seq: 4, expected: 3, found: 4 },
    ]);
    const chain = new HashChain(STREAM);
    const before = lines(3, chain);
    const rewound = new HashChain(STREAM, {
      seq: 1,
      hash: (JSON.parse(before[0] ?? "{}") as { hash: string }).hash,
    });
    const after = lines(2, rewound);
    const report = verifyAuditChain([...before, ...after]);
    expect(report.findings).toEqual([
      { code: "CHAIN_SEQ_GAP", line: 4, stream: STREAM, seq: 2, expected: 4, found: 2 },
    ]);
  });

  it("reports a line whose sequence fits but whose predecessor is not the one written", () => {
    const input = lines(3);
    const forged = new HashChain(STREAM, { seq: 3, hash: `sha256:${"f".repeat(64)}` });
    input.push(forged.link({ event: "E", n: 3 }, () => undefined).line);
    const report = verifyAuditChain(input);
    expect(report.findings).toEqual([
      {
        code: "CHAIN_PREV_MISMATCH",
        line: 4,
        stream: STREAM,
        seq: 4,
        expected: (JSON.parse(input[2] ?? "{}") as { hash: string }).hash,
        found: `sha256:${"f".repeat(64)}`,
      },
    ]);
  });

  it("reports reordered lines", () => {
    const input = lines(4);
    [input[1], input[2]] = [input[2] ?? "", input[1] ?? ""];
    const report = verifyAuditChain(input);
    expect(report.ok).toBe(false);
    expect(report.findings.map((finding) => [finding.code, finding.line])).toEqual([
      ["CHAIN_SEQ_GAP", 2],
      ["CHAIN_SEQ_GAP", 3],
      ["CHAIN_SEQ_GAP", 4],
    ]);
  });

  it("continues across a restart from a persisted head, and counts a restart from genesis", () => {
    const first = new HashChain(STREAM);
    const before = lines(3, first);
    const resumed = new HashChain(STREAM, first.head);
    const after = lines(2, resumed);
    const continued = verifyAuditChain([...before, ...after]);
    expect(continued.ok).toBe(true);
    expect(continued.streams[STREAM]).toMatchObject({ lines: 5, starts: 1 });
    const fresh = verifyAuditChain([...before, ...lines(2)]);
    expect(fresh.ok).toBe(true);
    expect(fresh.streams[STREAM]).toMatchObject({ lines: 5, starts: 2 });
    expect(fresh.streams[STREAM]?.head.seq).toBe(2);
    const rotated = verifyAuditChain(after);
    expect(rotated.ok).toBe(true);
    expect(rotated.streams[STREAM]).toMatchObject({ lines: 2, starts: 0 });
  });

  it("verifies interleaved streams independently and ignores lines that belong to none", () => {
    const evidence = new HashChain("agent-safe.executor-evidence/1");
    const security = new HashChain("agent-safe.security/1");
    const input = [
      '{"event":"POSTURE_VERIFIED","mode":"ENFORCED"}',
      evidence.link({ event: "INTENT_CAPTURED" }, () => undefined).line,
      security.link({ event: "SECRET_ROTATED" }, () => undefined).line,
      "",
      evidence.link({ event: "EXECUTION_COMPLETED" }, () => undefined).line,
      '{"event":"LISTENING","port":8443}',
      security.link({ event: "POSTURE_DRIFT" }, () => undefined).line,
    ];
    const report = verifyAuditChain(input);
    expect(report.ok).toBe(true);
    expect(report.lines).toBe(7);
    expect(report.ignored).toBe(3);
    expect(Object.keys(report.streams)).toEqual([
      "agent-safe.executor-evidence/1",
      "agent-safe.security/1",
    ]);
    expect(report.streams["agent-safe.executor-evidence/1"]?.head.seq).toBe(2);
    expect(report.streams["agent-safe.security/1"]?.head.seq).toBe(2);
  });

  it("reports a line that is not one: not JSON, or chained but malformed", () => {
    const [good] = lines(1);
    const report = verifyAuditChain([
      "not json",
      '{"stream":"s","seq":"1","prev_hash":"x","hash":"y"}',
      '{"stream":"","seq":1,"prev_hash":"x","hash":"y"}',
      '{"stream":"s","seq":0,"prev_hash":"x","hash":"y"}',
      '{"stream":"s","seq":1,"prev_hash":1,"hash":"y"}',
      '{"stream":"s","seq":1,"prev_hash":"x","hash":null}',
      "[1,2]",
      "42",
      good ?? "",
    ]);
    expect(report.findings.map((finding) => [finding.code, finding.line])).toEqual([
      ["CHAIN_LINE_INVALID", 1],
      ["CHAIN_LINE_INVALID", 2],
      ["CHAIN_LINE_INVALID", 3],
      ["CHAIN_LINE_INVALID", 4],
      ["CHAIN_LINE_INVALID", 5],
      ["CHAIN_LINE_INVALID", 6],
    ]);
    expect(report.ignored).toBe(2);
    expect(report.streams[STREAM]).toMatchObject({ lines: 1, starts: 1 });
    expect(report.streams[STREAM]?.head).toEqual({
      seq: 1,
      hash: (JSON.parse(good ?? "{}") as { hash: string }).hash,
    });
  });

  it("recognises genesis only as sequence one from the genesis hash", () => {
    const forged = new HashChain(STREAM, { seq: 0, hash: `sha256:${"1".repeat(64)}` });
    const report = verifyAuditChain([
      ...lines(2),
      forged.link({ event: "E" }, () => undefined).line,
    ]);
    expect(report.findings.map((finding) => finding.code)).toEqual(["CHAIN_SEQ_GAP"]);
    expect(report.streams[STREAM]?.starts).toBe(1);
    const genesisLater = new HashChain(STREAM);
    const late = verifyAuditChain([
      ...lines(2),
      genesisLater.link({ event: "E" }, () => undefined).line,
    ]);
    expect(late.ok).toBe(true);
    expect(late.streams[STREAM]?.starts).toBe(2);
    expect(CHAIN_GENESIS).toMatch(/^sha256:0{64}$/);
  });
});

describe("a hosted process's chains", () => {
  it("holds each tenant's chain of a stream apart, so one process's output verifies whole", () => {
    const acme = new HashChain(STREAM, null, "acme");
    const globex = new HashChain(STREAM, null, "globex");
    const output: string[] = [];
    for (let index = 0; index < 5; index += 1) {
      acme.link({ event: "A" }, (line) => output.push(line));
      globex.link({ event: "G" }, (line) => output.push(line));
    }
    const report = verifyAuditChain(output);
    expect(report.ok).toBe(true);
    expect(report.streams).toEqual({
      [`acme/${STREAM}`]: { lines: 5, head: acme.head, starts: 1 },
      [`globex/${STREAM}`]: { lines: 5, head: globex.head, starts: 1 },
    });
  });

  it("breaks the chain of a line moved to another tenant, and names whose chain broke", () => {
    const chain = new HashChain(STREAM, null, "acme");
    const output: string[] = [];
    for (let index = 0; index < 3; index += 1)
      chain.link({ event: "A" }, (line) => output.push(line));
    const moved = output.map((line, index) =>
      index === 1 ? line.replace('"tenant":"acme"', '"tenant":"globex"') : line,
    );
    const report = verifyAuditChain(moved);
    expect(report.ok).toBe(false);
    expect(report.findings[0]).toMatchObject({
      code: "CHAIN_HASH_MISMATCH",
      line: 2,
      stream: STREAM,
      tenant: "globex",
      seq: 2,
    });
    // Its successor now follows nothing in acme's chain.
    expect(report.findings.map((finding) => [finding.code, finding.tenant])).toEqual([
      ["CHAIN_HASH_MISMATCH", "globex"],
      ["CHAIN_SEQ_GAP", "acme"],
    ]);
  });

  it("refuses a tenant that is not a name", () => {
    const line = JSON.parse(lines(1)[0] ?? "{}") as Record<string, unknown>;
    for (const tenant of ["", 7, null, ["acme"]]) {
      const report = verifyAuditChain([JSON.stringify({ ...line, tenant })]);
      expect([tenant, report.findings.map((finding) => finding.code)]).toEqual([
        tenant,
        ["CHAIN_LINE_INVALID"],
      ]);
    }
  });
});
