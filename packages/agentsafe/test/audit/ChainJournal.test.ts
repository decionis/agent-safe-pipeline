import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { ChainJournal, type ChainJournalFs } from "../../src/audit/ChainJournal.js";
import { HashChain } from "../../src/audit/HashChain.js";
import { SECURITY_STREAM, SecurityEvents } from "../../src/incident/SecurityEvents.js";
import { verifyAuditChain } from "../../src/verify/VerifyAuditChain.js";
import { collectedEvents } from "../support/Environment.js";

function memoryFs(): ChainJournalFs & {
  readonly files: Map<string, string>;
  readonly made: string[];
} {
  const files = new Map<string, string>();
  const made: string[] = [];
  return {
    files,
    made,
    mkdir: (path) => {
      made.push(path);
    },
    read: (path) => files.get(path) ?? null,
    write: (path, text) => {
      files.set(path, text);
    },
    rename: (from, to) => {
      files.set(to, files.get(from) ?? "");
      files.delete(from);
    },
  };
}

const STREAM = "agent-safe.executor-evidence/1";
const FILE = "/journal/chain/agent-safe.executor-evidence_1.json";

describe("ChainJournal", () => {
  const directory = mkdtempSync(join(tmpdir(), "agent-safe-journal-"));
  afterAll(() => rmSync(directory, { recursive: true, force: true }));

  it("creates its directory, restores a head it wrote, and refuses one that is not one", () => {
    const fs = memoryFs();
    const journal = new ChainJournal("/journal", { checkpointLines: 100, fs });
    expect(fs.made).toEqual(["/journal/chain"]);
    expect(journal.restore(STREAM)).toBeNull();
    const cases: [string, string][] = [
      ["not json", "not-json"],
      ["[]", "array"],
      ['{"stream":"other","seq":3,"hash":"sha256:' + "a".repeat(64) + '"}', "other-stream"],
      ['{"stream":"' + STREAM + '","seq":0,"hash":"sha256:' + "a".repeat(64) + '"}', "zero"],
      ['{"stream":"' + STREAM + '","seq":1.5,"hash":"sha256:' + "a".repeat(64) + '"}', "fraction"],
      [
        '{"stream":"' + STREAM + '","seq":"3","hash":"sha256:' + "a".repeat(64) + '"}',
        "string-seq",
      ],
      ['{"stream":"' + STREAM + '","seq":3,"hash":"sha256:short"}', "short-hash"],
      ['{"stream":"' + STREAM + '","seq":3,"hash":42}', "number-hash"],
    ];
    for (const [text, label] of cases) {
      fs.files.set(FILE, text);
      expect([label, journal.restore(STREAM)]).toEqual([label, null]);
    }
    fs.files.set(
      FILE,
      JSON.stringify({ stream: STREAM, seq: 3, hash: `sha256:${"a".repeat(64)}` }),
    );
    expect(journal.restore(STREAM)).toEqual({ seq: 3, hash: `sha256:${"a".repeat(64)}` });
  });

  it("persists the head every N links through a temporary file, reports it, and once more on stop", () => {
    const fs = memoryFs();
    const lines: string[] = [];
    const events = collectedEvents(lines);
    const journal = new ChainJournal("/journal", { checkpointLines: 2, fs });
    const chain = new HashChain(STREAM);
    const stop = journal.follow(chain, events);
    chain.link({ event: "ONE" }, () => undefined);
    expect(fs.files.has(FILE)).toBe(false);
    chain.link({ event: "TWO" }, () => undefined);
    expect(JSON.parse(fs.files.get(FILE) ?? "{}")).toEqual({ stream: STREAM, ...chain.head });
    expect(fs.files.has(`${FILE}.tmp`)).toBe(false);
    chain.link({ event: "THREE" }, () => undefined);
    expect(JSON.parse(fs.files.get(FILE) ?? "{}")).toMatchObject({ seq: 2 });
    stop();
    expect(JSON.parse(fs.files.get(FILE) ?? "{}")).toEqual({ stream: STREAM, ...chain.head });
    chain.link({ event: "FOUR" }, () => undefined);
    chain.link({ event: "FIVE" }, () => undefined);
    expect(JSON.parse(fs.files.get(FILE) ?? "{}")).toMatchObject({ seq: 3 });
    expect(lines.map((line) => JSON.parse(line) as Record<string, unknown>)).toEqual([
      expect.objectContaining({ event: "CHAIN_CHECKPOINT", chain: STREAM, head: 2 }),
      expect.objectContaining({ event: "CHAIN_CHECKPOINT", chain: STREAM, head: 3 }),
    ]);
  });

  it("keeps the security chain's own checkpoint line inside the head it persists", () => {
    const fs = memoryFs();
    const lines: string[] = [];
    const events = new SecurityEvents((line) => lines.push(line));
    const journal = new ChainJournal("/journal", { checkpointLines: 3, fs });
    const stop = journal.follow(events.chain, events);
    events.emit({ event: "POSTURE_RESTORED" });
    events.emit({ event: "POSTURE_RESTORED" });
    events.emit({ event: "POSTURE_RESTORED" });
    stop();
    const persisted = journal.restore(SECURITY_STREAM);
    expect(persisted).toEqual(events.head);
    expect(lines.map((line) => (JSON.parse(line) as { event: string; seq: number }).seq)).toEqual([
      1, 2, 3, 4, 5,
    ]);
    const resumed = new SecurityEvents((line) => lines.push(line), {
      chain: new HashChain(SECURITY_STREAM, persisted),
    });
    resumed.emit({ event: "CHAIN_RESUMED", chain: SECURITY_STREAM, head: persisted?.seq ?? 0 });
    expect(verifyAuditChain(lines).ok).toBe(true);
    expect(verifyAuditChain(lines).streams[SECURITY_STREAM]?.head.seq).toBe(6);
  });

  it("writes real files privately and round-trips through them", () => {
    const journal = new ChainJournal(directory, { checkpointLines: 1 });
    const chain = new HashChain(STREAM);
    const stop = journal.follow(chain, collectedEvents());
    chain.link({ event: "ONE" }, () => undefined);
    stop();
    const path = join(directory, "chain", "agent-safe.executor-evidence_1.json");
    expect(statSync(join(directory, "chain")).mode & 0o777).toBe(0o700);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ stream: STREAM, ...chain.head });
    expect(new ChainJournal(directory, { checkpointLines: 1 }).restore(STREAM)).toEqual(chain.head);
  });
});
