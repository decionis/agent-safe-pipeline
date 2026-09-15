import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { JournalError, type JournalRecord } from "../../src/journal/ExecutionJournal.js";
import { FileExecutionJournal, MAX_RECORD_BYTES } from "../../src/journal/FileExecutionJournal.js";

const root = mkdtempSync(join(tmpdir(), "agentsafe-attempts-"));
const HASH = `sha256:${"c".repeat(64)}`;

afterAll(() => rmSync(root, { recursive: true, force: true }));

let sequence = 0;
function directory(): string {
  sequence += 1;
  return join(root, `journal-${sequence}`);
}

const opened = (id: string, at = "2026-09-15T10:00:00.000Z"): JournalRecord => ({
  record: "ATTEMPT_OPENED",
  at,
  intent_id: id,
  intent_hash: HASH,
  idempotency_key: `payout-${id}`,
  decision_id: "decision-1",
  dossier_id: "dossier-1",
  caller_principal: null,
  intent: { intentId: id, action: "forward_request" },
});

const closed = (id: string): JournalRecord => ({
  record: "ATTEMPT_CLOSED",
  at: "2026-09-15T10:00:01.000Z",
  intent_id: id,
  intent_hash: HASH,
  outcome: "COMPLETED",
  executed: true,
  finalization: "RECORDED",
});

describe("FileExecutionJournal", () => {
  it("creates its directory private to the process and appends one JSON line per record", async () => {
    const path = directory();
    const journal = new FileExecutionJournal(path, {
      clock: () => new Date("2026-09-15T10:00:00Z"),
    });
    await journal.append(opened("intent-1"));
    await journal.append(closed("intent-1"));
    await journal.append(opened("intent-2"));
    expect(statSync(path).mode & 0o777).toBe(0o700);
    const file = join(path, "attempts-2026-09-15.jsonl");
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const lines = readFileSync(file, "utf8").trim().split("\n");
    expect(lines).toHaveLength(3);
    expect(JSON.parse(lines[0] ?? "{}")).toEqual(opened("intent-1"));
    expect((await journal.openAttempts()).map((attempt) => attempt.intentId)).toEqual(["intent-2"]);
    journal.close();
    // A second journal over the same directory reads what the first wrote.
    const reopened = new FileExecutionJournal(path, {
      clock: () => new Date("2026-09-15T10:00:00Z"),
    });
    expect((await reopened.openAttempts()).map((attempt) => attempt.intentId)).toEqual([
      "intent-2",
    ]);
    reopened.close();
  });

  it("writes one file per UTC day and reads back only the retained days, oldest first", async () => {
    const path = directory();
    let now = new Date("2026-09-10T23:59:59Z");
    const journal = new FileExecutionJournal(path, { retainDays: 2, clock: () => now });
    await journal.append(opened("old", "2026-09-10T23:59:59.000Z"));
    now = new Date("2026-09-14T00:00:00Z");
    await journal.append(opened("recent", "2026-09-14T00:00:00.000Z"));
    now = new Date("2026-09-15T00:00:00Z");
    await journal.append(opened("today", "2026-09-15T00:00:00.000Z"));
    expect(statSync(join(path, "attempts-2026-09-10.jsonl")).isFile()).toBe(true);
    expect(statSync(join(path, "attempts-2026-09-14.jsonl")).isFile()).toBe(true);
    expect(statSync(join(path, "attempts-2026-09-15.jsonl")).isFile()).toBe(true);
    // Two days back from the 15th: the 10th is outside the window and the
    // file is left alone rather than deleted.
    expect((await journal.openAttempts()).map((attempt) => attempt.intentId)).toEqual([
      "recent",
      "today",
    ]);
    journal.close();
  });

  it("skips a line that is not a record and keeps the rest", async () => {
    const path = directory();
    const journal = new FileExecutionJournal(path, {
      clock: () => new Date("2026-09-15T10:00:00Z"),
    });
    await journal.append(opened("good"));
    const file = join(path, "attempts-2026-09-15.jsonl");
    writeFileSync(
      file,
      `${readFileSync(file, "utf8")}not json\n{"record":"ATTEMPT_OPENED"}\n\n${JSON.stringify(opened("later"))}\n`,
    );
    expect((await journal.openAttempts()).map((attempt) => attempt.intentId)).toEqual([
      "good",
      "later",
    ]);
    journal.close();
  });

  it("refuses a record larger than the bound rather than truncating it", async () => {
    const path = directory();
    const journal = new FileExecutionJournal(path);
    const huge = {
      ...opened("huge"),
      intent: { intentId: "huge", padding: "x".repeat(MAX_RECORD_BYTES) },
    };
    await expect(journal.append(huge)).rejects.toThrow(
      new JournalError("JOURNAL_RECORD_TOO_LARGE"),
    );
    expect(await journal.openAttempts()).toEqual([]);
    journal.close();
  });

  it("refuses a directory it cannot use and a path that is not a directory", () => {
    const file = join(root, "a-file");
    writeFileSync(file, "not a directory");
    expect(() => new FileExecutionJournal(file)).toThrow(
      new JournalError("JOURNAL_DIRECTORY_UNUSABLE"),
    );
    expect(() => new FileExecutionJournal(join(file, "under-a-file"))).toThrow(
      new JournalError("JOURNAL_DIRECTORY_UNUSABLE"),
    );
  });

  it("refuses to write when the day's file cannot be opened", async () => {
    const path = directory();
    const journal = new FileExecutionJournal(path, {
      clock: () => new Date("2026-09-15T10:00:00Z"),
    });
    await journal.append(opened("first"));
    journal.close();
    chmodSync(path, 0o500);
    try {
      const blocked = new FileExecutionJournal(path, {
        clock: () => new Date("2026-09-16T10:00:00Z"),
      });
      await expect(blocked.append(opened("second"))).rejects.toThrow(
        new JournalError("JOURNAL_UNWRITABLE"),
      );
      blocked.close();
    } finally {
      chmodSync(path, 0o700);
    }
  });

  it("reads nothing from a directory whose entries cannot be listed", async () => {
    const path = directory();
    const journal = new FileExecutionJournal(path);
    await journal.append(opened("one"));
    journal.close();
    chmodSync(path, 0o300);
    try {
      const unreadable = new FileExecutionJournal(path);
      expect(await unreadable.openAttempts()).toEqual([]);
      unreadable.close();
    } finally {
      chmodSync(path, 0o700);
    }
  });
});
