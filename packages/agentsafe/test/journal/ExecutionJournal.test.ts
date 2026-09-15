import { describe, expect, it } from "vitest";
import {
  JOURNAL_VERSION,
  JournalRecordSchema,
  openAttemptsFrom,
  type JournalRecord,
} from "../../src/journal/ExecutionJournal.js";
import { InMemoryExecutionJournal } from "../../src/journal/InMemoryExecutionJournal.js";
import { TENANT_ID } from "../support/Environment.js";

const HASH = `sha256:${"a".repeat(64)}`;
const OTHER = `sha256:${"b".repeat(64)}`;
const AT = "2026-09-15T10:00:00.000Z";

const intent = (): Record<string, unknown> => ({
  intentId: "intent-1",
  tenantId: TENANT_ID,
  action: "forward_request",
});

const opened = (id = "intent-1"): JournalRecord => ({
  record: "ATTEMPT_OPENED",
  at: AT,
  intent_id: id,
  intent_hash: HASH,
  idempotency_key: "payout-1-v1",
  decision_id: "decision-1",
  dossier_id: "dossier-1",
  caller_principal: "synthetic-treasury-workflow",
  intent: intent(),
});

const claimed = (id = "intent-1"): JournalRecord => ({
  record: "GRANT_CLAIMED",
  at: AT,
  intent_id: id,
  intent_hash: HASH,
  idempotency_key: "payout-1-v1",
  grant_id: "grant-1",
  expires_at: AT,
  request_digest: OTHER,
});

const closed = (id = "intent-1"): JournalRecord => ({
  record: "ATTEMPT_CLOSED",
  at: AT,
  intent_id: id,
  intent_hash: HASH,
  outcome: "COMPLETED",
  executed: true,
  finalization: "RECORDED",
});

describe("the journal's record contract", () => {
  it("names its version and accepts exactly the four records, with nothing extra", () => {
    expect(JOURNAL_VERSION).toBe("agent-safe.attempts/1");
    for (const record of [
      opened(),
      claimed(),
      closed(),
      {
        record: "RECONCILED",
        at: AT,
        intent_id: "intent-1",
        intent_hash: HASH,
        status: "COMPLETED",
        source: "STARTUP",
      } as JournalRecord,
    ]) {
      expect(JournalRecordSchema.parse(record)).toEqual(record);
    }
    expect(JournalRecordSchema.safeParse({ ...opened(), extra: 1 }).success).toBe(false);
    expect(
      JournalRecordSchema.safeParse({ ...opened(), intent_hash: "sha256:short" }).success,
    ).toBe(false);
    expect(JournalRecordSchema.safeParse({ ...claimed(), expires_at: "tomorrow" }).success).toBe(
      false,
    );
    expect(JournalRecordSchema.safeParse({ ...closed(), executed: "yes" }).success).toBe(false);
    expect(JournalRecordSchema.safeParse({ record: "SOMETHING_ELSE", at: AT }).success).toBe(false);
    expect(JournalRecordSchema.safeParse({ ...opened(), caller_principal: null }).success).toBe(
      true,
    );
  });

  it("folds the stream into the attempts still open, remembering which ones claimed a grant", () => {
    expect(openAttemptsFrom([])).toEqual([]);
    const open = openAttemptsFrom([opened(), opened("intent-2"), claimed("intent-2")]);
    expect(open.map((attempt) => [attempt.intentId, attempt.state])).toEqual([
      ["intent-1", "OPENED"],
      ["intent-2", "CLAIMED"],
    ]);
    expect(open[1]).toMatchObject({
      grantId: "grant-1",
      expiresAt: AT,
      idempotencyKey: "payout-1-v1",
      decisionId: "decision-1",
      dossierId: "dossier-1",
      callerPrincipal: "synthetic-treasury-workflow",
      intent: intent(),
    });
    expect(openAttemptsFrom([opened(), claimed(), closed()])).toEqual([]);
    expect(
      openAttemptsFrom([
        opened(),
        claimed(),
        {
          record: "RECONCILED",
          at: AT,
          intent_id: "intent-1",
          intent_hash: HASH,
          status: "UNKNOWN_AFTER_DISPATCH",
          source: "CALLER",
        },
      ]),
    ).toEqual([]);
    // A claim for an attempt nobody opened is not an attempt; the record is
    // kept for the reader, not folded into state.
    expect(openAttemptsFrom([claimed("intent-9")])).toEqual([]);
  });
});

describe("InMemoryExecutionJournal", () => {
  it("keeps records for this process only, and can be made to fail once", async () => {
    const journal = new InMemoryExecutionJournal();
    await journal.append(opened());
    await journal.append(claimed());
    expect(journal.all).toHaveLength(2);
    expect((await journal.openAttempts()).map((attempt) => attempt.state)).toEqual(["CLAIMED"]);
    journal.failNextAppend();
    await expect(journal.append(closed())).rejects.toThrow("JOURNAL_WRITE_FAILED");
    await journal.append(closed());
    expect(await journal.openAttempts()).toEqual([]);
    journal.failNextAppend("JOURNAL_FULL");
    await expect(journal.append(opened())).rejects.toThrow("JOURNAL_FULL");
    journal.close();
    expect(journal.all).toEqual([]);
  });
});
