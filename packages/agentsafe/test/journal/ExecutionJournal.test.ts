import { describe, expect, it } from "vitest";
import {
  JOURNAL_VERSION,
  JournalError,
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

  it("is four records discriminated on one field, each with exactly its own fields", () => {
    // A reader in another language implements against this shape, so the
    // discriminator and each record's field list are the contract and not
    // an implementation detail of the schema.
    const definition = JournalRecordSchema.def as unknown as {
      readonly discriminator: string;
      readonly options: readonly { readonly def: { readonly shape: Record<string, unknown> } }[];
    };
    expect(definition.discriminator).toBe("record");
    expect(definition.options).toHaveLength(4);
    expect(definition.options.map((option) => Object.keys(option.def.shape))).toEqual([
      [
        "record",
        "at",
        "intent_id",
        "intent_hash",
        "idempotency_key",
        "decision_id",
        "dossier_id",
        "caller_principal",
        "intent",
      ],
      [
        "record",
        "at",
        "intent_id",
        "intent_hash",
        "idempotency_key",
        "grant_id",
        "expires_at",
        "request_digest",
      ],
      ["record", "at", "intent_id", "intent_hash", "outcome", "executed", "finalization"],
      ["record", "at", "intent_id", "intent_hash", "status", "source"],
    ]);
  });

  it("names its own refusal", () => {
    const error = new JournalError("JOURNAL_RECORD_INVALID");
    expect(error.name).toBe("JournalError");
    expect(error.message).toBe("JOURNAL_RECORD_INVALID");
  });

  it("anchors the digest it stores, at both ends", () => {
    // A stored hash is what a restart re-hashes an intent against, so a
    // substring match would let a longer string stand in for the digest.
    for (const value of [
      `x${HASH}`,
      `${HASH}x`,
      `sha256:${"A".repeat(64)}`,
      `sha256:${"a".repeat(63)}`,
      `sha256:${"a".repeat(65)}`,
      `sha1:${"a".repeat(64)}`,
    ]) {
      expect(
        JournalRecordSchema.safeParse({ ...opened(), intent_hash: value }).success,
        value,
      ).toBe(false);
    }
    expect(
      JournalRecordSchema.safeParse({ ...claimed(), request_digest: `${OTHER} ` }).success,
    ).toBe(false);
  });

  it("stores an identifier trimmed, and refuses one that is only whitespace", () => {
    // Journal records are matched by identifier across a restart, so " x "
    // and "x" must not be two different attempts.
    const parsed = JournalRecordSchema.parse({ ...opened(), intent_id: "  intent-1  " });
    expect(parsed.intent_id).toBe("intent-1");
    const key = JournalRecordSchema.parse({ ...claimed(), idempotency_key: " payout-1-v1 " });
    expect(key.record === "GRANT_CLAIMED" && key.idempotency_key).toBe("payout-1-v1");
    // The opened record carries the same key and trims it the same way: a
    // claim and the attempt it claims have to match on this string.
    const openedKey = JournalRecordSchema.parse({ ...opened(), idempotency_key: " payout-1-v1 " });
    expect(openedKey.record === "ATTEMPT_OPENED" && openedKey.idempotency_key).toBe("payout-1-v1");
    const outcome = JournalRecordSchema.parse({ ...closed(), outcome: " COMPLETED " });
    expect(outcome.record === "ATTEMPT_CLOSED" && outcome.outcome).toBe("COMPLETED");
    for (const blank of ["", "   ", "\t"]) {
      expect(JournalRecordSchema.safeParse({ ...opened(), intent_id: blank }).success, blank).toBe(
        false,
      );
      expect(
        JournalRecordSchema.safeParse({ ...claimed(), idempotency_key: blank }).success,
        blank,
      ).toBe(false);
      expect(JournalRecordSchema.safeParse({ ...closed(), outcome: blank }).success, blank).toBe(
        false,
      );
    }
  });

  it("holds each record to its own shape, and to no other record's", () => {
    // The discriminator is `record`: a claim's fields do not make an opened
    // attempt, and neither does a record naming itself something else.
    const withoutIntent: Record<string, unknown> = { ...opened() };
    delete withoutIntent["intent"];
    expect(JournalRecordSchema.safeParse(withoutIntent).success).toBe(false);
    expect(JournalRecordSchema.safeParse({ ...opened(), record: "GRANT_CLAIMED" }).success).toBe(
      false,
    );
    expect(JournalRecordSchema.safeParse({ ...claimed(), record: "ATTEMPT_OPENED" }).success).toBe(
      false,
    );
    for (const extra of [{ grant_id: "grant-1" }, { status: "COMPLETED" }, { source: "STARTUP" }]) {
      expect(JournalRecordSchema.safeParse({ ...opened(), ...extra }).success).toBe(false);
    }
    expect(JournalRecordSchema.safeParse({ ...closed(), request_digest: OTHER }).success).toBe(
      false,
    );
    // And a record with no discriminator at all is not the first of the four.
    const withoutKind: Record<string, unknown> = { ...opened() };
    delete withoutKind["record"];
    expect(JournalRecordSchema.safeParse(withoutKind).success).toBe(false);
  });

  it("names every finalization, status and source it will ever store, and no other", () => {
    for (const finalization of ["RECORDED", "PENDING", "UNSUPPORTED", null]) {
      expect(
        JournalRecordSchema.safeParse({ ...closed(), finalization }).success,
        `${finalization}`,
      ).toBe(true);
    }
    for (const finalization of ["RECORD", "QUEUED", "", "recorded"]) {
      expect(
        JournalRecordSchema.safeParse({ ...closed(), finalization }).success,
        finalization,
      ).toBe(false);
    }
    const reconciled = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
      record: "RECONCILED",
      at: AT,
      intent_id: "intent-1",
      intent_hash: HASH,
      status: "COMPLETED",
      source: "STARTUP",
      ...overrides,
    });
    for (const status of [
      "COMPLETED",
      "DEFINITELY_NOT_EXECUTED",
      "UNKNOWN_AFTER_DISPATCH",
      "BLOCKED",
    ]) {
      expect(JournalRecordSchema.safeParse(reconciled({ status })).success, status).toBe(true);
    }
    for (const status of ["FAILED", "", "completed", "NOT_EXECUTED"]) {
      expect(JournalRecordSchema.safeParse(reconciled({ status })).success, status).toBe(false);
    }
    for (const source of ["STARTUP", "CALLER"]) {
      expect(JournalRecordSchema.safeParse(reconciled({ source })).success, source).toBe(true);
    }
    for (const source of ["OPERATOR", "", "startup"]) {
      expect(JournalRecordSchema.safeParse(reconciled({ source })).success, source).toBe(false);
    }
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
