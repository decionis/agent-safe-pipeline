import { z } from "zod";

export const JOURNAL_VERSION = "agent-safe.attempts/1";

const identifier = z.string().trim().min(1).max(200);
const hash = z.string().regex(/^sha256:[0-9a-f]{64}$/);

/**
 * What the journal records about one attempt, in the order it happens:
 * opened before the executor runs, claimed after the grant is consumed and
 * before the provider is touched, closed once the outcome is known, and
 * reconciled when a lost outcome is resolved later. The intent is stored
 * whole on `ATTEMPT_OPENED`, because reconciliation needs the exact intent
 * it was and nothing less will re-hash to the same value.
 */
export const JournalRecordSchema = z.discriminatedUnion("record", [
  z.strictObject({
    record: z.literal("ATTEMPT_OPENED"),
    at: z.string().datetime(),
    intent_id: identifier,
    intent_hash: hash,
    idempotency_key: z.string().trim().min(1).max(180),
    decision_id: identifier,
    dossier_id: identifier,
    caller_principal: identifier.nullable(),
    /** The captured intent, verbatim, so a restart can present it again. */
    intent: z.record(z.string(), z.unknown()),
  }),
  z.strictObject({
    record: z.literal("GRANT_CLAIMED"),
    at: z.string().datetime(),
    intent_id: identifier,
    intent_hash: hash,
    idempotency_key: z.string().trim().min(1).max(180),
    grant_id: identifier,
    expires_at: z.string().datetime(),
    /** SHA-256 over the canonical parameters the handler is about to send. */
    request_digest: hash,
  }),
  z.strictObject({
    record: z.literal("ATTEMPT_CLOSED"),
    at: z.string().datetime(),
    intent_id: identifier,
    intent_hash: hash,
    outcome: z.string().trim().min(1).max(64),
    executed: z.boolean().nullable(),
    finalization: z.enum(["RECORDED", "PENDING", "UNSUPPORTED"]).nullable(),
  }),
  z.strictObject({
    record: z.literal("RECONCILED"),
    at: z.string().datetime(),
    intent_id: identifier,
    intent_hash: hash,
    status: z.enum(["COMPLETED", "DEFINITELY_NOT_EXECUTED", "UNKNOWN_AFTER_DISPATCH", "BLOCKED"]),
    source: z.enum(["STARTUP", "CALLER"]),
  }),
]);

export type JournalRecord = z.infer<typeof JournalRecordSchema>;
export type JournalRecordKind = JournalRecord["record"];

/** An attempt whose outcome the journal does not know, as the reconciler finds it. */
export interface OpenAttempt {
  readonly intentId: string;
  readonly intentHash: string;
  readonly idempotencyKey: string;
  readonly openedAt: string;
  readonly decisionId: string;
  readonly dossierId: string;
  readonly grantId: string | null;
  readonly expiresAt: string | null;
  readonly callerPrincipal: string | null;
  /** `CLAIMED`: a grant was consumed, so the provider may have acted. `OPENED`: it never was. */
  readonly state: "OPENED" | "CLAIMED";
  readonly intent: Readonly<Record<string, unknown>>;
}

/** A refusal by the journal: the code, never a path or a value. */
export class JournalError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "JournalError";
  }
}

/**
 * Where the executor writes what it is about to do, before it does it. The
 * contract is deliberately small: append a record, and read back the
 * attempts whose outcome is not yet known. Nothing here reaches the audit
 * stream or an evidence export; the journal holds the request's own
 * parameters, which the evidence planes never carry.
 */
export interface ExecutionJournal {
  /** Appends one record durably. It must throw rather than lose a record. */
  append(record: JournalRecord): Promise<void>;
  /** Attempts opened and not closed or reconciled, oldest first. */
  openAttempts(): Promise<readonly OpenAttempt[]>;
  close(): void;
}

/** Folds a stream of records into the attempts still open, oldest first. */
export function openAttemptsFrom(records: Iterable<JournalRecord>): readonly OpenAttempt[] {
  const open = new Map<string, OpenAttempt>();
  for (const record of records) {
    if (record.record === "ATTEMPT_OPENED") {
      open.set(record.intent_id, {
        intentId: record.intent_id,
        intentHash: record.intent_hash,
        idempotencyKey: record.idempotency_key,
        openedAt: record.at,
        decisionId: record.decision_id,
        dossierId: record.dossier_id,
        grantId: null,
        expiresAt: null,
        callerPrincipal: record.caller_principal,
        state: "OPENED",
        intent: record.intent,
      });
      continue;
    }
    if (record.record === "GRANT_CLAIMED") {
      const attempt = open.get(record.intent_id);
      if (attempt !== undefined) {
        open.set(record.intent_id, {
          ...attempt,
          grantId: record.grant_id,
          expiresAt: record.expires_at,
          state: "CLAIMED",
        });
      }
      continue;
    }
    open.delete(record.intent_id);
  }
  return [...open.values()];
}
