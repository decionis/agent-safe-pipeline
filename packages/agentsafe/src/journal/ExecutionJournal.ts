/**
 * The journal port moved into `@decionis/agent-safe-pipeline` with the runner
 * that journals through it (`GovernedExecutionRunner`). Re-exported here so
 * every journal in this package, and every existing import, implements and
 * names the one contract.
 */
export {
  authorizationsFrom,
  dispatchedUnderFrom,
  IDEMPOTENCY_KEY_DISPATCHED,
  JOURNAL_VERSION,
  JournalError,
  JournalRecordSchema,
  openAttemptsFrom,
  type DispatchedAuthorization,
  type ExecutionJournal,
  type JournalRecord,
  type JournalRecordKind,
  type OpenAttempt,
} from "@decionis/agent-safe-pipeline";
