import {
  authorizationsFrom,
  dispatchedUnderFrom,
  IDEMPOTENCY_KEY_DISPATCHED,
  JournalError,
  JournalRecordSchema,
  openAttemptsFrom,
  type DispatchedAuthorization,
  type ExecutionJournal,
  type JournalRecord,
  type OpenAttempt,
} from "./ExecutionJournal.js";
import type { SqlClient } from "./PostgresReplayStore.js";

export interface PostgresExecutionJournalOptions {
  readonly client: SqlClient;
  /**
   * Whose attempts these are: the organisation the executor runs for. Two
   * deployments that share a database never read each other's records, and
   * an idempotency key is single-use within one namespace.
   */
  readonly namespace: string;
  /** The journal table, optionally schema-qualified; `agentsafe_execution_journal` by default. */
  readonly table?: string;
}

export const DEFAULT_JOURNAL_TABLE = "agentsafe_execution_journal";

/** A lowercase SQL identifier, or `schema.table`: interpolated into SQL, so nothing else is. */
const TABLE = /^[a-z_][a-z0-9_]{0,62}(?:\.[a-z_][a-z0-9_]{0,62})?$/;
/** The SQLSTATE a unique index answers a second insert with. */
const UNIQUE_VIOLATION = "23505";

/**
 * The execution journal every replica shares: one row per record, appended
 * and never updated, read back in insertion order and folded with the same
 * functions the file journal uses, so the two cannot disagree about which
 * attempts are open or what an intent was dispatched under.
 *
 * It is the durable form of what `journaledActionHandler` does in the
 * runtime: the `GRANT_CLAIMED` record is written after the grant is consumed
 * and before the provider is touched, and a write that fails throws, so the
 * runner reports a failure before dispatch rather than an effect nobody
 * journaled. Single use of an idempotency key is the database's decision: a
 * partial unique index on `(namespace, idempotency_key)` over claim records
 * refuses the second claim, so two replicas racing on one key dispatch once,
 * and the loser is told `IDEMPOTENCY_KEY_DISPATCHED`.
 *
 * The operator creates the table (`PostgresExecutionJournal.schema()`); the
 * executor's role needs SELECT and INSERT on it and nothing else. Rows hold
 * the captured intent, parameters included, so the table is as sensitive as
 * the requests themselves.
 */
export class PostgresExecutionJournal implements ExecutionJournal {
  private readonly client: SqlClient;
  private readonly namespace: string;
  private readonly table: string;

  public constructor(options: PostgresExecutionJournalOptions) {
    const table = options.table ?? DEFAULT_JOURNAL_TABLE;
    if (!TABLE.test(table)) throw new Error("JOURNAL_TABLE_INVALID");
    if (options.namespace.length === 0 || options.namespace.length > 200) {
      throw new Error("JOURNAL_NAMESPACE_INVALID");
    }
    this.client = options.client;
    this.namespace = options.namespace;
    this.table = table;
  }

  /** The DDL an operator runs once, before the first replica starts. */
  public static schema(table = DEFAULT_JOURNAL_TABLE): string {
    if (!TABLE.test(table)) throw new Error("JOURNAL_TABLE_INVALID");
    const index = table.replace(".", "_");
    return [
      `CREATE TABLE IF NOT EXISTS ${table} (`,
      "  seq bigserial PRIMARY KEY,",
      "  namespace text NOT NULL,",
      "  intent_id text NOT NULL,",
      "  record_kind text NOT NULL,",
      "  idempotency_key text,",
      "  record jsonb NOT NULL,",
      "  recorded_at timestamptz NOT NULL DEFAULT now()",
      ");",
      `CREATE INDEX IF NOT EXISTS ${index}_intent ON ${table} (namespace, intent_id, seq);`,
      `CREATE UNIQUE INDEX IF NOT EXISTS ${index}_claim_once ON ${table} (namespace, idempotency_key) WHERE record_kind = 'GRANT_CLAIMED';`,
      "",
    ].join("\n");
  }

  public async append(record: JournalRecord): Promise<void> {
    const parsed = JournalRecordSchema.safeParse(record);
    if (!parsed.success) throw new JournalError("JOURNAL_RECORD_INVALID");
    const value = parsed.data;
    // Only a claim carries the key into its indexed column: the unique index
    // is over claims, and an opening record with the same key is not a use.
    const key = value.record === "GRANT_CLAIMED" ? value.idempotency_key : null;
    try {
      await this.client.query(
        `INSERT INTO ${this.table} (namespace, intent_id, record_kind, idempotency_key, record) VALUES ($1, $2, $3, $4, $5)`,
        [this.namespace, value.intent_id, value.record, key, JSON.stringify(value)],
      );
    } catch (error) {
      if ((error as { readonly code?: unknown } | null)?.code === UNIQUE_VIOLATION) {
        throw new JournalError(IDEMPOTENCY_KEY_DISPATCHED);
      }
      throw new JournalError("JOURNAL_WRITE_FAILED");
    }
  }

  public async openAttempts(): Promise<readonly OpenAttempt[]> {
    // An attempt is open until its intent has a closing record. Intent ids
    // are fresh per capture and opened once, so excluding every intent that
    // has one is exactly the fold's answer, without reading closed history.
    const rows = await this.read(
      `SELECT record FROM ${this.table} WHERE namespace = $1 AND intent_id IN (` +
        `SELECT intent_id FROM ${this.table} WHERE namespace = $1 AND record_kind = 'ATTEMPT_OPENED' ` +
        `EXCEPT SELECT intent_id FROM ${this.table} WHERE namespace = $1 AND record_kind IN ('ATTEMPT_CLOSED', 'RECONCILED')` +
        `) ORDER BY seq`,
      [this.namespace],
    );
    return openAttemptsFrom(rows);
  }

  public async authorizationsOf(intentId: string): Promise<readonly DispatchedAuthorization[]> {
    const rows = await this.read(
      `SELECT record FROM ${this.table} WHERE namespace = $1 AND intent_id = $2 ORDER BY seq`,
      [this.namespace, intentId],
    );
    return authorizationsFrom(rows, intentId);
  }

  public async dispatchedUnder(
    idempotencyKey: string,
  ): Promise<readonly DispatchedAuthorization[]> {
    const rows = await this.read(
      `SELECT record FROM ${this.table} WHERE namespace = $1 AND intent_id IN (` +
        `SELECT intent_id FROM ${this.table} WHERE namespace = $1 AND record_kind = 'GRANT_CLAIMED' AND idempotency_key = $2` +
        `) ORDER BY seq`,
      [this.namespace, idempotencyKey],
    );
    return dispatchedUnderFrom(rows, idempotencyKey);
  }

  /** Throws unless the table exists with the columns this journal uses. */
  public async probe(): Promise<void> {
    await this.client.query(
      `SELECT seq, namespace, intent_id, record_kind, idempotency_key, record FROM ${this.table} LIMIT 0`,
      [],
    );
  }

  /** The client belongs to the caller, who opened it and closes it. */
  public close(): void {}

  /** The rows' records that parse, in order; a row that does not is skipped, as a bad file line is. */
  private async read(text: string, values: readonly unknown[]): Promise<JournalRecord[]> {
    const result = await this.client.query(text, values);
    // Stryker disable next-line ArrayDeclaration: a seed element is not a record, and every fold ignores what is not one.
    const records: JournalRecord[] = [];
    // Stryker disable next-line ArrayDeclaration: an element of the fallback is not a row with a record, and is skipped.
    for (const row of result.rows ?? []) {
      const raw = (row as { readonly record?: unknown }).record;
      const value: unknown = typeof raw === "string" ? PostgresExecutionJournal.json(raw) : raw;
      const parsed = JournalRecordSchema.safeParse(value);
      if (parsed.success) records.push(parsed.data);
    }
    return records;
  }

  // Stryker disable all: an unparsable row is skipped either way, read as null or as undefined.
  private static json(text: string): unknown {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return null;
    }
  }
  // Stryker restore all
}
