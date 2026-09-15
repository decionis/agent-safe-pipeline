import {
  openAttemptsFrom,
  type ExecutionJournal,
  type JournalRecord,
  type JournalRecordKind,
} from "./ExecutionJournal.js";

/**
 * A journal that keeps its records in memory. It is honest about what it is:
 * nothing survives the process, so a deployment that needs an attempt to
 * outlive a restart configures `EXECUTOR_JOURNAL_DIR` and gets the file
 * journal. This exists for shadow mode, for the offline proof, and for tests.
 */
export class InMemoryExecutionJournal implements ExecutionJournal {
  private readonly records: JournalRecord[] = [];
  private failure: string | null = null;
  private failingKind: JournalRecordKind | null = null;

  /** Makes the next append throw; for the tests that prove a claim is never lost. */
  public failNextAppend(code = "JOURNAL_WRITE_FAILED"): void {
    this.failure = code;
  }

  /** Makes every append of one kind throw, until cleared with null. */
  public failEvery(kind: JournalRecordKind | null, code = "JOURNAL_WRITE_FAILED"): void {
    this.failingKind = kind;
    if (kind !== null) this.failure = code;
  }

  /** Forgets every record, as a fresh process would; the failures stay as set. */
  public clear(): void {
    this.records.length = 0;
  }

  public get all(): readonly JournalRecord[] {
    return this.records;
  }

  public async append(record: JournalRecord): Promise<void> {
    if (this.failingKind === record.record) throw new Error(this.failure ?? "JOURNAL_WRITE_FAILED");
    const failure = this.failingKind === null ? this.failure : null;
    if (this.failingKind === null) this.failure = null;
    if (failure !== null) throw new Error(failure);
    this.records.push(record);
    await Promise.resolve();
  }

  public async openAttempts(): Promise<ReturnType<typeof openAttemptsFrom>> {
    return await Promise.resolve(openAttemptsFrom(this.records));
  }

  public close(): void {
    this.records.length = 0;
  }
}
