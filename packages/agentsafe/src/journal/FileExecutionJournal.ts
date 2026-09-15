import {
  closeSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  statSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import {
  JournalError,
  JournalRecordSchema,
  openAttemptsFrom,
  type ExecutionJournal,
  type JournalRecord,
  type OpenAttempt,
} from "./ExecutionJournal.js";

/** The most a single record may be, so one attempt cannot fill the volume. */
export const MAX_RECORD_BYTES = 256 * 1024;
const FILE_PATTERN = /^attempts-(\d{4}-\d{2}-\d{2})\.jsonl$/;

export interface FileExecutionJournalOptions {
  /** How many days of files to read back at start; older files are left alone. */
  readonly retainDays?: number;
  readonly clock?: () => Date;
}

/**
 * The journal as append-only JSONL, one file per UTC day, each record
 * flushed to the device before the call returns: an attempt is on disk
 * before the provider is touched, or the append throws and nothing is
 * dispatched. The directory is created private to this process, a path that
 * is not a regular file is refused, and a record larger than the bound is
 * refused rather than truncated.
 *
 * What it is not: replicated. A pod that loses its volume loses its open
 * attempts, which the deployment answers with a per-pod claim and the
 * authority's own lease recovery.
 */
export class FileExecutionJournal implements ExecutionJournal {
  private readonly clock: () => Date;
  private readonly retainDays: number;
  private handle: { readonly day: string; readonly fd: number } | null = null;

  public constructor(
    private readonly directory: string,
    options: FileExecutionJournalOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.retainDays = options.retainDays ?? 7;
    try {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const stat = statSync(directory);
      if (!stat.isDirectory()) throw new Error("not a directory");
    } catch {
      throw new JournalError("JOURNAL_DIRECTORY_UNUSABLE");
    }
  }

  public async append(record: JournalRecord): Promise<void> {
    const line = `${JSON.stringify(JournalRecordSchema.parse(record))}\n`;
    const bytes = Buffer.from(line, "utf8");
    if (bytes.byteLength > MAX_RECORD_BYTES) throw new JournalError("JOURNAL_RECORD_TOO_LARGE");
    const fd = this.fileFor(FileExecutionJournal.day(this.clock()));
    try {
      writeSync(fd, bytes);
      fsyncSync(fd);
    } catch {
      throw new JournalError("JOURNAL_WRITE_FAILED");
    }
    await Promise.resolve();
  }

  public async openAttempts(): Promise<readonly OpenAttempt[]> {
    return await Promise.resolve(openAttemptsFrom(this.records()));
  }

  public close(): void {
    if (this.handle !== null) closeSync(this.handle.fd);
    this.handle = null;
  }

  /** Every record in the retained files, oldest day first; a line that is not one is skipped. */
  private records(): JournalRecord[] {
    const records: JournalRecord[] = [];
    for (const day of this.days()) {
      let text: string;
      try {
        text = readFileSync(join(this.directory, `attempts-${day}.jsonl`), "utf8");
      } catch {
        continue;
      }
      for (const line of text.split("\n")) {
        if (line.trim() === "") continue;
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          continue;
        }
        const record = JournalRecordSchema.safeParse(parsed);
        if (record.success) records.push(record.data);
      }
    }
    return records;
  }

  /** The retained days present in the directory, oldest first. */
  private days(): string[] {
    const floor = new Date(this.clock().getTime() - this.retainDays * 86_400_000);
    const earliest = FileExecutionJournal.day(floor);
    let entries: string[];
    try {
      entries = readdirSync(this.directory);
    } catch {
      return [];
    }
    return entries
      .map((entry) => FILE_PATTERN.exec(entry)?.[1])
      .filter((day): day is string => day !== undefined && day >= earliest)
      .sort();
  }

  /** The day's file, opened for appending only, private to this process. */
  private fileFor(day: string): number {
    if (this.handle?.day === day) return this.handle.fd;
    if (this.handle !== null) closeSync(this.handle.fd);
    this.handle = null;
    const path = join(this.directory, `attempts-${day}.jsonl`);
    let fd: number;
    try {
      // "a" never follows a symlink into a file it would then append to
      // without noticing: the descriptor is checked before anything is written.
      fd = openSync(path, "a", 0o600);
    } catch {
      throw new JournalError("JOURNAL_UNWRITABLE");
    }
    try {
      if (!fstatSync(fd).isFile()) throw new Error("not a regular file");
    } catch {
      closeSync(fd);
      throw new JournalError("JOURNAL_NOT_A_FILE");
    }
    this.handle = { day, fd };
    return fd;
  }

  private static day(at: Date): string {
    return at.toISOString().slice(0, 10);
  }
}
