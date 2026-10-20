import { constants, mkdirSync, statSync } from "node:fs";
import { open, readFile, readdir, type FileHandle } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";
import { CardOutcomeFactSchema, type CardOutcomeFact } from "./CardOutcomeFact.js";
import {
  CardOutcomeLedgerError,
  oldestFirst,
  type CardOutcomeLedger,
} from "./CardOutcomeLedger.js";

/** The longest line a read takes for a fact; a longer one is skipped, never parsed. */
export const MAX_FACT_BYTES = 16 * 1024;
const FILE_PATTERN = /^card-outcomes-(\d{4}-\d{2}-\d{2})\.([a-z0-9-]{1,63})\.jsonl$/;
/**
 * Append, create, write only; never through a symbolic link planted where the file should be,
 * and never waiting on a pipe planted there either.
 */
const APPEND_FLAGS =
  constants.O_WRONLY |
  constants.O_APPEND |
  constants.O_CREAT |
  (constants.O_NOFOLLOW ?? 0) |
  (constants.O_NONBLOCK ?? 0);

export interface FileCardOutcomeLedgerOptions {
  /** This replica's name in its files; the host's name when absent. */
  readonly replica?: string;
}

/**
 * The outcome facts as append-only JSONL, one file per UTC day and per replica:
 * `card-outcomes-<day>.<replica>.jsonl`. Replicas that share the directory (a volume every
 * replica mounts) each write their own file, so no two processes append to one; the producer
 * reads every replica's files and orders the facts by time, so a purchase held on one replica
 * and claimed on another reads as one purchase.
 *
 * The directory is created private to this process, a path that is not a regular file is
 * refused, and a line that is not a fact, or is longer than the bound, is skipped when read
 * rather than trusted. Nothing here is deleted: older days are left for the operator's
 * retention, and only the days a read asks for are opened.
 */
export class FileCardOutcomeLedger implements CardOutcomeLedger {
  private readonly replica: string;

  public constructor(
    private readonly directory: string,
    options: FileCardOutcomeLedgerOptions = {},
  ) {
    try {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      if (!statSync(directory).isDirectory()) throw new Error("not a directory");
    } catch {
      throw new CardOutcomeLedgerError("CARD_OUTCOMES_DIRECTORY_UNUSABLE");
    }
    this.replica = FileCardOutcomeLedger.replicaName(options.replica ?? hostname());
  }

  /**
   * A replica's name as a file may carry it: lowercase letters, digits and dashes, at most 63,
   * so a pod name is kept as it reads and anything else becomes a dash. Linear, with no pattern
   * a hostile name could make backtrack.
   */
  public static replicaName(value: string): string {
    let name = "";
    for (const character of value.toLowerCase()) {
      const unit = character.charCodeAt(0);
      const kept =
        character.length === 1 &&
        ((unit >= 0x61 && unit <= 0x7a) || (unit >= 0x30 && unit <= 0x39));
      name += kept ? character : "-";
      if (name.length >= 63) break;
    }
    let start = 0;
    let end = name.length;
    while (start < end && name[start] === "-") start += 1;
    while (end > start && name[end - 1] === "-") end -= 1;
    return start === end ? "local" : name.slice(start, end);
  }

  public async append(facts: readonly CardOutcomeFact[]): Promise<void> {
    const days = new Map<string, string[]>();
    for (const fact of facts) {
      const parsed = CardOutcomeFactSchema.safeParse(fact);
      if (!parsed.success) throw new CardOutcomeLedgerError("CARD_OUTCOMES_FACT_INVALID");
      // The schema bounds every field, so a fact's line is always well inside the read bound.
      const line = `${JSON.stringify(parsed.data)}\n`;
      const day = new Date(parsed.data.at).toISOString().slice(0, 10);
      const lines = days.get(day) ?? [];
      lines.push(line);
      days.set(day, lines);
    }
    for (const [day, lines] of days) {
      await this.write(join(this.directory, `card-outcomes-${day}.${this.replica}.jsonl`), lines);
    }
  }

  public async since(from: Date): Promise<readonly CardOutcomeFact[]> {
    const earliest = from.toISOString().slice(0, 10);
    let entries: string[];
    try {
      entries = await readdir(this.directory);
    } catch {
      throw new CardOutcomeLedgerError("CARD_OUTCOMES_UNREADABLE");
    }
    const files = entries
      .map((entry) => ({ entry, match: FILE_PATTERN.exec(entry) }))
      .filter(({ match }) => match !== null && (match[1] ?? "") >= earliest)
      .map(({ entry }) => entry)
      .sort();
    const facts: CardOutcomeFact[] = [];
    for (const entry of files) {
      let text: string;
      try {
        text = await readFile(join(this.directory, entry), "utf8");
      } catch {
        // A file another replica is rotating, or one removed by retention: nothing to read.
        continue;
      }
      for (const line of text.split("\n")) {
        if (line.trim() === "" || line.length > MAX_FACT_BYTES) continue;
        let value: unknown;
        try {
          value = JSON.parse(line);
        } catch {
          continue;
        }
        const fact = CardOutcomeFactSchema.safeParse(value);
        if (fact.success) facts.push(fact.data);
      }
    }
    return oldestFirst(facts, from);
  }

  /** One day's lines, appended in one write to a file that is a regular file and nothing else. */
  private async write(path: string, lines: readonly string[]): Promise<void> {
    let handle: FileHandle;
    try {
      handle = await open(path, APPEND_FLAGS, 0o600);
    } catch {
      throw new CardOutcomeLedgerError("CARD_OUTCOMES_UNWRITABLE");
    }
    try {
      if (!(await handle.stat()).isFile()) {
        throw new CardOutcomeLedgerError("CARD_OUTCOMES_NOT_A_FILE");
      }
      await handle.write(lines.join(""));
    } catch (error) {
      throw error instanceof CardOutcomeLedgerError
        ? error
        : new CardOutcomeLedgerError("CARD_OUTCOMES_WRITE_FAILED");
    } finally {
      await handle.close().catch(() => undefined);
    }
  }
}
