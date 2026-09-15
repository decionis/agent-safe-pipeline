import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import type { ChainHead, HashChain } from "./HashChain.js";

/** The file operations the journal needs; the real filesystem unless a test injects one. */
export interface ChainJournalFs {
  mkdir(path: string): void;
  read(path: string): string | null;
  write(path: string, text: string): void;
  rename(from: string, to: string): void;
}

export interface ChainJournalOptions {
  /** How many links between persisted heads; the head is also persisted when the journal stops. */
  readonly checkpointLines: number;
  readonly fs?: ChainJournalFs;
}

const HEAD_PATTERN = /^sha256:[0-9a-f]{64}$/;

function realFs(): ChainJournalFs {
  return {
    mkdir: (path) => {
      mkdirSync(path, { recursive: true, mode: 0o700 });
    },
    read: (path) => {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return null;
      }
    },
    write: (path, text) => {
      writeFileSync(path, text, { mode: 0o600 });
    },
    rename: (from, to) => {
      renameSync(from, to);
    },
  };
}

/**
 * Persists each chain's head under the journal directory, so a chain
 * continues across a restart within the life of the volume instead of
 * starting again from genesis. The head is written every N links and once
 * more when the journal stops; a process that dies between two checkpoints
 * resumes from the older head, and the verifier reports the overlap as a
 * sequence gap at the point of the crash rather than hiding it. The log
 * pipeline that keeps the lines is the durable store; this keeps the
 * sequence honest across restarts.
 */
export class ChainJournal {
  private readonly fs: ChainJournalFs;
  private readonly directory: string;

  public constructor(
    directory: string,
    private readonly options: ChainJournalOptions,
  ) {
    this.fs = options.fs ?? realFs();
    this.directory = join(directory, "chain");
    this.fs.mkdir(this.directory);
  }

  /** The persisted head of a stream, or null when there is none or it is not one. */
  public restore(stream: string): ChainHead | null {
    const text = this.fs.read(this.path(stream));
    if (text === null) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return null;
    }
    if (typeof parsed !== "object" || parsed === null) return null;
    const record = parsed as Record<string, unknown>;
    const seq = record["seq"];
    const hash = record["hash"];
    if (record["stream"] !== stream) return null;
    if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 1) return null;
    if (typeof hash !== "string" || !HEAD_PATTERN.test(hash)) return null;
    return { seq, hash };
  }

  /** Persists the chain's head every N links; the returned stop persists it once more. */
  public follow(chain: HashChain, events: SecurityEvents): () => void {
    let since = 0;
    const unsubscribe = chain.onLink(() => {
      since += 1;
      if (since < this.options.checkpointLines) return;
      since = 0;
      this.checkpoint(chain, events);
    });
    return () => {
      unsubscribe();
      this.checkpoint(chain, events);
    };
  }

  /** The event first, so the security chain's own checkpoint line is inside the head it persists. */
  public checkpoint(chain: HashChain, events: SecurityEvents): void {
    events.emit({ event: "CHAIN_CHECKPOINT", chain: chain.stream, head: chain.head.seq });
    const head = chain.head;
    const path = this.path(chain.stream);
    this.fs.write(`${path}.tmp`, JSON.stringify({ stream: chain.stream, ...head }));
    this.fs.rename(`${path}.tmp`, path);
  }

  private path(stream: string): string {
    return join(this.directory, `${stream.replace(/[^\w.-]/g, "_")}.json`);
  }
}
