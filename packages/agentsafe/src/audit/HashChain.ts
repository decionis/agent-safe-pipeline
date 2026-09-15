import { createHash } from "node:crypto";
import { CanonicalIntentHasher, type JsonValue } from "@decionis/agent-safe-pipeline";

/** The `prev_hash` of a chain's first line. */
export const CHAIN_GENESIS = `sha256:${"0".repeat(64)}`;

export interface ChainHead {
  readonly seq: number;
  readonly hash: string;
}

export type ChainFields = Readonly<Record<string, JsonValue>>;

export interface ChainedRecord {
  readonly seq: number;
  readonly prev_hash: string;
  readonly hash: string;
  /** The line as written: `stream`, `seq`, `prev_hash`, the fields, then `hash`. */
  readonly line: string;
}

export type ChainWriter = (line: string) => void;

/**
 * A hash chain over the lines of one stream. Each line carries its sequence
 * number, the hash of the line before it, and its own hash: SHA-256 over
 * the canonical JSON (keys sorted, recursively) of every field but `hash`.
 * A deleted, altered, or reordered line is detectable by anyone holding the
 * lines and nothing else; it is continuity and integrity, not origin, which
 * a signature over an export provides. Linking is synchronous, so two lines
 * can never interleave their sequence numbers.
 */
export class HashChain {
  private current: ChainHead;
  private readonly listeners: ((head: ChainHead) => void)[] = [];

  public constructor(
    public readonly stream: string,
    head: ChainHead | null = null,
  ) {
    this.current = head ?? { seq: 0, hash: CHAIN_GENESIS };
  }

  public get head(): ChainHead {
    return this.current;
  }

  /** Called after every link with the new head; for the journal that persists it. */
  public onLink(listener: (head: ChainHead) => void): () => void {
    this.listeners.push(listener);
    return () => {
      const index = this.listeners.indexOf(listener);
      if (index !== -1) this.listeners.splice(index, 1);
    };
  }

  /** Links the fields, writes the line, moves the head, then tells the listeners. */
  public link(fields: ChainFields, write: ChainWriter): ChainedRecord {
    const seq = this.current.seq + 1;
    const previous = this.current.hash;
    // The envelope wins over a field of the same name: nothing a line says
    // can move it in the chain.
    const record: Record<string, JsonValue> = { stream: this.stream, seq, prev_hash: previous };
    for (const [key, value] of Object.entries(fields)) {
      if (!(key in record)) record[key] = value;
    }
    const hash = HashChain.digest(record);
    const line = JSON.stringify({ ...record, hash });
    this.current = { seq, hash };
    write(line);
    for (const listener of this.listeners) listener(this.current);
    return { seq, prev_hash: previous, hash, line };
  }

  /** SHA-256 over the canonical JSON of every field but `hash`, as the verifier recomputes it. */
  public static digest(record: Readonly<Record<string, JsonValue>>): string {
    const material: Record<string, JsonValue> = {};
    for (const [key, value] of Object.entries(record)) {
      if (key !== "hash") material[key] = value;
    }
    return `sha256:${createHash("sha256").update(CanonicalIntentHasher.stringify(material)).digest("hex")}`;
  }
}
