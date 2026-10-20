import { CardOutcomeFactSchema, type CardOutcomeFact } from "./CardOutcomeFact.js";
import type { CardOutcomeLedger } from "./CardOutcomeLedger.js";

/** How many facts may wait to be written; beyond it a fact is dropped and counted. */
export const CARD_OUTCOME_QUEUE_CAPACITY = 10_000;

export interface CardOutcomeRecorderOptions {
  readonly ledger: CardOutcomeLedger;
  /** Told when facts could not be kept: how many, and the code that says why. */
  readonly onDropped?: (count: number, code: string) => void;
  readonly capacity?: number;
}

/**
 * The cards family's outcome facts, kept after the fact. `note` is what the request path
 * calls, once its answer is decided: it queues the fact and returns, never awaits anything and
 * never throws, so recording can neither slow, fail nor change an authorization. The facts are
 * checked and written after the current turn of the event loop, in order, one append per batch.
 *
 * What is lost is counted, never retried into the request path: a full queue, a fact that does
 * not fit its schema, and a ledger that refuses a write each drop their facts and report how
 * many. The evidence such a purchase leads to is then incomplete, and stays at what the facts
 * that were kept establish.
 */
export class CardOutcomeRecorder {
  private readonly queue: CardOutcomeFact[] = [];
  private readonly capacity: number;
  private writing: Promise<void> | null = null;

  public constructor(private readonly options: CardOutcomeRecorderOptions) {
    this.capacity = options.capacity ?? CARD_OUTCOME_QUEUE_CAPACITY;
  }

  /** Queues one fact. Returns at once; nothing here can reach the caller. */
  public note(fact: CardOutcomeFact): void {
    try {
      if (this.queue.length >= this.capacity) {
        this.dropped(1, "CARD_OUTCOMES_QUEUE_FULL");
        return;
      }
      this.queue.push(fact);
      this.writing ??= this.drain();
    } catch {
      // Recording is evidence after the fact; it never becomes the request's failure.
    }
  }

  /** Resolves once every fact queued so far has been written or dropped. */
  public async flush(): Promise<void> {
    while (this.writing !== null) await this.writing;
  }

  private async drain(): Promise<void> {
    try {
      // The answer goes out first: nothing is checked or written in the turn that queued it.
      await new Promise<void>((resolve) => setImmediate(resolve));
      while (this.queue.length > 0) {
        const batch = this.queue.splice(0, this.queue.length);
        const facts: CardOutcomeFact[] = [];
        for (const fact of batch) {
          const parsed = CardOutcomeFactSchema.safeParse(fact);
          if (parsed.success) facts.push(parsed.data);
        }
        if (facts.length < batch.length) {
          this.dropped(batch.length - facts.length, "CARD_OUTCOMES_FACT_INVALID");
        }
        if (facts.length === 0) continue;
        try {
          await this.options.ledger.append(facts);
        } catch (error) {
          const code =
            error instanceof Error && /^CARD_OUTCOMES_[A-Z_]{1,40}$/.test(error.message)
              ? error.message
              : "CARD_OUTCOMES_WRITE_FAILED";
          this.dropped(facts.length, code);
        }
      }
    } finally {
      this.writing = null;
    }
  }

  private dropped(count: number, code: string): void {
    try {
      this.options.onDropped?.(count, code);
    } catch {
      // A reporter that throws loses the report, not the process.
    }
  }
}
