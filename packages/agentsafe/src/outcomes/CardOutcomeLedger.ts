import type { CardOutcomeFact } from "./CardOutcomeFact.js";

/** A refusal by a ledger: the code, never a path or a value. */
export class CardOutcomeLedgerError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "CardOutcomeLedgerError";
  }
}

/**
 * Where the card purchases' outcome facts are kept until the producer reads them. Append-only:
 * a fact is never changed, and what a purchase came to is read from all of its facts together.
 */
export interface CardOutcomeLedger {
  /** Keeps the facts, in order; throws when they could not be kept. */
  append(facts: readonly CardOutcomeFact[]): Promise<void>;
  /** Every fact recorded at or after `from`, oldest first; facts with the same time keep their order. */
  since(from: Date): Promise<readonly CardOutcomeFact[]>;
}

/** The ledger in memory: for tests, and for a process that records without a directory. */
export class InMemoryCardOutcomeLedger implements CardOutcomeLedger {
  private readonly facts: CardOutcomeFact[] = [];

  public get all(): readonly CardOutcomeFact[] {
    return this.facts;
  }

  public async append(facts: readonly CardOutcomeFact[]): Promise<void> {
    this.facts.push(...facts);
    await Promise.resolve();
  }

  public async since(from: Date): Promise<readonly CardOutcomeFact[]> {
    return await Promise.resolve(oldestFirst(this.facts, from));
  }
}

/** The facts at or after `from`, by time; a stable sort keeps the recorded order within one instant. */
export function oldestFirst(facts: readonly CardOutcomeFact[], from: Date): CardOutcomeFact[] {
  const floor = from.getTime();
  return facts
    .filter((fact) => Date.parse(fact.at) >= floor)
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}
