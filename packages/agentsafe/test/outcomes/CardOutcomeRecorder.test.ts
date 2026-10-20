import { describe, expect, it } from "vitest";
import type { CardOutcomeFact } from "../../src/outcomes/CardOutcomeFact.js";
import {
  CardOutcomeLedgerError,
  InMemoryCardOutcomeLedger,
  type CardOutcomeLedger,
} from "../../src/outcomes/CardOutcomeLedger.js";
import { CardOutcomeRecorder } from "../../src/outcomes/CardOutcomeRecorder.js";
import { claimed, decided, settled } from "../support/CardOutcomeFacts.js";

function recorder(
  ledger: CardOutcomeLedger,
  capacity?: number,
): { recorder: CardOutcomeRecorder; dropped: [number, string][] } {
  const dropped: [number, string][] = [];
  return {
    recorder: new CardOutcomeRecorder({
      ledger,
      onDropped: (count, code) => dropped.push([count, code]),
      ...(capacity === undefined ? {} : { capacity }),
    }),
    dropped,
  };
}

describe("the outcome recorder", () => {
  it("writes nothing in the turn that noted it, then every fact in order, in one append", async () => {
    const ledger = new InMemoryCardOutcomeLedger();
    const appends: number[] = [];
    const counting: CardOutcomeLedger = {
      append: async (facts) => {
        appends.push(facts.length);
        await ledger.append(facts);
      },
      since: async (from) => await ledger.since(from),
    };
    const { recorder: subject, dropped } = recorder(counting);
    subject.note(decided());
    subject.note(claimed());
    subject.note(settled());
    expect(ledger.all).toEqual([]);
    await subject.flush();
    expect(ledger.all).toEqual([decided(), claimed(), settled()]);
    expect(appends).toEqual([3]);
    // Facts noted while a write is under way follow it.
    subject.note(decided({ intent_id: "7b2d3e4f-5061-4b72-8c83-a4b5c6d7e8f9" }));
    await subject.flush();
    expect(ledger.all).toHaveLength(4);
    expect(dropped).toEqual([]);
    await subject.flush();
  });

  it("drops and counts what it cannot keep, and never throws to the caller", async () => {
    const ledger = new InMemoryCardOutcomeLedger();
    const { recorder: subject, dropped } = recorder(ledger, 2);
    subject.note(decided());
    subject.note(claimed());
    subject.note(settled());
    subject.note({
      ...settled(),
      card_token_ref: "fixture_card_ref_1",
    } as unknown as CardOutcomeFact);
    await subject.flush();
    expect(ledger.all).toEqual([decided(), claimed()]);
    expect(dropped).toEqual([
      [1, "CARD_OUTCOMES_QUEUE_FULL"],
      [1, "CARD_OUTCOMES_QUEUE_FULL"],
    ]);

    const invalid = recorder(ledger);
    invalid.recorder.note({ ...decided(), amount_minor: 0 });
    invalid.recorder.note({ ...claimed(), extra: true } as unknown as CardOutcomeFact);
    await invalid.recorder.flush();
    expect(invalid.dropped).toEqual([[2, "CARD_OUTCOMES_FACT_INVALID"]]);
    expect(ledger.all).toHaveLength(2);

    const refusing = recorder({
      append: async () => {
        await Promise.resolve();
        throw new CardOutcomeLedgerError("CARD_OUTCOMES_UNWRITABLE");
      },
      since: async () => await Promise.resolve([]),
    });
    refusing.recorder.note(decided());
    refusing.recorder.note({ ...claimed(), extra: true } as unknown as CardOutcomeFact);
    await refusing.recorder.flush();
    expect(refusing.dropped).toEqual([
      [1, "CARD_OUTCOMES_FACT_INVALID"],
      [1, "CARD_OUTCOMES_UNWRITABLE"],
    ]);

    const failing = recorder({
      append: async () => {
        await Promise.resolve();
        throw new Error("disk on fire at /var/lib/agent-safe");
      },
      since: async () => await Promise.resolve([]),
    });
    failing.recorder.note(decided());
    await failing.recorder.flush();
    expect(failing.dropped).toEqual([[1, "CARD_OUTCOMES_WRITE_FAILED"]]);

    // A reporter that throws loses its report, not the recorder.
    const loud = new CardOutcomeRecorder({
      ledger: new InMemoryCardOutcomeLedger(),
      capacity: 0,
      onDropped: () => {
        throw new Error("reporter down");
      },
    });
    expect(() => loud.note(decided())).not.toThrow();
    await loud.flush();
  });
});
