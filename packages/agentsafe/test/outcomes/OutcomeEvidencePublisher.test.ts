import { afterEach, describe, expect, it, vi } from "vitest";
import { CardOutcomeEvidenceProvider } from "../../src/outcomes/CardOutcomeEvidence.js";
import type { CardOutcomeFact } from "../../src/outcomes/CardOutcomeFact.js";
import {
  CardOutcomeLedgerError,
  InMemoryCardOutcomeLedger,
} from "../../src/outcomes/CardOutcomeLedger.js";
import {
  OutcomeEvidenceRefusal,
  type OutcomeEvidenceSink,
} from "../../src/outcomes/CoreOutcomeEvidenceClient.js";
import {
  OutcomeEvidenceSubmissionSchema,
  type OutcomeEvidenceSubmission,
} from "../../src/outcomes/OutcomeEvidence.js";
import {
  OutcomeEvidencePublisher,
  type OutcomePublishSummary,
} from "../../src/outcomes/OutcomeEvidencePublisher.js";
import { OutcomeEvidenceStore } from "../../src/outcomes/OutcomeEvidenceStore.js";
import { ORG_ID, at, claimed, decided, settled } from "../support/CardOutcomeFacts.js";

afterEach(() => {
  vi.useRealTimers();
});

/** Core's resource as a double: what it was sent, and what it answers next. */
class CoreDouble implements OutcomeEvidenceSink {
  public readonly received: OutcomeEvidenceSubmission[] = [];
  /** Revisions Core holds per subject, with the content, as Core keys them. */
  public readonly held = new Map<string, string>();
  public answers: (OutcomeEvidenceRefusal | "accept")[] = [];

  public async submit(
    submission: OutcomeEvidenceSubmission,
  ): Promise<{ accepted: number; duplicates: number }> {
    await Promise.resolve();
    // Whatever the publisher sends is a submission the contract accepts.
    OutcomeEvidenceSubmissionSchema.parse(submission);
    this.received.push(submission);
    const next = this.answers.shift() ?? "accept";
    if (next !== "accept") throw next;
    let accepted = 0;
    let duplicates = 0;
    for (const evidence of submission.evidence) {
      const key = `${evidence.subject_digest}:${evidence.revision}`;
      const content = JSON.stringify(evidence);
      const existing = this.held.get(key);
      if (existing === undefined) {
        this.held.set(key, content);
        accepted += 1;
      } else if (existing === content) duplicates += 1;
      else
        throw new OutcomeEvidenceRefusal(
          "OUTCOME_EVIDENCE_REVISION_CONFLICT",
          false,
          evidence.subject_digest,
        );
    }
    return { accepted, duplicates };
  }
}

const intent = (index: number): string =>
  `6a1c2d3e-4f50-4a61-8b72-${index.toString(16).padStart(12, "0")}`;

function purchase(index: number, facts: readonly CardOutcomeFact[]): CardOutcomeFact[] {
  return facts.map((fact) => ({ ...fact, intent_id: intent(index) }));
}

interface Harness {
  readonly ledger: InMemoryCardOutcomeLedger;
  readonly store: OutcomeEvidenceStore;
  readonly core: CoreDouble;
  readonly publisher: OutcomeEvidencePublisher;
  readonly reports: OutcomePublishSummary[];
  now: Date;
}

function harness(options: { batchSize?: number; intervalMs?: number } = {}): Harness {
  const ledger = new InMemoryCardOutcomeLedger();
  const store = new OutcomeEvidenceStore();
  const core = new CoreDouble();
  const reports: OutcomePublishSummary[] = [];
  const state = { now: new Date(Date.parse(at(3_600))) };
  const publisher = new OutcomeEvidencePublisher({
    ledger,
    provider: new CardOutcomeEvidenceProvider(),
    store,
    sink: core,
    orgId: ORG_ID,
    intervalMs: options.intervalMs ?? 3_600_000,
    clock: () => state.now,
    report: (summary) => reports.push(summary),
    ...(options.batchSize === undefined ? {} : { batchSize: options.batchSize }),
  });
  return {
    ledger,
    store,
    core,
    publisher,
    reports,
    get now() {
      return state.now;
    },
    set now(value: Date) {
      state.now = value;
    },
  };
}

describe("the outcome evidence publisher", () => {
  it("states each purchase once, and sends nothing Core already holds", async () => {
    const run = harness();
    await run.ledger.append([
      ...purchase(1, [decided(), claimed(), settled()]),
      ...purchase(2, [decided({ verdict: "BLOCK", held_until: null })]),
    ]);
    const first = await run.publisher.publish();
    expect(first).toMatchObject({
      collected: 2,
      recorded: 2,
      submitted: 2,
      accepted: 2,
      duplicates: 0,
      refused: null,
    });
    expect(run.core.received).toHaveLength(1);
    expect(run.core.received[0]).toMatchObject({
      version: "decionis.outcomes.submission/1",
      producer: "agentsafe",
      org_id: ORG_ID,
    });
    // Nothing changed: the second run states the same evidence and sends nothing.
    const second = await run.publisher.publish();
    expect(second).toMatchObject({ collected: 2, recorded: 0, unchanged: 2, submitted: 0 });
    expect(run.core.received).toHaveLength(1);
    expect(run.reports).toHaveLength(2);
  });

  it("sends a changed purchase again under its next revision, as a correction", async () => {
    const run = harness();
    run.now = new Date(Date.parse(at(120)));
    await run.ledger.append(purchase(1, [decided()]));
    await run.publisher.publish();
    expect(run.core.received[0]?.evidence[0]).toMatchObject({ revision: 1, execution: null });
    await run.ledger.append(purchase(1, [claimed(), settled()]));
    run.now = new Date(Date.parse(at(3_600)));
    const corrected = await run.publisher.publish();
    expect(corrected).toMatchObject({ recorded: 1, submitted: 1, accepted: 1 });
    expect(run.core.received[1]?.evidence[0]).toMatchObject({
      revision: 2,
      execution: { status: "COMMITTED" },
    });
  });

  it("moves a conflicting subject to its next revision and sends the batch again", async () => {
    const run = harness();
    await run.ledger.append(purchase(1, [decided()]));
    // Core holds revision 1 of this subject with other content, as after a lost state file.
    const draft = new CardOutcomeEvidenceProvider().map(purchase(1, [decided()]), run.now);
    run.core.held.set(`${draft?.subject_digest ?? ""}:1`, "other content");
    const summary = await run.publisher.publish();
    expect(summary).toMatchObject({ conflicts: 1, submitted: 1, accepted: 1, refused: null });
    expect(run.core.received.map((sent) => sent.evidence[0]?.revision)).toEqual([1, 2]);
  });

  it("keeps the evidence owed when Core refuses the producer, and sends it once Core allows it", async () => {
    const run = harness();
    await run.ledger.append(purchase(1, [decided()]));
    run.core.answers = [new OutcomeEvidenceRefusal("OUTCOME_PRODUCER_NOT_ALLOWED", true)];
    const refused = await run.publisher.publish();
    expect(refused).toMatchObject({
      submitted: 0,
      refused: "OUTCOME_PRODUCER_NOT_ALLOWED",
      retry: false,
    });
    expect(await run.store.owed(10)).toHaveLength(1);
    const later = await run.publisher.publish();
    expect(later).toMatchObject({ submitted: 1, accepted: 1, refused: null });
    expect(await run.store.owed(10)).toEqual([]);
  });

  it("retries an outage, and reports a failure it could not read as one", async () => {
    const run = harness();
    await run.ledger.append(purchase(1, [decided()]));
    run.core.answers = [new OutcomeEvidenceRefusal("OUTCOME_EVIDENCE_UNAVAILABLE", false)];
    expect(await run.publisher.publish()).toMatchObject({
      refused: "OUTCOME_EVIDENCE_UNAVAILABLE",
      retry: true,
    });
    const odd: OutcomeEvidenceSink = {
      submit: async () => {
        await Promise.resolve();
        throw new Error("socket hang up");
      },
    };
    const other = new OutcomeEvidencePublisher({
      ledger: run.ledger,
      provider: new CardOutcomeEvidenceProvider(),
      store: run.store,
      sink: odd,
      orgId: ORG_ID,
      intervalMs: 60_000,
      clock: () => run.now,
    });
    expect(await other.publish()).toMatchObject({
      refused: "OUTCOME_EVIDENCE_UNAVAILABLE",
      retry: true,
    });
    // A ledger that cannot be read fails the run, with its code, and throws nothing.
    const unreadable = new OutcomeEvidencePublisher({
      ledger: {
        append: async () => await Promise.resolve(),
        since: async () => {
          await Promise.resolve();
          throw new CardOutcomeLedgerError("CARD_OUTCOMES_UNREADABLE");
        },
      },
      provider: new CardOutcomeEvidenceProvider(),
      store: run.store,
      sink: run.core,
      orgId: ORG_ID,
      intervalMs: 60_000,
      report: () => {
        throw new Error("reporter down");
      },
    });
    expect(await unreadable.publish()).toMatchObject({
      refused: "CARD_OUTCOMES_UNREADABLE",
      retry: true,
    });
    const broken = new OutcomeEvidencePublisher({
      ledger: {
        append: async () => await Promise.resolve(),
        since: async () => {
          await Promise.resolve();
          throw new Error("EIO at /var/lib/agent-safe");
        },
      },
      provider: new CardOutcomeEvidenceProvider(),
      store: run.store,
      sink: run.core,
      orgId: ORG_ID,
      intervalMs: 60_000,
    });
    expect(await broken.publish()).toMatchObject({ refused: "CARD_OUTCOMES_RUN_FAILED" });
  });

  it("sends at most a batch per request, and leaves what is left over to the next run", async () => {
    const run = harness({ batchSize: 2 });
    for (let index = 1; index <= 25; index += 1) {
      await run.ledger.append(purchase(index, [decided({ at: at(index) })]));
    }
    const first = await run.publisher.publish();
    expect(first).toMatchObject({ collected: 25, submitted: 20, accepted: 20 });
    expect(run.core.received.every((sent) => sent.evidence.length <= 2)).toBe(true);
    const second = await run.publisher.publish();
    expect(second).toMatchObject({ submitted: 5, accepted: 5 });
    expect(await run.store.owed(100)).toEqual([]);
  });

  it("never records a draft the contract would refuse", async () => {
    const run = harness();
    await run.ledger.append(purchase(1, [decided({ dossier_id: "d".repeat(201) })]));
    expect(await run.publisher.publish()).toMatchObject({ collected: 1, invalid: 1, recorded: 0 });
    expect(run.core.received).toEqual([]);
  });

  it("joins a run already under way rather than starting a second", async () => {
    const run = harness();
    await run.ledger.append(purchase(1, [decided()]));
    const [a, b] = await Promise.all([run.publisher.publish(), run.publisher.publish()]);
    expect(a).toBe(b);
    expect(run.core.received).toHaveLength(1);
  });

  it("runs on its own timer, sooner after an outage, and stops when told", async () => {
    vi.useFakeTimers();
    const run = harness({ intervalMs: 600_000 });
    await run.ledger.append(purchase(1, [decided()]));
    run.core.answers = [
      new OutcomeEvidenceRefusal("OUTCOME_EVIDENCE_UNAVAILABLE", false),
      new OutcomeEvidenceRefusal("OUTCOME_EVIDENCE_UNAVAILABLE", false),
    ];
    run.publisher.start();
    run.publisher.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(run.core.received).toHaveLength(1);
    // The first retry waits thirty seconds, the next four times that.
    await vi.advanceTimersByTimeAsync(30_000);
    expect(run.core.received).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(119_000);
    expect(run.core.received).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(run.core.received).toHaveLength(3);
    expect(await run.store.owed(10)).toEqual([]);
    // Then the interval, with nothing owed: a run, but nothing sent.
    await vi.advanceTimersByTimeAsync(600_000);
    expect(run.reports).toHaveLength(4);
    run.publisher.stop();
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(run.reports).toHaveLength(4);
    run.publisher.stop();
  });

  it("refuses a batch or an interval it could not keep", () => {
    const base = {
      ledger: new InMemoryCardOutcomeLedger(),
      provider: new CardOutcomeEvidenceProvider(),
      store: new OutcomeEvidenceStore(),
      sink: new CoreDouble(),
      orgId: ORG_ID,
      intervalMs: 60_000,
    };
    expect(() => new OutcomeEvidencePublisher({ ...base, batchSize: 1_001 })).toThrow(
      "CARD_OUTCOMES_BATCH_INVALID",
    );
    expect(() => new OutcomeEvidencePublisher({ ...base, batchSize: 0 })).toThrow(
      "CARD_OUTCOMES_BATCH_INVALID",
    );
    expect(() => new OutcomeEvidencePublisher({ ...base, intervalMs: 0 })).toThrow(
      "CARD_OUTCOMES_INTERVAL_INVALID",
    );
  });
});
