import type { JsonValue } from "@decionis/agent-safe-pipeline";
import type { CardOutcomeEvidenceProvider } from "./CardOutcomeEvidence.js";
import type { CardOutcomeLedger } from "./CardOutcomeLedger.js";
import { OutcomeEvidenceRefusal, type OutcomeEvidenceSink } from "./CoreOutcomeEvidenceClient.js";
import {
  OUTCOME_EVIDENCE_LIMITS,
  OUTCOME_SUBMISSION_VERSION,
  OutcomeEvidenceSchema,
  OutcomeEvidenceSubmissionSchema,
  outcomeDigest,
} from "./OutcomeEvidence.js";
import type { OutcomeEvidenceEntry, OutcomeEvidenceStore } from "./OutcomeEvidenceStore.js";

/**
 * How far back a run reads facts. A card purchase's facts all arrive within its intent's
 * lifetime and the claim's lease, minutes after its decision; three days covers that with room
 * for a publisher that was down, and owed evidence is kept in the store until Core takes it.
 */
export const OUTCOME_LOOKBACK_DAYS = 3;
/** Batches one run may send before it leaves the rest to the next run. */
const BATCHES_PER_RUN = 10;
/** Revision conflicts one run settles before it leaves the rest to the next run. */
const CONFLICTS_PER_RUN = 20;
/** The first retry after Core could not be reached; each further one waits four times longer. */
const FIRST_RETRY_MS = 30_000;
const DAY_MS = 86_400_000;

/** What one run did, in counts and codes: what the security stream and the tests read. */
export interface OutcomePublishSummary {
  collected: number;
  recorded: number;
  unchanged: number;
  exhausted: number;
  invalid: number;
  submitted: number;
  accepted: number;
  duplicates: number;
  conflicts: number;
  /** A refusal that stopped the run: Core's, the store's or the ledger's code; null when none. */
  refused: string | null;
  /** Whether the refusal is one a later run may get past (Core unreachable, for one). */
  retry: boolean;
}

export interface OutcomeEvidencePublisherOptions {
  readonly ledger: CardOutcomeLedger;
  readonly provider: CardOutcomeEvidenceProvider;
  readonly store: OutcomeEvidenceStore;
  readonly sink: OutcomeEvidenceSink;
  /** The Decionis organization the evidence is about. */
  readonly orgId: string;
  /** How often a run starts while nothing is owed or refused. */
  readonly intervalMs: number;
  /** Told what each run did; never awaited, and a throw is ignored. */
  readonly report?: (summary: OutcomePublishSummary) => void;
  readonly clock?: () => Date;
  /** At most the contract's 1000. */
  readonly batchSize?: number;
}

/**
 * Feeds Core's outcome meter with the card purchases' evidence, after the fact and off the
 * request path: a timer this process runs, never an authorization. A run reads the recorded
 * facts, states each purchase through the producer, records a subject at a new revision only
 * when its evidence changed, then sends what Core has not accepted, at most a thousand subjects
 * per request. Nothing unchanged is ever sent again, so a run is idempotent and a restart
 * resends nothing Core already holds. Core alone classifies and calculates.
 *
 * Core refuses a batch whole. A revision conflict (Core holds that revision with other content)
 * moves the subject to its next revision and the batch goes again; a refusal the same batch
 * cannot pass (a producer Core does not allow, evidence it refuses) stops the run until the next
 * interval with the evidence still owed; an outage is retried sooner, backing off. A run never
 * throws, and only one runs at a time.
 */
export class OutcomeEvidencePublisher {
  private readonly clock: () => Date;
  private readonly batchSize: number;
  private running: Promise<OutcomePublishSummary> | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private failures = 0;
  private stopped = true;

  public constructor(private readonly options: OutcomeEvidencePublisherOptions) {
    this.clock = options.clock ?? ((): Date => new Date());
    const batch = options.batchSize ?? OUTCOME_EVIDENCE_LIMITS.batch;
    if (!Number.isInteger(batch) || batch < 1 || batch > OUTCOME_EVIDENCE_LIMITS.batch) {
      throw new Error("CARD_OUTCOMES_BATCH_INVALID");
    }
    if (!Number.isInteger(options.intervalMs) || options.intervalMs < 1) {
      throw new Error("CARD_OUTCOMES_INTERVAL_INVALID");
    }
    this.batchSize = batch;
  }

  /** Runs now, then every interval, sooner after an outage; the timer never holds the process open. */
  public start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.schedule(0);
  }

  public stop(): void {
    this.stopped = true;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }

  /** One run; a run already under way is joined rather than doubled. */
  public async publish(): Promise<OutcomePublishSummary> {
    this.running ??= this.run().finally(() => {
      this.running = null;
    });
    return await this.running;
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.publish().then((summary) => {
        this.failures = summary.retry ? this.failures + 1 : 0;
        this.schedule(this.nextDelay());
      });
    }, delayMs);
    this.timer.unref();
  }

  /** The interval, or after an outage a shorter wait that grows fourfold and never exceeds it. */
  private nextDelay(): number {
    if (this.failures === 0) return this.options.intervalMs;
    const backoff = FIRST_RETRY_MS * 4 ** Math.min(this.failures - 1, 10);
    return Math.min(this.options.intervalMs, backoff);
  }

  private async run(): Promise<OutcomePublishSummary> {
    const summary: OutcomePublishSummary = {
      collected: 0,
      recorded: 0,
      unchanged: 0,
      exhausted: 0,
      invalid: 0,
      submitted: 0,
      accepted: 0,
      duplicates: 0,
      conflicts: 0,
      refused: null,
      retry: false,
    };
    try {
      await this.sync(summary);
      await this.submit(summary);
    } catch (error) {
      summary.refused = OutcomeEvidencePublisher.code(error);
      summary.retry = true;
    }
    try {
      this.options.report?.(summary);
    } catch {
      // The report is for an operator; losing it never stops the meter.
    }
    return summary;
  }

  /** States every purchase in the window and records what changed. */
  private async sync(summary: OutcomePublishSummary): Promise<void> {
    const to = this.clock();
    const from = new Date(to.getTime() - OUTCOME_LOOKBACK_DAYS * DAY_MS);
    const facts = await this.options.ledger.since(from);
    const entries: OutcomeEvidenceEntry[] = [];
    for (const draft of this.options.provider.collect(facts, { from, to })) {
      summary.collected += 1;
      // Never record a draft the contract would refuse; the revision is the store's to assign.
      if (!OutcomeEvidenceSchema.safeParse({ ...draft, revision: 1 }).success) {
        summary.invalid += 1;
        continue;
      }
      entries.push({ draft, sha256: outcomeDigest(draft as unknown as JsonValue) });
    }
    const recorded = await this.options.store.record(entries);
    summary.recorded += recorded.recorded;
    summary.unchanged += recorded.unchanged;
    summary.exhausted += recorded.exhausted;
    await this.options.store.prune(new Date(from.getTime() - DAY_MS));
  }

  /** Sends what Core has not accepted, a batch at a time; Core's acceptance marks each revision sent. */
  private async submit(summary: OutcomePublishSummary): Promise<void> {
    const { store, sink } = this.options;
    let batches = 0;
    while (batches < BATCHES_PER_RUN) {
      const owed = await store.owed(this.batchSize);
      if (owed.length === 0) return;
      const submission = OutcomeEvidenceSubmissionSchema.parse({
        version: OUTCOME_SUBMISSION_VERSION,
        producer: "agentsafe",
        org_id: this.options.orgId,
        evidence: owed,
      });
      let answer: { readonly accepted: number; readonly duplicates: number };
      try {
        answer = await sink.submit(submission);
      } catch (error) {
        const refusal =
          error instanceof OutcomeEvidenceRefusal
            ? error
            : new OutcomeEvidenceRefusal("OUTCOME_EVIDENCE_UNAVAILABLE", false);
        if (refusal.conflict !== null && summary.conflicts < CONFLICTS_PER_RUN) {
          summary.conflicts += 1;
          // The same evidence goes again under the next revision; a subject with none left stops the run.
          if (await store.supersede(refusal.conflict)) continue;
        }
        summary.refused = refusal.code;
        summary.retry = !refusal.permanent;
        return;
      }
      await store.sent(owed);
      batches += 1;
      summary.submitted += owed.length;
      summary.accepted += answer.accepted;
      summary.duplicates += answer.duplicates;
      if (owed.length < this.batchSize) return;
    }
  }

  /** A failure's own code when it carries one in the outcome vocabulary; a generic one otherwise. */
  private static code(error: unknown): string {
    const code = (error as { readonly code?: unknown } | null)?.code;
    return typeof code === "string" && /^(?:CARD_OUTCOMES|OUTCOME)_[A-Z_]{1,60}$/.test(code)
      ? code
      : "CARD_OUTCOMES_RUN_FAILED";
  }
}
