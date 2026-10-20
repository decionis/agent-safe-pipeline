import { join } from "node:path";
import type { CapturedIntent } from "@decionis/agent-safe-pipeline";
import { cardPurchaseOf, isCardActionName } from "../adapters/cards/CardPurchase.js";
import type { CardOutcomesConfig } from "../config/ExecutorConfig.js";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import type { ActionResponse } from "../service/Requests.js";
import { CardOutcomeEvidenceProvider } from "./CardOutcomeEvidence.js";
import { CARD_OUTCOME_FACT_VERSION } from "./CardOutcomeFact.js";
import type { CardOutcomeLedger } from "./CardOutcomeLedger.js";
import { CardOutcomeRecorder } from "./CardOutcomeRecorder.js";
import {
  CoreOutcomeEvidenceClient,
  type OutcomeEvidenceSink,
} from "./CoreOutcomeEvidenceClient.js";
import { FileCardOutcomeLedger } from "./FileCardOutcomeLedger.js";
import {
  OutcomeEvidencePublisher,
  type OutcomePublishSummary,
} from "./OutcomeEvidencePublisher.js";
import { OutcomeEvidenceStore } from "./OutcomeEvidenceStore.js";

/** The state file the publisher keeps beside the facts. */
export const CARD_OUTCOMES_STATE_FILE = "card-outcomes-state.json";

export interface CardOutcomesOptions {
  readonly config: CardOutcomesConfig;
  /** The authority's normalized base URL: Core serves the meter beside it. */
  readonly authorityUrl: string;
  /** The producer token, read from its secret handle at each request. */
  readonly token: () => string;
  /** The guarded fetch. */
  readonly fetch: FetchLike;
  readonly events: SecurityEvents;
  /** Test seams: the ledger, Core's resource, the clock and this replica's name. */
  readonly ledger?: CardOutcomeLedger;
  readonly sink?: OutcomeEvidenceSink;
  readonly clock?: () => Date;
  readonly replica?: string;
}

/**
 * The card purchases' outcome evidence, as the executor runs it: a recorder the card path
 * tells what each purchase came to once its answer is decided, and, when publishing, the
 * publisher that states it to Decionis on its own timer. Every method the request path calls
 * returns at once and never throws; none of them is awaited, so with outcomes on or off every
 * authorization is answered exactly the same.
 *
 * What is recorded is read from what the path already holds (the captured intent, the answer,
 * the claim, the issuer's result), and only identifiers, codes, times and the purchase's amount
 * are kept: the card reference, the merchant and the authorization id stay where they are.
 */
export class CardOutcomes {
  private constructor(
    private readonly recorder: CardOutcomeRecorder,
    private readonly publisher: OutcomeEvidencePublisher | null,
  ) {}

  /** Null when the configuration leaves outcomes off. */
  public static create(options: CardOutcomesOptions): CardOutcomes | null {
    const { config, events } = options;
    if (config.mode === "off") return null;
    const ledger =
      options.ledger ??
      new FileCardOutcomeLedger(
        config.dir,
        options.replica === undefined ? {} : { replica: options.replica },
      );
    const recorder = new CardOutcomeRecorder({
      ledger,
      onDropped: (count, code) => events.emit({ event: "CARD_OUTCOMES_DROPPED", count, code }),
    });
    if (config.mode === "record") return new CardOutcomes(recorder, null);
    const publisher = new OutcomeEvidencePublisher({
      ledger,
      provider: new CardOutcomeEvidenceProvider(),
      store: new OutcomeEvidenceStore(join(config.dir, CARD_OUTCOMES_STATE_FILE)),
      sink:
        options.sink ??
        new CoreOutcomeEvidenceClient({
          baseUrl: options.authorityUrl,
          token: options.token,
          fetch: options.fetch,
        }),
      orgId: config.orgId,
      intervalMs: config.intervalSeconds * 1_000,
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      report: (summary) => {
        if (summary.submitted > 0) {
          events.emit({
            event: "CARD_OUTCOMES_PUBLISHED",
            submitted: summary.submitted,
            accepted: summary.accepted,
            duplicates: summary.duplicates,
            conflicts: summary.conflicts,
          });
        }
        if (summary.refused !== null) {
          events.emit({
            event: "CARD_OUTCOMES_REFUSED",
            code: summary.refused,
            retry: summary.retry,
          });
        }
      },
    });
    return new CardOutcomes(recorder, publisher);
  }

  /** Starts publishing, when this deployment publishes. */
  public start(): void {
    this.publisher?.start();
  }

  public stop(): void {
    this.publisher?.stop();
  }

  /** Resolves once every fact recorded so far is written or dropped. */
  public async flush(): Promise<void> {
    await this.recorder.flush();
  }

  /** One run now, for an operator or a test; never throws. */
  public async publish(): Promise<OutcomePublishSummary | null> {
    return this.publisher === null ? null : await this.publisher.publish();
  }

  /**
   * The first decision a card purchase was given: in enforcement the held grant or the hold, in
   * shadow what would have been decided. A decision the authority never took (it did not
   * answer, and the boundary refused on its own) is not a decision to measure.
   */
  public decided(captured: CapturedIntent, answer: ActionResponse): void {
    try {
      if (!isCardActionName(captured.intent.action)) return;
      if (answer.verdict === null || answer.fail_closed) return;
      const purchase = cardPurchaseOf(captured.intent.parameters);
      this.recorder.note({
        version: CARD_OUTCOME_FACT_VERSION,
        kind: "DECIDED",
        at: new Date().toISOString(),
        intent_id: captured.intent.intentId,
        tenant_id: captured.intent.tenantId,
        mode: answer.mode,
        verdict: answer.verdict,
        decision_id: answer.decision_id,
        dossier_id: answer.dossier_id,
        reason_codes: answer.reason_codes.slice(0, 50),
        held_until: CardOutcomes.heldUntil(answer),
        expires_at: captured.intent.expiresAt,
        currency: purchase.currency,
        amount_minor: purchase.amountMinor,
      });
    } catch {
      // Evidence after the fact; never the request's failure.
    }
  }

  /**
   * A fresh decision on an open escalation. Only an `ALLOW` or a `BLOCK` is a resolution: an
   * answer still pending, or a hold that is still escalated, changes nothing yet.
   */
  public resumed(
    captured: CapturedIntent,
    answer: ActionResponse,
    via: "ATTESTATION" | "PRESENCE",
  ): void {
    try {
      if (!isCardActionName(captured.intent.action)) return;
      if (answer.verdict !== "ALLOW" && answer.verdict !== "BLOCK") return;
      this.recorder.note({
        version: CARD_OUTCOME_FACT_VERSION,
        kind: "RESUMED",
        at: new Date().toISOString(),
        intent_id: captured.intent.intentId,
        via,
        verdict: answer.verdict,
        decision_id: answer.decision_id,
        dossier_id: answer.dossier_id,
        reason_codes: answer.reason_codes.slice(0, 50),
        held_until: CardOutcomes.heldUntil(answer),
      });
    } catch {
      // Evidence after the fact; never the request's failure.
    }
  }

  /** The issuer's authorization matched the hold and claimed its grant. */
  public claimed(intentId: string, grantId: string): void {
    try {
      this.recorder.note({
        version: CARD_OUTCOME_FACT_VERSION,
        kind: "CLAIMED",
        at: new Date().toISOString(),
        intent_id: intentId,
        grant_id: grantId,
      });
    } catch {
      // Evidence after the fact; never the request's failure.
    }
  }

  /** What the issuer said it did with the authorization that claimed the grant. */
  public settled(
    intentId: string,
    outcome: "COMMITTED" | "FAILED" | "INDETERMINATE",
    receiptDigest: string,
  ): void {
    try {
      this.recorder.note({
        version: CARD_OUTCOME_FACT_VERSION,
        kind: "SETTLED",
        at: new Date().toISOString(),
        intent_id: intentId,
        outcome,
        receipt_digest: /^sha256:[0-9a-f]{64}$/.test(receiptDigest) ? receiptDigest : null,
      });
    } catch {
      // Evidence after the fact; never the request's failure.
    }
  }

  /** The held grant's expiry, when the answer held one for the issuer. */
  private static heldUntil(answer: ActionResponse): string | null {
    if (answer.outcome !== "HELD_FOR_AUTHORIZATION") return null;
    const expires = (answer.result as { readonly expires_at?: unknown } | null)?.expires_at;
    return typeof expires === "string" ? expires : null;
  }
}
