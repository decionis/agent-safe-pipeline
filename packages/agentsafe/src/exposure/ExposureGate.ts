import { createHash } from "node:crypto";
import { Rfc8785, type JsonValue } from "@decionis/agent-safe-pipeline";
import type { ChainFields } from "../audit/HashChain.js";
import type { ExposureFacts } from "./ExposureFacts.js";
import {
  ExposureUnavailable,
  type ExposureAnswer,
  type ExposureLedger,
  type ExposureLimit,
  type ExposureReservationRequest,
} from "./ExposureLedger.js";

/**
 * The subject digest scheme Decionis Commerce uses (`Subject.digest`), so one
 * vendor is one subject whichever channel paid it: the identifier trimmed and
 * lower-cased, scoped by the organisation.
 */
export const EXPOSURE_DIGEST_VERSION = "decionis-exposure-v1";
/** The steps a sequence limit spreads across actors, by the action type that takes them. */
const STEP_OF: Readonly<Record<string, string>> = {
  PAYMENT_RELEASE: "payment_release",
  VENDOR_BANK_CHANGE: "vendor_bank_change",
};
/** `source.platform` and `source.channel` of every reservation the gateway makes. */
const SOURCE = { platform: "agentsafe", channel: "gateway" } as const;
/** An enforced reservation key: what an earlier attempt's record may name. */
export const RESERVATION_KEY = /^agentsafe:[0-9a-f]{64}$/;

/** One reservation held against one limit. */
export interface HeldReservation {
  readonly limitKey: string;
  readonly reservationId: string;
}

/** What the intent the reservations are made for is, as the ledger and the evidence name it. */
export interface ExposureBinding {
  readonly intentId: string;
  readonly intentHash: string;
  readonly capturedAt: string;
  /**
   * The reservation key of the INDETERMINATE attempt this one retries under
   * the same idempotency key, for the same request. The retry reserves under
   * it, so the ledger answers with what the earlier attempt kept: one
   * operation, drawn once, and ended once its outcome is known.
   */
  readonly retryOf?: string;
}

/**
 * What the ledger said about one money release, across every limit that
 * covers it. `unstated` names a limit that covers the action but whose
 * subject the route does not state: the payment is not counted against it,
 * and the evidence says so.
 */
export type ExposureCheck =
  | {
      readonly status: "WITHIN_LIMIT";
      readonly held: readonly HeldReservation[];
      readonly unstated: readonly string[];
      /** The limits whose reservation the ledger already held under the key: no second draw. */
      readonly replayed?: readonly string[];
    }
  | {
      readonly status: "EXCEEDED";
      readonly limitKey: string;
      readonly onExceed: "HOLD" | "ESCALATE";
      readonly reasonCode: string;
      readonly unstated: readonly string[];
    }
  | {
      readonly status: "UNAVAILABLE";
      readonly code: string;
      /** Kept only under a route's explicit fail-open; released otherwise. */
      readonly held: readonly HeldReservation[];
      readonly unstated: readonly string[];
      /** The route fails open: the payment goes on, uncounted where nothing was held. */
      readonly ungoverned: boolean;
    };

/** How the forwarded payment ended, as the executor classified it. */
export type PaymentOutcome = "COMMITTED" | "NOT_EXECUTED" | "INDETERMINATE";

/** What became of the reservations once the payment's outcome was known. */
export type Settlement = "SETTLED" | "RELEASED" | "KEPT" | "NONE" | "FAILED";

export interface ExposureGateOptions {
  readonly ledger: ExposureLedger;
  /** The organisation that scopes every subject digest: the gateway's tenant. */
  readonly orgId: string;
  /** The gateway's actor type, for a limit restricted to some actor types. */
  readonly actorType: string;
  /** Writes one chained line on the gateway's own stream. */
  readonly evidence: (fields: ChainFields) => void;
  /** Counts each outcome, by a code the gateway produced. */
  readonly count?: (outcome: string) => void;
  /** How many times a settle or release is attempted before it is recorded as failed. */
  readonly attempts?: number;
  readonly retryDelayMs?: number;
  readonly sleep?: (ms: number) => Promise<void>;
}

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/**
 * The cumulative-limit check on the execution path. After the authority's
 * ALLOW and the claim of its grant, and before the payment is sent, it
 * reserves the amount against every limit in the organisation's policy that
 * covers the route's action type, in key order, under a reservation key
 * derived from the intent hash, so the same intent never draws twice. Any
 * limit that would be exceeded refuses the payment and gives back what was
 * already reserved. Once the upstream has answered, a committed payment is
 * settled, one that was not executed is released, and one whose outcome is
 * unknown keeps its reservation, so the ledger errs toward the cap.
 */
export class ExposureGate {
  private readonly attempts: number;
  private readonly retryDelayMs: number;
  private readonly sleep: (ms: number) => Promise<void>;

  public constructor(private readonly options: ExposureGateOptions) {
    this.attempts = Math.max(1, Math.min(options.attempts ?? 3, 5));
    this.retryDelayMs = Math.max(0, Math.min(options.retryDelayMs ?? 200, 2_000));
    this.sleep =
      options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, Math.max(ms, 0))));
  }

  /** A subject's digest as the ledger receives it; the identifier itself never leaves. */
  public digest(kind: string, id: string): string {
    return sha256(
      [
        EXPOSURE_DIGEST_VERSION,
        this.options.orgId.toLowerCase(),
        kind,
        id.trim().toLowerCase(),
      ].join("\n"),
    );
  }

  /**
   * The reservation key for an intent: the same intent, the same key, on
   * every retry. A retry of an INDETERMINATE attempt takes that attempt's
   * key; a shadow observation never does.
   */
  public static reservationKey(binding: ExposureBinding, shadow = false): string {
    if (!shadow && binding.retryOf !== undefined && RESERVATION_KEY.test(binding.retryOf)) {
      return binding.retryOf;
    }
    return ExposureGate.ownKey(binding, shadow);
  }

  /** The key derived from the intent's own hash. */
  private static ownKey(binding: ExposureBinding, shadow: boolean): string {
    const hex = binding.intentHash.replace(/^sha256:/, "");
    return `${shadow ? "agentsafe-shadow" : "agentsafe"}:${hex}`;
  }

  /**
   * Reserves against every covering limit. A refusal releases what was
   * held; so does a fault, unless the route explicitly fails open, when
   * what was held is kept to be settled or released with the payment.
   */
  public async reserve(
    facts: ExposureFacts,
    binding: ExposureBinding,
    failOpen: boolean,
  ): Promise<ExposureCheck> {
    const key = ExposureGate.reservationKey(binding);
    const own = ExposureGate.ownKey(binding, false);
    const check = await this.draw(facts, binding, key, key === own ? null : own);
    if (check.status === "WITHIN_LIMIT") {
      this.record({
        event: "EXPOSURE_RESERVED",
        intent_id: binding.intentId,
        intent_hash: binding.intentHash,
        reservation_key: key,
        limits: check.held.map((entry) => entry.limitKey),
        unstated: [...check.unstated],
        ...(key === own ? {} : { retry_of: true, replayed: [...(check.replayed ?? [])] }),
      });
      this.options.count?.(check.held.length === 0 ? "NOT_APPLICABLE" : "WITHIN_LIMIT");
      return check;
    }
    if (check.status === "EXCEEDED") {
      this.record({
        event: "EXPOSURE_EXCEEDED",
        intent_id: binding.intentId,
        intent_hash: binding.intentHash,
        limit_key: check.limitKey,
        on_exceed: check.onExceed,
        reason_code: check.reasonCode,
      });
      this.options.count?.("EXCEEDED");
      return check;
    }
    const held = failOpen ? check.held : [];
    if (!failOpen) await this.end(check.held, "release", binding);
    this.record({
      event: failOpen ? "EXPOSURE_UNGOVERNED" : "EXPOSURE_UNAVAILABLE",
      intent_id: binding.intentId,
      intent_hash: binding.intentHash,
      reason_codes: ["EXPOSURE_UNAVAILABLE", check.code],
      failure_policy: failOpen ? "FAIL_OPEN" : "FAIL_CLOSED",
      limits: held.map((entry) => entry.limitKey),
    });
    this.options.count?.(failOpen ? "UNGOVERNED" : "UNAVAILABLE");
    return { ...check, held, ungoverned: failOpen };
  }

  /**
   * In shadow, what the ledger would have said, without counting the
   * payment: each reservation is made under a shadow key of its own and
   * released at once. The payment itself went through unchanged.
   */
  public async observe(facts: ExposureFacts, binding: ExposureBinding): Promise<ExposureCheck> {
    const check = await this.draw(facts, binding, ExposureGate.reservationKey(binding, true));
    if (check.status !== "EXCEEDED") await this.end(check.held, "release", binding);
    this.record({
      event: "EXPOSURE_OBSERVED",
      intent_id: binding.intentId,
      intent_hash: binding.intentHash,
      would: check.status,
      ...(check.status === "EXCEEDED"
        ? { limit_key: check.limitKey, on_exceed: check.onExceed, reason_code: check.reasonCode }
        : {}),
      ...(check.status === "UNAVAILABLE" ? { reason_code: check.code } : {}),
      unstated: [...check.unstated],
    });
    return check;
  }

  /**
   * Ends the reservations once the payment's outcome is known: settled
   * when it committed (for the amount the answer states, when the route
   * names where and it is no more than reserved), released when it was not
   * executed, kept when nobody can say. A failure to settle or release is
   * retried and then recorded; it never changes what already executed.
   */
  public async conclude(
    check: ExposureCheck,
    outcome: PaymentOutcome,
    binding: ExposureBinding,
    settledAmount: number | null = null,
  ): Promise<Settlement> {
    const held = check.status === "EXCEEDED" ? [] : check.held;
    if (held.length === 0) return "NONE";
    if (outcome === "INDETERMINATE") {
      this.record({
        event: "EXPOSURE_KEPT",
        intent_id: binding.intentId,
        intent_hash: binding.intentHash,
        reason_codes: ["EXECUTION_INDETERMINATE"],
        reservations: held.map((entry) => ({ ...entry })),
      });
      return "KEPT";
    }
    const end = outcome === "COMMITTED" ? "settle" : "release";
    const failed = await this.end(held, end, binding, settledAmount);
    this.record({
      event: end === "settle" ? "EXPOSURE_SETTLED" : "EXPOSURE_RELEASED",
      intent_id: binding.intentId,
      intent_hash: binding.intentHash,
      limits: held.filter((entry) => !failed.includes(entry)).map((entry) => entry.limitKey),
      ...(end === "settle" && settledAmount !== null ? { amount_stated: true } : {}),
    });
    if (failed.length > 0) return "FAILED";
    return end === "settle" ? "SETTLED" : "RELEASED";
  }

  /** The limits that cover the facts, the reservations made against them, in key order. */
  private async draw(
    facts: ExposureFacts,
    binding: ExposureBinding,
    reservationKey: string,
    /** Reserved under instead where the earlier attempt's reservation was released by hand. */
    fallbackKey: string | null = null,
  ): Promise<ExposureCheck> {
    let limits: readonly ExposureLimit[];
    try {
      limits = await this.retrying(() => this.options.ledger.limits());
    } catch (error) {
      return {
        status: "UNAVAILABLE",
        code: ExposureGate.codeOf(error),
        held: [],
        unstated: [],
        ungoverned: false,
      };
    }
    const held: HeldReservation[] = [];
    const unstated: string[] = [];
    const replayed: string[] = [];
    const covering = limits
      .filter((limit) => this.covers(limit, facts))
      .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    for (const limit of covering) {
      const request = this.request(limit, facts, binding, reservationKey);
      if (request === null) {
        unstated.push(limit.key);
        continue;
      }
      try {
        // The same reservation_key and body on a retry: the ledger answers
        // with the reservation it already holds, never a second draw.
        let answer: ExposureAnswer;
        try {
          answer = await this.retrying(() => this.options.ledger.reserve(limit.key, request));
        } catch (error) {
          // The earlier attempt's reservation was released: someone found its
          // payment did not happen. This one draws afresh, under its own key.
          if (
            fallbackKey === null ||
            !(error instanceof ExposureUnavailable) ||
            error.code !== "EXPOSURE_RESERVATION_RELEASED"
          ) {
            throw error;
          }
          const fresh = this.request(limit, facts, binding, fallbackKey)!;
          answer = await this.retrying(() => this.options.ledger.reserve(limit.key, fresh));
        }
        if (answer.decision !== "PROCEED") {
          await this.end(held, "release", binding);
          return {
            status: "EXCEEDED",
            limitKey: limit.key,
            onExceed: answer.decision,
            reasonCode: answer.reasonCode,
            unstated,
          };
        }
        if (answer.reservationId !== null) {
          held.push({ limitKey: limit.key, reservationId: answer.reservationId });
          if (answer.replayed) replayed.push(limit.key);
        }
      } catch (error) {
        return {
          status: "UNAVAILABLE",
          code: ExposureGate.codeOf(error),
          held,
          unstated,
          ungoverned: false,
        };
      }
    }
    return {
      status: "WITHIN_LIMIT",
      held,
      unstated,
      ...(replayed.length === 0 ? {} : { replayed }),
    };
  }

  /** Whether a limit governs this action: its action type, its actor type, and an amount to count. */
  private covers(limit: ExposureLimit, facts: ExposureFacts): boolean {
    if (!limit.actionTypes.includes(facts.actionType)) return false;
    if (limit.actorTypes !== undefined && !limit.actorTypes.includes(this.options.actorType)) {
      return false;
    }
    if (limit.kind === "sequence") {
      const step = STEP_OF[facts.actionType];
      return step !== undefined && (limit.steps?.includes(step) ?? true);
    }
    return facts.amount > 0;
  }

  /** The reservation for one limit; null when the route does not state its subject. */
  private request(
    limit: ExposureLimit,
    facts: ExposureFacts,
    binding: ExposureBinding,
    reservationKey: string,
  ): ExposureReservationRequest | null {
    let idDigest: string | undefined;
    if (limit.subject !== "org") {
      const id = facts.subjects[limit.subject as keyof ExposureFacts["subjects"]];
      if (id === undefined) return null;
      idDigest = this.digest(limit.subject, id);
    }
    const sequence = limit.kind === "sequence";
    const agent = facts.subjects.agent;
    if (sequence && agent === undefined) return null;
    const core = {
      subject: { kind: limit.subject, ...(idDigest === undefined ? {} : { id_digest: idDigest }) },
      amount: facts.amount,
      currency: facts.currency,
      action_type: facts.actionType,
      reservation_key: reservationKey,
      ...(sequence && agent !== undefined
        ? {
            actor: { kind: "agent" as const, id_digest: this.digest("actor", agent) },
            step: STEP_OF[facts.actionType]!,
          }
        : {}),
    };
    return {
      ...core,
      // Binds the key to this request: the same key with anything else is a conflict.
      request_digest: sha256(Rfc8785.stringify({ limit: limit.key, ...core } as JsonValue)),
      occurred_at: binding.capturedAt,
      source: { ...SOURCE, record_id: binding.intentId },
    };
  }

  /** Settles or releases each reservation; the ones that still failed, each recorded. */
  private async end(
    held: readonly HeldReservation[],
    end: "settle" | "release",
    binding: ExposureBinding,
    amount: number | null = null,
  ): Promise<readonly HeldReservation[]> {
    const failed: HeldReservation[] = [];
    for (const entry of held) {
      try {
        await this.retrying(() =>
          end === "settle"
            ? this.options.ledger.settle(entry.limitKey, entry.reservationId, amount ?? undefined)
            : this.options.ledger.release(entry.limitKey, entry.reservationId),
        );
      } catch (error) {
        failed.push(entry);
        // An unsettled reservation keeps counting, and an unreleased one counts
        // until it leaves the window: either errs toward the cap. The line names
        // the reservation, so it can be ended by hand.
        this.record({
          event: end === "settle" ? "EXPOSURE_SETTLE_FAILED" : "EXPOSURE_RELEASE_FAILED",
          intent_id: binding.intentId,
          intent_hash: binding.intentHash,
          limit_key: entry.limitKey,
          reservation_id: entry.reservationId,
          reason_code: ExposureGate.codeOf(error),
        });
        this.options.count?.(end === "settle" ? "SETTLE_FAILED" : "RELEASE_FAILED");
      }
    }
    return failed;
  }

  /** Asks again only where asking again cannot count twice, a bounded number of times. */
  private async retrying<T>(call: () => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await call();
      } catch (error) {
        const retryable = error instanceof ExposureUnavailable && error.retryable;
        if (!retryable || attempt >= this.attempts) throw error;
        await this.sleep(this.retryDelayMs * attempt);
      }
    }
  }

  private record(fields: ChainFields): void {
    try {
      this.options.evidence(fields);
    } catch {
      // A line that cannot be written leaves the payment's outcome as it was.
    }
  }

  private static codeOf(error: unknown): string {
    return error instanceof ExposureUnavailable ? error.code : "EXPOSURE_FAILED";
  }
}
