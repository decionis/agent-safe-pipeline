import { z } from "zod";
import { withoutTrailingSlash } from "../edge/Entitlement.js";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import {
  ExposureUnavailable,
  type ExposureAnswer,
  type ExposureLedger,
  type ExposureLimit,
  type ExposureSubjectUsage,
  type ExposureReservationRequest,
} from "./ExposureLedger.js";

/** Where Decionis serves the exposure ledger (`COMMERCE_EXPOSURE_PATH`). */
export const EXPOSURE_PATH = "/v1/commerce/exposure";
/** An answer is capped before it is parsed, like every authority answer. */
const MAX_ANSWER_BYTES = 100 * 1024;
const ERROR_CODE = /^[A-Z][A-Z0-9_]{2,63}$/;
const LIMIT_KEY = /^[a-z0-9][\w.:-]{0,127}$/i;

const LimitSchema = z.object({
  key: z.string().regex(LIMIT_KEY),
  kind: z.enum(["refund", "price_drop", "discount", "payment_release", "sequence"]),
  subject: z.enum(["sku", "customer", "vendor", "agent", "org"]),
  on_exceed: z.enum(["HOLD", "ESCALATE"]),
  action_types: z.array(z.string().max(64)).max(16),
  actor_types: z.array(z.string().max(40)).max(16).optional(),
  steps: z.array(z.string().max(40)).max(8).optional(),
  caps: z
    .array(
      z.object({ currency: z.string().regex(/^[A-Z]{3}$/), max_amount: z.number().int().min(0) }),
    )
    .max(32)
    .optional(),
  subject_usage: z
    .array(z.object({ currency: z.string().regex(/^[A-Z]{3}$/), used: z.number().int().min(0) }))
    .max(32)
    .nullable()
    .optional(),
});
const LimitsSchema = z.object({ limits: z.array(LimitSchema).max(64) });
const AnswerSchema = z.object({
  decision: z.enum(["PROCEED", "HOLD", "ESCALATE"]),
  reason_code: z.string().regex(ERROR_CODE),
  reservation_id: z.string().uuid().nullable(),
  replayed: z.boolean(),
});

export interface DecionisExposureLedgerOptions {
  readonly baseUrl: string;
  /** Read at each call, so a rotated key takes effect at once. */
  readonly apiKey: () => string;
  /** The authority's guarded egress. */
  readonly fetch: FetchLike;
  readonly timeoutMs: number;
  readonly userAgent?: string;
}

/**
 * The Decionis exposure ledger over HTTP (`apps/api` ExposureRoutes):
 *
 * - `GET /v1/commerce/exposure`: the limits in the org's active bundle;
 * - `POST /v1/commerce/exposure/{key}/reservations`: reserve, idempotent
 *   by `reservation_key`;
 * - `POST …/reservations/{id}/settle` and `…/release`: end it.
 *
 * The org is the one the API key belongs to; the key needs a draw scope
 * (`decision:write`, `decision:*` or `org:*`). Every fault is an
 * `ExposureUnavailable` with a stable code and nothing of the body.
 */
export class DecionisExposureLedger implements ExposureLedger {
  private readonly base: string;

  public constructor(private readonly options: DecionisExposureLedgerOptions) {
    this.base = withoutTrailingSlash(options.baseUrl);
  }

  public async limits(): Promise<readonly ExposureLimit[]> {
    const parsed = LimitsSchema.safeParse(await this.call("GET", EXPOSURE_PATH));
    if (!parsed.success) throw new ExposureUnavailable("EXPOSURE_LIMITS_MALFORMED", false);
    return parsed.data.limits.map((limit) => ({
      key: limit.key,
      kind: limit.kind,
      subject: limit.subject,
      onExceed: limit.on_exceed,
      actionTypes: limit.action_types,
      ...(limit.actor_types === undefined ? {} : { actorTypes: limit.actor_types }),
      ...(limit.steps === undefined ? {} : { steps: limit.steps }),
      ...(limit.caps === undefined
        ? {}
        : {
            caps: limit.caps.map((cap) => ({ currency: cap.currency, maxAmount: cap.max_amount })),
          }),
    }));
  }

  /**
   * `GET /v1/commerce/exposure?subject_kind&subject_digest`: the subject's usage of each limit,
   * read-only. The only call a hosted gateway's shadow key may make to the ledger.
   */
  public async subjectUsage(
    kind: string,
    idDigest: string,
  ): Promise<ReadonlyMap<string, readonly ExposureSubjectUsage[] | null>> {
    if (!/^[a-z]+$/.test(kind) || !/^[0-9a-f]{64}$/.test(idDigest))
      throw new ExposureUnavailable("EXPOSURE_SUBJECT_INVALID", false);
    const query = `?subject_kind=${encodeURIComponent(kind)}&subject_digest=${idDigest}`;
    const parsed = LimitsSchema.safeParse(await this.call("GET", `${EXPOSURE_PATH}${query}`));
    if (!parsed.success) throw new ExposureUnavailable("EXPOSURE_LIMITS_MALFORMED", false);
    return new Map(parsed.data.limits.map((limit) => [limit.key, limit.subject_usage ?? null]));
  }

  public async reserve(
    limitKey: string,
    request: ExposureReservationRequest,
  ): Promise<ExposureAnswer> {
    const parsed = AnswerSchema.safeParse(
      await this.call("POST", `${DecionisExposureLedger.path(limitKey)}/reservations`, request),
    );
    // A refusal never carries a reservation; one that does is not an answer to act on.
    if (!parsed.success || (parsed.data.decision !== "PROCEED" && parsed.data.reservation_id)) {
      throw new ExposureUnavailable("EXPOSURE_ANSWER_MALFORMED", false);
    }
    return {
      decision: parsed.data.decision,
      reasonCode: parsed.data.reason_code,
      reservationId: parsed.data.reservation_id,
      replayed: parsed.data.replayed,
    };
  }

  public async settle(limitKey: string, reservationId: string, amount?: number): Promise<void> {
    await this.call(
      "POST",
      `${DecionisExposureLedger.path(limitKey)}/reservations/${encodeURIComponent(reservationId)}/settle`,
      amount === undefined ? {} : { amount },
    );
  }

  public async release(limitKey: string, reservationId: string): Promise<void> {
    await this.call(
      "POST",
      `${DecionisExposureLedger.path(limitKey)}/reservations/${encodeURIComponent(reservationId)}/release`,
      {},
    );
  }

  private static path(limitKey: string): string {
    if (!LIMIT_KEY.test(limitKey))
      throw new ExposureUnavailable("EXPOSURE_LIMIT_KEY_INVALID", false);
    return `${EXPOSURE_PATH}/${encodeURIComponent(limitKey)}`;
  }

  private async call(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);
    let response: Response;
    let text: string | null;
    try {
      response = await this.options.fetch(`${this.base}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${this.options.apiKey()}`,
          accept: "application/json",
          ...(body === undefined ? {} : { "content-type": "application/json" }),
          ...(this.options.userAgent === undefined ? {} : { "user-agent": this.options.userAgent }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
      });
      text = await DecionisExposureLedger.bounded(response);
    } catch {
      throw new ExposureUnavailable("EXPOSURE_UNREACHABLE", true);
    } finally {
      clearTimeout(timeout);
    }
    if (text === null) throw new ExposureUnavailable("EXPOSURE_ANSWER_TOO_LARGE", false);
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
    if (response.ok) {
      if (parsed === null) throw new ExposureUnavailable("EXPOSURE_ANSWER_MALFORMED", false);
      return parsed;
    }
    const error = (parsed as { error?: unknown } | null)?.error;
    throw new ExposureUnavailable(
      typeof error === "string" && ERROR_CODE.test(error)
        ? error
        : `EXPOSURE_HTTP_${String(response.status)}`,
      response.status >= 500,
    );
  }

  /** The body as text, or null once it passes the cap; the rest is never read. */
  private static async bounded(response: Response): Promise<string | null> {
    const reader = response.body?.getReader();
    if (reader === undefined) return "";
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_ANSWER_BYTES) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  }
}
