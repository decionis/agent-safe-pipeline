import { randomUUID } from "node:crypto";

/** One amount limit as the double holds it: a cap per currency, per subject. */
export interface DoubleLimit {
  readonly key: string;
  readonly kind?: string;
  readonly subject: "vendor" | "agent" | "org" | "customer" | "sku";
  readonly caps: Readonly<Record<string, number>>;
  readonly on_exceed?: "HOLD" | "ESCALATE";
  readonly action_types?: readonly string[];
  readonly actor_types?: readonly string[];
  readonly steps?: readonly string[];
  readonly max_steps?: number;
  /** Decionis#1722: a payment step to a vendor with a bank change on record inside it is held. */
  readonly cooling_off_seconds?: number;
}

/** One reservation the double holds. */
export interface DoubleReservation {
  readonly id: string;
  readonly limitKey: string;
  readonly reservationKey: string;
  readonly requestDigest: string;
  readonly subjectDigest: string;
  readonly currency: string;
  amount: number;
  state: "RESERVED" | "SETTLED" | "RELEASED";
  readonly step: string | null;
}

/** One call the double answered: what was sent, never re-serialized. */
export interface DoubleCall {
  readonly method: string;
  readonly path: string;
  readonly authorization: string | null;
  readonly body: string;
}

const RESERVE_KEYS = new Set([
  "subject",
  "amount",
  "currency",
  "action_type",
  "reservation_key",
  "request_digest",
  "occurred_at",
  "source",
  "actor",
  "step",
  "policy_version",
]);
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * A stand-in for the Decionis exposure ledger (`apps/api` ExposureRoutes and
 * CommerceExposureRepo), in process: the same paths, the same answer shapes,
 * a reservation counted from the moment it is reserved until it is released,
 * idempotency by `reservation_key` with a conflict on a different request,
 * 409 for a key whose reservation was released. It is reached through the
 * gateway's authority transport, so the gateway's real HTTP client is what
 * is tested.
 */
export class ExposureLedgerDouble {
  public readonly calls: DoubleCall[] = [];
  public readonly reservations: DoubleReservation[] = [];
  /** Every request answers 503, as a ledger whose table is missing does. */
  public down = false;
  /** Every request is a transport failure. */
  public unreachable = false;
  /** How many of the next reservation requests fail with a 503 after being recorded. */
  public failReservesAfterWrite = 0;
  /** How many of the next settle or release requests fail with a 503. */
  public failEnds = 0;

  public constructor(public limits: DoubleLimit[] = []) {}

  /** A fetch for the gateway's authority egress: the ledger's paths here, everything else to `next`. */
  public transport(next: typeof fetch = fetch): typeof fetch {
    return async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (!url.pathname.startsWith("/v1/commerce/exposure")) return await next(input, init);
      const body =
        typeof init?.body === "string"
          ? init.body
          : init?.body === undefined || init.body === null
            ? ""
            : Buffer.from(init.body as Uint8Array).toString("utf8");
      const headers = new Headers(init?.headers ?? {});
      this.calls.push({
        method: init?.method ?? "GET",
        path: url.pathname,
        authorization: headers.get("authorization"),
        body,
      });
      if (this.unreachable) {
        throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } });
      }
      if (this.down) return ExposureLedgerDouble.json(503, { error: "EXPOSURE_UNAVAILABLE" });
      return this.answer(init?.method ?? "GET", url.pathname, body, url.searchParams);
    };
  }

  /** The read-only usage Decionis reports for one subject; null where the limit does not count it. */
  private subjectUsage(
    limit: DoubleLimit,
    kind: string,
    digest: string,
  ): { currency: string; used: number }[] | null {
    if ((limit.kind ?? "payment_release") === "sequence") return null;
    if (limit.subject !== kind && limit.subject !== "org") return null;
    const subjectDigest = limit.subject === "org" ? "0".repeat(64) : digest;
    const totals = new Map<string, number>();
    for (const entry of this.reservations) {
      if (entry.limitKey !== limit.key || entry.subjectDigest !== subjectDigest) continue;
      if (entry.state === "RELEASED") continue;
      totals.set(entry.currency, (totals.get(entry.currency) ?? 0) + entry.amount);
    }
    return [...totals].map(([currency, used]) => ({ currency, used }));
  }

  public used(limitKey: string): number {
    return this.reservations
      .filter((entry) => entry.limitKey === limitKey && entry.state !== "RELEASED")
      .reduce((sum, entry) => sum + entry.amount, 0);
  }

  public reservesOf(limitKey: string): DoubleCall[] {
    return this.calls.filter(
      (call) => call.path === `/v1/commerce/exposure/${limitKey}/reservations`,
    );
  }

  private answer(
    method: string,
    path: string,
    body: string,
    query: URLSearchParams = new URLSearchParams(),
  ): Response {
    const segments = path.split("/").slice(4);
    const kind = query.get("subject_kind");
    const digest = query.get("subject_digest");
    if (method === "GET" && segments.length === 0) {
      return ExposureLedgerDouble.json(200, {
        service: "decionis",
        policy_version: "synthetic-v1",
        limits: this.limits.map((limit) => ({
          key: limit.key,
          kind: limit.kind ?? "payment_release",
          subject: limit.subject,
          window_seconds: 86_400,
          caps: Object.entries(limit.caps).map(([currency, max]) => ({
            currency,
            max_amount: max,
          })),
          on_exceed: limit.on_exceed ?? "ESCALATE",
          action_types: [...(limit.action_types ?? ["PAYMENT_RELEASE"])],
          ...(limit.actor_types === undefined ? {} : { actor_types: [...limit.actor_types] }),
          ...(limit.steps === undefined ? {} : { steps: [...limit.steps] }),
          usage: [],
          // As Decionis answers a named subject: its own live usage, read-only.
          ...(kind !== null && digest !== null
            ? { subject_usage: this.subjectUsage(limit, kind, digest) }
            : {}),
        })),
      });
    }
    const limit = this.limits.find((entry) => entry.key === decodeURIComponent(segments[0] ?? ""));
    if (method !== "POST" || limit === undefined) {
      return ExposureLedgerDouble.json(404, { error: "EXPOSURE_LIMIT_NOT_FOUND" });
    }
    if (segments.length === 2 && segments[1] === "reservations") return this.reserve(limit, body);
    if (segments.length === 4 && (segments[3] === "settle" || segments[3] === "release")) {
      return this.end(limit, segments[2] ?? "", segments[3], body);
    }
    return ExposureLedgerDouble.json(404, { error: "NOT_FOUND" });
  }

  private reserve(limit: DoubleLimit, text: string): Response {
    const request = JSON.parse(text) as Record<string, unknown>;
    const subject = request["subject"] as { kind?: unknown; id_digest?: unknown } | undefined;
    const valid =
      Object.keys(request).every((key) => RESERVE_KEYS.has(key)) &&
      typeof request["reservation_key"] === "string" &&
      typeof request["request_digest"] === "string" &&
      HEX64.test(request["request_digest"]) &&
      typeof request["occurred_at"] === "string" &&
      Number.isSafeInteger(request["amount"]) &&
      typeof request["currency"] === "string" &&
      subject !== undefined &&
      (subject.kind === "org" ||
        (typeof subject.id_digest === "string" && HEX64.test(subject.id_digest)));
    if (!valid) return ExposureLedgerDouble.json(400, { error: "VALIDATION_ERROR" });
    if (subject.kind !== limit.subject) {
      return ExposureLedgerDouble.json(400, { error: "EXPOSURE_SUBJECT_MISMATCH" });
    }
    const key = request["reservation_key"] as string;
    const digest = request["request_digest"] as string;
    const currency = request["currency"] as string;
    const amount = request["amount"] as number;
    const subjectDigest = (subject.id_digest as string | undefined) ?? "0".repeat(64);
    const prior = this.reservations.find(
      (entry) => entry.limitKey === limit.key && entry.reservationKey === key,
    );
    const base = {
      service: "decionis",
      limit_key: limit.key,
      kind: limit.kind ?? "payment_release",
      reservation_key: key,
      amount,
      currency,
      window: { seconds: 86_400, from: "2026-11-17T00:00:00.000Z", to: "2026-11-18T00:00:00.000Z" },
      policy_version: "synthetic-v1",
    };
    if (prior !== undefined) {
      if (prior.requestDigest !== digest) {
        return ExposureLedgerDouble.json(409, { error: "EXPOSURE_RESERVATION_CONFLICT" });
      }
      if (prior.state === "RELEASED") {
        return ExposureLedgerDouble.json(409, { error: "EXPOSURE_RESERVATION_RELEASED" });
      }
      return ExposureLedgerDouble.json(200, {
        ...base,
        decision: "PROCEED",
        reason_code: "EXPOSURE_WITHIN_LIMIT",
        reservation_id: prior.id,
        state: prior.state,
        used: 0,
        cap: null,
        remaining: null,
        replayed: true,
      });
    }
    if ((limit.kind ?? "payment_release") === "sequence") {
      // The ledger's sequence rule, as far as the gateway sees it: a step
      // proceeds and is recorded, except a payment to a vendor whose bank
      // change is on record (not released) under a limit with a cooling-off.
      const step = typeof request["step"] === "string" ? request["step"] : null;
      const changed =
        limit.cooling_off_seconds !== undefined &&
        step === "payment_release" &&
        this.reservations.some(
          (entry) =>
            entry.limitKey === limit.key &&
            entry.subjectDigest === subjectDigest &&
            entry.step === "vendor_bank_change" &&
            entry.state !== "RELEASED",
        );
      if (changed)
        return ExposureLedgerDouble.json(200, {
          ...base,
          decision: limit.on_exceed ?? "ESCALATE",
          reason_code: "SOD_COOLING_OFF",
          reservation_id: null,
          state: null,
          used: 0,
          cap: null,
          remaining: null,
          replayed: false,
        });
    }
    const cap =
      (limit.kind ?? "payment_release") === "sequence"
        ? Number.MAX_SAFE_INTEGER
        : limit.caps[currency];
    const used = this.reservations
      .filter(
        (entry) =>
          entry.limitKey === limit.key &&
          entry.subjectDigest === subjectDigest &&
          entry.currency === currency &&
          entry.state !== "RELEASED",
      )
      .reduce((sum, entry) => sum + entry.amount, 0);
    const refused =
      cap === undefined
        ? "EXPOSURE_CURRENCY_NOT_CAPPED"
        : amount > cap - used
          ? "EXPOSURE_LIMIT_EXCEEDED"
          : null;
    if (refused !== null) {
      return ExposureLedgerDouble.json(200, {
        ...base,
        decision: limit.on_exceed ?? "ESCALATE",
        reason_code: refused,
        reservation_id: null,
        state: null,
        used,
        cap: cap ?? null,
        remaining: cap === undefined ? null : Math.max(0, cap - used),
        replayed: false,
      });
    }
    const reservation: DoubleReservation = {
      id: randomUUID(),
      limitKey: limit.key,
      reservationKey: key,
      requestDigest: digest,
      subjectDigest,
      currency,
      amount,
      state: "RESERVED",
      step: typeof request["step"] === "string" ? request["step"] : null,
    };
    this.reservations.push(reservation);
    if (this.failReservesAfterWrite > 0) {
      // Written, then the answer is lost: a retry must find this reservation.
      this.failReservesAfterWrite -= 1;
      return ExposureLedgerDouble.json(503, { error: "EXPOSURE_UNAVAILABLE" });
    }
    return ExposureLedgerDouble.json(200, {
      ...base,
      decision: "PROCEED",
      reason_code: "EXPOSURE_WITHIN_LIMIT",
      reservation_id: reservation.id,
      state: "RESERVED",
      used: used + amount,
      cap,
      remaining: (cap ?? 0) - used - amount,
      replayed: false,
    });
  }

  private end(limit: DoubleLimit, id: string, end: "settle" | "release", text: string): Response {
    if (this.failEnds > 0) {
      this.failEnds -= 1;
      return ExposureLedgerDouble.json(503, { error: "EXPOSURE_UNAVAILABLE" });
    }
    const body = (text === "" ? {} : JSON.parse(text)) as { amount?: number };
    const reservation = this.reservations.find(
      (entry) => entry.id === id && entry.limitKey === limit.key,
    );
    if (reservation === undefined) {
      return ExposureLedgerDouble.json(404, { error: "EXPOSURE_RESERVATION_NOT_FOUND" });
    }
    const target = end === "settle" ? "SETTLED" : "RELEASED";
    if (reservation.state !== target && reservation.state !== "RESERVED") {
      return ExposureLedgerDouble.json(409, { error: `EXPOSURE_RESERVATION_${reservation.state}` });
    }
    if (body.amount !== undefined && body.amount > reservation.amount) {
      return ExposureLedgerDouble.json(400, { error: "EXPOSURE_SETTLE_EXCEEDS_RESERVED" });
    }
    if (reservation.state === "RESERVED") {
      reservation.state = target;
      if (end === "settle" && body.amount !== undefined) reservation.amount = body.amount;
    }
    return ExposureLedgerDouble.json(200, {
      service: "decionis",
      reservation_id: reservation.id,
      limit_key: limit.key,
      state: reservation.state,
      amount: reservation.amount,
    });
  }

  private static json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }
}
