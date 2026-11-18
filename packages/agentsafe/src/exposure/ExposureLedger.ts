/**
 * The exposure ledger the gateway records money releases against: the
 * organisation's cumulative limits, read from its active policy, and a
 * reservation per limit that is settled once the payment happened and
 * released when it did not. Decionis keeps it (DecionisExposureLedger); a
 * deployment may supply its own through the same interface.
 */

/** One cumulative limit, as much of it as the gateway needs to decide whether it applies. */
export interface ExposureLimit {
  readonly key: string;
  /** `refund`, `price_drop`, `discount`, `payment_release` or `sequence`. */
  readonly kind: string;
  /** Whose total it caps: `vendor`, `customer`, `sku`, `agent` or `org`. */
  readonly subject: string;
  readonly onExceed: "HOLD" | "ESCALATE";
  /** The action types it covers, its defaults already applied by the ledger. */
  readonly actionTypes: readonly string[];
  /** The actor types it is limited to; absent, every actor. */
  readonly actorTypes?: readonly string[];
  /** A sequence limit's segregation-of-duties steps. */
  readonly steps?: readonly string[];
}

/** `CommerceExposureReserveSchema`: what one reservation states. Subjects arrive as digests only. */
export interface ExposureReservationRequest {
  readonly subject: { readonly kind: string; readonly id_digest?: string };
  readonly amount: number;
  readonly currency: string;
  readonly action_type: string;
  readonly reservation_key: string;
  readonly request_digest: string;
  readonly occurred_at: string;
  readonly source: {
    readonly platform?: string;
    readonly channel?: string;
    readonly record_id?: string;
  };
  readonly actor?: { readonly kind: "agent"; readonly id_digest: string };
  readonly step?: string;
}

export type ExposureDecision = "PROCEED" | "HOLD" | "ESCALATE";

/** The ledger's answer to one reservation. */
export interface ExposureAnswer {
  readonly decision: ExposureDecision;
  readonly reasonCode: string;
  /** Present for a `PROCEED` that counts; null when the limit did not apply, or refused. */
  readonly reservationId: string | null;
  /** The same reservation_key was already reserved: this is the earlier reservation, not a new draw. */
  readonly replayed: boolean;
}

/**
 * The ledger could not be asked, or its answer could not be read: a stable
 * code, never the response body. `retryable` is true only where asking again
 * cannot double-count: a transport failure or a server error, retried under
 * the same reservation_key.
 */
export class ExposureUnavailable extends Error {
  public constructor(
    public readonly code: string,
    public readonly retryable: boolean,
  ) {
    super(code);
    this.name = "ExposureUnavailable";
  }
}

export interface ExposureLedger {
  /** The organisation's limits under its active policy; none when it has no policy. */
  limits(): Promise<readonly ExposureLimit[]>;
  reserve(limitKey: string, request: ExposureReservationRequest): Promise<ExposureAnswer>;
  /** The payment happened: for `amount` minor units when given, else for the amount reserved. */
  settle(limitKey: string, reservationId: string, amount?: number): Promise<void>;
  /** The payment did not happen: the reservation stops counting. */
  release(limitKey: string, reservationId: string): Promise<void>;
}
