/**
 * What the interceptor saw, kept by the interceptor itself: for every
 * connection it placed, the destination and the protocol, counted, with the
 * bytes that crossed each way and the HTTP methods where the protocol showed
 * them; for every connection it refused, the reason. It is the report an
 * operator reads to learn what a workload actually reaches before any of it
 * is governed, and it is counts and names only: host names and ports, never
 * a path, a header, a body or an address of the caller.
 */
import type { DestinationRefusal, InterceptProtocol } from "./Destination.js";

export type InterceptRefusal =
  | DestinationRefusal
  /** The client sent nothing decisive within the peek window. */
  | "PEEK_TIMEOUT"
  /** The destination could not be reached from here. */
  | "UPSTREAM_UNREACHABLE"
  /** The destination is this interceptor's own listener: a loop, refused. */
  | "HOST_IS_INTERCEPTOR"
  /** The interceptor holds as many connections as it will. */
  | "TOO_MANY_CONNECTIONS"
  /** The operator governs a list of destinations and refuses the rest; this was the rest. */
  | "UNLISTED_DESTINATION"
  /** A governed connection could not be taken: no authority to mint with, a failed handshake, no gateway. */
  | "GOVERN_UNAVAILABLE";

/** A destination whose connections were spliced through: what the hop itself measured. */
export interface SplicedCounts {
  readonly protocol: InterceptProtocol;
  readonly governed: false;
  readonly connections: number;
  readonly bytes_to_destination: number;
  readonly bytes_from_destination: number;
  /** HTTP methods seen in the clear; empty for TLS, whose requests are not read. */
  readonly methods: Readonly<Record<string, number>>;
}

/** What the gateway for a governed destination did with the requests it was handed. */
export interface GovernedGatewayCounts {
  readonly mode: "SHADOW" | "ENFORCEMENT";
  /** The gateway's own counts by name: `governed`, `interceptions`, `allows`, `blocks`, `escalations`, `shadow`, `passthrough`, ... */
  readonly requests: Readonly<Record<string, number>>;
}

/**
 * A destination whose connections the gateway took: the hop counted the
 * connections and read the first request's method where it was in the clear,
 * and the requests themselves are the gateway's account, not a byte count.
 */
export interface GovernedCounts {
  readonly protocol: InterceptProtocol;
  readonly governed: true;
  readonly connections: number;
  readonly methods: Readonly<Record<string, number>>;
  /** Null until the report is written, or when no request reached the gateway. */
  readonly gateway: GovernedGatewayCounts | null;
}

export type DestinationCounts = SplicedCounts | GovernedCounts;

/** The gateway counts for a governed destination at report time, or null when none was created. */
export type GovernedCountsSource = (
  host: string,
  protocol: InterceptProtocol,
) => GovernedGatewayCounts | null;

export interface InterceptSummary {
  readonly since: string | null;
  readonly until: string | null;
  readonly connections: number;
  readonly placed: number;
  readonly refused: Readonly<Record<string, number>>;
  /** By `host:port`, the destinations this workload reached. */
  readonly destinations: Readonly<Record<string, DestinationCounts>>;
}

export interface InterceptReport {
  readonly event: "INTERCEPT_REPORT";
  readonly at: string;
  readonly intercept: InterceptSummary;
  /** What an operator does with the list, in their own terms. */
  readonly next: string;
}

/** The most destinations kept apart; the rest are counted under one name. */
const MAX_DESTINATIONS = 1_000;
const OTHER = "other";

export class InterceptLedger {
  private since: string | null = null;
  private until: string | null = null;
  private count = 0;
  private spliced = 0;
  private readonly refusals = new Map<string, number>();
  private readonly destinations = new Map<string, DestinationCounts>();

  /** A connection whose destination was read; returns the key `bytes` takes. */
  public record(
    host: string,
    port: number,
    protocol: InterceptProtocol,
    method: string | null,
    at: string,
    governed = false,
  ): string {
    this.touch(at);
    const wanted = `${host}:${port}`;
    const key =
      this.destinations.has(wanted) || this.destinations.size < MAX_DESTINATIONS ? wanted : OTHER;
    const counts: DestinationCounts = this.destinations.get(key) ?? this.fresh(protocol, governed);
    const methods =
      method === null
        ? counts.methods
        : { ...counts.methods, [method]: (counts.methods[method] ?? 0) + 1 };
    this.destinations.set(key, { ...counts, connections: counts.connections + 1, methods });
    return key;
  }

  private fresh(protocol: InterceptProtocol, governed: boolean): DestinationCounts {
    return governed
      ? { protocol, governed: true, connections: 0, methods: {}, gateway: null }
      : {
          protocol,
          governed: false,
          connections: 0,
          bytes_to_destination: 0,
          bytes_from_destination: 0,
          methods: {},
        };
  }

  /** Bytes that crossed for a spliced connection, by the key `record` returned; a governed destination has none to count. */
  public bytes(key: string, toDestination: number, fromDestination: number): void {
    const counts = this.destinations.get(key);
    if (counts === undefined || counts.governed) return;
    this.destinations.set(key, {
      ...counts,
      bytes_to_destination: counts.bytes_to_destination + toDestination,
      bytes_from_destination: counts.bytes_from_destination + fromDestination,
    });
  }

  /** A recorded connection whose destination answered: the splice is up. */
  public placed(): void {
    this.spliced += 1;
  }

  /**
   * A connection that was not placed, by the reason. A connection refused
   * before its destination was read has not been counted yet and is counted
   * here; one refused after `record` has.
   */
  public refuse(reason: InterceptRefusal, at: string, countConnection: boolean): void {
    if (countConnection) this.touch(at);
    else this.until = at;
    this.refusals.set(reason, (this.refusals.get(reason) ?? 0) + 1);
  }

  /**
   * The summary so far. A governed destination's `gateway` is filled from
   * `governed`, the gateway's account of the requests it was handed, when one
   * is given; the key is `host:port`, and the port names the protocol.
   */
  public summary(governed: GovernedCountsSource = () => null): InterceptSummary {
    const destinations = [...this.destinations.entries()].sort().map(([key, counts]) => {
      if (!counts.governed) return [key, counts] as const;
      const host = key.slice(0, key.lastIndexOf(":"));
      return [key, { ...counts, gateway: governed(host, counts.protocol) }] as const;
    });
    return {
      since: this.since,
      until: this.until,
      connections: this.count,
      placed: this.spliced,
      refused: Object.fromEntries([...this.refusals.entries()].sort()),
      destinations: Object.fromEntries(destinations),
    };
  }

  public report(at: string, governed?: GovernedCountsSource): InterceptReport {
    return {
      event: "INTERCEPT_REPORT",
      at,
      intercept: this.summary(governed),
      next: "Every destination listed is somewhere this workload acts. Name the ones to govern in AGENTSAFE_INTERCEPT_GOVERN, with the authority the workload trusts, and this same hop asks Decionis before each consequential request reaches them.",
    };
  }

  /** How many connections have been counted so far, placed or refused. */
  public get connections(): number {
    return this.count;
  }

  private touch(at: string): void {
    this.since ??= at;
    this.until = at;
    this.count += 1;
  }
}
