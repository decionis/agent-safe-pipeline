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
  | "TOO_MANY_CONNECTIONS";

export interface DestinationCounts {
  readonly protocol: InterceptProtocol;
  readonly connections: number;
  readonly bytes_to_destination: number;
  readonly bytes_from_destination: number;
  /** HTTP methods seen in the clear; empty for TLS, whose requests are not read. */
  readonly methods: Readonly<Record<string, number>>;
}

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
  private connections = 0;
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
  ): string {
    this.touch(at);
    const wanted = `${host}:${port}`;
    const key =
      this.destinations.has(wanted) || this.destinations.size < MAX_DESTINATIONS ? wanted : OTHER;
    const counts = this.destinations.get(key) ?? {
      protocol,
      connections: 0,
      bytes_to_destination: 0,
      bytes_from_destination: 0,
      methods: {},
    };
    const methods =
      method === null
        ? counts.methods
        : { ...counts.methods, [method]: (counts.methods[method] ?? 0) + 1 };
    this.destinations.set(key, { ...counts, connections: counts.connections + 1, methods });
    return key;
  }

  /** Bytes that crossed for a placed connection, by the key `record` returned. */
  public bytes(key: string, toDestination: number, fromDestination: number): void {
    const counts = this.destinations.get(key);
    if (counts === undefined) return;
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

  public summary(): InterceptSummary {
    return {
      since: this.since,
      until: this.until,
      connections: this.connections,
      placed: this.spliced,
      refused: Object.fromEntries([...this.refusals.entries()].sort()),
      destinations: Object.fromEntries([...this.destinations.entries()].sort()),
    };
  }

  public report(at: string): InterceptReport {
    return {
      event: "INTERCEPT_REPORT",
      at,
      intercept: this.summary(),
      next: "Every destination listed is somewhere this workload acts. agentsafe proxy --upstream https://<host> governs one today; governing them transparently, in this same hop, is the interceptor's next phase.",
    };
  }

  private touch(at: string): void {
    this.since ??= at;
    this.until = at;
    this.connections += 1;
  }
}
