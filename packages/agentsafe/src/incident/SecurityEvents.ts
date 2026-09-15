import { z } from "zod";
import { HashChain, type ChainHead } from "../audit/HashChain.js";
import type { LineWriter } from "../audit/LineAuditSink.js";

const code = z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/);
const name = z.string().min(1).max(64);
const origin = z.string().min(1).max(256);
const sequence = z.number().int().nonnegative();

/**
 * What the security stream may say. Every field is an identifier, a code, an
 * origin, or a count; no value, parameter, header, path, or body has a place
 * in this schema, so an event cannot carry one by mistake.
 */
export const SecurityEventSchema = z.discriminatedUnion("event", [
  z.strictObject({
    event: z.literal("POSTURE_VERIFIED"),
    checks: z.number().int().nonnegative(),
    waived: z.number().int().nonnegative(),
  }),
  z.strictObject({ event: z.literal("POSTURE_WAIVED"), check: code }),
  z.strictObject({ event: z.literal("POSTURE_DRIFT"), check: code }),
  z.strictObject({ event: z.literal("POSTURE_RESTORED") }),
  z.strictObject({ event: z.literal("SECRET_ROTATED"), name }),
  z.strictObject({ event: z.literal("SECRET_RELOAD_REFUSED"), name, code }),
  z.strictObject({ event: z.literal("AUTHORITY_CLIENTS_REBUILT"), name }),
  z.strictObject({
    event: z.literal("LEAK_SUSPECTED"),
    patterns: z.array(z.string().max(32)).max(8),
  }),
  z.strictObject({ event: z.literal("EGRESS_REFUSED"), origin: origin.nullable(), code }),
  z.strictObject({ event: z.literal("AUTH_FAILED"), method: z.enum(["bearer", "mtls"]) }),
  z.strictObject({ event: z.literal("TLS_CONTEXT_ROTATED") }),
  z.strictObject({ event: z.literal("CHAIN_RESUMED"), chain: name, head: sequence }),
  z.strictObject({ event: z.literal("CHAIN_CHECKPOINT"), chain: name, head: sequence }),
]);

export type SecurityEvent = z.infer<typeof SecurityEventSchema>;

export const SECURITY_STREAM = "agent-safe.security/1";

export interface SecurityEventsOptions {
  readonly clock?: () => Date;
  /** The chain to link lines on; a fresh one from genesis when the process has no checkpoint. */
  readonly chain?: HashChain;
}

/**
 * The security stream: one JSON line per event on stderr, validated against
 * the schema before it is written and linked on its own hash chain. An
 * event that does not fit is dropped and counted rather than thrown,
 * because a request path must never fail on its own evidence. Subscribers
 * (the metrics) see each event after it is written.
 */
export class SecurityEvents {
  private droppedCount = 0;
  private readonly clock: () => Date;
  public readonly chain: HashChain;
  private readonly listeners: ((event: SecurityEvent) => void)[] = [];

  public constructor(
    private readonly write: LineWriter,
    options: SecurityEventsOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.chain = options.chain ?? new HashChain(SECURITY_STREAM);
  }

  public get dropped(): number {
    return this.droppedCount;
  }

  public get head(): ChainHead {
    return this.chain.head;
  }

  public subscribe(listener: (event: SecurityEvent) => void): () => void {
    this.listeners.push(listener);
    return () => {
      const index = this.listeners.indexOf(listener);
      if (index !== -1) this.listeners.splice(index, 1);
    };
  }

  public emit(event: SecurityEvent): void {
    const parsed = SecurityEventSchema.safeParse(event);
    if (!parsed.success) {
      this.droppedCount += 1;
      return;
    }
    this.chain.link({ at: this.clock().toISOString(), ...parsed.data }, this.write);
    for (const listener of this.listeners) listener(parsed.data);
  }
}
