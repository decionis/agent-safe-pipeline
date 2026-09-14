import { z } from "zod";
import type { LineWriter } from "../audit/LineAuditSink.js";

const code = z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/);
const name = z.string().min(1).max(64);

/**
 * What the security stream may say. Every field is an identifier, a code, or
 * a count; no value, parameter, header, or body has a place in this schema,
 * so an event cannot carry one by mistake.
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
]);

export type SecurityEvent = z.infer<typeof SecurityEventSchema>;

export const SECURITY_STREAM = "agent-safe.security/1";

/**
 * The security stream: one JSON line per event on stderr, validated against
 * the schema before it is written. An event that does not fit is dropped and
 * counted rather than thrown, because a request path must never fail on its
 * own evidence.
 */
export class SecurityEvents {
  private droppedCount = 0;

  public constructor(
    private readonly write: LineWriter,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  public get dropped(): number {
    return this.droppedCount;
  }

  public emit(event: SecurityEvent): void {
    const parsed = SecurityEventSchema.safeParse(event);
    if (!parsed.success) {
      this.droppedCount += 1;
      return;
    }
    this.write(
      JSON.stringify({ stream: SECURITY_STREAM, at: this.clock().toISOString(), ...parsed.data }),
    );
  }
}
