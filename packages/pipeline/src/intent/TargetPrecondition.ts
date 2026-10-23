import { z } from "zod";
import type { JsonObject } from "./JsonValue.js";
import { RESERVED_CONTEXT_AGENT_SAFE } from "./ExecutionSignals.js";

/**
 * The state of the target an intent was decided against, as the trusted
 * runtime read it immediately before the authority was asked: its version
 * (an ETag, a resource version, a row version), what the read said its state
 * was, which read said so, and when.
 *
 * Revalidation at the claim catches a policy or a signal that changed. It
 * cannot catch a target that changed underneath an unchanged policy: the
 * firewall rule edited by someone else between the grant and the commit.
 * The version closes that. It rides inside the hashed `context` under
 * `agent_safe.precondition`, so a grant is issued for exactly that version;
 * the authority carries it into the claim's attestation as
 * `binding.expected_state_version`; and a verifying provider applies it as
 * the precondition of its write, as an `If-Match` is, refusing
 * `TARGET_STATE_CHANGED` when the target is no longer at that version.
 *
 * The runtime states it, never the agent: an agent's proposal cannot reach
 * `context`, and a caller that writes the reserved key by hand is refused.
 * An intent without one carries no `agent_safe` key at all and hashes
 * exactly as it did before this existed.
 */
export const TargetPreconditionSchema = z.strictObject({
  /**
   * Opaque, compared byte for byte: visible ASCII, so an entity tag keeps its
   * quotes and its `W/`, and nothing in it can break a header line.
   */
  version: z.string().regex(/^[\x21-\x7e]{1,256}$/),
  /** The target's state as the read named it, for a transition rule to match; absent when the read names none. */
  state: z
    .string()
    .min(1)
    .max(200)
    .regex(/^\P{Cc}+$/u)
    .optional(),
  /** Which read produced the version: `<profile>#<operation>` for a profile, or the adapter's own name. */
  source: z
    .string()
    .min(1)
    .max(200)
    .regex(/^[a-z0-9][\w.:/#-]*$/i),
  /** When the runtime read it, as `toISOString()` writes it. */
  read_at: z.string().datetime(),
});

export type TargetPrecondition = z.infer<typeof TargetPreconditionSchema>;

/** The reserved entry a precondition contributes to a context. */
export function preconditionContext(precondition: TargetPrecondition): JsonObject {
  return {
    [RESERVED_CONTEXT_AGENT_SAFE]: { precondition: TargetPreconditionSchema.parse(precondition) },
  } as JsonObject;
}

/**
 * The precondition an intent was captured with, read back from its context.
 * Anything that does not parse is no precondition rather than a partial one.
 */
export function preconditionOf(context: JsonObject): TargetPrecondition | null {
  const namespace = context[RESERVED_CONTEXT_AGENT_SAFE];
  const candidate = TargetPreconditionSchema.safeParse(
    namespace !== null && typeof namespace === "object" && !Array.isArray(namespace)
      ? namespace["precondition"]
      : undefined,
  );
  return candidate.success ? candidate.data : null;
}
