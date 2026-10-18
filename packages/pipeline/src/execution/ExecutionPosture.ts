import type { DecisionGate } from "../decision/DecisionAuthority.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";

/**
 * What a governed surface does with an action when it cannot reach the
 * authority. The vocabulary is Decionis Core's (`FailurePosture`, shared
 * with the AgentSafe gateway), and so is the invariant every posture keeps:
 * failing to reach the authority is never an authorization.
 *
 * - `STRICT`: the action does not run.
 * - `BOUNDED_CONTINUITY`: the surface may let the action continue without
 *   an evaluation, ungoverned and never approved, where it was configured
 *   for a bounded exposure.
 * - `CUSTOM`: the institution decides, per action.
 *
 * The runner applies posture only to a decision that failed closed: an
 * authority that answered `BLOCK` was reached, and no posture overrides it.
 * And the runner itself never writes without a grant, under any posture: an
 * ungoverned continuation is the surface's own act, which the runner reports
 * as a coverage gap in the evidence line instead of hiding it.
 */
export type FailurePosture = "STRICT" | "BOUNDED_CONTINUITY" | "CUSTOM";

/**
 * What happened to an action the authority could not decide, in the gateway's
 * own tokens: refused, held for someone to look at, or let through
 * ungoverned by the surface.
 */
export type UnavailableDisposition = "NOT_FORWARDED" | "HELD" | "FORWARDED_UNGOVERNED";

/** The authority state an evidence line names: decided, or unreachable. */
export type AuthorityState = "DECIDED" | "AUTHORITY_UNAVAILABLE";

export interface PostureContext {
  readonly captured: CapturedIntent;
  readonly decision: DecisionGate;
}

export type ExecutionPosture =
  | { readonly posture: "STRICT" }
  | { readonly posture: "BOUNDED_CONTINUITY" }
  | {
      readonly posture: "CUSTOM";
      /** The institution's choice for one action; it may hold or refuse, never authorize. */
      readonly decide: (context: PostureContext) => UnavailableDisposition;
    };

export const STRICT_POSTURE: ExecutionPosture = Object.freeze({ posture: "STRICT" });

/**
 * The disposition for an action whose decision failed closed. A custom rule
 * that throws, or answers something else, is `NOT_FORWARDED`: the posture
 * that cannot be read is the strict one.
 */
export function unavailableDisposition(
  posture: ExecutionPosture,
  context: PostureContext,
): UnavailableDisposition {
  if (posture.posture === "STRICT") return "NOT_FORWARDED";
  if (posture.posture === "BOUNDED_CONTINUITY") return "FORWARDED_UNGOVERNED";
  try {
    const chosen = posture.decide(context);
    return chosen === "HELD" || chosen === "FORWARDED_UNGOVERNED" ? chosen : "NOT_FORWARDED";
  } catch {
    return "NOT_FORWARDED";
  }
}
