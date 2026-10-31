import type {
  CapturedIntent,
  DecisionAuthority,
  DecisionEvaluationOptions,
  DecisionEvidence,
  DecisionGate,
} from "@decionis/agent-safe-pipeline";

/**
 * `UNCHECKED` until a decision names the action space its release was
 * checked against; then `MATCH` or `DRIFT` as the last one that named one.
 */
export type ActionSpaceState = "UNCHECKED" | "MATCH" | "DRIFT";

export interface ActionSpaceStatus {
  /** The digest of the action space this gateway loaded; null when no manifest describes it. */
  readonly loaded: string | null;
  /** The digest the last decision that named one gave for the release that decided. */
  readonly release: string | null;
  readonly state: ActionSpaceState;
  /** The releases' digests recorded as drift, oldest first. */
  readonly drifted: readonly string[];
}

/** How many drifting releases are remembered; past it the oldest is forgotten, and recorded again if it returns. */
export const MAX_REMEMBERED_RELEASES = 64;

/**
 * Compares the action space this gateway loaded with the one each deciding
 * release was checked against, as the authority names it on the decision
 * (`actionManifestDigest`). A release that differs is a release whose coverage
 * gate never saw some action this gateway can propose, or saw one it cannot:
 * recorded once per release, through `onDrift`, and shown. It is a report and
 * nothing more: no decision is changed, delayed or refused for it, and a
 * failure to record it never reaches the decision.
 */
export class ActionSpaceDrift {
  private release: string | null = null;
  private readonly recorded = new Set<string>();

  public constructor(
    private readonly loaded: string | null,
    private readonly onDrift: (release: string, decision: DecisionGate) => void,
  ) {}

  public get state(): ActionSpaceState {
    if (this.release === null) return "UNCHECKED";
    return this.release === this.loaded ? "MATCH" : "DRIFT";
  }

  public status(): ActionSpaceStatus {
    return {
      loaded: this.loaded,
      release: this.release,
      state: this.state,
      drifted: [...this.recorded],
    };
  }

  /** One decision: nothing when it names no release's action space. */
  public observe(decision: DecisionGate): void {
    const release = decision.actionManifestDigest;
    if (release === undefined || release === null) return;
    this.release = release;
    if (release === this.loaded || this.recorded.has(release)) return;
    if (this.recorded.size === MAX_REMEMBERED_RELEASES) {
      this.recorded.delete(this.recorded.values().next().value as string);
    }
    this.recorded.add(release);
    try {
      this.onDrift(release, decision);
    } catch {
      // Report-only: a record that cannot be written leaves the decision as it was.
    }
  }

  /** The authority, with each decision it returns observed before anyone uses it. */
  public observing(authority: DecisionAuthority): DecisionAuthority {
    return {
      ...(authority.evaluationMode === undefined
        ? {}
        : { evaluationMode: authority.evaluationMode }),
      evaluate: async (
        captured: CapturedIntent,
        evidence?: DecisionEvidence,
        options?: DecisionEvaluationOptions,
      ): Promise<DecisionGate> => {
        const decision = await authority.evaluate(captured, evidence, options);
        this.observe(decision);
        return decision;
      },
    };
  }
}
