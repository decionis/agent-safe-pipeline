/**
 * The adoption funnel, as the process itself can see it: which milestones
 * this gateway has reached, and when. Each is reported once, on the report
 * stream, as a name and a time and nothing else: no payload, no credential,
 * no path, no verdict. Nothing here is sent anywhere; the milestones are for
 * the person at the terminal and for an operator's own log pipeline, and
 * the only thing the authority learns is what every hosted call already
 * carries in its `User-Agent`. `installation` is the installer's own last
 * line, because a process cannot see itself being installed.
 */
export const ACTIVATION_MILESTONES = [
  "gateway_started",
  "shadow_enabled",
  "enforcement_enabled",
  "decionis_connected",
  "production_deployment",
  "first_interception",
  "first_governed_action",
] as const;

export type ActivationMilestone = (typeof ACTIVATION_MILESTONES)[number];

export interface ActivationReport {
  readonly event: "ACTIVATION";
  readonly milestone: ActivationMilestone;
  readonly at: string;
}

/** What the funnel needs to know at start: the mode, the authority, the environment. */
export interface ActivationContext {
  readonly mode: "SHADOW" | "ENFORCEMENT";
  readonly authority: "LOCAL" | "DECIONIS";
  readonly production: boolean;
}

export class ActivationFunnel {
  private readonly reached = new Map<ActivationMilestone, string>();

  public constructor(
    private readonly report: (milestone: ActivationMilestone, at: string) => void,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** The milestones a start reaches, from what was configured. */
  public started(context: ActivationContext): void {
    this.reach("gateway_started");
    this.reach(context.mode === "SHADOW" ? "shadow_enabled" : "enforcement_enabled");
    if (context.authority === "DECIONIS") this.reach("decionis_connected");
    if (context.production) this.reach("production_deployment");
  }

  /** A consequential request was captured and evaluated, in either mode. */
  public intercepted(): void {
    this.reach("first_interception");
  }

  /** The authority's verdict was enforced: forwarded once, held, or refused. */
  public governed(): void {
    this.reach("first_governed_action");
  }

  /** Every milestone, with the time it was reached or null. */
  public snapshot(): Readonly<Record<ActivationMilestone, string | null>> {
    const snapshot = {} as Record<ActivationMilestone, string | null>;
    for (const milestone of ACTIVATION_MILESTONES) {
      snapshot[milestone] = this.reached.get(milestone) ?? null;
    }
    return snapshot;
  }

  private reach(milestone: ActivationMilestone): void {
    if (this.reached.has(milestone)) return;
    const at = new Date(this.clock()).toISOString();
    this.reached.set(milestone, at);
    this.report(milestone, at);
  }
}
