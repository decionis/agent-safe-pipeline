/**
 * What shadow mode found, kept by the gateway itself: for every consequential
 * request it forwarded unchanged, what the authority said it would have
 * decided, counted by verdict and by action name, with the first and last
 * time. It is the report an operator reads before turning enforcement on,
 * and it is counts only: the action names are the route table's, the
 * verdicts are the authority's, and no path, body, parameter or identifier
 * is kept. The authority keeps its own record of the same observations, with
 * the dossiers; this is the gateway's, available where the gateway runs.
 */
import type { GatewayConfig } from "./GatewayConfig.js";

export type ShadowVerdict = "ALLOW" | "ESCALATE" | "BLOCK" | "NONE";

export interface ShadowCounts {
  readonly ALLOW: number;
  readonly ESCALATE: number;
  readonly BLOCK: number;
  /** The authority could not be asked, or did not answer in time: no verdict to count. */
  readonly NONE: number;
}

export interface ShadowSummary {
  /** When the first and the last observation settled; null before any did. */
  readonly since: string | null;
  readonly until: string | null;
  readonly observed: number;
  readonly would: ShadowCounts;
  readonly by_action: Readonly<Record<string, ShadowCounts>>;
}

/** What `agentsafe` prints on a terminal for a shadow summary, and the switch it ends with. */
export interface ShadowReport {
  readonly event: "SHADOW_REPORT";
  readonly at: string;
  readonly shadow: ShadowSummary;
  /** How enforcement is turned on for this configuration, in the operator's own terms. */
  readonly enforce: string;
}

const ZERO: ShadowCounts = { ALLOW: 0, ESCALATE: 0, BLOCK: 0, NONE: 0 };
/** The most action names the ledger keeps apart; the route table bounds them long before this. */
const MAX_ACTIONS = 1_000;

export class ShadowLedger {
  private since: string | null = null;
  private until: string | null = null;
  private observed = 0;
  private would: ShadowCounts = ZERO;
  private readonly byAction = new Map<string, ShadowCounts>();

  public record(action: string, verdict: ShadowVerdict | null, at: string): void {
    const outcome: ShadowVerdict = verdict ?? "NONE";
    this.since ??= at;
    this.until = at;
    this.observed += 1;
    this.would = { ...this.would, [outcome]: this.would[outcome] + 1 };
    const name = this.byAction.has(action) || this.byAction.size < MAX_ACTIONS ? action : "other";
    const counts = this.byAction.get(name) ?? ZERO;
    this.byAction.set(name, { ...counts, [outcome]: counts[outcome] + 1 });
  }

  public summary(): ShadowSummary {
    return {
      since: this.since,
      until: this.until,
      observed: this.observed,
      would: this.would,
      by_action: Object.fromEntries(
        [...this.byAction.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
      ),
    };
  }
}

/**
 * The one control the report ends with, in the terms this gateway was
 * configured in: a provisional workspace cannot enforce at all, a file
 * changes its own line, and the flag or the variable serves the rest.
 */
export function enforcementSwitch(config: GatewayConfig): string {
  if (config.authority.provisional) {
    return "a provisional workspace evaluates in shadow only; for enforcement, run `agentsafe login` with a key from your Decionis organization, then `agentsafe proxy --mode enforcement`";
  }
  switch (config.sources["authority.mode"]) {
    case "file":
      return "set `authority.mode: enforcement` in agentsafe.yaml (`gateway.mode: enforcement` in the chart's values) and restart";
    case "environment":
      return "set `AGENTSAFE_MODE=enforcement` and restart";
    default:
      return "`agentsafe proxy --mode enforcement`, or `AGENTSAFE_MODE=enforcement`, or `authority.mode: enforcement` in agentsafe.yaml";
  }
}

const ESC = String.fromCharCode(27);
const RESET = `${ESC}[0m`;
const BOLD = `${ESC}[1m`;
const DIM = `${ESC}[2m`;

function plural(count: number, noun: string): string {
  return `${String(count)} ${noun}${count === 1 ? "" : "s"}`;
}

/** The report for a terminal: the counts, the actions, what enforcement would have changed, and the switch. */
export function renderShadowReport(
  report: ShadowReport,
  options: { readonly color: boolean },
): string {
  const bold = (text: string): string => (options.color ? `${BOLD}${text}${RESET}` : text);
  const dim = (text: string): string => (options.color ? `${DIM}${text}${RESET}` : text);
  const row = (label: string, value: string): string => `${label.padEnd(12)} ${value}`;
  const { shadow } = report;
  const lines = [bold("Shadow report"), ""];
  if (shadow.observed === 0) {
    lines.push(
      row(
        "Observed",
        "no consequential action yet; every one will be forwarded unchanged and counted here",
      ),
      "",
      row("Turn it on", report.enforce),
      "",
    );
    return lines.join("\n");
  }
  const { would } = shadow;
  lines.push(
    row(
      "Since",
      `${shadow.since ?? ""}${shadow.until === shadow.since ? "" : ` until ${shadow.until ?? ""}`}`,
    ),
    row(
      "Observed",
      `${plural(shadow.observed, "consequential action")}, every one forwarded unchanged`,
    ),
    row("Would ALLOW", String(would.ALLOW)),
    row(
      "Would hold",
      `${String(would.ESCALATE)}${would.ESCALATE === 0 ? "" : dim("   ESCALATE: a person would have been asked first")}`,
    ),
    row(
      "Would BLOCK",
      `${String(would.BLOCK)}${would.BLOCK === 0 ? "" : dim("   nothing would have reached the upstream")}`,
    ),
    row(
      "No verdict",
      `${String(would.NONE)}${would.NONE === 0 ? "" : dim("   the authority could not be asked, or not in time")}`,
    ),
  );
  const actions = Object.entries(shadow.by_action);
  if (actions.length > 0) {
    const width = Math.max(...actions.map(([name]) => name.length));
    actions.forEach(([name, counts], index) => {
      const total = counts.ALLOW + counts.ESCALATE + counts.BLOCK + counts.NONE;
      lines.push(
        row(
          index === 0 ? "By action" : "",
          `${name.padEnd(width)}  ${String(total).padStart(5)}   ${dim(`allow ${String(counts.ALLOW)}  hold ${String(counts.ESCALATE)}  block ${String(counts.BLOCK)}${counts.NONE === 0 ? "" : `  none ${String(counts.NONE)}`}`)}`,
        ),
      );
    });
  }
  const changed = would.ESCALATE + would.BLOCK;
  lines.push(
    "",
    changed === 0
      ? `Enforcement would have changed nothing: all ${String(shadow.observed)} would have gone through as they did.`
      : `Enforcement would have held ${String(would.ESCALATE)} and refused ${String(would.BLOCK)} of ${String(shadow.observed)}; ${String(would.ALLOW)} would have gone through as they did.`,
    row("Turn it on", report.enforce),
    "",
  );
  return lines.join("\n");
}
