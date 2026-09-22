/**
 * What the gateway says about itself and each request, in two renderings:
 * human lines for a terminal, one JSON object per line for everything else.
 * The vocabulary keeps the authority's verdicts and the runtime's failure
 * states apart, so an unreachable authority never reads as a policy BLOCK.
 */
import { renderShadowReport, type ShadowReport } from "./ShadowLedger.js";

export type GatewayState =
  | "ALLOW"
  | "BLOCK"
  | "ESCALATE"
  | "SHADOW"
  | "AUTHORITY_UNAVAILABLE"
  | "EXECUTION_FAILED"
  | "EXECUTION_INDETERMINATE"
  | "ERROR";

export type ExecutionDisposition =
  | "FORWARDED"
  | "NOT_FORWARDED"
  | "HELD"
  | "PASSTHROUGH"
  | "FORWARDED_UNGOVERNED"
  | "FAILED"
  | "INDETERMINATE";

export interface InterceptionReport {
  readonly event: "INTERCEPTED";
  readonly at: string;
  readonly method: string;
  readonly path: string;
  readonly action: string;
  readonly state: GatewayState;
  readonly verdict: "ALLOW" | "ESCALATE" | "BLOCK" | null;
  readonly reason_codes: readonly string[];
  readonly execution: ExecutionDisposition;
  readonly mode: "SHADOW" | "ENFORCEMENT";
  readonly authority: string;
  readonly intent_id: string | null;
  readonly intent_hash: string | null;
  readonly decision_id: string | null;
  readonly dossier_id: string | null;
  readonly upstream_status: number | null;
  readonly finalization: string | null;
  readonly latency_ms: number;
  readonly authority_ms: number | null;
}

export interface StartedReport {
  readonly event: "GATEWAY_STARTED";
  readonly at: string;
  readonly gateway: string;
  readonly upstream: string;
  readonly mode: "SHADOW" | "ENFORCEMENT";
  readonly authority: string;
  readonly failure_policy: "FAIL_CLOSED" | "FAIL_OPEN";
  readonly routes: number;
  readonly evidence: string;
  readonly version: string;
}

export interface NoteReport {
  readonly event: "NOTE";
  readonly at: string;
  readonly level: "info" | "warn" | "error";
  readonly code: string;
  readonly message: string;
}

export interface StoppedReport {
  readonly event: "GATEWAY_STOPPED";
  readonly at: string;
  readonly signal: string;
}

/**
 * Which enforcement boundary this process is, said once at start. It carries
 * identifiers and versions only: no address, no host, no container.
 */
export interface BoundaryIdentifiedReport {
  readonly event: "BOUNDARY_IDENTIFIED";
  readonly at: string;
  readonly boundary_id: string;
  readonly boundary_source: "configured" | "derived";
  readonly deployment_type: string;
  readonly environment: string | null;
  readonly protocol_version: string;
  readonly conformance_version: string;
}

/**
 * What software this boundary is standing in front of, said once at start.
 * Identifiers and digests only, and `trust_level` is always beside them: a
 * reader must never have to guess whether a digest was checked.
 */
export interface WorkloadResolvedReport {
  readonly event: "WORKLOAD_RESOLVED";
  readonly at: string;
  readonly runtime: string | null;
  readonly artifact_type: string | null;
  readonly image: string | null;
  readonly digest: string | null;
  readonly publisher: string | null;
  readonly source: string;
  readonly trust_level: string;
}

export interface ActivationMilestoneReport {
  readonly event: "ACTIVATION";
  readonly milestone: string;
  readonly at: string;
}

export type GatewayReport =
  | InterceptionReport
  | StartedReport
  | BoundaryIdentifiedReport
  | WorkloadResolvedReport
  | NoteReport
  | StoppedReport
  | ActivationMilestoneReport
  | ShadowReport;

const ESC = String.fromCharCode(27);
const RESET = `${ESC}[0m`;
const BOLD = `${ESC}[1m`;
const DIM = `${ESC}[2m`;
const COLORS: Readonly<Record<GatewayState, string>> = {
  ALLOW: `${ESC}[32m`,
  BLOCK: `${ESC}[31m`,
  ESCALATE: `${ESC}[33m`,
  SHADOW: `${ESC}[36m`,
  AUTHORITY_UNAVAILABLE: `${ESC}[35m`,
  EXECUTION_FAILED: `${ESC}[35m`,
  EXECUTION_INDETERMINATE: `${ESC}[35m`,
  ERROR: `${ESC}[35m`,
};

/** The label a state prints under, spaced for reading. */
export function stateLabel(state: GatewayState): string {
  return state.replace(/_/g, " ");
}

export function executionLabel(execution: ExecutionDisposition): string {
  switch (execution) {
    case "FORWARDED":
      return "FORWARDED";
    case "NOT_FORWARDED":
      return "NOT FORWARDED";
    case "HELD":
      return "HELD";
    case "PASSTHROUGH":
      return "PASSTHROUGH";
    case "FORWARDED_UNGOVERNED":
      return "FORWARDED (fail-open, ungoverned)";
    case "FAILED":
      return "FAILED";
    case "INDETERMINATE":
      return "INDETERMINATE";
  }
}

export interface RenderOptions {
  readonly color: boolean;
}

/**
 * Renders one report for a terminal. Every state is a distinct heading, and
 * with color on, a distinct color; a shadow observation says what would have
 * been decided and that the request went through regardless.
 */
export function renderHuman(report: GatewayReport, options: RenderOptions): string {
  const paint = (state: GatewayState, text: string): string =>
    options.color ? `${BOLD}${COLORS[state]}${text}${RESET}` : text;
  const dim = (text: string): string => (options.color ? `${DIM}${text}${RESET}` : text);
  const row = (label: string, value: string, width = 12): string =>
    `${label.padEnd(width)} ${value}`;
  switch (report.event) {
    case "GATEWAY_STARTED":
      return [
        `${options.color ? BOLD : ""}AgentSafe${options.color ? RESET : ""} ${dim(report.version)}`,
        "",
        row("Gateway", report.gateway),
        row("Upstream", report.upstream),
        row("Mode", report.mode),
        row("Authority", report.authority),
        row(
          "Failure",
          report.failure_policy === "FAIL_CLOSED" ? "fail-closed" : "fail-open (explicit)",
        ),
        row(
          "Routes",
          report.routes === 0
            ? "none named; every unsafe method is governed"
            : String(report.routes),
        ),
        row("Evidence", report.evidence),
        row("Status", "READY"),
        "",
        dim("Waiting for consequential actions..."),
        "",
      ].join("\n");
    case "BOUNDARY_IDENTIFIED":
      return [
        row("Boundary", `${report.boundary_id} (${report.boundary_source})`),
        row(
          "Runtime",
          `${report.deployment_type}${report.environment === null ? "" : `, ${report.environment}`}`,
        ),
        "",
      ].join("\n");
    case "WORKLOAD_RESOLVED":
      return [
        row("Workload", report.image ?? report.digest ?? "declared"),
        row("Provenance", `${report.source}, ${report.trust_level}`),
        "",
      ].join("\n");
    case "GATEWAY_STOPPED":
      return `${dim(`Stopped on ${report.signal}.`)}\n`;
    case "ACTIVATION":
      return `${dim(`✓ ${report.milestone.replace(/_/g, " ")}`)}\n`;
    case "SHADOW_REPORT":
      return renderShadowReport(report, options);
    case "NOTE": {
      const prefix =
        report.level === "error" ? "ERROR" : report.level === "warn" ? "WARNING" : "NOTE";
      return `${report.level === "info" ? dim(prefix) : paint("ERROR", prefix)} ${report.message}\n`;
    }
    case "INTERCEPTED": {
      const heading = paint(report.state, stateLabel(report.state));
      const reason = report.reason_codes[0] ?? "none";
      const width = report.state === "SHADOW" ? 17 : 12;
      const lines = [
        heading,
        "",
        `${report.method} ${report.path}`,
        "",
        row("Action", report.action, width),
      ];
      if (report.state === "SHADOW") {
        lines.push(
          row("Would decide", report.verdict ?? "none (authority unavailable)", width),
          row("Reason", reason, width),
          row(
            "Actual execution",
            `PASSTHROUGH${report.upstream_status === null ? "" : ` (${report.upstream_status})`}`,
            width,
          ),
        );
      } else {
        lines.push(
          row(
            "Decision",
            report.verdict ??
              (report.state === "AUTHORITY_UNAVAILABLE" ? "none (authority unreachable)" : "none"),
            width,
          ),
          row("Reason", reason, width),
          row(
            "Execution",
            `${executionLabel(report.execution)}${report.upstream_status === null ? "" : ` (${report.upstream_status})`}`,
            width,
          ),
        );
      }
      lines.push(row("Dossier", report.dossier_id ?? "none", width));
      if (report.finalization !== null) lines.push(row("Finalized", report.finalization, width));
      lines.push(row("Latency", `${report.latency_ms}ms`, width), "");
      return lines.join("\n");
    }
  }
}

/** One line of JSON; the same fields, nothing rendered. */
export function renderJson(report: GatewayReport): string {
  return JSON.stringify(report);
}
