/**
 * `agentsafe test [name=host:port]...`: the boundary test as a command. The
 * synthetic run in `gateway/BoundaryTest.ts` is the whole of it; a target
 * named on the command line adds the containment probe, a TCP dial from
 * this machine that says whether the real system of record answers without
 * the gateway, which is what an agent could reach if it went around. The
 * exit status is the finding: 0 when the boundary holds and no named target
 * answered, 1 when something adversarial got through or a target answered,
 * 2 when the test did not run: the arguments were wrong, or the process is
 * marked production, where the synthetic authority refuses to start.
 */
import {
  parseTarget,
  probeContainment,
  type ContainmentReport,
  type ContainmentTarget,
} from "../containment/ContainmentProbe.js";
import { dial as tcpDial } from "../egress/TcpProbe.js";
import {
  runBoundaryTest,
  type BoundaryCaseResult,
  type BoundaryTestOptions,
  type BoundaryTestReport,
  type PassOutcome,
} from "../gateway/BoundaryTest.js";
import { executionLabel, stateLabel } from "../gateway/GatewayReport.js";
import { packageVersion } from "../Version.js";
import { ArgumentError, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const TEST_ARGUMENTS = { valued: [], flags: ["json"] } as const;

/** The report the command prints: the synthetic run, and the containment probe when asked. */
export interface TestReport extends BoundaryTestReport {
  readonly containment: ContainmentReport | null;
  /** 0 when the boundary holds and no named target answered; 1 otherwise. */
  readonly exit: 0 | 1;
}

export interface TestOptions {
  readonly run?: (options: BoundaryTestOptions) => Promise<BoundaryTestReport>;
  readonly dial?: typeof tcpDial;
  readonly timeoutMs?: number;
}

const ESC = String.fromCharCode(27);
const RESET = `${ESC}[0m`;
const BOLD = `${ESC}[1m`;
const DIM = `${ESC}[2m`;
const RED = `${ESC}[31m`;
const GREEN = `${ESC}[32m`;
const YELLOW = `${ESC}[33m`;

function status(outcome: PassOutcome): string {
  return outcome.status === null ? "no answer" : String(outcome.status);
}

/** What the target saw, in the words the exposure is counted in. */
function reachedLabel(outcome: PassOutcome): string {
  if (!outcome.reached) return "not reached";
  return outcome.forwarded === 1
    ? `reached ${status(outcome)}`
    : `reached ${String(outcome.forwarded)}x`;
}

function directColumn(result: BoundaryCaseResult): string {
  const label = reachedLabel(result.direct);
  return result.direct.forgedHeadersReached ? `${label}, forged headers accepted` : label;
}

function shadowColumn(result: BoundaryCaseResult): string {
  const label = reachedLabel(result.shadow);
  if (result.shadow.state !== "SHADOW") return label;
  return `${label}, would ${result.shadow.verdict ?? "decide nothing (authority unreachable)"}`;
}

function enforcementColumn(result: BoundaryCaseResult): string {
  const outcome = result.enforcement;
  if (outcome.state === null) return `${reachedLabel(outcome)} (not consequential)`;
  if (outcome.state === "ALLOW") {
    const times = outcome.forwarded === 1 ? "once" : `${String(outcome.forwarded)}x`;
    return `ALLOW: forwarded ${times}, ${status(outcome)}${outcome.dossier ? ", dossier" : ""}`;
  }
  const execution = outcome.execution === null ? "" : `, ${executionLabel(outcome.execution)}`;
  return `${stateLabel(outcome.state)} ${status(outcome)}${execution}`;
}

function paintEnforcement(result: BoundaryCaseResult, text: string, color: boolean): string {
  if (!color) return text;
  const tone =
    result.enforcement.state === null
      ? DIM
      : result.enforcement.state === "ALLOW"
        ? GREEN
        : result.enforcement.reached
          ? RED
          : YELLOW;
  return `${tone}${text}${RESET}`;
}

/** The report for a terminal: one row per case, the exposure, the evidence, the verdict. */
export function renderTestReport(report: TestReport, options: { readonly color: boolean }): string {
  const bold = (text: string): string => (options.color ? `${BOLD}${text}${RESET}` : text);
  const dim = (text: string): string => (options.color ? `${DIM}${text}${RESET}` : text);
  const row = (label: string, value: string): string => `${label.padEnd(11)} ${value}`;
  // The columns are as wide as their widest cell, so nothing runs into its neighbour.
  const cells = report.cases.map((result) => [
    result.title,
    directColumn(result),
    shadowColumn(result),
    enforcementColumn(result),
  ]);
  const widths = ["", "direct", "shadow", "enforcement"].map((heading, column) =>
    Math.max(heading.length, ...cells.map((cell) => cell[column]?.length ?? 0)),
  );
  const pad = (text: string, column: number): string => text.padEnd(widths[column] ?? 0);
  const lines = [
    `${bold("AgentSafe")} ${dim(report.runtime)} boundary test`,
    "",
    row("Target", "synthetic loopback service; nothing real is called"),
    row("Authority", "local/demo (synthetic policy on loopback; not Decionis)"),
    "",
    `${pad("", 0)}  ${bold(pad("direct", 1))}  ${bold(pad("shadow", 2))}  ${bold("enforcement")}`,
  ];
  report.cases.forEach((result, index) => {
    const [title = "", direct = "", shadow = "", enforcement = ""] = cells[index] ?? [];
    lines.push(
      `${pad(title, 0)}  ${pad(direct, 1)}  ${pad(shadow, 2)}  ${paintEnforcement(result, enforcement, options.color)}`,
    );
    if (result.failOpen !== null) {
      lines.push(
        `${pad("", 0)}  ${dim(
          `with failurePolicy failOpen (explicit): ${reachedLabel(result.failOpen)}, marked ${
            result.failOpen.execution === null
              ? "nothing"
              : executionLabel(result.failOpen.execution)
          }`,
        )}`,
      );
    }
  });
  const { exposure } = report;
  const of = (count: number): string => `${String(count)} of ${String(exposure.adversarial)}`;
  lines.push(
    "",
    row(
      "Exposure",
      `${of(exposure.direct)} adversarial actions reached the target directly, ${of(exposure.shadow)} in shadow, ${of(exposure.enforcement)} under enforcement`,
    ),
    row(
      "Work",
      report.workFlowed
        ? "routine actions went through under enforcement, once each"
        : "a routine action did not go through under enforcement",
    ),
    row(
      "Evidence",
      `${String(report.evidence.lines)} chained lines, ${report.evidence.verified ? "verified" : "NOT verified"}`,
    ),
  );
  if (report.containment !== null) {
    for (const finding of report.containment.findings) {
      lines.push(
        row(
          "Target",
          `${finding.target} ${finding.address}: ${finding.verdict}${
            finding.verdict === "REACHABLE"
              ? " without the gateway; an agent here can go around it"
              : ""
          }`,
        ),
      );
    }
  }
  const holds = report.exit === 0;
  const verdict =
    report.verdict === "BOUNDARY_BROKEN"
      ? "BOUNDARY BROKEN: something adversarial got through under enforcement"
      : report.containment !== null && !report.containment.noneReachable
        ? "BOUNDARY HOLDS, BUT A TARGET ANSWERS DIRECTLY"
        : "BOUNDARY HOLDS";
  lines.push(
    "",
    row("Verdict", options.color ? `${BOLD}${holds ? GREEN : RED}${verdict}${RESET}` : verdict),
    "",
    dim(
      holds
        ? "Next: agentsafe proxy --upstream <your service> --mode shadow, then --mode enforcement."
        : report.verdict === "BOUNDARY_BROKEN"
          ? "This is a defect in the runtime, not in your service; please report it with agentsafe test --json."
          : "Put the gateway where the agent must pass through it, and the target where only the gateway reaches it.",
    ),
    "",
  );
  return lines.join("\n");
}

export async function runTest(
  io: CliProcess,
  argv: readonly string[],
  options: TestOptions = {},
): Promise<TestReport | null> {
  let json = false;
  let targets: ContainmentTarget[];
  try {
    const parsed = parseArguments(argv, TEST_ARGUMENTS);
    json = parsed.options.get("json") === true;
    targets = parsed.positionals.map(parseTarget);
  } catch (error) {
    const message =
      error instanceof ArgumentError
        ? error.message
        : error instanceof Error
          ? error.message
          : "ARGUMENTS_INVALID";
    io.stderr(`${message}\n`);
    io.exit(2);
    return null;
  }
  let boundary: BoundaryTestReport;
  try {
    boundary = await (options.run ?? runBoundaryTest)({ version: packageVersion() });
  } catch (error) {
    const reason = error instanceof Error ? error.message : "TEST_FAILED";
    io.stderr(
      json
        ? `${JSON.stringify({ event: "TEST_REFUSED", reason })}\n`
        : `AgentSafe did not run the boundary test.\n\n${reason}${
            reason === "LOCAL_DOUBLE_FORBIDDEN"
              ? ": the synthetic authority is refused where NODE_ENV=production. Run the test where you installed the runtime, or start the container with NODE_ENV unset."
              : ""
          }\n`,
    );
    io.exit(2);
    return null;
  }
  const containment =
    targets.length === 0
      ? null
      : await probeContainment({
          targets,
          dial: options.dial ?? tcpDial,
          ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
        });
  const exit: 0 | 1 =
    boundary.verdict === "BOUNDARY_HOLDS" && (containment === null || containment.noneReachable)
      ? 0
      : 1;
  const report: TestReport = { ...boundary, containment, exit };
  io.stdout(json ? `${JSON.stringify(report)}\n` : renderTestReport(report, { color: io.color }));
  io.exit(exit);
  return report;
}
