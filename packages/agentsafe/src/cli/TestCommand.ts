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
 *
 * `agentsafe test --hosted` is the same requests with Decionis deciding, in
 * shadow, against the workspace this machine is logged into
 * (`gateway/HostedBoundaryTest.ts`): the first governed action for that
 * workspace and the signed record it leaves. Exit 0 when Decionis decided
 * every consequential request, 1 when it could not be reached for some or
 * all, 2 when there is no login to run it with.
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
import { runAuthorityAttacks, type AttackReport } from "../gateway/AuthorityAttacks.js";
import { executionLabel, stateLabel } from "../gateway/GatewayReport.js";
import {
  HostedTestError,
  runHostedBoundaryTest,
  type HostedBoundaryTestOptions,
  type HostedBoundaryTestReport,
  type HostedCaseResult,
} from "../gateway/HostedBoundaryTest.js";
import { processSurface } from "../gateway/InstallSurface.js";
import { packageVersion } from "../Version.js";
import { ArgumentError, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { readCredentials } from "./Credentials.js";

export const TEST_ARGUMENTS = { valued: [], flags: ["json", "hosted"] } as const;

/** The report the command prints: the synthetic run, and the containment probe when asked. */
export interface TestReport extends BoundaryTestReport {
  readonly containment: ContainmentReport | null;
  /**
   * The six attacks that live inside the lifecycle rather than in a request:
   * each needs an authority to exist before it can be attempted, so none of
   * them can be expressed as bytes sent at a target.
   */
  readonly attacks: AttackReport;
  /** 0 when the boundary holds and no named target answered; 1 otherwise. */
  readonly exit: 0 | 1;
  /**
   * The step of the adoption path this command is: the test ran, whatever
   * it found. Reported here because the gateway cannot see a test that ran
   * before it, as the installer reports `installation`; nothing is sent.
   */
  readonly activation: { readonly milestone: "boundary_tested"; readonly at: string };
}

/** The hosted report the command prints: the run, and the step of the adoption path it is. */
export interface HostedTestReport extends HostedBoundaryTestReport {
  /** 0 when Decionis decided every consequential request; 1 otherwise. */
  readonly exit: 0 | 1;
  readonly activation: { readonly milestone: "boundary_tested"; readonly at: string };
}

export interface TestOptions {
  readonly run?: (options: BoundaryTestOptions) => Promise<BoundaryTestReport>;
  readonly runHosted?: (options: HostedBoundaryTestOptions) => Promise<HostedBoundaryTestReport>;
  readonly dial?: typeof tcpDial;
  readonly attacks?: () => Promise<AttackReport>;
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
  // The attacks that need an authority before they can be attempted. They are
  // not requests, so they are not rows in the table above.
  const attackWidth = Math.max(
    ...report.attacks.results.map((result) => result.title.length),
    "After the authority is issued".length,
  );
  lines.push(
    "",
    options.color
      ? `${BOLD}After the authority is issued${RESET}`
      : "After the authority is issued",
    "",
  );
  for (const result of report.attacks.results) {
    const mark = result.held ? "✓" : "✗";
    const said = result.refusal ?? "NOTHING REFUSED";
    lines.push(
      `${options.color ? (result.held ? GREEN : RED) : ""}${mark}${options.color ? RESET : ""} ${result.title.padEnd(attackWidth)}  ${result.attempt}`,
    );
    lines.push(`${" ".repeat(attackWidth + 3)}${dim(`${result.expected}: ${said}`)}`);
  }
  lines.push(
    "",
    row(
      "Attacks",
      `${report.attacks.results.filter((result) => result.held).length} of ${report.attacks.attempts} refused; ${report.attacks.executions} authorized execution, which the replay needed`,
    ),
  );
  const holds = report.exit === 0;
  const verdict =
    report.verdict === "BOUNDARY_BROKEN"
      ? "BOUNDARY BROKEN: something adversarial got through under enforcement"
      : !report.attacks.held
        ? "BOUNDARY BROKEN: an authority was reused or an action changed after it was issued"
        : report.containment !== null && !report.containment.noneReachable
          ? "BOUNDARY HOLDS, BUT A TARGET ANSWERS DIRECTLY"
          : "BOUNDARY HOLDS";
  lines.push(
    "",
    row(
      "Caller",
      "the same on every row, and never the reason: the target took every direct request; the boundary decided on the action",
    ),
    row("Verdict", options.color ? `${BOLD}${holds ? GREEN : RED}${verdict}${RESET}` : verdict),
    "",
    dim(
      holds
        ? "Next: agentsafe proxy --upstream <your service> --mode shadow, then --mode enforcement."
        : report.verdict === "BOUNDARY_BROKEN" || !report.attacks.held
          ? "This is a defect in the runtime, not in your service; please report it with agentsafe test --json."
          : "Put the gateway where the agent must pass through it, and the target where only the gateway reaches it.",
    ),
    dim(`✓ ${report.activation.milestone.replace(/_/g, " ")}`),
    "",
  );
  return lines.join("\n");
}

/** What Decionis said about a case, in the words the local report uses for a lane. */
function decionisColumn(result: HostedCaseResult): string {
  const { decionis } = result;
  const answered = decionis.status === null ? "no answer" : String(decionis.status);
  if (!decionis.consequential) {
    return decionis.state === null
      ? `reached ${answered} (not consequential)`
      : `refused ${answered} by the gateway, nothing asked`;
  }
  const would =
    decionis.verdict === null
      ? "no verdict (Decionis could not be asked, or not in time)"
      : `would ${decionis.verdict === "ESCALATE" ? "hold" : decionis.verdict}`;
  return `reached ${answered}, ${would}${decionis.dossier_id === null ? "" : ", dossier"}`;
}

/** The hosted report for a terminal: one row per case, what was decided, the record, the verdict. */
export function renderHostedTestReport(
  report: HostedTestReport,
  options: { readonly color: boolean },
): string {
  const bold = (text: string): string => (options.color ? `${BOLD}${text}${RESET}` : text);
  const dim = (text: string): string => (options.color ? `${DIM}${text}${RESET}` : text);
  const row = (label: string, value: string): string => `${label.padEnd(11)} ${value}`;
  const cells = report.cases.map((result) => [
    result.title,
    directColumn(result as unknown as BoundaryCaseResult),
    decionisColumn(result),
  ]);
  const widths = ["", "direct", "Decionis, in shadow"].map((heading, column) =>
    Math.max(heading.length, ...cells.map((cell) => cell[column]?.length ?? 0)),
  );
  const pad = (text: string, column: number): string => text.padEnd(widths[column] ?? 0);
  const { authority, decided } = report;
  const lines = [
    `${bold("AgentSafe")} ${dim(report.runtime)} boundary test, Decionis deciding`,
    "",
    row("Target", "synthetic loopback service; nothing real is called"),
    row(
      "Authority",
      `Decionis, workspace ${authority.tenant}, shadow${
        authority.provisional ? " (provisional: no account; it decides in shadow only)" : ""
      }; at ${authority.endpoint}`,
    ),
    "",
    `${pad("", 0)}  ${bold(pad("direct", 1))}  ${bold("Decionis, in shadow")}`,
  ];
  report.cases.forEach((result, index) => {
    const [title = "", direct = "", decionis = ""] = cells[index] ?? [];
    const painted =
      !options.color || result.decionis.verdict === null
        ? decionis
        : `${result.decionis.verdict === "ALLOW" ? GREEN : YELLOW}${decionis}${RESET}`;
    lines.push(`${pad(title, 0)}  ${pad(direct, 1)}  ${painted}`);
  });
  const { would } = decided;
  const decidedCount = decided.consequential - would.NONE;
  lines.push(
    "",
    row(
      "Decided",
      `Decionis decided ${String(decidedCount)} of ${String(decided.consequential)} consequential actions: would allow ${String(would.ALLOW)}, hold ${String(would.ESCALATE)}, refuse ${String(would.BLOCK)}`,
    ),
    row(
      "Dossiers",
      report.dossiers.length === 0
        ? "none were left"
        : `${String(report.dossiers.length)} signed record${report.dossiers.length === 1 ? "" : "s"} under this workspace, the first ${report.dossiers[0] ?? ""}`,
    ),
  );
  if (report.signed !== null) {
    const { signed } = report;
    const by =
      signed.keyId === null
        ? "unsigned record"
        : `${signed.algorithm ?? "signed"} by key ${signed.keyId}${signed.issuedAt === null ? "" : ` at ${signed.issuedAt}`}`;
    lines.push(
      row(
        "Signed",
        `${by}, ${String(signed.artifacts)} signed artifact(s); issuer ${signed.issuerTier ?? "not stated"}${
          signed.issuerTier === "provisional_anonymous"
            ? " (a workspace without an account; claim it to keep it)"
            : ""
        }`,
      ),
    );
  } else if (report.signedUnavailable !== null) {
    lines.push(
      row(
        "Signed",
        `not fetched (${report.signedUnavailable}); the records are still there under your key`,
      ),
    );
  }
  const holds = report.exit === 0;
  const verdict =
    report.verdict === "DECIONIS_DECIDED"
      ? "DECIONIS DECIDED"
      : report.verdict === "AUTHORITY_UNREACHABLE"
        ? "AUTHORITY UNREACHABLE: Decionis decided nothing"
        : "PARTLY DECIDED: Decionis could not be asked about every action";
  lines.push(
    "",
    row("Verdict", options.color ? `${BOLD}${holds ? GREEN : RED}${verdict}${RESET}` : verdict),
    "",
    dim(
      holds
        ? `Next: agentsafe proxy --upstream <your service>; this workspace decides in shadow${
            authority.provisional
              ? ", and agentsafe login with a key from your organization enables enforcement."
              : "; --mode enforcement when the shadow report reads right."
          }`
        : "Check agentsafe doctor: the endpoint, the key and the network between them.",
    ),
    dim(
      [...report.milestones, report.activation.milestone]
        .map((milestone) => `✓ ${milestone.replace(/_/g, " ")}`)
        .join("  "),
    ),
    "",
  );
  return lines.join("\n");
}

async function runHosted(
  io: CliProcess,
  json: boolean,
  options: TestOptions,
): Promise<HostedTestReport | null> {
  let hosted: HostedBoundaryTestReport;
  try {
    hosted = await (options.runHosted ?? runHostedBoundaryTest)({
      version: packageVersion(),
      credentials: readCredentials(io),
      env: io.env,
      surface: processSurface(io.env),
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : "TEST_FAILED";
    io.stderr(
      json
        ? `${JSON.stringify({ event: "TEST_REFUSED", reason })}\n`
        : `AgentSafe did not run the hosted boundary test.\n\n${reason}${
            error instanceof HostedTestError && error.code === "NO_LOGIN"
              ? "\n\nRun agentsafe login --provision for a free workspace that decides in shadow, or agentsafe login with a key from your organization."
              : ""
          }\n`,
    );
    io.exit(2);
    return null;
  }
  const exit: 0 | 1 = hosted.verdict === "DECIONIS_DECIDED" ? 0 : 1;
  const report: HostedTestReport = {
    ...hosted,
    exit,
    activation: { milestone: "boundary_tested", at: hosted.at },
  };
  io.stdout(
    json ? `${JSON.stringify(report)}\n` : renderHostedTestReport(report, { color: io.color }),
  );
  io.exit(exit);
  return report;
}

export async function runTest(
  io: CliProcess,
  argv: readonly string[],
  options: TestOptions = {},
): Promise<TestReport | HostedTestReport | null> {
  let json = false;
  let targets: ContainmentTarget[];
  let hosted = false;
  try {
    const parsed = parseArguments(argv, TEST_ARGUMENTS);
    json = parsed.options.get("json") === true;
    hosted = parsed.options.get("hosted") === true;
    targets = parsed.positionals.map(parseTarget);
    if (hosted && targets.length > 0) {
      throw new ArgumentError(
        "VALUE_INVALID",
        "--hosted takes no targets; name them to the local test",
      );
    }
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
  if (hosted) return await runHosted(io, json, options);
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
  const attacks = await (options.attacks ?? runAuthorityAttacks)();
  const exit: 0 | 1 =
    boundary.verdict === "BOUNDARY_HOLDS" &&
    attacks.held &&
    (containment === null || containment.noneReachable)
      ? 0
      : 1;
  const report: TestReport = {
    ...boundary,
    containment,
    attacks,
    exit,
    activation: { milestone: "boundary_tested", at: boundary.at },
  };
  io.stdout(json ? `${JSON.stringify(report)}\n` : renderTestReport(report, { color: io.color }));
  io.exit(exit);
  return report;
}
