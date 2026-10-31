import { GATEWAY_PREFIX, shortDigest, type GatewayStatus } from "../gateway/Gateway.js";
import {
  enforcementSwitch,
  renderShadowReport,
  type ShadowSummary,
} from "../gateway/ShadowLedger.js";
import type { ActionSpaceStatus } from "../posture/ActionSpaceDrift.js";
import { parseArguments, ArgumentError } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { explainRefusal, resolveGateway, PROXY_ARGUMENTS } from "./Proxy.js";
import {
  describeVerification,
  verifyAcceptance,
  type AcceptanceVerification,
} from "./VerifyAcceptance.js";

const STATUS_TIMEOUT_MS = 3_000;

/** `proxy`'s arguments, and the acceptance report to hold against the running gateway. */
export const STATUS_ARGUMENTS = {
  valued: [...PROXY_ARGUMENTS.valued, "acceptance"],
  flags: [...PROXY_ARGUMENTS.flags],
} as const;
/** Room for the fingerprint's route table: up to 200 routes and a profile's writes, each a path of up to 500 characters. */
const MAX_STATUS_BYTES = 512 * 1024;

/** Where a gateway listening here answers its status; a wildcard listener is asked on loopback. */
export function statusUrl(listen: { readonly host: string; readonly port: number }): string {
  const host = listen.host === "0.0.0.0" || listen.host === "::" ? "127.0.0.1" : listen.host;
  return `http://${host.includes(":") ? `[${host}]` : host}:${listen.port}${GATEWAY_PREFIX}/status`;
}

/** The running gateway's status, or the code of why none answered. Nothing is started. */
export async function readStatus(
  io: CliProcess,
  url: string,
  timeoutMs: number = STATUS_TIMEOUT_MS,
): Promise<{ readonly status: GatewayStatus } | { readonly error: string }> {
  try {
    const response = await io.fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    const text = await response.text();
    if (!response.ok || text.length > MAX_STATUS_BYTES)
      throw new Error(`STATUS_${response.status}`);
    return { status: JSON.parse(text) as GatewayStatus };
  } catch (error) {
    return {
      error:
        (error as { cause?: { code?: string } }).cause?.code ??
        (error instanceof Error ? error.message : "UNREACHABLE"),
    };
  }
}

/**
 * The action space in one line: what the deciding release was checked
 * against, beside what the gateway loaded. An older gateway does not say.
 */
export function describeActionSpace(space: ActionSpaceStatus | undefined): string {
  if (space === undefined) return "not reported by this gateway";
  if (space.state === "UNCHECKED") return "no decision has named its release's action space yet";
  const release = shortDigest(space.release ?? "");
  if (space.state === "MATCH") return `matches the deciding release (${release})`;
  const loaded =
    space.loaded === null ? "an action space no manifest describes" : shortDigest(space.loaded);
  return `DRIFT: the deciding release was checked against ${release}; this gateway loaded ${loaded}`;
}

/**
 * `agentsafe status`: asks a running gateway, at the address the same
 * configuration would bind, what it is doing. Nothing is started.
 */
export async function runStatus(io: CliProcess, argv: readonly string[]): Promise<void> {
  let parsed;
  let listen: { host: string; port: number };
  let enforce: string;
  try {
    parsed = parseArguments(argv, STATUS_ARGUMENTS);
    const { config } = resolveGateway(io, parsed);
    listen = config.listen;
    enforce = enforcementSwitch(config);
  } catch (error) {
    io.stderr(
      explainRefusal(error).replace("refused to start", "cannot resolve where the gateway listens"),
    );
    io.exit(error instanceof ArgumentError ? 2 : 1);
    return;
  }
  const url = statusUrl(listen);
  const answer = await readStatus(io, url);
  if ("error" in answer) {
    io.stderr(
      `No gateway answered at ${url} (${answer.error}).\n\nStart one with: agentsafe proxy\n`,
    );
    io.exit(1);
    return;
  }
  const status = answer.status;
  const acceptance = await acceptanceStanding(io, parsed.options.get("acceptance"), status);
  if (parsed.options.get("json") === true) {
    io.stdout(
      `${JSON.stringify(acceptance === undefined ? status : { ...status, acceptance_report: acceptance })}\n`,
    );
  } else {
    const counts = Object.entries(status.counts)
      .map(([name, value]) => `${name}=${value}`)
      .join(" ");
    io.stdout(
      [
        `AgentSafe ${status.version}`,
        "",
        `Gateway       ${url.replace(`${GATEWAY_PREFIX}/status`, "")}`,
        `Upstream      ${status.upstream}`,
        `Mode          ${status.mode}`,
        `Authority     ${status.authority}`,
        `Failure       ${status.failure_policy === "FAIL_CLOSED" ? "fail-closed" : "fail-open (explicit)"}`,
        `Routes        ${status.routes}`,
        `Surface       ${status.surface ?? "not named; set AGENTSAFE_SURFACE"}`,
        `Held          ${status.held}`,
        `Counts        ${counts === "" ? "none yet" : counts}`,
        `Evidence      seq ${status.evidence.seq}`,
        `Fingerprint   ${status.fingerprint === undefined ? "not reported by this gateway" : shortDigest(status.fingerprint.digest)}`,
        `Action space  ${describeActionSpace(status.action_space)}`,
        ...(acceptance === undefined
          ? []
          : [
              `Acceptance    ${typeof acceptance === "string" ? acceptance : describeVerification(acceptance)}`,
            ]),
        `Status        ${status.status.toUpperCase()}`,
        "",
      ].join("\n"),
    );
    // A gateway in shadow carries its report: what enforcement would have
    // changed so far, and the switch that turns it on. An older gateway
    // answers without the field, which reads as no report, or without the
    // accepted counts, which read as none.
    const answered = status.shadow ?? null;
    if (answered !== null) {
      const shadow: ShadowSummary = {
        ...answered,
        accepted: (answered as Partial<ShadowSummary>).accepted ?? { ESCALATE: 0, BLOCK: 0 },
      };
      io.stdout(
        `\n${renderShadowReport(
          { event: "SHADOW_REPORT", at: new Date().toISOString(), shadow, enforce },
          { color: io.color },
        )}`,
      );
    }
  }
  io.exit(0);
}

/**
 * An acceptance report held against the gateway that answered: checked with
 * the key that gateway serves, and its fingerprint compared with the one it
 * runs. Undefined when none was named; a sentence when it cannot be checked.
 * It is the operator's view of the gateway's own word: a buyer pins the key
 * from `agentsafe identity` and runs `agentsafe verify acceptance` instead.
 */
async function acceptanceStanding(
  io: CliProcess,
  path: string | true | undefined,
  status: GatewayStatus,
): Promise<AcceptanceVerification | string | undefined> {
  if (typeof path !== "string") return undefined;
  const token = io.files.read(path);
  if (token === null) return `cannot read ${path}`;
  const key = status.acceptance?.public_jwk;
  if (key === undefined || key === null) return "this gateway serves no acceptance key";
  if (status.fingerprint === undefined) return "this gateway reports no fingerprint";
  return await verifyAcceptance(token, key, Date.now(), status.fingerprint);
}
