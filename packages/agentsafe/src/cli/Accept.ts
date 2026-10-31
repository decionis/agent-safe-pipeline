/**
 * `agentsafe accept --plan <file> --token-file <file> [--tenant-key-file <file>] [--out <file>] [--json]`:
 * an acceptance run, from the agent's zone, against the deployed gateway the
 * plan names
 * ([ADR 0009](../../../../docs/architecture/decisions/0009-acceptance-run-on-named-targets.md)).
 *
 * It sends nothing the plan does not name. The gateway decides, forwards,
 * reads its targets and signs; this side sends the plan's writes, probes the
 * zone's own routes, and hands the gateway its findings, which the report
 * carries as the zone's word. Exit `0` when the gateway signed `ACCEPTED`,
 * `1` when it signed `NOT_ACCEPTED`, `2` when nothing was signed.
 */
import { parse as parseYaml } from "yaml";
import {
  AcceptancePlanError,
  parseAcceptancePlan,
  writeBody,
  withoutTrailingSlashes,
  type AcceptancePlan,
  type PlanWrite,
} from "../acceptance/AcceptancePlan.js";
import { ACCEPTANCE_RUN_HEADER } from "../acceptance/AcceptanceRun.js";
import {
  probeMcp,
  probeMetadata,
  probeOrigin,
  probeProvider,
  scanCredentials,
  type ZoneFindings,
} from "../acceptance/ZoneProbes.js";
import { dial } from "../egress/TcpProbe.js";
import { zoneHttp } from "../egress/ZoneHttpClient.js";
import { GATEWAY_PREFIX } from "../gateway/Gateway.js";
import { TENANT_KEY_HEADER } from "../gateway/GatewayConfig.js";
import { ArgumentError, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const ACCEPT_ARGUMENTS = {
  valued: ["plan", "token-file", "tenant-key-file", "out", "timeout-ms"],
  flags: ["json"],
} as const;

/** Where the report goes unless `--out` says otherwise. */
export const DEFAULT_REPORT_FILE = "acceptance.jws";

const TOKEN_FILE_VARIABLE = "AGENTSAFE_ACCEPTANCE_TOKEN_FILE";
const DEFAULT_TIMEOUT_MS = 10_000;
/** The close waits for reads after refusals and the outage case: room for both. */
const CLOSE_TIMEOUT_MS = 120_000;

/** One step of the run, as the person running it sees it. */
interface Step {
  readonly case: string;
  readonly name: string;
  readonly outcome: string;
}

export async function runAccept(io: CliProcess, argv: readonly string[]): Promise<void> {
  const refuse = (event: string, detail?: string): void => {
    io.stderr(`${JSON.stringify(detail === undefined ? { event } : { event, detail })}\n`);
    io.exit(2);
  };
  let parsed;
  try {
    parsed = parseArguments(argv, ACCEPT_ARGUMENTS);
  } catch (error) {
    if (!(error instanceof ArgumentError)) throw error;
    return refuse("ARGUMENT_INVALID", error.message);
  }
  const option = (name: string): string | null => {
    const value = parsed.options.get(name);
    return typeof value === "string" ? value : null;
  };
  const planPath = option("plan");
  if (planPath === null) return refuse("ACCEPTANCE_PLAN_REQUIRED");
  const planText = io.files.read(planPath);
  if (planText === null) return refuse("ACCEPTANCE_PLAN_UNREADABLE", planPath);
  let plan: AcceptancePlan;
  try {
    plan = parseAcceptancePlan(parseYaml(planText) as unknown);
  } catch (error) {
    return refuse(
      "ACCEPTANCE_PLAN_INVALID",
      error instanceof AcceptancePlanError ? error.detail : "not YAML",
    );
  }
  const tokenPath = option("token-file") ?? io.env[TOKEN_FILE_VARIABLE] ?? null;
  const token = tokenPath === null ? null : (io.files.read(tokenPath)?.trim() ?? null);
  if (tokenPath === null || token === null || token === "") {
    return refuse("ACCEPTANCE_TOKEN_REQUIRED");
  }
  const tenantKeyPath = option("tenant-key-file");
  const tenantKey = tenantKeyPath === null ? null : (io.files.read(tenantKeyPath)?.trim() ?? null);
  if (tenantKeyPath !== null && (tenantKey === null || tenantKey === "")) {
    return refuse("TENANT_KEY_UNREADABLE");
  }
  const timeoutMs = Number(option("timeout-ms") ?? DEFAULT_TIMEOUT_MS);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
    return refuse("ARGUMENT_INVALID", "timeout-ms");
  }
  const out = option("out") ?? DEFAULT_REPORT_FILE;
  const json = parsed.options.get("json") === true;
  const gateway = withoutTrailingSlashes(plan.gateway);
  const tenant: Record<string, string> =
    tenantKey === null ? {} : { [TENANT_KEY_HEADER]: tenantKey };

  /** One call to the gateway's acceptance endpoints: its status and JSON body, or why there is none. */
  const call = async (
    name: "runs" | "decisions" | "close",
    body: unknown,
    limit: number = timeoutMs,
  ): Promise<{ readonly status: number; readonly body: Record<string, unknown> } | string> => {
    try {
      const response = await io.fetch(`${gateway}${GATEWAY_PREFIX}/v1/acceptance/${name}`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(limit),
      });
      return { status: response.status, body: (await response.json()) as Record<string, unknown> };
    } catch (error) {
      return (
        (error as { cause?: { code?: string } }).cause?.code ??
        (error instanceof Error ? error.name : "UNREACHABLE")
      );
    }
  };

  const opened = await call("runs", plan);
  if (typeof opened === "string" || opened.status !== 201) {
    return refuse(
      "ACCEPTANCE_RUN_NOT_OPENED",
      typeof opened === "string"
        ? opened
        : `${opened.status} ${String(opened.body["code"] ?? "")} ${String(opened.body["detail"] ?? "")}`.trim(),
    );
  }
  const runId = String(opened.body["run_id"]);
  const steps: Step[] = [];

  /** A write the plan names, through the gateway, tagged as this run's. */
  const send = async (write: PlanWrite): Promise<string> => {
    const body = writeBody(write);
    try {
      const response = await io.fetch(`${gateway}${write.path}`, {
        method: write.method,
        headers: {
          ...tenant,
          ...(body.length === 0 ? {} : { "content-type": "application/json" }),
          [ACCEPTANCE_RUN_HEADER]: `${runId}:${write.name}`,
        },
        ...(body.length === 0 ? {} : { body: new Uint8Array(body) }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      await response.arrayBuffer();
      return `${response.status} ${response.headers.get("agentsafe-execution") ?? ""}`.trim();
    } catch (error) {
      return (error as { cause?: { code?: string } }).cause?.code ?? "UNREACHABLE";
    }
  };

  for (const write of plan.prohibited) {
    const decided = await call("decisions", { run_id: runId, write: write.name });
    const verdict =
      typeof decided === "string"
        ? decided
        : String(decided.body["verdict"] ?? decided.body["code"]);
    // Sent only after the authority refused it in shadow; the gateway refuses it otherwise too.
    const sent = verdict === "BLOCK" || verdict === "ESCALATE" ? await send(write) : "not sent";
    steps.push({ case: "prohibited", name: write.name, outcome: `shadow ${verdict}, ${sent}` });
  }
  for (const write of plan.permitted) {
    steps.push({ case: "permitted", name: write.name, outcome: await send(write) });
  }

  const probes = { dial, http: zoneHttp, timeoutMs };
  const origins = [];
  for (const origin of plan.origins) {
    origins.push(await probeOrigin(origin, { ...probes, gateway, gatewayHeaders: tenant }));
  }
  const providers = [];
  for (const provider of plan.providers) {
    providers.push(
      await probeProvider(
        {
          name: provider.name,
          url: provider.url,
          write: {
            method: provider.write.method,
            path: provider.write.path,
            body: provider.write.body === undefined ? null : JSON.stringify(provider.write.body),
          },
        },
        probes,
      ),
    );
  }
  const zone: ZoneFindings = {
    origins,
    providers,
    mcp: await probeMcp(plan.mcp, { dial, timeoutMs }),
    credentials: scanCredentials({
      env: io.env,
      home: io.home,
      own: [TOKEN_FILE_VARIABLE, `$${TOKEN_FILE_VARIABLE}`],
    }),
    metadata: plan.metadata ? await probeMetadata(probes) : null,
  };
  for (const finding of [...zone.origins, ...zone.providers, ...zone.mcp]) {
    steps.push({ case: "zone", name: finding.name, outcome: finding.verdict });
  }
  if (zone.metadata !== null) {
    steps.push({ case: "zone", name: "metadata", outcome: zone.metadata.verdict });
  }

  const closed = await call("close", { run_id: runId, zone }, CLOSE_TIMEOUT_MS);
  if (typeof closed === "string" || closed.status !== 200) {
    return refuse(
      "ACCEPTANCE_REPORT_NOT_SIGNED",
      typeof closed === "string" ? closed : `${closed.status} ${String(closed.body["code"] ?? "")}`,
    );
  }
  const report = String(closed.body["report"]);
  const verdict = String(closed.body["verdict"]);
  io.files.write(out, `${report}\n`);
  const failures = failuresOf(report);
  if (json) {
    io.stdout(`${JSON.stringify({ verdict, report: out, steps, failures })}\n`);
  } else {
    io.stdout(
      [
        `AgentSafe acceptance run against ${gateway}`,
        "",
        ...steps.map((step) => `  ${step.case.padEnd(11)} ${step.name.padEnd(28)} ${step.outcome}`),
        "",
        `Report       ${verdict}, signed by the gateway, written to ${out}`,
        ...failures.map((failure) => `  failed     ${failure}`),
        "",
        "Verify it with the key `agentsafe identity --json` prints on the gateway:",
        `  agentsafe verify acceptance ${out} --key acceptance-key.json`,
        "",
      ].join("\n"),
    );
  }
  io.exit(verdict === "ACCEPTED" ? 0 : 1);
}

/** The failing cases a report names, read for display only: `verify acceptance` checks it. */
function failuresOf(token: string): readonly string[] {
  try {
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as {
      failures?: { case: string; name: string; code: string }[];
    };
    return (payload.failures ?? []).map(
      (failure) => `${failure.case} ${failure.name}: ${failure.code}`,
    );
  } catch {
    return [];
  }
}
