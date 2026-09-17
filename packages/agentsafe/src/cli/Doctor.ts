import type { GatewayConfig } from "../gateway/GatewayConfig.js";
import { packageVersion } from "../Version.js";
import { parseArguments, ArgumentError } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { credentialsPath, readCredentials } from "./Credentials.js";
import { explainRefusal, resolveGateway, PROXY_ARGUMENTS } from "./Proxy.js";

export const DOCTOR_ARGUMENTS = {
  valued: [...PROXY_ARGUMENTS.valued],
  flags: [...PROXY_ARGUMENTS.flags, "no-network"],
} as const;

export interface DoctorCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
  /** What to do about it, when it is not ok. */
  readonly remedy: readonly string[];
}

export interface DoctorOptions {
  readonly nodeVersion?: string;
  readonly timeoutMs?: number;
}

const MIN_NODE = [22, 14, 0] as const;
const PROBE_TIMEOUT_MS = 3_000;

function nodeIsRecent(version: string): boolean {
  const parts = version.replace(/^v/, "").split(".").map(Number);
  for (let index = 0; index < MIN_NODE.length; index += 1) {
    const actual = parts[index] ?? 0;
    const required = MIN_NODE[index] ?? 0;
    if (actual > required) return true;
    if (actual < required) return false;
  }
  return true;
}

async function probe(
  fetchImpl: CliProcess["fetch"],
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<{ readonly status: number } | { readonly error: string }> {
  try {
    const response = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    await response.body?.cancel();
    return { status: response.status };
  } catch (error) {
    const cause = (error as { cause?: { code?: string } }).cause?.code;
    return { error: cause ?? (error instanceof Error ? error.name : "UNREACHABLE") };
  }
}

/**
 * `agentsafe doctor`: what would stop the gateway from governing anything,
 * each with what to do about it. Network checks reach the upstream and the
 * authority the configuration names and nothing else; `--no-network` skips
 * them. The credential check sends an empty request the authority refuses
 * as malformed once it has accepted the key, so it mints no decision.
 */
export async function runDoctor(
  io: CliProcess,
  argv: readonly string[],
  options: DoctorOptions = {},
): Promise<readonly DoctorCheck[]> {
  const checks: DoctorCheck[] = [];
  const nodeVersion = options.nodeVersion ?? process.versions.node;
  const timeoutMs = options.timeoutMs ?? PROBE_TIMEOUT_MS;
  const version = packageVersion();
  checks.push({
    name: "AgentSafe binary",
    ok: nodeIsRecent(nodeVersion),
    detail: `${version} on node v${nodeVersion}`,
    remedy: ["Node.js 22.14 or later is required; install a current release."],
  });
  let parsed;
  try {
    parsed = parseArguments(argv, DOCTOR_ARGUMENTS);
  } catch (error) {
    io.stderr(`${error instanceof ArgumentError ? error.message : "ARGUMENTS_INVALID"}\n`);
    io.exit(2);
    return checks;
  }
  const json = parsed.options.get("json") === true;
  const network = parsed.options.get("no-network") !== true;
  let config: GatewayConfig | null = null;
  let env: Readonly<Record<string, string | undefined>> = io.env;
  try {
    const resolved = resolveGateway(io, parsed);
    config = resolved.config;
    env = resolved.env;
    checks.push({
      name: "configuration valid",
      ok: true,
      detail: resolved.configPath ?? "flags and environment; no file",
      remedy: [],
    });
  } catch (error) {
    checks.push({
      name: "configuration valid",
      ok: false,
      detail: explainRefusal(error)
        .replace(/^AgentSafe refused to start\.\n\n/, "")
        .trim(),
      remedy: ["Fix the setting named above; agentsafe config shows where each one comes from."],
    });
  }
  if (config !== null && network) {
    const upstream = await probe(io.fetch, config.upstream.url, { method: "GET" }, timeoutMs);
    checks.push({
      name: "upstream reachable",
      ok: "status" in upstream,
      detail:
        "status" in upstream
          ? `${config.upstream.url} answered ${upstream.status}`
          : `${config.upstream.url}: ${upstream.error}`,
      remedy: ["Nothing answers at the upstream. Start the service, or point --upstream at it."],
    });
    if (config.authority.kind === "LOCAL") {
      checks.push({
        name: "Decionis reachable",
        ok: true,
        detail: "local/demo authority runs in this process; nothing to reach",
        remedy: [],
      });
      checks.push({
        name: "credentials valid",
        ok: true,
        detail: "no key: the local demo authority accepts its own",
        remedy: [],
      });
    } else {
      const health = await probe(
        io.fetch,
        `${config.authority.endpoint}/v1/health`,
        { method: "GET" },
        timeoutMs,
      );
      checks.push({
        name: "Decionis reachable",
        ok: "status" in health && health.status < 500,
        detail:
          "status" in health
            ? `${config.authority.endpoint}/v1/health answered ${health.status}`
            : `${config.authority.endpoint}: ${health.error}`,
        remedy: ["Decionis did not answer. Check DECIONIS_API_URL and the network path to it."],
      });
      const key = env["DECIONIS_API_KEY"] ?? readKeyFile(io, env);
      if (key === null) {
        checks.push({
          name: "credentials valid",
          ok: false,
          detail: "no Decionis key",
          remedy: ["Set DECIONIS_API_KEY, or run: agentsafe login"],
        });
      } else {
        const auth = await probe(
          io.fetch,
          `${config.authority.endpoint}/v1/authority/enforce-and-bind`,
          {
            method: "POST",
            headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
            body: "{}",
          },
          timeoutMs,
        );
        const rejected = "status" in auth && (auth.status === 401 || auth.status === 403);
        const accepted = "status" in auth && (auth.status === 400 || auth.status === 422);
        checks.push({
          name: "credentials valid",
          ok: accepted,
          detail: rejected
            ? "Decionis authentication failed. The configured API key was rejected."
            : accepted
              ? `key accepted by ${config.authority.endpoint}`
              : "status" in auth
                ? `${config.authority.endpoint} answered ${auth.status}`
                : `${config.authority.endpoint}: ${auth.error}`,
          remedy: rejected
            ? [
                `Check DECIONIS_API_KEY${readCredentials(io) === null ? "" : ` (or the login at ${credentialsPath(io)})`}`,
                "or run: agentsafe login",
              ]
            : ["Decionis did not accept the probe; see the status above."],
        });
      }
    }
  } else if (config !== null) {
    checks.push({
      name: "network checks",
      ok: true,
      detail: "skipped (--no-network)",
      remedy: [],
    });
  }
  if (config !== null) {
    checks.push({
      name: "Presence configuration",
      ok: true,
      detail:
        config.escalation.mode === "NONE"
          ? "none: an ESCALATE is held and reported"
          : `${config.escalation.mode}; approver ${config.escalation.approverId}`,
      remedy: [],
    });
    const evidence =
      config.evidence.journalDir !== null
        ? `chained lines and heads under ${config.evidence.journalDir}`
        : config.output.format === "JSON" || config.output.verbose
          ? "chained lines on the terminal"
          : "not written; add evidence.journalDir or --verbose";
    checks.push({
      name: "evidence configuration",
      ok: config.evidence.enabled,
      detail: config.evidence.enabled ? evidence : "disabled by evidence.enabled: false",
      remedy: ["Enable evidence: it is what a decision leaves behind."],
    });
  }
  const failed = checks.filter((check) => !check.ok);
  if (json) {
    io.stdout(`${JSON.stringify({ version, ok: failed.length === 0, checks })}\n`);
  } else {
    const lines = [`AgentSafe doctor ${version}`, ""];
    for (const check of checks) {
      lines.push(`${check.ok ? "✓" : "✗"} ${check.name.padEnd(24)} ${check.detail}`);
      if (!check.ok) for (const remedy of check.remedy) lines.push(`${" ".repeat(27)}${remedy}`);
    }
    lines.push(
      "",
      failed.length === 0 ? "Ready to govern." : `${failed.length} check(s) need attention.`,
      "",
    );
    io.stdout(lines.join("\n"));
  }
  io.exit(failed.length === 0 ? 0 : 1);
  return checks;
}

function readKeyFile(
  io: CliProcess,
  env: Readonly<Record<string, string | undefined>>,
): string | null {
  const path = env["DECIONIS_API_KEY_FILE"];
  if (path === undefined) return null;
  const text = io.files.read(path);
  return text === null ? null : text.trim();
}
