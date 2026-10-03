/**
 * `agentsafe edge <command>`: the edge evaluator's operator commands, all
 * offline except `usage-report --send` and `usage-key --register`.
 *
 *   usage-report         Count a month's edge decisions from a collected log and sign the report
 *   verify-usage-report  Check a report's signature and recount it from the log
 *   usage-key            Print the usage-report key's kid and public JWK; `--register` registers it
 *   replay-schema        Print the DDL for the shared Postgres replay store
 *
 * Exit 0 when the command did its job, 1 when a count or a check failed,
 * 2 when it could not run: an option it does not know, or a file it needs
 * that is not there.
 */
import { PostgresReplayStore } from "@decionis/agent-safe-pipeline";
import { EVIDENCE_STREAM } from "../audit/HashChainedAuditSink.js";
import { countUsage, verifyUsage } from "../edge/UsageCount.js";
import { usagePeriod } from "../edge/UsagePeriod.js";
import {
  claimedUsage,
  readUsageReport,
  signUsageReport,
  usageReportClaims,
  usageSigningKey,
  type UsageSigningKey,
} from "../edge/UsageReport.js";
import { registerUsageKey } from "../edge/UsageKeyRegistration.js";
import { UrlUsageDelivery } from "../edge/UsageMeter.js";
import { ArgumentError, optionValue, parseArguments, type ParsedArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";

export const EDGE_COMMANDS = [
  "usage-report",
  "verify-usage-report",
  "usage-key",
  "replay-schema",
] as const;

const SPECS = {
  "usage-report": {
    valued: ["period", "log", "head", "installation", "org", "key", "key-id", "out", "stream"],
    flags: ["send"],
  },
  "verify-usage-report": { valued: ["log", "public-jwk", "key"], flags: [] },
  "usage-key": { valued: ["key", "key-id", "installation"], flags: ["register"] },
  "replay-schema": { valued: ["table"], flags: [] },
} as const;

class UsageError extends Error {}

function lines(text: string): string[] {
  return text.replace(/\n$/, "").split("\n");
}

/** A file the command cannot do without, or a usage error naming it. */
function required(io: CliProcess, path: string | undefined, what: string): string {
  if (path === undefined) throw new UsageError(`${what.toUpperCase()}_REQUIRED`);
  const text = io.files.read(path);
  if (text === null) throw new UsageError(`${what.toUpperCase()}_UNREADABLE`);
  return text;
}

/** The usage-report key: `--key`, or the executor's own variable (or its `_FILE`). */
function signingKey(io: CliProcess, parsed: ParsedArguments): UsageSigningKey {
  const file = optionValue(parsed, "key") ?? io.env["EXECUTOR_EDGE_USAGE_SIGNING_KEY_FILE"];
  const pem =
    file === undefined ? io.env["EXECUTOR_EDGE_USAGE_SIGNING_KEY"] : required(io, file, "key");
  if (pem === undefined) throw new UsageError("KEY_REQUIRED");
  try {
    return usageSigningKey(
      pem,
      optionValue(parsed, "key-id") ?? io.env["EXECUTOR_EDGE_USAGE_KEY_ID"] ?? null,
    );
  } catch {
    throw new UsageError("KEY_INVALID");
  }
}

/**
 * The installation the report is for: `--installation`, the configured id,
 * or the id the executor generated and kept beside its tally.
 */
function installation(io: CliProcess, parsed: ParsedArguments): string {
  const named = optionValue(parsed, "installation") ?? io.env["EXECUTOR_EDGE_INSTALLATION_ID"];
  if (named !== undefined) return named;
  const journal = io.env["EXECUTOR_JOURNAL_DIR"];
  const state = journal === undefined ? null : io.files.read(`${journal}/edge/usage.json`);
  try {
    const id = (JSON.parse(state ?? "null") as { installation_id?: unknown } | null)
      ?.installation_id;
    if (typeof id === "string") return id;
  } catch {
    // An unreadable tally names no installation.
  }
  throw new UsageError("INSTALLATION_REQUIRED");
}

/** Where Decionis is and the key to call it with: `DECIONIS_API_URL`, `DECIONIS_API_KEY(_FILE)`. */
function decionis(io: CliProcess): { baseUrl: string; apiKey: string } {
  const baseUrl = io.env["DECIONIS_API_URL"];
  const apiKeyFile = io.env["DECIONIS_API_KEY_FILE"];
  const apiKey =
    apiKeyFile === undefined ? io.env["DECIONIS_API_KEY"] : io.files.read(apiKeyFile)?.trim();
  if (baseUrl === undefined || apiKey === undefined) throw new UsageError("DECIONIS_REQUIRED");
  return { baseUrl, apiKey };
}

async function usageReport(io: CliProcess, parsed: ParsedArguments): Promise<number> {
  const period = usagePeriod(optionValue(parsed, "period") ?? "");
  if (period === null) throw new UsageError("PERIOD_REQUIRED");
  const org = optionValue(parsed, "org") ?? io.env["EXECUTOR_EDGE_ORG_ID"];
  if (org === undefined) throw new UsageError("ORG_REQUIRED");
  const log = required(io, optionValue(parsed, "log"), "log");
  const key = signingKey(io, parsed);
  const issuer = installation(io, parsed);
  const stream = optionValue(parsed, "stream") ?? EVIDENCE_STREAM;
  const head = optionValue(parsed, "head");
  const count = countUsage(lines(log), {
    stream,
    period,
    ...(head === undefined ? {} : { head }),
  });
  if (!count.ok) {
    io.stderr(`${JSON.stringify({ event: "USAGE_COUNT_FAILED", findings: count.findings })}\n`);
    return 1;
  }
  const claims = usageReportClaims({
    installationId: issuer,
    orgId: org,
    period,
    usage: count.usage,
    stream,
    now: Date.now(),
  });
  const report = await signUsageReport(claims, key);
  const out = optionValue(parsed, "out");
  if (out === undefined) io.stdout(`${report}\n`);
  else io.files.write(out, `${report}\n`, 0o600);
  io.stderr(
    `${JSON.stringify({ event: "USAGE_REPORT_SIGNED", kid: key.kid, period: claims.period, counts: claims.counts, delegated: claims.delegated, chain: claims.chain })}\n`,
  );
  if (parsed.options.get("send") !== true) return 0;
  const { baseUrl, apiKey } = decionis(io);
  const code = await new UrlUsageDelivery({
    baseUrl,
    apiKey: () => apiKey,
    fetch: io.fetch,
  }).deliver(claims.period, issuer, report);
  io.stderr(`${JSON.stringify({ event: "USAGE_REPORT_SENT", result: code })}\n`);
  return code === "DELIVERED" ? 0 : 1;
}

async function verifyUsageReport(io: CliProcess, parsed: ParsedArguments): Promise<number> {
  const token = required(io, parsed.positionals[0], "report").trim();
  const log = required(io, optionValue(parsed, "log"), "log");
  const jwkFile = optionValue(parsed, "public-jwk");
  let jwk: Record<string, unknown>;
  if (jwkFile === undefined) {
    jwk = { ...signingKey(io, parsed).publicJwk };
  } else {
    try {
      jwk = JSON.parse(required(io, jwkFile, "public-jwk")) as Record<string, unknown>;
    } catch (error) {
      if (error instanceof UsageError) throw error;
      throw new UsageError("PUBLIC_JWK_INVALID");
    }
  }
  const read = await readUsageReport(token, jwk);
  if (!read.ok) {
    io.stdout(`${JSON.stringify({ ok: false, code: read.code })}\n`);
    return 1;
  }
  const period = usagePeriod(read.claims.period);
  const recount = verifyUsage(
    lines(log),
    claimedUsage(read.claims),
    period as NonNullable<typeof period>,
  );
  io.stdout(
    `${JSON.stringify({ ok: recount.ok, kid: read.kid, iss: read.claims.iss, aud: read.claims.aud, period: read.claims.period, findings: recount.findings, recounted: recount.usage })}\n`,
  );
  return recount.ok ? 0 : 1;
}

async function usageKey(io: CliProcess, parsed: ParsedArguments): Promise<number> {
  const key = signingKey(io, parsed);
  const register = parsed.options.get("register") === true;
  let issuer: string;
  try {
    issuer = installation(io, parsed);
  } catch (error) {
    // Printing works before the installation has an id; registering does not.
    if (register) throw error;
    issuer = "<installation id>";
  }
  const registration = {
    kid: key.kid,
    issuer,
    algorithm: "EdDSA",
    public_jwk: key.publicJwk,
    purpose: "usage_report",
  };
  if (!register) {
    // The body for POST /v1/execution/provider-keys; `issuer` is the installation id.
    io.stdout(`${JSON.stringify({ kid: key.kid, public_jwk: key.publicJwk, registration })}\n`);
    return 0;
  }
  const { baseUrl, apiKey } = decionis(io);
  const outcome = await registerUsageKey({
    baseUrl,
    apiKey,
    fetch: io.fetch,
    key,
    installationId: issuer,
  });
  io.stdout(
    `${JSON.stringify({ event: "USAGE_KEY_REGISTRATION", kid: key.kid, installation: issuer, ...outcome })}\n`,
  );
  return outcome.result === "REGISTERED" ? 0 : 1;
}

function replaySchema(io: CliProcess, parsed: ParsedArguments): number {
  let schema: string;
  try {
    schema = PostgresReplayStore.schema(optionValue(parsed, "table"));
  } catch {
    throw new UsageError("TABLE_INVALID");
  }
  io.stdout(schema);
  return 0;
}

export async function runEdge(io: CliProcess, argv: readonly string[]): Promise<void> {
  const command = argv[0];
  if (command === undefined || !(EDGE_COMMANDS as readonly string[]).includes(command)) {
    io.stderr(`${JSON.stringify({ event: "EDGE_COMMAND_REQUIRED", commands: EDGE_COMMANDS })}\n`);
    io.exit(2);
    return;
  }
  const name = command as (typeof EDGE_COMMANDS)[number];
  let exit: number;
  try {
    const parsed = parseArguments(argv.slice(1), SPECS[name]);
    switch (name) {
      case "usage-report":
        exit = await usageReport(io, parsed);
        break;
      case "verify-usage-report":
        exit = await verifyUsageReport(io, parsed);
        break;
      case "usage-key":
        exit = await usageKey(io, parsed);
        break;
      case "replay-schema":
        exit = replaySchema(io, parsed);
        break;
    }
  } catch (error) {
    if (!(error instanceof UsageError || error instanceof ArgumentError)) throw error;
    io.stderr(`${JSON.stringify({ event: "EDGE_USAGE_ERROR", code: error.message })}\n`);
    exit = 2;
  }
  io.exit(exit);
}
