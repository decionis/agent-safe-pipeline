import { createHash } from "node:crypto";
import { z } from "zod";
import { DEFAULT_AUTHORITY_ENDPOINT } from "../gateway/GatewayConfig.js";
import { packageVersion } from "../Version.js";
import { ArgumentError, optionValue, parseArguments, type ParsedArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { readCredentials } from "./Credentials.js";

export const RECORDS_COMMANDS = ["upload"] as const;

const SPEC = {
  valued: ["domain", "kind", "platform", "from", "to", "policy", "total", "endpoint"],
  flags: ["truncated", "json"],
} as const;

/** The limits of Decionis's records intake (decionis.assessments.records/1). */
const FILE_LIMIT = 4_000_000;
const RECORD_LIMIT = 5_000;
const ENDPOINT = /^https:\/\/[^\s/]+$/;
const LOCAL = /^http:\/\/(?:127\.0\.0\.1|localhost)(?::\d{1,5})?$/;

const Options = z.object({
  domain: z.enum(["commerce", "cards", "agents"]),
  kind: z.enum(["transaction", "event", "audit"]),
  platform: z.string().regex(/^[a-z0-9][a-z0-9-]{0,99}$/),
  from: z.string().datetime({ offset: true }),
  to: z.string().datetime({ offset: true }),
  policy: z.string().uuid().optional(),
  total: z.coerce.number().int().min(0).optional(),
});

class UsageError extends Error {}

/**
 * `agentsafe records upload <file.jsonl>`: sends a JSON Lines file of records to Decionis's
 * central policy intake with this machine's Decionis key. Decionis finds the exposures in the
 * records, signs the findings and hands them to the desk, who proposes the policy; nothing
 * changes in any policy here. The same file for the same window is the same assessment, so a
 * repeated upload returns the findings signed the first time.
 *
 * Each line is one record in Decionis's shape for the domain (for commerce: the action with its
 * facts, its time and its money). AgentSafe's own audit log is redacted by design (no action, no
 * facts) and is not such a file.
 */
export async function runRecords(io: CliProcess, argv: readonly string[]): Promise<void> {
  const command = argv[0];
  if (command === undefined || !(RECORDS_COMMANDS as readonly string[]).includes(command)) {
    io.stderr(
      `${JSON.stringify({ event: "RECORDS_COMMAND_REQUIRED", commands: RECORDS_COMMANDS })}\n`,
    );
    io.exit(2);
    return;
  }
  let parsed: ParsedArguments;
  let request: { url: string; body: Record<string, unknown>; key: string };
  try {
    parsed = parseArguments(argv.slice(1), SPEC);
    request = prepare(io, parsed);
  } catch (error) {
    const code =
      error instanceof UsageError
        ? error.message
        : error instanceof ArgumentError
          ? `${error.code}: ${error.option}`
          : "ARGUMENTS_INVALID";
    io.stderr(`${JSON.stringify({ event: "RECORDS_USAGE", command, code })}\n`);
    io.exit(2);
    return;
  }
  let response: Response;
  try {
    response = await io.fetch(request.url, {
      method: "POST",
      redirect: "error",
      headers: {
        authorization: `Bearer ${request.key}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(request.body),
      signal: AbortSignal.timeout(60_000),
    });
  } catch {
    io.stderr(`${JSON.stringify({ event: "RECORDS_UNREACHABLE", url: request.url })}\n`);
    io.exit(1);
    return;
  }
  const text = await response.text();
  let body: Record<string, unknown> = {};
  try {
    const value: unknown = text.length === 0 ? {} : JSON.parse(text);
    if (value !== null && typeof value === "object" && !Array.isArray(value))
      body = value as Record<string, unknown>;
  } catch {
    // An answer that is not JSON is reported by its status alone.
  }
  if (!response.ok) {
    io.stderr(
      `${JSON.stringify({ event: "RECORDS_REFUSED", status: response.status, ...body })}\n`,
    );
    io.exit(1);
    return;
  }
  io.stdout(
    parsed.options.get("json") === true
      ? `${JSON.stringify(body)}\n`
      : summary(body, response.status),
  );
  io.exit(0);
}

function prepare(io: CliProcess, parsed: ParsedArguments) {
  const path = parsed.positionals[0];
  if (path === undefined || parsed.positionals.length > 1) throw new UsageError("FILE_REQUIRED");
  const options = Options.safeParse({
    domain: optionValue(parsed, "domain") ?? "commerce",
    kind: optionValue(parsed, "kind"),
    platform: optionValue(parsed, "platform"),
    from: optionValue(parsed, "from"),
    to: optionValue(parsed, "to"),
    policy: optionValue(parsed, "policy"),
    total: optionValue(parsed, "total"),
  });
  if (!options.success)
    throw new UsageError(
      `${String(options.error.issues[0]?.path[0] ?? "options").toUpperCase()}_INVALID`,
    );
  const { domain, kind, platform, from, to, policy, total } = options.data;
  if (Date.parse(from) >= Date.parse(to)) throw new UsageError("WINDOW_INVALID");
  const content = io.files.read(path);
  if (content === null) throw new UsageError("FILE_UNREADABLE");
  if (content.length > FILE_LIMIT) throw new UsageError("FILE_TOO_LARGE");
  let records = 0;
  for (const line of content.split(/\r?\n/)) {
    if (!line.trim()) continue;
    records += 1;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      throw new UsageError(`LINE_INVALID: ${records}`);
    }
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new UsageError(`LINE_INVALID: ${records}`);
  }
  if (records === 0) throw new UsageError("FILE_EMPTY");
  if (records > RECORD_LIMIT) throw new UsageError("TOO_MANY_RECORDS");
  const stored = readCredentials(io);
  const key = io.env["DECIONIS_API_KEY"] ?? keyFile(io) ?? stored?.apiKey ?? null;
  if (key === null) throw new UsageError("KEY_REQUIRED");
  const endpoint =
    optionValue(parsed, "endpoint") ??
    io.env["DECIONIS_API_URL"] ??
    stored?.endpoint ??
    DEFAULT_AUTHORITY_ENDPOINT;
  if (!ENDPOINT.test(endpoint) && !LOCAL.test(endpoint)) throw new UsageError("ENDPOINT_INVALID");
  const window = { from, to };
  const hex = createHash("sha256")
    .update(JSON.stringify([domain, kind, platform, window, content]))
    .digest("hex");
  const variant = ((parseInt(hex[16]!, 16) & 0x3) | 0x8).toString(16);
  const assessmentId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  const name = path.split("/").at(-1)?.slice(0, 200);
  return {
    key,
    url: `${endpoint}/v1/assessments/${assessmentId}/records`,
    body: {
      version: "decionis.assessments.records/1",
      assessment_id: assessmentId,
      domain,
      kind,
      platform,
      producer: { product: "agentsafe", surface: "cli", version: packageVersion() },
      // The records were read up to the window's end.
      as_of: to,
      window,
      ...(policy === undefined ? {} : { policy_id: policy }),
      total: total ?? null,
      truncated: parsed.options.get("truncated") === true,
      file: { format: "jsonl", ...(name ? { name } : {}), content },
    },
  };
}

function keyFile(io: CliProcess): string | null {
  const path = io.env["DECIONIS_API_KEY_FILE"];
  if (path === undefined) return null;
  return io.files.read(path)?.trim() ?? null;
}

/** What the intake signed, in a few lines: records, findings by type, coverage and what happens next. */
function summary(body: Record<string, unknown>, status: number): string {
  const findings = (body.findings ?? {}) as {
    verification?: string;
    artifact?: {
      findings_id?: string;
      status?: string;
      findings?: { type: string }[];
      coverage?: { gaps?: { code: string }[] };
    };
  };
  const artifact = findings.artifact ?? {};
  const types = new Map<string, number>();
  for (const finding of artifact.findings ?? [])
    types.set(finding.type, (types.get(finding.type) ?? 0) + 1);
  const gaps = (artifact.coverage?.gaps ?? []).map((gap) => gap.code);
  return [
    `${status === 201 ? "Signed" : "Already signed"} findings ${artifact.findings_id ?? ""} (${findings.verification ?? "unknown"}, ${artifact.status ?? "unknown"}).`,
    `Records: ${String(body.received ?? 0)} received, ${String(body.assessed ?? 0)} assessed.`,
    types.size
      ? `Findings: ${[...types.entries()].map(([type, count]) => `${count} ${type}`).join(", ")}.`
      : "Findings: none.",
    ...(gaps.length ? [`Missing history: ${gaps.join(", ")}.`] : []),
    "The Decionis desk proposes the policy from these findings; nothing changed in any policy.",
    "",
  ].join("\n");
}
