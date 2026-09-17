import { GATEWAY_PREFIX, type GatewayStatus } from "../gateway/Gateway.js";
import { parseArguments, ArgumentError } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { explainRefusal, resolveGateway, PROXY_ARGUMENTS } from "./Proxy.js";

const STATUS_TIMEOUT_MS = 3_000;
const MAX_STATUS_BYTES = 64 * 1024;

/**
 * `agentsafe status`: asks a running gateway, at the address the same
 * configuration would bind, what it is doing. Nothing is started.
 */
export async function runStatus(io: CliProcess, argv: readonly string[]): Promise<void> {
  let parsed;
  let listen: { host: string; port: number };
  try {
    parsed = parseArguments(argv, PROXY_ARGUMENTS);
    listen = resolveGateway(io, parsed).config.listen;
  } catch (error) {
    io.stderr(
      explainRefusal(error).replace("refused to start", "cannot resolve where the gateway listens"),
    );
    io.exit(error instanceof ArgumentError ? 2 : 1);
    return;
  }
  const host = listen.host === "0.0.0.0" || listen.host === "::" ? "127.0.0.1" : listen.host;
  const url = `http://${host.includes(":") ? `[${host}]` : host}:${listen.port}${GATEWAY_PREFIX}/status`;
  let status: GatewayStatus;
  try {
    const response = await io.fetch(url, { signal: AbortSignal.timeout(STATUS_TIMEOUT_MS) });
    const text = await response.text();
    if (!response.ok || text.length > MAX_STATUS_BYTES)
      throw new Error(`STATUS_${response.status}`);
    status = JSON.parse(text) as GatewayStatus;
  } catch (error) {
    const code =
      (error as { cause?: { code?: string } }).cause?.code ??
      (error instanceof Error ? error.message : "UNREACHABLE");
    io.stderr(`No gateway answered at ${url} (${code}).\n\nStart one with: agentsafe proxy\n`);
    io.exit(1);
    return;
  }
  if (parsed.options.get("json") === true) {
    io.stdout(`${JSON.stringify(status)}\n`);
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
        `Held          ${status.held}`,
        `Counts        ${counts === "" ? "none yet" : counts}`,
        `Evidence      seq ${status.evidence.seq}`,
        `Status        ${status.status.toUpperCase()}`,
        "",
      ].join("\n"),
    );
  }
  io.exit(0);
}
