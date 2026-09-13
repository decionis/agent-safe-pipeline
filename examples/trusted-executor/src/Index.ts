/**
 * The trusted executor as a process, proved offline.
 *
 * Starts the loopback Decionis double from the package's testing entry and a
 * loopback stand-in for a downstream provider, then runs this example's
 * executor twice over real HTTP: in shadow, where nothing executes, and in
 * enforcement, where one ALLOW is one dispatch. Every expectation is
 * asserted, so the run is a self-checking proof: the process exits 0 only
 * when every refusal held, every legitimate path executed exactly once, a
 * lost provider response was reconciled without a second send, and no
 * credential, token, or key reached a response or an audit line.
 *
 * All identities are synthetic; the tokens are generated at run time.
 */
import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import process from "node:process";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { CONFIG_KEYS, ExecutorConfigLoader } from "./Config.js";
import { FORWARD_REQUEST_ACTION } from "./Handlers.js";
import { ExecutorHttpServer, MAX_BODY_BYTES, RESPONSE_HEADERS } from "./Http.js";
import { TrustedExecutorService } from "./Service.js";

const LOOPBACK_ORIGIN = "http://127.0.0.1";
const TENANT_ID = "00000000-0000-4000-8000-000000000007";
const callerToken = randomBytes(24).toString("base64url");
const downstreamCredential = `Bearer ${randomBytes(24).toString("base64url")}`;

const out = (line: string): void => {
  process.stdout.write(`${line}\n`);
};
let failures = 0;
const check = (passed: boolean, name: string, detail: string): void => {
  if (!passed) failures += 1;
  out(`  ${passed ? "ok  " : "FAIL"} ${name.padEnd(46)} ${detail}`);
};
const heading = (text: string): void => {
  out("");
  out(text);
  out("-".repeat(text.length));
};

/**
 * A downstream provider with the two properties that matter: it deduplicates
 * on the idempotency key, and it can lose a response after taking effect.
 */
class ProviderDouble {
  public readonly effects = new Set<string>();
  public readonly requests: {
    readonly path: string;
    readonly headers: IncomingMessage["headers"];
  }[] = [];
  private loseNextResponse = false;
  private server: Server | null = null;
  private port = 0;

  public get baseUrl(): string {
    return `${LOOPBACK_ORIGIN}:${this.port}`;
  }

  public loseNext(): void {
    this.loseNextResponse = true;
  }

  public async start(): Promise<void> {
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        const path = request.url ?? "/";
        this.requests.push({ path, headers: request.headers });
        const reply = (status: number, body: unknown): void => {
          response.writeHead(status, { "content-type": "application/json" });
          response.end(JSON.stringify(body));
        };
        if (request.method === "POST" && path === "/dispatches") {
          const key = String(request.headers["idempotency-key"] ?? "");
          if (this.effects.has(key)) return reply(200, { duplicate: true });
          this.effects.add(key);
          if (this.loseNextResponse) {
            this.loseNextResponse = false;
            request.socket.destroy();
            return;
          }
          return reply(202, { accepted: true });
        }
        if (request.method === "GET" && path.startsWith("/dispatches/")) {
          const key = decodeURIComponent(path.slice("/dispatches/".length));
          return this.effects.has(key) ? reply(200, { effected: true }) : reply(404, {});
        }
        reply(404, {});
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    this.port = typeof address === "object" && address !== null ? address.port : 0;
    this.server = server;
  }

  public async stop(): Promise<void> {
    const server = this.server;
    if (server === null) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const authority = new LocalAuthority();
const provider = new ProviderDouble();
await authority.start();
await provider.start();

/** The executor's environment, as a deployment would mount it. */
function environment(mode: "SHADOW" | "ENFORCEMENT"): Record<string, string> {
  return {
    EXECUTOR_MODE: mode,
    EXECUTOR_BIND_ADDRESS: "127.0.0.1",
    PORT: "1",
    EXECUTOR_TENANT_ID: TENANT_ID,
    EXECUTOR_ACTOR_ID: "synthetic-payout-agent",
    EXECUTOR_ACTOR_TYPE: "AI_AGENT",
    EXECUTOR_ACTOR_RUNTIME: "trusted-executor-proof",
    EXECUTOR_CALLER_TOKEN: callerToken,
    DECIONIS_API_URL: authority.baseUrl,
    DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
    DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    DOWNSTREAM_URL: `${provider.baseUrl}/dispatches`,
    DOWNSTREAM_LOOKUP_URL: `${provider.baseUrl}/dispatches/{idempotency_key}`,
    DOWNSTREAM_SYSTEM: "synthetic-payout-rail",
    DOWNSTREAM_OPERATION: "create_payout",
    DOWNSTREAM_ENVIRONMENT: "local",
    DOWNSTREAM_CREDENTIAL: downstreamCredential,
    DOWNSTREAM_CREDENTIAL_HEADER: "Authorization",
    DOWNSTREAM_TIMEOUT_MS: "2000",
  };
}

const auditLines: string[] = [];
const responses: string[] = [];

interface RunningExecutor {
  readonly baseUrl: string;
  readonly server: ExecutorHttpServer;
}

async function startExecutor(mode: "SHADOW" | "ENFORCEMENT"): Promise<RunningExecutor> {
  const config = ExecutorConfigLoader.load(environment(mode));
  const service = TrustedExecutorService.create(config, {
    emit: (line) => auditLines.push(line),
  });
  const server = new ExecutorHttpServer(service, config.callerToken);
  const address = await server.listen(0, "127.0.0.1");
  return { baseUrl: `${LOOPBACK_ORIGIN}:${address.port}`, server };
}

interface Reply {
  readonly status: number;
  readonly headers: Headers;
  readonly body: Record<string, unknown>;
}

async function call(
  executor: RunningExecutor,
  path: string,
  init: { readonly method?: string; readonly body?: string; readonly token?: string | null },
): Promise<Reply> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const token = init.token === undefined ? callerToken : init.token;
  if (token !== null) headers["authorization"] = `Bearer ${token}`;
  const response = await fetch(`${executor.baseUrl}${path}`, {
    method: init.method ?? "POST",
    headers,
    ...(init.body === undefined ? {} : { body: init.body }),
  });
  const text = await response.text();
  responses.push(text);
  return { status: response.status, headers: response.headers, body: JSON.parse(text) };
}

let sequence = 0;
/** The idempotency key of the most recent proposal, as the caller derived it. */
let lastKey = "";
function proposal(amountMinor: number, overrides: Record<string, unknown> = {}): string {
  sequence += 1;
  lastKey = `payout-${sequence}-v1`;
  return JSON.stringify({
    proposal: {
      action: FORWARD_REQUEST_ACTION,
      target: `payout:synthetic-beneficiary-${sequence}`,
      parameters: { amountMinor, currency: "USD", reference: `synthetic-payout-${sequence}` },
    },
    idempotency_key: lastKey,
    correlation_id: `synthetic-run-${sequence}`,
    ...overrides,
  });
}

const refusal = (env: Record<string, string>): string => {
  try {
    ExecutorConfigLoader.load(env);
    return "";
  } catch (error) {
    return error instanceof Error ? error.message : "unknown";
  }
};

heading("Refusals to start");
{
  const missingKey = { ...environment("ENFORCEMENT") };
  delete missingKey["DECIONIS_API_KEY"];
  const reason = refusal(missingKey);
  check(
    reason.includes("DECIONIS_API_KEY") && !reason.includes(callerToken),
    "a missing secret names the variable only",
    reason,
  );
  const production = { ...environment("ENFORCEMENT"), NODE_ENV: "production" };
  check(
    refusal(production).includes("DECIONIS_ALLOW_INSECURE_LOOPBACK"),
    "plain HTTP is refused in production",
    refusal(production),
  );
  const insecure = { ...environment("ENFORCEMENT") };
  delete insecure["DECIONIS_ALLOW_INSECURE_LOOPBACK"];
  check(
    refusal(insecure).includes("https required"),
    "plain HTTP is refused unless asked for",
    refusal(insecure),
  );
  const ambiguous = { ...environment("ENFORCEMENT"), DECIONIS_API_KEY_FILE: "/dev/null" };
  check(
    refusal(ambiguous).includes("CONFIG_SECRET_AMBIGUOUS"),
    "a secret given twice is refused",
    refusal(ambiguous),
  );
  const listed = Object.keys(environment("ENFORCEMENT")).every((key) =>
    (CONFIG_KEYS as readonly string[]).includes(key),
  );
  check(listed, "every variable the proof sets is in CONFIG_KEYS", `${CONFIG_KEYS.length} keys`);
}

heading("Shadow: observe, record, never execute");
{
  const executor = await startExecutor("SHADOW");
  const ready = await call(executor, "/ready", { method: "GET", token: null });
  check(
    ready.status === 200 && ready.body["mode"] === "SHADOW",
    "the process reports its mode",
    JSON.stringify(ready.body),
  );
  const allowed = await call(executor, "/v1/actions", { body: proposal(5_000) });
  check(
    allowed.status === 200 &&
      allowed.body["mode"] === "SHADOW" &&
      allowed.body["verdict"] === "ALLOW" &&
      allowed.body["outcome"] === "OBSERVED" &&
      allowed.body["executed"] === false &&
      allowed.body["authorization"] === null,
    "an ALLOW is observed, not executed",
    `verdict ${String(allowed.body["verdict"])}, executed ${String(allowed.body["executed"])}`,
  );
  const blocked = await call(executor, "/v1/actions", { body: proposal(500_000) });
  check(
    blocked.body["verdict"] === "BLOCK" && blocked.body["executed"] === false,
    "a BLOCK is observed",
    `verdict ${String(blocked.body["verdict"])}`,
  );
  check(
    provider.requests.length === 0,
    "the provider saw nothing",
    `${provider.requests.length} requests`,
  );
  check(
    authority.grants.size === 0,
    "the authority issued no grant",
    `${authority.grants.size} grants`,
  );
  const observational = auditLines.filter(
    (line) => line.includes('"SHADOW_EVALUATED"') && line.includes('"OBSERVATIONAL"'),
  );
  check(
    observational.length === 2,
    "each observation is an OBSERVATIONAL audit event",
    `${observational.length} events`,
  );
  await executor.server.close();
}

heading("Enforcement: one ALLOW, one dispatch");
const executor = await startExecutor("ENFORCEMENT");
{
  const allowed = await call(executor, "/v1/actions", { body: proposal(5_000) });
  const allowedKey = lastKey;
  const authorization = allowed.body["authorization"] as Record<string, unknown> | null;
  check(
    allowed.status === 200 &&
      allowed.body["outcome"] === "COMPLETED" &&
      allowed.body["executed"] === true &&
      typeof authorization?.["grant_id"] === "string" &&
      allowed.body["finalization"] === "RECORDED",
    "an ALLOW executes once on a claimed grant",
    `outcome ${String(allowed.body["outcome"])}, finalization ${String(allowed.body["finalization"])}`,
  );
  const dispatch = provider.requests[0];
  check(
    provider.requests.length === 1 &&
      dispatch?.headers["idempotency-key"] === allowedKey &&
      dispatch.headers["authorization"] === downstreamCredential &&
      dispatch.headers["x-agent-safe-intent-hash"] === allowed.body["intent_hash"],
    "the provider received the credential and the intent-bound key",
    `${provider.requests.length} request`,
  );
  check(
    allowed.headers.get("content-security-policy") ===
      RESPONSE_HEADERS["content-security-policy"] &&
      allowed.headers.get("x-content-type-options") === "nosniff",
    "a success carries the protective headers",
    String(allowed.headers.get("content-security-policy")),
  );
}
{
  const before = provider.requests.length;
  const escalated = await call(executor, "/v1/actions", { body: proposal(50_000) });
  check(
    escalated.body["verdict"] === "ESCALATE" &&
      escalated.body["executed"] === false &&
      escalated.body["authorization"] === null &&
      provider.requests.length === before,
    "an ESCALATE is the hold itself: no grant, no dispatch",
    `verdict ${String(escalated.body["verdict"])}, outcome ${String(escalated.body["outcome"])}`,
  );
  const blocked = await call(executor, "/v1/actions", { body: proposal(500_000) });
  check(
    blocked.body["verdict"] === "BLOCK" &&
      blocked.body["executed"] === false &&
      provider.requests.length === before,
    "a BLOCK dispatches nothing",
    `verdict ${String(blocked.body["verdict"])}`,
  );
}

heading("Refusals at the door");
{
  const authorityBefore = authority.requests.length;
  const providerBefore = provider.requests.length;
  const trusted = await call(executor, "/v1/actions", {
    body: proposal(5_000, { tenant_id: TENANT_ID }),
  });
  check(
    trusted.status === 400 && trusted.body["code"] === "REQUEST_INVALID",
    "a proposal carrying trusted fields is refused",
    `${trusted.status} ${String(trusted.body["code"])}`,
  );
  const unregistered = await call(executor, "/v1/actions", {
    body: proposal(5_000).replace(FORWARD_REQUEST_ACTION, "delete_everything"),
  });
  check(
    unregistered.status === 422 && authority.requests.length === authorityBefore,
    "an unregistered action never reaches the authority",
    `${unregistered.status} ${String(unregistered.body["code"])}`,
  );
  const anonymous = await call(executor, "/v1/actions", { body: proposal(5_000), token: null });
  const wrong = await call(executor, "/v1/actions", { body: proposal(5_000), token: "not-it" });
  check(
    anonymous.status === 401 &&
      wrong.status === 401 &&
      anonymous.headers.get("content-security-policy") ===
        RESPONSE_HEADERS["content-security-policy"],
    "a caller without the token is refused, with the same headers",
    `${anonymous.status}, ${wrong.status}`,
  );
  const oversized = await call(executor, "/v1/actions", {
    body: proposal(5_000, { note: "x".repeat(MAX_BODY_BYTES) }),
  });
  const malformed = await call(executor, "/v1/actions", { body: "{not json" });
  check(
    oversized.status === 413 &&
      malformed.status === 400 &&
      Object.keys(malformed.body).join() === "code",
    "an oversized or malformed body is refused without an echo",
    `${oversized.status}, ${malformed.status} ${String(malformed.body["code"])}`,
  );
  const missing = await call(executor, "/v1/nothing", { method: "GET", token: null });
  check(
    missing.status === 404 &&
      missing.headers.get("x-frame-options") === "DENY" &&
      provider.requests.length === providerBefore,
    "an unknown route is refused with the same headers",
    `${missing.status}`,
  );
}

heading("A lost response is reconciled, never re-sent");
{
  provider.loseNext();
  const effectsBefore = provider.effects.size;
  const lost = await call(executor, "/v1/actions", { body: proposal(5_000) });
  const lostKey = lastKey;
  const recovery = lost.body["recovery"] as Record<string, unknown> | null;
  check(
    lost.body["outcome"] === "UNKNOWN_AFTER_DISPATCH" &&
      lost.body["executed"] === null &&
      recovery !== null &&
      provider.effects.size === effectsBefore + 1,
    "a lost response is UNKNOWN, with a recovery reference",
    `outcome ${String(lost.body["outcome"])}, executed ${String(lost.body["executed"])}`,
  );
  const dispatchesBefore = provider.requests.filter(
    (request) => request.path === "/dispatches",
  ).length;
  const reconciled = await call(executor, "/v1/reconciliations", {
    body: JSON.stringify(recovery),
  });
  const dispatchesAfter = provider.requests.filter(
    (request) => request.path === "/dispatches",
  ).length;
  check(
    reconciled.status === 200 &&
      reconciled.body["outcome"] === "COMPLETED" &&
      reconciled.body["recovered"] === true &&
      dispatchesAfter === dispatchesBefore,
    "reconciliation reads the provider and sends nothing",
    `outcome ${String(reconciled.body["outcome"])}, recovered ${String(reconciled.body["recovered"])}`,
  );
  const tampered = JSON.parse(JSON.stringify(recovery)) as {
    intent: { parameters: Record<string, unknown> };
  };
  tampered.intent.parameters["amountMinor"] = 5_000_000;
  const refused = await call(executor, "/v1/reconciliations", { body: JSON.stringify(tampered) });
  check(
    refused.body["outcome"] === "BLOCKED" &&
      (refused.body["reason_codes"] as string[]).includes("RECOVERY_BINDING_MISMATCH"),
    "a changed intent no longer matches its recovery reference",
    `outcome ${String(refused.body["outcome"])}`,
  );
  const repeated = await call(executor, "/v1/actions", {
    body: proposal(5_000, { idempotency_key: lostKey }),
  });
  check(
    repeated.body["outcome"] === "COMPLETED" && provider.effects.size === effectsBefore + 1,
    "a repeated key is a new decision the provider deduplicates",
    `${provider.effects.size} effects for ${provider.requests.filter((r) => r.path === "/dispatches").length} dispatches`,
  );
}

heading("Nothing secret left the process");
{
  const everything = [...responses, ...auditLines].join("\n");
  const tokens = [...authority.grants.keys()];
  const leaked = [
    everything.includes(callerToken) ? "caller token" : null,
    everything.includes(downstreamCredential) ? "downstream credential" : null,
    everything.includes(LOCAL_AUTHORITY_API_KEY) ? "authority key" : null,
    tokens.some((token) => everything.includes(token)) ? "grant token" : null,
  ].filter((item) => item !== null);
  check(
    leaked.length === 0 && tokens.length > 0,
    "no credential, token, or key in any response or audit line",
    `${responses.length} responses, ${auditLines.length} audit lines, ${tokens.length} grants`,
  );
  const executions = auditLines.filter((line) => line.includes('"EXECUTION_COMPLETED"')).length;
  const reconciliations = auditLines.filter((line) =>
    line.includes('"RECONCILIATION_COMPLETED"'),
  ).length;
  check(
    executions === 2 && reconciliations === 1,
    "the audit stream counts every execution and reconciliation",
    `${executions} executions, ${reconciliations} reconciliation`,
  );
}

await executor.server.close();
await provider.stop();
await authority.stop();

out(
  `\n${failures === 0 ? "PROVEN" : "NOT PROVEN"}: ${authority.grants.size} grants claimed, ${provider.effects.size} provider effects, one lost response reconciled without a second send; ${failures} failed expectations.`,
);
process.exitCode = failures === 0 ? 0 : 1;
