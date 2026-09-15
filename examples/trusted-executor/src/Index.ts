/**
 * The trusted executor as a process, proved offline.
 *
 * Starts the loopback Decionis and Presence doubles from the pipeline's
 * testing entry and a loopback stand-in for a downstream provider, then runs
 * the executor from `@decionis/agentsafe`, with this example's handlers, over
 * real HTTP in every configuration: shadow, where nothing executes;
 * enforcement, where one ALLOW is one dispatch; and enforcement with each
 * escalation shape, where a person's answer is fetched once and the authority
 * decides again. Every expectation is asserted, so the run is a self-checking
 * proof: the process exits 0 only when every refusal held, every legitimate
 * path executed exactly once, a lost provider response was reconciled without
 * a second send, named principals each reached only what they may, a rotated
 * caller token retired the old one, and no
 * credential, token, or key reached a response, an audit line, or a security
 * line.
 *
 * All identities are synthetic; the tokens are generated at run time. The
 * host posture is declared as development, so the host checks a deployment
 * enforces are waived here and said so on the security stream.
 */
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { JsonObjectSchema } from "@decionis/agent-safe-pipeline";
import {
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_PRESENCE_API_KEY,
  LocalAuthority,
  LocalPresence,
} from "@decionis/agent-safe-pipeline/testing";
import {
  CONFIG_KEYS,
  CompositeSecretStore,
  ExecutorConfigLoader,
  FORWARD_REQUEST_ACTION,
  MAX_BODY_BYTES,
  RESPONSE_HEADERS,
  FileExecutionJournal,
  HaltSwitch,
  type ExecutionJournal,
  SecurityEvents,
  bankingHandlers,
  createTrustedExecutor,
  expectedEffect,
  transportActionName,
  transportTarget,
  verifyAuditChain,
  verifyEvidenceBundle,
  type BankingAction,
  type HandlerRegistration,
  type TrustedExecutor,
} from "@decionis/agentsafe";
import { compactVerify, importSPKI } from "jose";
import { handlers } from "./Handlers.js";

/** A canonical BEAP action, synthetic throughout, as the profile's own example shapes it. */
function bankingAction(requestId: string): BankingAction {
  return {
    profile: "decionis.beap/v0.1",
    domain: "LOAN_DISBURSEMENT",
    action: { type: "DISBURSE_LOAN", request_id: requestId },
    actor: {
      type: "AGENT",
      id: "synthetic-treasury-agent",
      runtime: "trusted-executor-proof",
    },
    principal: { type: "ORGANIZATIONAL_FUNCTION", id: "synthetic-credit-operations" },
    subject: { type: "CUSTOMER", ref: "fixture_customer_28491" },
    target: { type: "LOAN", ref: "fixture_loan_84721" },
    financial_context: { amount: "2500.00", currency: "CHF" },
    requested_effect: { operation: "DISBURSE", destination_ref: "fixture_account_1921" },
    downstream: {
      provider: "SYNTHETIC_CORE",
      product: "LENDING",
      operation: "LOAN_DISBURSEMENT",
      environment: "LOCAL",
    },
    evidence_refs: [],
  };
}

/** The proposal that carries one, mapped as Appendix B.5 says. */
function beapProposal(action: BankingAction): string {
  return JSON.stringify({
    proposal: {
      action: transportActionName(action),
      target: transportTarget(action),
      parameters: action,
    },
    idempotency_key: action.action.request_id,
  });
}

const LOOPBACK_ORIGIN = "http://127.0.0.1";
const TENANT_ID = "00000000-0000-4000-8000-000000000007";
const APPROVER_ID = "synthetic-approver";
const callerToken = randomBytes(24).toString("base64url");
// The principals the named-caller section admits, each with its own token.
const treasuryToken = randomBytes(24).toString("base64url");
const batchToken = randomBytes(24).toString("base64url");
const operatorToken = randomBytes(24).toString("base64url");
const digestOf = (token: string): string =>
  createHash("sha256").update(token, "utf8").digest("hex");
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
  /** How many banking actions were posted, and what a read-back reports. */
  public actions = 0;
  public effect: Record<string, unknown> | null = null;
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
        // The banking endpoints: a core that posts the action and can be read
        // back, and whose read-back a test can make disagree on purpose.
        if (request.method === "POST" && path === "/actions") {
          this.actions += 1;
          return reply(200, { status: "POSTED", reference: `fixture_ref_${this.actions}` });
        }
        if (request.method === "GET" && path.startsWith("/actions/")) {
          const effect = this.effect;
          return effect === null ? reply(404, {}) : reply(200, { status: "POSTED", effect });
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

// The person completes every ceremony by hand: nothing auto-approves.
const presence = new LocalPresence({ autoComplete: "MANUAL", roles: { [APPROVER_ID]: "CRO" } });
const authority = new LocalAuthority({ presence });
const provider = new ProviderDouble();
await presence.start();
await authority.start();
await provider.start();

type Escalation = "NONE" | "DIRECT" | "MANAGED";

/** The executor's environment, as a deployment would mount it. */
function environment(
  mode: "SHADOW" | "ENFORCEMENT",
  escalation: Escalation = "NONE",
): Record<string, string> {
  const presenceShape =
    escalation === "NONE"
      ? {}
      : {
          PRESENCE_APPROVER_ID: APPROVER_ID,
          PRESENCE_VERIFICATION_LEVEL: "HIGH_CONFIDENCE",
          PRESENCE_VERIFICATION_METHODS: "WEBAUTHN,ACTIVE_LIVENESS",
          ...(escalation === "DIRECT"
            ? {
                PRESENCE_API_URL: presence.baseUrl,
                PRESENCE_API_KEY: LOCAL_PRESENCE_API_KEY,
                PRESENCE_ORGANIZATION: "Synthetic Treasury",
                PRESENCE_HARDWARE_PKI_REQUIRED: "false",
                PRESENCE_DISALLOW_VIRTUAL_CAMERAS: "true",
              }
            : { PRESENCE_APPROVER_ROLE: "CRO" }),
        };
  return {
    EXECUTOR_MODE: mode,
    EXECUTOR_ESCALATION: escalation,
    EXECUTOR_INTENT_TTL_SECONDS: "300",
    // This proof runs on whatever machine runs it: the host checks are waived
    // and said so, and the listener is plaintext on loopback.
    EXECUTOR_POSTURE: "DEVELOPMENT",
    EXECUTOR_ALLOW_PLAINTEXT_LISTENER: "true",
    // No volume here: the attempt journal is in memory and said so. The
    // production shape below mounts one, because production requires it.
    EXECUTOR_JOURNAL_REQUIRED: "false",
    ...presenceShape,
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

/** A production deployment's shape, with nothing reachable: every address is a reserved example host. */
function productionEnvironment(): Record<string, string> {
  const env = environment("ENFORCEMENT");
  delete env["EXECUTOR_POSTURE"];
  delete env["DECIONIS_ALLOW_INSECURE_LOOPBACK"];
  delete env["EXECUTOR_ALLOW_PLAINTEXT_LISTENER"];
  delete env["EXECUTOR_JOURNAL_REQUIRED"];
  return {
    ...env,
    NODE_ENV: "production",
    EXECUTOR_JOURNAL_DIR: "/var/lib/agent-safe/journal",
    // This shape has no principals file, which production allows only when
    // asked for by name; the principals section proves the refusal without it.
    EXECUTOR_ALLOW_LEGACY_CALLER: "true",
    DECIONIS_API_URL: "https://authority.decionis.example",
    DOWNSTREAM_URL: "https://payouts.provider.example/v1/payouts",
    DOWNSTREAM_LOOKUP_URL: "https://payouts.provider.example/v1/payouts/{idempotency_key}",
    EXECUTOR_SECRETS_DIR: "/var/run/agent-safe",
    EXECUTOR_TLS_CERT_FILE: "/var/run/agent-safe/tls/tls.crt",
    EXECUTOR_TLS_KEY_FILE: "/var/run/agent-safe/tls/tls.key",
  };
}

/** How many provider responses were lost on purpose, and how many a restart resolved. */
let lostResponses = 0;
let startupRecoveries = 0;
const loseNextResponse = (): void => {
  lostResponses += 1;
  provider.loseNext();
};

const auditLines: string[] = [];
const securityLines: string[] = [];
const responses: string[] = [];

interface RunningExecutor {
  readonly baseUrl: string;
  readonly executor: TrustedExecutor;
  readonly secrets: CompositeSecretStore;
  /** This executor's own evidence lines, for the chain to be verified over. */
  readonly evidence: string[];
}

async function startExecutor(
  mode: "SHADOW" | "ENFORCEMENT",
  escalation: Escalation = "NONE",
  overrides: Record<string, string | undefined> = {},
  registration: HandlerRegistration = handlers,
  attempts?: ExecutionJournal,
): Promise<RunningExecutor> {
  const env: Record<string, string> = { ...environment(mode, escalation) };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  const config = ExecutorConfigLoader.load(env);
  const security = new SecurityEvents((line) => securityLines.push(line));
  const secrets = CompositeSecretStore.fromEnvironment(env, config.secrets.required, {
    events: security,
    production: config.production,
    enforcePermissions: false,
    watch: false,
  });
  const evidence: string[] = [];
  const executor = await createTrustedExecutor({
    config,
    secrets,
    handlers: registration,
    dependencies: {
      ...(attempts === undefined ? {} : { attempts }),
      emit: (line) => {
        auditLines.push(line);
        evidence.push(line);
      },
      security,
    },
  });
  const address = await executor.listen(0, "127.0.0.1");
  return { baseUrl: `${LOOPBACK_ORIGIN}:${address.port}`, executor, secrets, evidence };
}

interface Reply {
  readonly status: number;
  readonly headers: Headers;
  readonly body: Record<string, unknown>;
}

async function call(
  running: RunningExecutor,
  path: string,
  init: { readonly method?: string; readonly body?: string; readonly token?: string | null },
): Promise<Reply> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const token = init.token === undefined ? callerToken : init.token;
  if (token !== null) headers["authorization"] = `Bearer ${token}`;
  const response = await fetch(`${running.baseUrl}${path}`, {
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

const refusal = (env: Record<string, string | undefined>): string => {
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
  const inEnvironment = refusal(productionEnvironment());
  check(
    inEnvironment.includes("CONFIG_SECRET_IN_ENV") && !inEnvironment.includes(callerToken),
    "a secret in the environment is refused in production",
    inEnvironment,
  );
  const development = refusal({ ...productionEnvironment(), EXECUTOR_POSTURE: "DEVELOPMENT" });
  check(
    development.includes("EXECUTOR_POSTURE"),
    "development posture is refused in production",
    development,
  );
  const plaintext = refusal({
    ...productionEnvironment(),
    EXECUTOR_ALLOW_PLAINTEXT_LISTENER: "true",
  });
  check(
    plaintext.includes("EXECUTOR_ALLOW_PLAINTEXT_LISTENER"),
    "a plaintext listener is refused in production",
    plaintext,
  );
  const unlistened = { ...environment("ENFORCEMENT") };
  delete unlistened["EXECUTOR_ALLOW_PLAINTEXT_LISTENER"];
  check(
    refusal(unlistened).includes("EXECUTOR_TLS_CERT_FILE"),
    "TLS material is required unless plaintext is asked for",
    refusal(unlistened),
  );
  const listed = Object.keys(environment("ENFORCEMENT", "DIRECT")).every((key) =>
    (CONFIG_KEYS as readonly string[]).includes(key),
  );
  check(listed, "every variable the proof sets is in CONFIG_KEYS", `${CONFIG_KEYS.length} keys`);
  const shadowEscalation = refusal(environment("SHADOW", "MANAGED"));
  check(
    shadowEscalation.includes("EXECUTOR_ESCALATION"),
    "shadow never escalates",
    shadowEscalation,
  );
  const halfDirect = { ...environment("ENFORCEMENT", "DIRECT") };
  delete halfDirect["PRESENCE_API_URL"];
  check(
    refusal(halfDirect).includes("PRESENCE_API_URL"),
    "direct escalation without a Presence address is refused",
    refusal(halfDirect),
  );
}

heading("Shadow: observe, record, never execute");
{
  const executor = await startExecutor("SHADOW");
  const ready = await call(executor, "/ready", { method: "GET", token: null });
  check(
    ready.status === 200 && ready.body["mode"] === "SHADOW" && ready.body["escalation"] === "NONE",
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
  await executor.executor.close();
}

heading("Enforcement: one ALLOW, one dispatch");
const executor = await startExecutor("ENFORCEMENT");
{
  const posture = executor.executor.posture;
  check(
    posture.mode === "DEVELOPMENT" &&
      posture.failed.length === 0 &&
      securityLines.some((line) => line.includes('"POSTURE_VERIFIED"')),
    "the host posture was verified, with development waivers said out loud",
    `${posture.findings.length} checks, ${posture.waived.length} waived`,
  );
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
  loseNextResponse();
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

heading("Rotation: a replaced caller token file retires the old one");
{
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-proof-"));
  const path = join(directory, "caller-token");
  const first = randomBytes(24).toString("base64url");
  const second = randomBytes(24).toString("base64url");
  writeFileSync(path, `${first}\n`, { mode: 0o600 });
  const rotating = await startExecutor("ENFORCEMENT", "NONE", {
    EXECUTOR_CALLER_TOKEN: undefined,
    EXECUTOR_CALLER_TOKEN_FILE: path,
  });
  const before = await call(rotating, "/v1/actions", { body: proposal(5_000), token: first });
  check(
    before.status === 200 && before.body["outcome"] === "COMPLETED",
    "the token read from the mounted file admits the caller",
    `${before.status} ${String(before.body["outcome"])}`,
  );
  writeFileSync(path, `${second}\n`);
  const report = await rotating.secrets.reload("SIGHUP");
  const stale = await call(rotating, "/v1/actions", { body: proposal(5_000), token: first });
  const fresh = await call(rotating, "/v1/actions", { body: proposal(5_000), token: second });
  check(
    report.rotated.includes("EXECUTOR_CALLER_TOKEN") &&
      stale.status === 401 &&
      fresh.status === 200 &&
      securityLines.some((line) => line.includes('"SECRET_ROTATED"')),
    "after the file changes, the old token is refused and the new one admitted",
    `rotated ${report.rotated.join(",")}; old ${stale.status}, new ${fresh.status}`,
  );
  check(
    !securityLines.join("\n").includes(first) && !securityLines.join("\n").includes(second),
    "the rotation event names the secret, not its values",
    `${securityLines.filter((line) => line.includes("SECRET_ROTATED")).length} rotation events`,
  );
  await rotating.executor.close();
  rmSync(directory, { recursive: true, force: true });
}

heading("The stop: a halted executor asks the authority for nothing");
{
  const stopped = await startExecutor("ENFORCEMENT");
  const grantsBefore = authority.grants.size;
  const effectsBefore = provider.effects.size;
  const auditBefore = stopped.evidence.length;
  stopped.executor.halt.halt("OPERATOR", "the treasury team asked us to stop");
  const refused = await call(stopped, "/v1/actions", { body: proposal(9_000) });
  check(
    refused.status === 503 &&
      refused.headers.get("retry-after") === "30" &&
      refused.body["verdict"] === "BLOCK" &&
      refused.body["outcome"] === "BLOCKED" &&
      refused.body["fail_closed"] === true &&
      (refused.body["reason_codes"] as string[])[0] === "EXECUTOR_HALTED" &&
      authority.grants.size === grantsBefore &&
      provider.effects.size === effectsBefore,
    "a halted executor refuses in the caller's own shape, and asks nothing",
    `${refused.status} ${String((refused.body["reason_codes"] as string[])[0])}, ${authority.grants.size - grantsBefore} grants, ${provider.effects.size - effectsBefore} effects`,
  );
  const blocked = stopped.evidence
    .slice(auditBefore)
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => line["event"] === "EXECUTION_BLOCKED");
  check(
    blocked.length === 1 && (blocked[0]?.["reason_codes"] as string[])[0] === "EXECUTOR_HALTED",
    "the refusal itself is evidence, on the chained stream",
    `${blocked.length} blocked line, reason ${String((blocked[0]?.["reason_codes"] as string[])[0])}`,
  );
  const ready = await call(stopped, "/ready", { method: "GET", token: null });
  const health = await call(stopped, "/health", { method: "GET", token: null });
  check(
    ready.status === 503 &&
      ready.body["status"] === "halted" &&
      health.status === 200 &&
      health.body["status"] === "ok",
    "readiness says halted while liveness stays up, so nothing restarts it",
    `ready ${ready.status}, health ${health.status}`,
  );
  // The halt file is the cause the operator has to remove first.
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-halt-"));
  const flag = join(directory, "halted");
  writeFileSync(flag, "stopped by the on-call operator\n");
  const filed = new HaltSwitch({
    events: new SecurityEvents((line) => securityLines.push(line)),
    haltFile: flag,
  });
  const startedHalted = filed.assertAtStartup().halted;
  const refusedResume = filed.resume("I would like it back");
  rmSync(flag);
  const allowedResume = filed.resume("the flag is gone");
  rmSync(directory, { recursive: true, force: true });
  check(
    startedHalted &&
      !refusedResume.resumed &&
      refusedResume.code === "HALT_CAUSE_PERSISTS" &&
      allowedResume.resumed,
    "a process starts halted while the flag is there, and resumes only once it is gone",
    `${refusedResume.code ?? "resumed"} then ${allowedResume.resumed ? "resumed" : "refused"}`,
  );
  const resumed = stopped.executor.halt.resume("we looked; it was nothing");
  const after = await call(stopped, "/v1/actions", { body: proposal(9_000) });
  check(
    resumed.resumed &&
      after.status === 200 &&
      after.body["outcome"] === "COMPLETED" &&
      provider.effects.size === effectsBefore + 1,
    "work goes through again once an operator resumes with a reason",
    `${String(after.body["outcome"])}, ${provider.effects.size - effectsBefore} effect`,
  );
  await stopped.executor.close();
}

heading("Ceilings: what this host will never run, whatever policy says");
{
  const bounded = await startExecutor("ENFORCEMENT", "NONE", {
    EXECUTOR_HARD_LIMIT_SINGLE_MINOR: "USD:500000",
    EXECUTOR_HARD_LIMIT_WINDOW_SECONDS: "60",
    EXECUTOR_HARD_LIMIT_WINDOW_COUNT: "1",
  });
  const grantsBefore = authority.grants.size;
  const over = await call(bounded, "/v1/actions", { body: proposal(500_001) });
  check(
    over.status === 422 &&
      over.body["code"] === "HARD_LIMIT_EXCEEDED" &&
      authority.grants.size === grantsBefore,
    "an amount above the ceiling is refused before the authority is asked",
    `${over.status} ${String(over.body["code"])}, ${authority.grants.size - grantsBefore} grants`,
  );
  const first = await call(bounded, "/v1/actions", { body: proposal(1_000) });
  const second = await call(bounded, "/v1/actions", { body: proposal(1_000) });
  check(
    first.body["outcome"] === "COMPLETED" &&
      second.status === 422 &&
      second.body["code"] === "HARD_LIMIT_WINDOW_COUNT_EXCEEDED",
    "the window counts what it let through, and refuses the next one",
    `${String(first.body["outcome"])} then ${String(second.body["code"])}`,
  );
  await bounded.executor.close();
}

heading("Banking: the effect is read back, compared, and a mismatch stops the executor");
{
  const banking = await startExecutor(
    "ENFORCEMENT",
    "NONE",
    {
      DOWNSTREAM_URL: `${provider.baseUrl}/actions`,
      DOWNSTREAM_LOOKUP_URL: `${provider.baseUrl}/actions/by-key/{idempotency_key}`,
      DOWNSTREAM_LOOKUP_BY_REFERENCE_URL: `${provider.baseUrl}/actions/by-reference/{provider_reference}`,
      DOWNSTREAM_SYSTEM: "synthetic_core",
      DOWNSTREAM_OPERATION: "loan_disbursement",
      DOWNSTREAM_ENVIRONMENT: "local",
      BANKING_ADAPTER_ID: "SYNTHETIC_CORE_BANKING",
      EXECUTOR_ACTOR_ID: "synthetic-treasury-agent",
    },
    // The adapter takes its identity and its read-back address from the
    // configuration above, so neither is named twice.
    bankingHandlers(),
  );
  const matching = bankingAction("synthetic-req-proof-1");
  provider.effect = expectedEffect(matching);
  const confirmed = await call(banking, "/v1/actions", { body: beapProposal(matching) });
  const effect = (confirmed.body["effect"] ?? {}) as Record<string, unknown>;
  check(
    confirmed.body["outcome"] === "COMPLETED" &&
      effect["comparison"] === "MATCH" &&
      effect["confirmation"] === "CONFIRMED" &&
      effect["observation_method"] === "READ_AFTER_WRITE" &&
      effect["observed_effect_digest"] === effect["expected_effect_digest"],
    "a read-back that matches what was authorised is the only confirmation",
    `${String(effect["comparison"])}, ${String(effect["confirmation"])}`,
  );
  const grantsBefore = authority.grants.size;
  const differing = bankingAction("synthetic-req-proof-2");
  provider.effect = { ...expectedEffect(differing), amount: "1.00" };
  const mismatched = await call(banking, "/v1/actions", { body: beapProposal(differing) });
  const seen = (mismatched.body["effect"] ?? {}) as Record<string, unknown>;
  check(
    mismatched.body["outcome"] === "COMPLETED" &&
      seen["comparison"] === "MISMATCH" &&
      seen["confirmation"] !== "CONFIRMED" &&
      (mismatched.body["reason_codes"] as string[]).includes("EFFECT_MISMATCH") &&
      JSON.stringify(seen["mismatched_fields"]) === JSON.stringify(["amount"]),
    "a provider that did something else is never confirmed, and names the field",
    `${String(seen["comparison"])}, ${String(seen["confirmation"])}`,
  );
  const grantsAfterMismatch = authority.grants.size;
  const halted = await call(banking, "/v1/actions", {
    body: beapProposal(bankingAction("synthetic-req-proof-3")),
  });
  check(
    halted.status === 503 &&
      (halted.body["reason_codes"] as string[])[0] === "EXECUTOR_HALTED" &&
      authority.grants.size === grantsAfterMismatch,
    "the mismatch halts the executor, so the next proposal asks for no grant",
    `${halted.status} ${String((halted.body["reason_codes"] as string[])[0])}, ${authority.grants.size - grantsBefore} grants since the match`,
  );
  // The same action, described over the transport as a payment rather than
  // the disbursement it is.
  const misdescribed = bankingAction("synthetic-req-proof-4");
  const refused = await call(banking, "/v1/actions", {
    body: JSON.stringify({
      proposal: {
        action: "beap.corporate_payments.send_payment",
        target: transportTarget(misdescribed),
        parameters: misdescribed,
      },
      idempotency_key: misdescribed.action.request_id,
    }),
  });
  check(
    refused.status === 422 && refused.body["code"] === "BANKING_ACTION_NAME_MISMATCH",
    "a transport name that disagrees with the action is refused before anything",
    `${refused.status} ${String(refused.body["code"])}`,
  );
  provider.effect = null;
  await banking.executor.close();
}

heading("Recovery: a lost dispatch is resolved from the journal, not re-sent");
{
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-journal-"));
  const attempts = new FileExecutionJournal(join(directory, "attempts"));
  const crashing = await startExecutor("ENFORCEMENT", "NONE", {}, handlers, attempts);
  loseNextResponse();
  const lost = await call(crashing, "/v1/actions", { body: proposal(4_000) });
  const dispatchesBefore = provider.requests.filter(
    (request) => request.path === "/dispatches",
  ).length;
  check(
    lost.body["outcome"] === "UNKNOWN_AFTER_DISPATCH" &&
      (await attempts.openAttempts()).length === 1 &&
      (await attempts.openAttempts())[0]?.state === "CLAIMED",
    "an outcome nobody knows stays open in the journal, with its claim recorded",
    `${String(lost.body["outcome"])}, ${(await attempts.openAttempts()).length} open`,
  );
  // The process is gone. A new one reads the same journal and resolves what
  // it finds by asking the provider, read-only, as part of starting up.
  await crashing.executor.close();
  const recovering = new FileExecutionJournal(join(directory, "attempts"));
  const eventsBefore = securityLines.length;
  const restarted = await startExecutor("ENFORCEMENT", "NONE", {}, handlers, recovering);
  startupRecoveries += 1;
  const resolutions = securityLines
    .slice(eventsBefore)
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((event) => event["event"] === "OPEN_ATTEMPT_RESOLVED");
  const dispatchesAfter = provider.requests.filter(
    (request) => request.path === "/dispatches",
  ).length;
  const stillOpen = (await recovering.openAttempts()).length;
  check(
    resolutions.length === 1 &&
      resolutions[0]?.["resolution"] === "RECONCILED_COMPLETED" &&
      dispatchesAfter === dispatchesBefore &&
      stillOpen === 0,
    "the next process resolves it by reading the provider, and never sends again",
    `${String(resolutions[0]?.["resolution"])}, ${dispatchesAfter - dispatchesBefore} new dispatches, ${stillOpen} still open`,
  );
  const again = await startExecutor("ENFORCEMENT", "NONE", {}, handlers, recovering);
  const askedAgain = securityLines
    .slice(eventsBefore)
    .filter((line) => line.includes('"OPEN_ATTEMPT_FOUND_AT_STARTUP"')).length;
  check(
    askedAgain === 1,
    "the resolved attempt is closed, so a later start does not ask about it again",
    `${askedAgain} attempt found across two starts`,
  );
  await again.executor.close();
  await restarted.executor.close();
  recovering.close();
  rmSync(directory, { recursive: true, force: true });
}

heading("Principals: who may call, as what, and for which actions");
{
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-principals-"));
  const path = join(directory, "principals.json");
  const proposer = (id: string, actorId: string, token: string, actions: string[]) => ({
    id,
    role: "PROPOSER",
    tenant_id: TENANT_ID,
    actor: { id: actorId, type: "AI_AGENT" },
    allowed_actions: actions,
    credential: { kind: "BEARER", token_sha256: digestOf(token) },
  });
  writeFileSync(
    path,
    JSON.stringify({
      version: "agent-safe.principals/1",
      principals: [
        proposer("synthetic-treasury-workflow", "synthetic-payout-agent", treasuryToken, [
          FORWARD_REQUEST_ACTION,
        ]),
        proposer("synthetic-batch-runner", "synthetic-batch-agent", batchToken, [
          "synthetic_second_action",
        ]),
        {
          id: "synthetic-ops-oncall",
          role: "OPERATOR",
          scopes: ["status", "metrics"],
          credential: { kind: "BEARER", token_sha256: digestOf(operatorToken) },
        },
      ],
    }),
    { mode: 0o600 },
  );
  // Two registered actions, so a principal can be allowed one and not the other.
  const SECOND_ACTION = "synthetic_second_action";
  const bothActions: HandlerRegistration = (context) => {
    const registered = handlers(context);
    context.registry.register(SECOND_ACTION, {
      parametersSchema: JsonObjectSchema,
      execute: ({ dispatch }) => dispatch.run(() => ({ recorded: true })),
    });
    return [...registered, SECOND_ACTION];
  };
  const named = await startExecutor(
    "ENFORCEMENT",
    "NONE",
    {
      EXECUTOR_PRINCIPALS_FILE: path,
      EXECUTOR_TENANT_ID: undefined,
      EXECUTOR_ACTOR_ID: undefined,
      EXECUTOR_ACTOR_TYPE: undefined,
      EXECUTOR_ACTOR_RUNTIME: undefined,
      EXECUTOR_CALLER_TOKEN: undefined,
    },
    bothActions,
  );
  check(
    named.executor.principals.size === 3 && !named.executor.principals.legacy,
    "the principals file replaces the one caller with named principals",
    `${named.executor.principals.size} principals, ${named.executor.principals.operators.length} operator`,
  );
  const evidenceBefore = named.evidence.length;
  const executed = await call(named, "/v1/actions", {
    body: proposal(6_000),
    token: treasuryToken,
  });
  const naming = named.evidence
    .slice(evidenceBefore)
    .map((line) => (JSON.parse(line) as { caller_principal: string }).caller_principal);
  check(
    executed.status === 200 &&
      executed.body["outcome"] === "COMPLETED" &&
      naming.length > 0 &&
      naming.every((principal) => principal === "synthetic-treasury-workflow"),
    "a named proposer executes, and every evidence line names it",
    `${naming.length} lines, all ${naming[0] ?? "none"}`,
  );
  const unknown = await call(named, "/v1/actions", {
    body: proposal(6_000),
    token: callerToken,
  });
  const wrongAction = await call(named, "/v1/actions", {
    body: proposal(6_000),
    token: batchToken,
  });
  const proposerOnControl = await call(named, "/v1/control/status", {
    method: "GET",
    token: treasuryToken,
  });
  check(
    unknown.status === 401 &&
      wrongAction.status === 403 &&
      wrongAction.body["code"] === "ACTION_NOT_PERMITTED_FOR_PRINCIPAL" &&
      proposerOnControl.status === 403 &&
      proposerOnControl.body["code"] === "ROLE_FORBIDDEN",
    "a token nobody holds, an action outside the list, and an operator route are refused",
    `unknown ${unknown.status}, action ${String(wrongAction.body["code"])}, control ${String(proposerOnControl.body["code"])}`,
  );
  const status = await call(named, "/v1/control/status", { method: "GET", token: operatorToken });
  const metrics = await fetch(`${named.baseUrl}/metrics`, {
    headers: { authorization: `Bearer ${operatorToken}` },
  });
  const exposition = await metrics.text();
  responses.push(exposition);
  check(
    status.status === 200 &&
      (status.body["principals"] as { mode: string }).mode === "PRINCIPALS" &&
      metrics.status === 200 &&
      exposition.includes('agentsafe_proposals_total{verdict="ALLOW"}'),
    "an operator reads the status and the metrics its scopes name",
    `status ${status.status}, metrics ${metrics.status}, ${exposition.split("\n").length} exposition lines`,
  );
  loseNextResponse();
  const lost = await call(named, "/v1/actions", { body: proposal(7_000), token: treasuryToken });
  const recovery = lost.body["recovery"] as Record<string, unknown>;
  const stranger = await call(named, "/v1/reconciliations", {
    body: JSON.stringify(recovery),
    token: batchToken,
  });
  const own = await call(named, "/v1/reconciliations", {
    body: JSON.stringify(recovery),
    token: treasuryToken,
  });
  check(
    lost.body["outcome"] === "UNKNOWN_AFTER_DISPATCH" &&
      stranger.status === 403 &&
      stranger.body["code"] === "INTENT_PRINCIPAL_MISMATCH" &&
      own.status === 200 &&
      own.body["outcome"] === "COMPLETED",
    "one proposer cannot reconcile another's intent; its own is reconciled",
    `stranger ${String(stranger.body["code"])}, own ${String(own.body["outcome"])}`,
  );
  const withoutFile = refusal({
    ...productionEnvironment(),
    EXECUTOR_ALLOW_LEGACY_CALLER: undefined,
  });
  const byName = refusal(productionEnvironment());
  check(
    withoutFile.includes("EXECUTOR_PRINCIPALS_FILE") &&
      !byName.includes("EXECUTOR_PRINCIPALS_FILE"),
    "production needs a principals file unless the legacy caller is asked for by name",
    `${withoutFile}; by name: ${byName === "" ? "accepted" : byName}`,
  );
  await named.executor.close();
  rmSync(directory, { recursive: true, force: true });
}

heading("Direct escalation: this process opens the Presence request");
{
  const direct = await startExecutor("ENFORCEMENT", "DIRECT");
  const effectsBefore = provider.effects.size;
  const held = await call(direct, "/v1/actions", { body: proposal(50_000) });
  const handoff = held.body["escalation"] as Record<string, unknown> | null;
  const requestId = String(handoff?.["request_id"] ?? "");
  check(
    held.body["verdict"] === "ESCALATE" &&
      held.body["outcome"] === "ESCALATE_PENDING" &&
      held.body["executed"] === false &&
      held.body["authorization"] === null &&
      handoff?.["mode"] === "DIRECT" &&
      requestId.length > 0 &&
      provider.effects.size === effectsBefore,
    "an ESCALATE hands back a Presence request, no grant",
    `outcome ${String(held.body["outcome"])}, request ${requestId.slice(0, 18)}…`,
  );
  check(
    presence.verification(requestId)?.intentHash === held.body["intent_hash"],
    "the person is shown the intent hash the authority evaluated",
    String(presence.verification(requestId)?.bindingSource ?? "unbound"),
  );
  const pending = await call(direct, "/v1/escalations", { body: JSON.stringify(handoff) });
  check(
    pending.body["outcome"] === "ESCALATE_PENDING" &&
      pending.body["executed"] === false &&
      provider.effects.size === effectsBefore,
    "resuming before the ceremony changes nothing",
    `outcome ${String(pending.body["outcome"])}`,
  );
  presence.approve(requestId);
  const tampered = JSON.parse(JSON.stringify(handoff)) as {
    intent: { parameters: Record<string, unknown> };
  };
  tampered.intent.parameters["amountMinor"] = 5_000_000;
  const refused = await call(direct, "/v1/escalations", { body: JSON.stringify(tampered) });
  check(
    refused.body["executed"] === false && provider.effects.size === effectsBefore,
    "a receipt cannot approve a changed intent",
    `verdict ${String(refused.body["verdict"])}, outcome ${String(refused.body["outcome"])}`,
  );
  const approved = await call(direct, "/v1/escalations", { body: JSON.stringify(handoff) });
  check(
    approved.body["outcome"] === "COMPLETED" &&
      approved.body["executed"] === true &&
      provider.effects.size === effectsBefore + 1,
    "the receipt goes back to the authority and the action runs once",
    `outcome ${String(approved.body["outcome"])}, finalization ${String(approved.body["finalization"])}`,
  );
  const again = await call(direct, "/v1/escalations", { body: JSON.stringify(handoff) });
  check(
    provider.effects.size === effectsBefore + 1,
    "presenting the receipt again moves nothing at the provider",
    `outcome ${String(again.body["outcome"])}, ${provider.effects.size - effectsBefore} effect`,
  );
  const heldAgain = await call(direct, "/v1/actions", { body: proposal(50_000) });
  const second = heldAgain.body["escalation"] as Record<string, unknown> | null;
  presence.deny(String(second?.["request_id"] ?? ""));
  const denied = await call(direct, "/v1/escalations", { body: JSON.stringify(second) });
  check(
    denied.body["verdict"] === "BLOCK" &&
      denied.body["executed"] === false &&
      provider.effects.size === effectsBefore + 1,
    "a denial is a BLOCK, and nothing runs",
    `reason ${(denied.body["reason_codes"] as string[]).join(",")}`,
  );
  await direct.executor.close();
}

heading("Managed escalation: the authority orchestrates Presence");
{
  const managed = await startExecutor("ENFORCEMENT", "MANAGED");
  const effectsBefore = provider.effects.size;
  const held = await call(managed, "/v1/actions", { body: proposal(50_000) });
  const handoff = held.body["escalation"] as {
    mode?: string;
    escalation?: { escalationId?: string };
  } | null;
  const escalationId = String(handoff?.escalation?.escalationId ?? "");
  check(
    held.body["verdict"] === "ESCALATE" &&
      held.body["outcome"] === "ESCALATE_PENDING" &&
      held.body["executed"] === false &&
      handoff?.mode === "MANAGED" &&
      escalationId.length > 0,
    "an ESCALATE hands back the authority's escalation state",
    `escalation ${escalationId.slice(0, 18)}…`,
  );
  const forged = JSON.parse(JSON.stringify(handoff)) as {
    escalation: { escalationId: string };
  };
  forged.escalation.escalationId = "synthetic-escalation-forged";
  const refused = await call(managed, "/v1/escalations", { body: JSON.stringify(forged) });
  check(
    refused.body["executed"] === false && provider.effects.size === effectsBefore,
    "an escalation that is not this intent's yields nothing",
    `verdict ${String(refused.body["verdict"])}, reason ${(refused.body["reason_codes"] as string[])[0] ?? ""}`,
  );
  const presenceRequestId = authority.escalations.get(escalationId)?.presenceRequestId ?? "";
  presence.approve(presenceRequestId);
  let resumed = await call(managed, "/v1/escalations", { body: JSON.stringify(handoff) });
  for (
    let lookups = 1;
    lookups < 10 && resumed.body["outcome"] === "ESCALATE_PENDING";
    lookups += 1
  ) {
    resumed = await call(managed, "/v1/escalations", {
      body: JSON.stringify(resumed.body["escalation"]),
    });
  }
  check(
    resumed.body["outcome"] === "COMPLETED" &&
      resumed.body["executed"] === true &&
      provider.effects.size === effectsBefore + 1,
    "the authority reaches GRANT_READY and the action runs once",
    `outcome ${String(resumed.body["outcome"])}, ${provider.effects.size - effectsBefore} effect`,
  );
  await managed.executor.close();
}

heading("Incident response: the evidence an operator can take, and verify");
{
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-evidence-"));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const keyPath = join(directory, "signing.pem");
  writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }).toString());
  const running = await startExecutor("ENFORCEMENT", "NONE", {
    EXECUTOR_EVIDENCE_DIR: join(directory, "bundles"),
    EXECUTOR_EVIDENCE_SIGNING_KEY_FILE: keyPath,
    EXECUTOR_PRINCIPALS_FILE: undefined,
  });
  // One execution, so there is something in the evidence stream to carry.
  await call(running, "/v1/actions", { body: proposal(3_000) });
  const operator = {
    id: "synthetic-ops-oncall",
    role: "OPERATOR" as const,
    tenantId: null,
    actor: null,
    scopes: new Set(["evidence", "status"]),
    allowedActions: new Set<string>(),
    credential: { kind: "BEARER" as const, token_sha256: "0".repeat(64) },
    rateLimit: null,
  };
  const bundle = await running.executor.service.exportEvidence(
    { reason: "drill: on-call took a bundle" },
    operator as never,
  );
  const files = readdirSync(bundle.directory).sort();
  check(
    files.length === 6 &&
      files.includes("manifest.json") &&
      files.includes("manifest.jws") &&
      bundle.signature !== null,
    "an operator with the evidence scope takes a bundle, signed",
    `${files.length} files, signed ${String(bundle.signature !== null)}`,
  );
  const read = (name: string): string | null => {
    try {
      return readFileSync(join(bundle.directory, name), "utf8");
    } catch {
      return null;
    }
  };
  const spki = publicKey.export({ type: "spki", format: "pem" }).toString();
  const verifySignature = async (signature: string, manifest: string): Promise<boolean> => {
    try {
      const verified = await compactVerify(signature, await importSPKI(spki, "EdDSA"));
      return Buffer.from(verified.payload).toString("utf8") === manifest;
    } catch {
      return false;
    }
  };
  const verified = await verifyEvidenceBundle({ read, verifySignature });
  check(
    verified.ok && verified.establishes === "ORIGIN_AND_CONSISTENCY",
    "the bundle verifies offline, and says it establishes origin too",
    `${verified.establishes}, ${verified.files} files, ${verified.findings.length} findings`,
  );
  // The same bundle, one byte different.
  const flipped = await verifyEvidenceBundle({
    read: (name) => (name === "posture.json" ? `${read(name) ?? ""} ` : read(name)),
    verifySignature,
  });
  check(
    !flipped.ok && flipped.findings.some((finding) => finding.subject === "posture.json"),
    "a flipped byte fails verification, and names the file it was in",
    `${flipped.findings[0]?.code ?? "nothing"} in ${String(flipped.findings[0]?.subject)}`,
  );
  // A signature over a different manifest establishes nothing.
  const restated = await verifyEvidenceBundle({
    read: (name) =>
      name === "manifest.json" ? (read(name) ?? "").replace("drill", "DRILL") : read(name),
    verifySignature,
  });
  check(
    !restated.ok &&
      restated.establishes === "INTERNAL_CONSISTENCY" &&
      restated.findings.some((finding) => finding.code === "BUNDLE_SIGNATURE_INVALID"),
    "a manifest that was changed after signing is refused, not downgraded quietly",
    `${restated.establishes}, ${restated.findings.length} findings`,
  );
  const manifest = JSON.parse(read("manifest.json") ?? "{}") as Record<string, unknown>;
  const everything = files.map((name) => read(name) ?? "").join("\n");
  const leaked = [
    everything.includes(LOCAL_AUTHORITY_API_KEY) ? "authority key" : null,
    everything.includes(callerToken) ? "caller token" : null,
    everything.includes(downstreamCredential) ? "downstream credential" : null,
    everything.includes("BEGIN PRIVATE KEY") ? "signing key" : null,
    everything.includes("amountMinor") ? "a request parameter" : null,
  ].filter((found): found is string => found !== null);
  check(
    leaked.length === 0 &&
      (manifest["image"] as { self_verified?: unknown })?.self_verified === false,
    "the bundle carries no secret and no parameter, and does not claim to verify its own image",
    `${leaked.join(", ") || "nothing leaked"}`,
  );
  await running.executor.close();
  rmSync(directory, { recursive: true, force: true });
}

heading("Nothing secret left the process");
{
  const everything = [...responses, ...auditLines, ...securityLines].join("\n");
  const tokens = [...authority.grants.keys()];
  const leaked = [
    everything.includes(callerToken) ? "caller token" : null,
    everything.includes(treasuryToken) ? "treasury principal token" : null,
    everything.includes(batchToken) ? "batch principal token" : null,
    everything.includes(operatorToken) ? "operator principal token" : null,
    everything.includes(downstreamCredential) ? "downstream credential" : null,
    everything.includes(LOCAL_AUTHORITY_API_KEY) ? "authority key" : null,
    everything.includes(LOCAL_PRESENCE_API_KEY) ? "presence key" : null,
    tokens.some((token) => everything.includes(token)) ? "grant token" : null,
  ].filter((item) => item !== null);
  check(
    leaked.length === 0 && tokens.length > 0,
    "no credential, token, or key in any response, exposition, audit line, or security line",
    `${responses.length} responses, ${auditLines.length} audit lines, ${securityLines.length} security lines, ${tokens.length} grants`,
  );
  const chain = verifyAuditChain(executor.evidence);
  const tampered = executor.evidence.map((line, index) =>
    index === 2 ? line.replace('"verdict"', '"verdiсt"') : line,
  );
  const broken = verifyAuditChain(tampered);
  check(
    chain.ok && executor.evidence.length > 3 && !broken.ok && broken.findings[0]?.seq === 3,
    "the evidence stream is a verifiable chain that reports one altered line",
    `${executor.evidence.length} lines verify; altered line 3 reports ${broken.findings[0]?.code ?? "nothing"} at seq ${String(broken.findings[0]?.seq)}`,
  );
  const refusals = securityLines.filter((line) => line.includes('"EGRESS_REFUSED"')).length;
  check(
    refusals === 0 && executor.executor.metrics.proposals.get({ verdict: "ALLOW" }) > 0,
    "every outbound request stayed inside the sealed policy and was counted",
    `${refusals} egress refusals, ${executor.executor.metrics.proposals.get({ verdict: "ALLOW" })} ALLOW proposals counted`,
  );
  const executions = auditLines.filter((line) => line.includes('"EXECUTION_COMPLETED"')).length;
  const reconciliations = auditLines.filter((line) =>
    line.includes('"RECONCILIATION_COMPLETED"'),
  ).length;
  // Every side effect the provider took, whichever family asked for it.
  const dispatches = provider.requests.filter(
    (request) => request.path === "/dispatches" || request.path === "/actions",
  ).length;
  const presenceEvents = auditLines.filter((line) => line.includes('"PRESENCE_')).length;
  check(
    executions === dispatches - lostResponses &&
      reconciliations === lostResponses - startupRecoveries &&
      lostResponses > 0 &&
      startupRecoveries > 0 &&
      presenceEvents >= 4,
    "the audit stream counts every execution, reconciliation and ceremony",
    `${executions} executions for ${dispatches} dispatches, ${lostResponses} lost (${startupRecoveries} recovered at start), ${reconciliations} reconciliations, ${presenceEvents} Presence events`,
  );
}

await executor.executor.close();
await provider.stop();
await authority.stop();
await presence.stop();

out(
  `\n${failures === 0 ? "PROVEN" : "NOT PROVEN"}: ${authority.grants.size} grants claimed, ${provider.effects.size} provider effects, ${presence.receipts.size} ceremonies completed by a person, one lost response reconciled without a second send, one caller token rotated; ${failures} failed expectations.`,
);
process.exitCode = failures === 0 ? 0 : 1;
