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
 * a second send, a rotated caller token retired the old one, and no
 * credential, token, or key reached a response, an audit line, or a security
 * line.
 *
 * All identities are synthetic; the tokens are generated at run time. The
 * host posture is declared as development, so the host checks a deployment
 * enforces are waived here and said so on the security stream.
 */
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
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
  SecurityEvents,
  createTrustedExecutor,
  verifyAuditChain,
  type TrustedExecutor,
} from "@decionis/agentsafe";
import { handlers } from "./Handlers.js";

const LOOPBACK_ORIGIN = "http://127.0.0.1";
const TENANT_ID = "00000000-0000-4000-8000-000000000007";
const APPROVER_ID = "synthetic-approver";
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
  return {
    ...env,
    NODE_ENV: "production",
    DECIONIS_API_URL: "https://authority.decionis.example",
    DOWNSTREAM_URL: "https://payouts.provider.example/v1/payouts",
    DOWNSTREAM_LOOKUP_URL: "https://payouts.provider.example/v1/payouts/{idempotency_key}",
    EXECUTOR_SECRETS_DIR: "/var/run/agent-safe",
    EXECUTOR_TLS_CERT_FILE: "/var/run/agent-safe/tls/tls.crt",
    EXECUTOR_TLS_KEY_FILE: "/var/run/agent-safe/tls/tls.key",
  };
}

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
    handlers,
    dependencies: {
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

heading("Nothing secret left the process");
{
  const everything = [...responses, ...auditLines, ...securityLines].join("\n");
  const tokens = [...authority.grants.keys()];
  const leaked = [
    everything.includes(callerToken) ? "caller token" : null,
    everything.includes(downstreamCredential) ? "downstream credential" : null,
    everything.includes(LOCAL_AUTHORITY_API_KEY) ? "authority key" : null,
    everything.includes(LOCAL_PRESENCE_API_KEY) ? "presence key" : null,
    tokens.some((token) => everything.includes(token)) ? "grant token" : null,
  ].filter((item) => item !== null);
  check(
    leaked.length === 0 && tokens.length > 0,
    "no credential, token, or key in any response, audit line, or security line",
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
  const dispatches = provider.requests.filter((request) => request.path === "/dispatches").length;
  const presenceEvents = auditLines.filter((line) => line.includes('"PRESENCE_')).length;
  check(
    executions === dispatches - 1 && reconciliations === 1 && presenceEvents >= 4,
    "the audit stream counts every execution, reconciliation and ceremony",
    `${executions} executions for ${dispatches} dispatches, ${reconciliations} reconciliation, ${presenceEvents} Presence events`,
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
