import { generateKeyPairSync } from "node:crypto";
import { JsonObjectSchema } from "@decionis/agent-safe-pipeline";
import { LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SignedRequestCredential } from "../../src/credential/SignedRequestCredential.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { forwardRequestHandlers } from "../../src/handlers/ForwardRequestHandler.js";
import type { HandlerRegistration } from "../../src/handlers/HandlerRegistration.js";
import type { Principal } from "../../src/identity/PrincipalRegistry.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import {
  CALLER_TOKEN,
  TENANT_ID,
  collectedEvents,
  loopbackEnvironment,
  openSecrets,
  proposal,
} from "../support/Environment.js";
import { principalsFile, sha256Hex } from "../support/Principals.js";
import { ProviderDouble } from "../support/ProviderDouble.js";

const authority = new LocalAuthority();
const provider = new ProviderDouble();
const PRINCIPALS_PATH = "/var/run/agent-safe/principals/principals.json";

beforeAll(async () => {
  await authority.start();
  await provider.start();
});

afterAll(async () => {
  await provider.stop();
  await authority.stop();
});

interface Built {
  readonly service: TrustedExecutorService;
  readonly lines: string[];
  readonly securityLines: string[];
}

/** A service in principals mode: the legacy variables gone, the file read through the injected reader. */
function build(
  options: {
    readonly file?: string;
    readonly env?: Record<string, string | undefined>;
    readonly handlers?: HandlerRegistration;
    readonly production?: boolean;
  } = {},
): Built {
  const env: Record<string, string> = loopbackEnvironment(
    { authority, providerBaseUrl: provider.baseUrl },
    "ENFORCEMENT",
  );
  for (const key of [
    "EXECUTOR_TENANT_ID",
    "EXECUTOR_ACTOR_ID",
    "EXECUTOR_ACTOR_TYPE",
    "EXECUTOR_ACTOR_RUNTIME",
    "EXECUTOR_CALLER_TOKEN",
  ]) {
    delete env[key];
  }
  env["EXECUTOR_PRINCIPALS_FILE"] = PRINCIPALS_PATH;
  for (const [key, value] of Object.entries(options.env ?? {})) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  const loaded = ExecutorConfigLoader.load(env);
  const config = options.production === true ? { ...loaded, production: true } : loaded;
  const lines: string[] = [];
  const securityLines: string[] = [];
  const secrets = openSecrets(env, loaded, collectedEvents(securityLines));
  const service = TrustedExecutorService.create(
    config,
    secrets,
    options.handlers ?? forwardRequestHandlers(),
    {
      emit: (line) => lines.push(line),
      security: collectedEvents(securityLines),
      readFile: (path) => {
        if (path === PRINCIPALS_PATH) return options.file ?? principalsFile();
        throw new Error(`unexpected read of ${path}`);
      },
    },
  );
  return { service, lines, securityLines };
}

/** The file with only bearer credentials, so no verifier or client CA is needed. */
function bearerOnlyFile(extra: Record<string, unknown>[] = []): string {
  const parsed = JSON.parse(principalsFile()) as { principals: Record<string, unknown>[] };
  parsed.principals = [
    parsed.principals[0] as Record<string, unknown>,
    {
      id: "ops-oncall",
      role: "OPERATOR",
      scopes: ["status", "metrics"],
      credential: {
        kind: "BEARER",
        token_sha256: sha256Hex("synthetic-operator-token-0123456789abcdef"),
      },
    },
    ...extra,
  ];
  return JSON.stringify(parsed);
}

async function refusal(work: Promise<unknown> | (() => unknown)): Promise<[number, string]> {
  try {
    await (typeof work === "function" ? work() : work);
  } catch (error) {
    if (error instanceof ServiceError) return [error.status, error.code];
    throw error;
  }
  throw new Error("expected a refusal");
}

const events = (lines: string[]): Record<string, unknown>[] =>
  lines.map((line) => JSON.parse(line) as Record<string, unknown>);

describe("principals mode", () => {
  it("loads the file, executes for a proposer as its own tenant and actor, and names it on every line", async () => {
    const { service, lines, securityLines } = build({ file: bearerOnlyFile() });
    expect(service.principals.legacy).toBe(false);
    expect(events(securityLines)).toContainEqual(
      expect.objectContaining({
        event: "PRINCIPALS_LOADED",
        principals: 2,
        proposers: 1,
        operators: 1,
      }),
    );
    const workflow = service.principals.principal("treasury-workflow") as Principal;
    const answer = await service.propose(proposal(25_00).body, workflow);
    expect(answer).toMatchObject({ verdict: "ALLOW", outcome: "COMPLETED", executed: true });
    const recovery = authority.grants.size;
    expect(recovery).toBeGreaterThan(0);
    for (const line of events(lines)) expect(line["caller_principal"]).toBe("treasury-workflow");
    const captured = events(lines).find((line) => line["event"] === "INTENT_CAPTURED");
    expect(captured).toBeDefined();
    const seen = provider.requests.at(-1);
    expect(seen?.headers["x-agent-safe-dossier-id"]).toBeDefined();
    service.close();
  });

  it("refuses a caller the door did not name, an operator proposing, and an action outside the principal's list", async () => {
    const handlers: HandlerRegistration = ({ registry, downstream, credential, fetch }) => {
      forwardRequestHandlers()({ registry, downstream, credential, fetch });
      registry.register("other_action", { parametersSchema: JsonObjectSchema, execute: () => 1 });
      return ["forward_request", "other_action"];
    };
    const { service } = build({ file: bearerOnlyFile(), handlers });
    expect(await refusal(service.propose(proposal(1).body))).toEqual([403, "ROLE_FORBIDDEN"]);
    const operator = service.principals.principal("ops-oncall") as Principal;
    expect(await refusal(service.propose(proposal(1).body, operator))).toEqual([
      403,
      "ROLE_FORBIDDEN",
    ]);
    const workflow = service.principals.principal("treasury-workflow") as Principal;
    const other = {
      ...proposal(1).body,
      proposal: { action: "other_action", target: "x:1", parameters: {} },
    };
    expect(await refusal(service.propose(other, workflow))).toEqual([
      403,
      "ACTION_NOT_PERMITTED_FOR_PRINCIPAL",
    ]);
    const unregistered = {
      ...proposal(1).body,
      proposal: { action: "missing_action", target: "x:1", parameters: {} },
    };
    expect(await refusal(service.propose(unregistered, workflow))).toEqual([
      422,
      "ACTION_NOT_REGISTERED",
    ]);
    expect(await refusal(service.reconcile({}, operator))).toEqual([403, "ROLE_FORBIDDEN"]);
    expect(await refusal(service.resume({}, operator))).toEqual([403, "ROLE_FORBIDDEN"]);
    service.close();
  });

  it("refuses a proposal whose actor is an operator, and a configuration whose approving person is a proposer", async () => {
    const conflicted = bearerOnlyFile([
      {
        id: "synthetic-oncall-operator",
        role: "OPERATOR",
        scopes: ["status"],
        credential: {
          kind: "BEARER",
          token_sha256: sha256Hex("synthetic-oncall-operator-token-0123456789"),
        },
      },
      {
        id: "self-serving",
        role: "PROPOSER",
        tenant_id: TENANT_ID,
        actor: { id: "synthetic-oncall-operator", type: "AI_AGENT" },
        allowed_actions: ["forward_request"],
        credential: {
          kind: "BEARER",
          token_sha256: sha256Hex("synthetic-self-token-0123456789abcdef"),
        },
      },
    ]);
    const { service } = build({ file: conflicted });
    const selfServing = service.principals.principal("self-serving") as Principal;
    expect(await refusal(service.propose(proposal(1).body, selfServing))).toEqual([
      422,
      "SEPARATION_OF_DUTIES_VIOLATED",
    ]);
    service.close();
    expect(() =>
      build({
        file: bearerOnlyFile(),
        env: {
          EXECUTOR_ESCALATION: "MANAGED",
          PRESENCE_APPROVER_ID: "treasury-workflow",
          PRESENCE_VERIFICATION_LEVEL: "STANDARD",
          PRESENCE_VERIFICATION_METHODS: "WEBAUTHN",
        },
      }),
    ).toThrow(
      "CONFIG_INVALID: PRESENCE_APPROVER_ID (separation of duties: also proposer treasury-workflow)",
    );
  });

  it("lets a proposer reconcile only an intent that is its own", async () => {
    const two = bearerOnlyFile([
      {
        id: "second-workflow",
        role: "PROPOSER",
        tenant_id: TENANT_ID,
        actor: { id: "synthetic-second-agent", type: "AI_AGENT" },
        allowed_actions: ["forward_request"],
        credential: {
          kind: "BEARER",
          token_sha256: sha256Hex("synthetic-second-token-0123456789abcdef"),
        },
      },
    ]);
    const { service } = build({ file: two });
    const first = service.principals.principal("treasury-workflow") as Principal;
    const second = service.principals.principal("second-workflow") as Principal;
    provider.loseNext();
    const lost = await service.propose(proposal(30_00).body, first);
    expect(lost.outcome).toBe("UNKNOWN_AFTER_DISPATCH");
    const recovery = lost.recovery as { intent: Record<string, unknown>; reference: unknown };
    expect(recovery.intent["context"]).toMatchObject({ caller_principal: "treasury-workflow" });
    expect(await refusal(service.reconcile(recovery, second))).toEqual([
      403,
      "INTENT_PRINCIPAL_MISMATCH",
    ]);
    const forged = {
      intent: {
        ...recovery.intent,
        context: { ...(recovery.intent["context"] as object), caller_principal: "second-workflow" },
      },
      reference: recovery.reference,
    };
    expect(await refusal(service.reconcile(forged, second))).toEqual([
      403,
      "INTENT_PRINCIPAL_MISMATCH",
    ]);
    const own = await service.reconcile(recovery, first);
    expect(own.outcome).toBe("COMPLETED");
    expect(
      await refusal(
        service.resume(
          {
            mode: "DIRECT",
            intent: recovery.intent,
            request_id: "synthetic-request-1",
            approval_url: null,
            expires_at: null,
          },
          second,
        ),
      ),
    ).toEqual([409, "ESCALATION_NOT_CONFIGURED"]);
    service.close();
  });

  it("answers an operator's status, reload and metrics within its scopes, and records each", async () => {
    const { service, securityLines } = build({ file: bearerOnlyFile() });
    const operator = service.principals.principal("ops-oncall") as Principal;
    const workflow = service.principals.principal("treasury-workflow") as Principal;
    const status = service.status(operator);
    expect(status).toMatchObject({
      status: "ready",
      mode: "ENFORCEMENT",
      escalation: "NONE",
      actions: ["forward_request"],
      posture: { degraded: false },
      principals: { mode: "PRINCIPALS", count: 2 },
      evidence: { seq: 0 },
    });
    expect(status.secrets).toEqual(["DECIONIS_API_KEY", "DOWNSTREAM_CREDENTIAL"]);
    expect(service.metricsText(operator)).toContain("# EOF");
    expect(await refusal(() => service.status(workflow))).toEqual([403, "ROLE_FORBIDDEN"]);
    expect(await refusal(() => service.status())).toEqual([403, "ROLE_FORBIDDEN"]);
    expect(await refusal(service.reloadSecrets(operator))).toEqual([403, "SCOPE_FORBIDDEN"]);
    expect(events(securityLines).filter((event) => event["event"] === "OPERATOR_ACTION")).toEqual([
      expect.objectContaining({ principal: "ops-oncall", action: "status" }),
      expect.objectContaining({ principal: "ops-oncall", action: "metrics" }),
    ]);
    const full = build({
      file: bearerOnlyFile().replace(
        '"scopes":["status","metrics"]',
        '"scopes":["status","metrics","secrets.reload"]',
      ),
    });
    const reload = await full.service.reloadSecrets(
      full.service.principals.principal("ops-oncall") as Principal,
    );
    expect(reload).toMatchObject({ reason: "OPERATOR", rotated: [], refused: [] });
    expect(full.service.metrics.operatorActions.get({ action: "secrets.reload" })).toBe(1);
    full.service.close();
    service.close();
  });

  it("says when a bearer principal is configured in production, and refuses a file it cannot read", () => {
    const { service, securityLines } = build({ file: bearerOnlyFile(), production: true });
    expect(
      events(securityLines)
        .filter((event) => event["event"] === "BEARER_PRINCIPAL_CONFIGURED")
        .map((event) => event["principal"]),
    ).toEqual(["treasury-workflow", "ops-oncall"]);
    service.close();
    expect(() =>
      build({ env: { EXECUTOR_PRINCIPALS_FILE: "/var/run/agent-safe/principals/missing.json" } }),
    ).toThrow("PRINCIPALS_UNREADABLE: EXECUTOR_PRINCIPALS_FILE");
    expect(() => build({ file: principalsFile() })).toThrow(
      "PRINCIPALS_MTLS_UNCONFIGURED: ops-oncall",
    );
    const jwtOnly = JSON.parse(principalsFile()) as { principals: Record<string, unknown>[] };
    jwtOnly.principals = [jwtOnly.principals[2] as Record<string, unknown>];
    expect(() => build({ file: JSON.stringify(jwtOnly) })).toThrow(
      "PRINCIPALS_JWT_UNCONFIGURED: batch-runner",
    );
  });
});

describe("credential kinds through the service", () => {
  it("signs each downstream request so the provider can verify it with the public key", async () => {
    const keys = generateKeyPairSync("ed25519");
    const pem = keys.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const publicKeyPem = keys.publicKey.export({ type: "spki", format: "pem" }) as string;
    const { service } = build({
      file: bearerOnlyFile(),
      env: {
        DOWNSTREAM_CREDENTIAL: undefined,
        DOWNSTREAM_CREDENTIAL_HEADER: undefined,
        DOWNSTREAM_CREDENTIAL_KIND: "SIGNED_REQUEST",
        DOWNSTREAM_SIGNING_KEY: pem,
        DOWNSTREAM_SIGNING_KEY_ID: "synthetic-key-1",
      },
    });
    const workflow = service.principals.principal("treasury-workflow") as Principal;
    const answer = await service.propose(proposal(40_00).body, workflow);
    expect(answer.outcome).toBe("COMPLETED");
    const seen = provider.requests.at(-1);
    expect(seen?.path).toBe("/dispatches");
    const headers = Object.fromEntries(
      Object.entries(seen?.headers ?? {}).map(([name, value]) => [name, String(value)]),
    );
    expect(headers["authorization"]).toBeUndefined();
    expect(
      SignedRequestCredential.verify(
        {
          method: "POST",
          path: "/dispatches",
          body: seen?.body ?? "",
          idempotencyKey: headers["idempotency-key"] ?? "",
          intentHash: headers["x-agent-safe-intent-hash"] ?? "",
        },
        headers,
        { publicKeyPem },
      ),
    ).toBe(true);
    expect(headers["x-agent-safe-intent-hash"]).toBe(answer.intent_hash);
    service.close();
  });

  it("obtains a token with a private-key assertion and presents it to the provider", async () => {
    const pem = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
      type: "pkcs8",
      format: "pem",
    }) as string;
    const { service } = build({
      file: bearerOnlyFile(),
      env: {
        DOWNSTREAM_CREDENTIAL: undefined,
        DOWNSTREAM_CREDENTIAL_HEADER: undefined,
        DOWNSTREAM_CREDENTIAL_KIND: "PRIVATE_KEY_JWT",
        DOWNSTREAM_TOKEN_URL: `${provider.baseUrl}/oauth/token`,
        DOWNSTREAM_CLIENT_ID: "synthetic-client",
        DOWNSTREAM_PRIVATE_KEY: pem,
        DOWNSTREAM_TOKEN_SCOPE: "payouts:write",
      },
    });
    const workflow = service.principals.principal("treasury-workflow") as Principal;
    const before = provider.requests.length;
    const answer = await service.propose(proposal(50_00).body, workflow);
    expect(answer.outcome).toBe("COMPLETED");
    const since = provider.requests.slice(before);
    expect(since.map((request) => request.path)).toEqual(["/oauth/token", "/dispatches"]);
    expect(new URLSearchParams(since[0]?.body ?? "").get("scope")).toBe("payouts:write");
    expect(since[1]?.headers["authorization"]).toBe(`Bearer ${provider.accessToken}`);
    await service.propose(proposal(51_00).body, workflow);
    expect(provider.requests.slice(before).map((request) => request.path)).toEqual([
      "/oauth/token",
      "/dispatches",
      "/dispatches",
    ]);
    service.close();
    expect(CALLER_TOKEN).not.toBe(provider.accessToken);
  });
});
