import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JsonObjectSchema } from "@decionis/agent-safe-pipeline";
import {
  LOCAL_AUTHORITY_API_KEY,
  LocalAuthority,
  LocalPresence,
} from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { forwardRequestHandlers } from "../../src/handlers/ForwardRequestHandler.js";
import type { HandlerRegistration } from "../../src/handlers/HandlerRegistration.js";
import type { PostureState } from "../../src/posture/HostPosture.js";
import type { CompositeSecretStore } from "../../src/secrets/CompositeSecretStore.js";
import type { EscalationHandoff } from "../../src/service/EscalationResolver.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import {
  APPROVER_ID,
  CALLER_TOKEN,
  DOWNSTREAM_CREDENTIAL,
  LOOPBACK_ORIGIN,
  closedPort,
  collectedEvents,
  loopbackEnvironment,
  openSecrets,
  proposal,
  type Escalation,
} from "../support/Environment.js";
import { ProviderDouble } from "../support/ProviderDouble.js";

// The person completes every ceremony by hand: nothing auto-approves.
const presence = new LocalPresence({ autoComplete: "MANUAL", roles: { [APPROVER_ID]: "CRO" } });
const authority = new LocalAuthority({ presence });
const provider = new ProviderDouble();
const lines: string[] = [];
const securityLines: string[] = [];

interface BuildOptions {
  readonly presenceBaseUrl?: string;
  readonly handlers?: HandlerRegistration;
  /** Variables to add, or to remove when `undefined`. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly posture?: PostureState;
}

function build(
  mode: "SHADOW" | "ENFORCEMENT",
  escalation: Escalation = "NONE",
  options: BuildOptions = {},
): { readonly service: TrustedExecutorService; readonly secrets: CompositeSecretStore } {
  const env: Record<string, string> = loopbackEnvironment(
    { authority, presence, providerBaseUrl: provider.baseUrl },
    mode,
    escalation,
    options.presenceBaseUrl,
  );
  for (const [key, value] of Object.entries(options.env ?? {})) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  const config = ExecutorConfigLoader.load(env);
  const secrets = openSecrets(env, config, collectedEvents(securityLines));
  const service = TrustedExecutorService.create(
    config,
    secrets,
    options.handlers ?? forwardRequestHandlers(),
    {
      emit: (line) => lines.push(line),
      security: collectedEvents(securityLines),
      ...(options.posture === undefined ? {} : { posture: options.posture }),
    },
  );
  return { service, secrets };
}

function create(
  mode: "SHADOW" | "ENFORCEMENT",
  escalation: Escalation = "NONE",
  options: BuildOptions = {},
): TrustedExecutorService {
  return build(mode, escalation, options).service;
}

async function refusal(work: Promise<unknown>): Promise<ServiceError> {
  try {
    await work;
  } catch (error) {
    if (error instanceof ServiceError) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

type Mutable = {
  intent: { parameters: Record<string, unknown>; expiresAt: string; action: string };
};
const copy = (handoff: EscalationHandoff | null): EscalationHandoff & Mutable =>
  JSON.parse(JSON.stringify(handoff)) as EscalationHandoff & Mutable;

beforeAll(async () => {
  await presence.start();
  await authority.start();
  await provider.start();
});

afterAll(async () => {
  await provider.stop();
  await authority.stop();
  await presence.stop();
});

describe("shadow", () => {
  it("observes every verdict and executes nothing", async () => {
    const service = create("SHADOW");
    expect(service.mode).toBe("SHADOW");
    expect(service.escalationMode).toBe("NONE");
    const allowed = await service.propose(proposal(5_000).body);
    expect(allowed).toMatchObject({
      mode: "SHADOW",
      verdict: "ALLOW",
      outcome: "OBSERVED",
      executed: false,
      authorization: null,
      fail_closed: false,
    });
    expect(allowed.decision_id).toEqual(expect.any(String));
    const blocked = await service.propose(proposal(500_000).body);
    expect(blocked).toMatchObject({ verdict: "BLOCK", executed: false });
    expect(provider.requests).toHaveLength(0);
    expect(authority.grants.size).toBe(0);
    const observational = lines.filter(
      (line) => line.includes('"SHADOW_EVALUATED"') && line.includes('"OBSERVATIONAL"'),
    );
    expect(observational.length).toBeGreaterThanOrEqual(2);
  });

  it("has no escalation to resume", async () => {
    const service = create("SHADOW");
    const held = await service.propose(proposal(50_000).body);
    const refused = await refusal(
      service.resume({
        mode: "DIRECT",
        intent: {},
        request_id: "synthetic-request-1",
        approval_url: null,
        expires_at: null,
      }),
    );
    expect(held.verdict).toBe("ESCALATE");
    expect(refused).toMatchObject({ status: 409, code: "ESCALATION_NOT_CONFIGURED" });
  });
});

describe("enforcement without an escalation shape", () => {
  const service = () => create("ENFORCEMENT");

  it("executes an ALLOW once on a claimed grant", async () => {
    const before = provider.dispatches;
    const { body, key } = proposal(5_000);
    const allowed = await service().propose(body);
    expect(allowed).toMatchObject({
      mode: "ENFORCEMENT",
      verdict: "ALLOW",
      outcome: "COMPLETED",
      executed: true,
      finalization: "RECORDED",
      fail_closed: false,
      recovery: null,
      escalation: null,
      result: { status: 202, accepted: true },
    });
    expect(allowed.authorization?.grant_id).toEqual(expect.any(String));
    expect(allowed.authorization?.decision_id).toBe(allowed.decision_id);
    expect(provider.dispatches).toBe(before + 1);
    const dispatch = provider.requests.at(-1);
    expect(dispatch?.headers["idempotency-key"]).toBe(key);
    expect(dispatch?.headers["authorization"]).toBe(DOWNSTREAM_CREDENTIAL);
    expect(dispatch?.headers["x-agent-safe-intent-hash"]).toBe(allowed.intent_hash);
    expect(dispatch?.headers["x-agent-safe-decision-id"]).toBe(allowed.decision_id);
  });

  it("returns an ESCALATE as the hold itself and a BLOCK as a refusal", async () => {
    const before = provider.dispatches;
    const held = await service().propose(proposal(50_000).body);
    expect(held).toMatchObject({
      verdict: "ESCALATE",
      outcome: "BLOCKED",
      executed: false,
      authorization: null,
      escalation: null,
    });
    expect(held.reason_codes).not.toContain("ESCALATION_HANDOFF_UNAVAILABLE");
    const blocked = await service().propose(proposal(500_000).body);
    expect(blocked).toMatchObject({ verdict: "BLOCK", outcome: "BLOCKED", executed: false });
    expect(provider.dispatches).toBe(before);
  });

  it("refuses a proposal that carries trusted fields", async () => {
    const refused = await refusal(
      service().propose(
        proposal(5_000, { tenant_id: "00000000-0000-4000-8000-000000000001" }).body,
      ),
    );
    expect(refused).toMatchObject({ status: 400, code: "REQUEST_INVALID" });
  });

  it("refuses an unregistered action before any authority is asked", async () => {
    const before = authority.requests.length;
    const { body } = proposal(5_000);
    const refused = await refusal(
      service().propose({
        ...body,
        proposal: { ...(body["proposal"] as object), action: "erase" },
      }),
    );
    expect(refused).toMatchObject({ status: 422, code: "ACTION_NOT_REGISTERED" });
    expect(authority.requests.length).toBe(before);
  });

  it("refuses a proposal the intent contract cannot capture", async () => {
    const handlers: HandlerRegistration = ({ registry }) => {
      registry.register("Not An Action", { parametersSchema: JsonObjectSchema, execute: () => 1 });
      return ["Not An Action"];
    };
    const custom = create("ENFORCEMENT", "NONE", { handlers });
    expect(custom.actions).toEqual(["Not An Action"]);
    const { body } = proposal(5_000);
    const refused = await refusal(
      custom.propose({
        ...body,
        proposal: { ...(body["proposal"] as object), action: "Not An Action" },
      }),
    );
    expect(refused).toMatchObject({ status: 400, code: "PROPOSAL_INVALID" });
  });

  it("has no escalation to resume", async () => {
    const refused = await refusal(
      service().resume({
        mode: "DIRECT",
        intent: {},
        request_id: "synthetic-request-1",
        approval_url: null,
        expires_at: null,
      }),
    );
    expect(refused).toMatchObject({ status: 409, code: "ESCALATION_NOT_CONFIGURED" });
  });
});

describe("reconciliation", () => {
  it("reconciles a lost response by reading the provider, never re-sending", async () => {
    const service = create("ENFORCEMENT");
    provider.loseNext();
    const effects = provider.effects.size;
    const { body, key } = proposal(5_000);
    const lost = await service.propose(body);
    expect(lost).toMatchObject({ outcome: "UNKNOWN_AFTER_DISPATCH", executed: null });
    expect(lost.recovery).not.toBeNull();
    expect(provider.effects.size).toBe(effects + 1);

    const dispatches = provider.dispatches;
    const reconciled = await service.reconcile(lost.recovery);
    expect(reconciled).toMatchObject({
      outcome: "COMPLETED",
      executed: true,
      recovered: true,
      intent_hash: lost.intent_hash,
      reason_codes: [],
    });
    expect(reconciled.authorization?.grant_id).toBe(lost.recovery?.reference.grantId);
    expect(provider.dispatches).toBe(dispatches);

    const tampered = JSON.parse(JSON.stringify(lost.recovery)) as {
      intent: { parameters: Record<string, unknown> };
    };
    tampered.intent.parameters["amountMinor"] = 5_000_000;
    const refused = await service.reconcile(tampered);
    expect(refused).toMatchObject({
      outcome: "BLOCKED",
      executed: false,
      recovered: false,
      reason_codes: ["RECOVERY_BINDING_MISMATCH"],
      authorization: null,
    });

    const repeated = await service.propose(proposal(5_000, { idempotency_key: key }).body);
    expect(repeated.outcome).toBe("COMPLETED");
    expect(provider.effects.size).toBe(effects + 1);
  });

  it("refuses a malformed request or an intent that is not one", async () => {
    const service = create("ENFORCEMENT");
    expect(await refusal(service.reconcile({}))).toMatchObject({
      status: 400,
      code: "REQUEST_INVALID",
    });
    const reference = {
      version: "agent-safe.recovery/1",
      decisionId: "fixture_decision_1",
      dossierId: "fixture_dossier_1",
      grantId: "fixture_grant_1",
      intentHash: `sha256:${"0".repeat(64)}`,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      idempotencyKey: "payout-0-v1",
    };
    expect(
      await refusal(service.reconcile({ intent: { nothing: true }, reference })),
    ).toMatchObject({ status: 400, code: "INTENT_INVALID" });
  });
});

describe("direct escalation", () => {
  it("opens the Presence request, resumes once the person answers, and runs once", async () => {
    const service = create("ENFORCEMENT", "DIRECT");
    expect(service.escalationMode).toBe("DIRECT");
    const effects = provider.effects.size;
    const held = await service.propose(proposal(50_000).body);
    expect(held).toMatchObject({
      verdict: "ESCALATE",
      outcome: "ESCALATE_PENDING",
      executed: false,
      authorization: null,
    });
    const handoff = held.escalation;
    if (handoff?.mode !== "DIRECT") throw new Error("expected a direct handoff");
    expect(presence.verification(handoff.request_id)?.intentHash).toBe(held.intent_hash);

    const pending = await service.resume(handoff);
    expect(pending).toMatchObject({
      outcome: "ESCALATE_PENDING",
      executed: false,
      reason_codes: ["PRESENCE_HUMAN_REQUIRED"],
    });
    expect(pending.escalation).toMatchObject({ mode: "DIRECT", request_id: handoff.request_id });
    expect(provider.effects.size).toBe(effects);

    presence.approve(handoff.request_id);
    const tampered = copy(handoff);
    tampered.intent.parameters["amountMinor"] = 5_000_000;
    const refused = await service.resume(tampered);
    expect(refused.executed).toBe(false);
    expect(provider.effects.size).toBe(effects);

    const approved = await service.resume(handoff);
    expect(approved).toMatchObject({ outcome: "COMPLETED", executed: true });
    expect(provider.effects.size).toBe(effects + 1);
    await service.resume(handoff);
    expect(provider.effects.size).toBe(effects + 1);
  });

  it("turns a denial into a BLOCK", async () => {
    const service = create("ENFORCEMENT", "DIRECT");
    const effects = provider.effects.size;
    const held = await service.propose(proposal(50_000).body);
    const handoff = held.escalation;
    if (handoff?.mode !== "DIRECT") throw new Error("expected a direct handoff");
    presence.deny(handoff.request_id);
    const denied = await service.resume(handoff);
    expect(denied).toMatchObject({ verdict: "BLOCK", executed: false });
    expect(provider.effects.size).toBe(effects);
  });

  it("refuses an expired intent, an unregistered action, and the wrong shape", async () => {
    const service = create("ENFORCEMENT", "DIRECT");
    const held = await service.propose(proposal(50_000).body);
    const handoff = held.escalation;
    if (handoff?.mode !== "DIRECT") throw new Error("expected a direct handoff");

    const expired = copy(handoff);
    expired.intent.expiresAt = new Date(Date.now() - 1_000).toISOString();
    expect(await refusal(service.resume(expired))).toMatchObject({
      status: 409,
      code: "INTENT_EXPIRED",
    });

    const unregistered = copy(handoff);
    unregistered.intent.action = "erase";
    expect(await refusal(service.resume(unregistered))).toMatchObject({
      status: 422,
      code: "ACTION_NOT_REGISTERED",
    });

    expect(await refusal(service.resume({ mode: "DIRECT" }))).toMatchObject({
      status: 400,
      code: "REQUEST_INVALID",
    });

    const managedShape = await service.resume({
      mode: "MANAGED",
      intent: handoff.intent,
      escalation: {
        escalationId: "synthetic-escalation-1",
        intentId: handoff.intent.intentId,
        status: "AWAITING_APPROVER",
        outcome: "ESCALATE_PENDING",
        expiresAt: handoff.intent.expiresAt,
        reasonCodes: [],
      },
    });
    expect(managedShape).toMatchObject({
      verdict: "BLOCK",
      outcome: "BLOCKED",
      fail_closed: true,
      reason_codes: ["ESCALATION_MODE_MISMATCH"],
    });
  });

  it("fails closed when Presence cannot be reached", async () => {
    const port = await closedPort();
    const service = create("ENFORCEMENT", "DIRECT", {
      presenceBaseUrl: `${LOOPBACK_ORIGIN}:${port}`,
    });
    const held = await service.propose(proposal(50_000).body);
    expect(held).toMatchObject({
      verdict: "ESCALATE",
      outcome: "BLOCKED",
      executed: false,
      escalation: null,
    });
    expect(held.reason_codes).toContain("ESCALATION_HANDOFF_UNAVAILABLE");
    const resumed = await service.resume({
      mode: "DIRECT",
      intent: JSON.parse(JSON.stringify(await captured(service))) as Record<string, unknown>,
      request_id: "synthetic-request-unreachable",
      approval_url: null,
      expires_at: null,
    });
    expect(resumed).toMatchObject({
      verdict: "BLOCK",
      fail_closed: true,
      reason_codes: ["PRESENCE_UNAVAILABLE"],
    });
  });
});

/** An intent the executor captured, as the caller would present it back. */
async function captured(service: TrustedExecutorService): Promise<unknown> {
  provider.loseNext();
  const lost = await service.propose(proposal(5_000).body);
  return lost.recovery?.intent;
}

describe("managed escalation", () => {
  it("hands back the authority's state and runs once at GRANT_READY", async () => {
    const service = create("ENFORCEMENT", "MANAGED");
    expect(service.escalationMode).toBe("MANAGED");
    const effects = provider.effects.size;
    const held = await service.propose(proposal(50_000).body);
    expect(held).toMatchObject({ verdict: "ESCALATE", outcome: "ESCALATE_PENDING" });
    const handoff = held.escalation;
    if (handoff?.mode !== "MANAGED") throw new Error("expected a managed handoff");
    const escalationId = handoff.escalation.escalationId;

    const forged = copy(handoff) as typeof handoff;
    (forged.escalation as { escalationId: string }).escalationId = "synthetic-escalation-forged";
    const refused = await service.resume(forged);
    expect(refused.executed).toBe(false);
    expect(provider.effects.size).toBe(effects);

    presence.approve(authority.escalations.get(escalationId)?.presenceRequestId ?? "");
    let resumed = await service.resume(handoff);
    for (let lookups = 1; lookups < 10 && resumed.outcome === "ESCALATE_PENDING"; lookups += 1) {
      resumed = await service.resume(resumed.escalation);
    }
    expect(resumed).toMatchObject({ outcome: "COMPLETED", executed: true });
    expect(provider.effects.size).toBe(effects + 1);
  });
});

describe("posture while running", () => {
  it("refuses new enforcement work while a drift stands and leaves shadow observation alone", async () => {
    const posture = { degraded: true };
    const enforcing = create("ENFORCEMENT", "NONE", { posture });
    const before = authority.requests.length;
    expect(await refusal(enforcing.propose(proposal(5_000).body))).toMatchObject({
      status: 503,
      code: "POSTURE_DEGRADED",
    });
    expect(authority.requests.length).toBe(before);
    expect(
      await refusal(
        enforcing.resume({
          mode: "DIRECT",
          intent: {},
          request_id: "synthetic-request-1",
          approval_url: null,
          expires_at: null,
        }),
      ),
    ).toMatchObject({ status: 409, code: "ESCALATION_NOT_CONFIGURED" });
    const observing = create("SHADOW", "NONE", { posture });
    expect(await observing.propose(proposal(5_000).body)).toMatchObject({ outcome: "OBSERVED" });
    posture.degraded = false;
    expect(await enforcing.propose(proposal(5_000).body)).toMatchObject({ outcome: "COMPLETED" });
  });
});

describe("credential rotation", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-rotation-"));
  afterAll(() => rmSync(directory, { recursive: true, force: true }));

  it("uses the authority key the file holds now, and fails closed on a wrong one", async () => {
    const path = join(directory, "decionis-api-key");
    writeFileSync(path, `${LOCAL_AUTHORITY_API_KEY}\n`, { mode: 0o600 });
    const { service, secrets } = build("ENFORCEMENT", "NONE", {
      env: { DECIONIS_API_KEY: undefined, DECIONIS_API_KEY_FILE: path },
    });
    expect(await service.propose(proposal(5_000).body)).toMatchObject({ outcome: "COMPLETED" });

    writeFileSync(path, "synthetic-wrong-key\n");
    expect((await secrets.reload("OPERATOR")).rotated).toEqual(["DECIONIS_API_KEY"]);
    const refused = await service.propose(proposal(5_000).body);
    expect(refused).toMatchObject({ verdict: "BLOCK", fail_closed: true, executed: false });
    expect(securityLines.some((line) => line.includes('"AUTHORITY_CLIENTS_REBUILT"'))).toBe(true);

    writeFileSync(path, `${LOCAL_AUTHORITY_API_KEY}\n`);
    await secrets.reload("OPERATOR");
    expect(await service.propose(proposal(5_000).body)).toMatchObject({ outcome: "COMPLETED" });
    service.close();
    secrets.close();
  });
});

describe("sealed egress", () => {
  it("refuses a handler that reaches an origin the configuration never named, before any socket exists", async () => {
    const handlers: HandlerRegistration = ({ registry, fetch }) => {
      registry.register("reach_elsewhere", {
        parametersSchema: JsonObjectSchema,
        execute: async ({ dispatch }) => {
          await fetch("https://elsewhere.example/v1/anything", { method: "POST", body: "{}" });
          return await dispatch.run(() => ({ reached: true }));
        },
      });
      return ["reach_elsewhere"];
    };
    const service = create("ENFORCEMENT", "NONE", { handlers });
    const before = securityLines.length;
    const answer = await service.propose({
      ...proposal(25_00).body,
      proposal: {
        action: "reach_elsewhere",
        target: "elsewhere:1",
        parameters: { amountMinor: 2500 },
      },
    });
    expect(answer.verdict).toBe("ALLOW");
    expect(answer.executed).toBe(false);
    expect(answer.outcome).toBe("FAILED_BEFORE_DISPATCH");
    expect(answer.reason_codes).toContain("HANDLER_FAILED_BEFORE_DISPATCH");
    const refusals = securityLines
      .slice(before)
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((event) => event["event"] === "EGRESS_REFUSED");
    expect(refusals).toEqual([
      expect.objectContaining({
        origin: "https://elsewhere.example",
        code: "EGRESS_ORIGIN_NOT_ALLOWED",
      }),
    ]);
    expect(service.metrics.egressRefused.get({ code: "EGRESS_ORIGIN_NOT_ALLOWED" })).toBe(1);
    expect(service.metrics.proposals.get({ verdict: "ALLOW" })).toBe(1);
    expect(service.metrics.executions.get({ outcome: "FAILED_BEFORE_DISPATCH" })).toBe(1);
    service.close();
  });
});

describe("evidence", () => {
  it("chains every audit line and names the legacy caller when the service is used directly", () => {
    const first = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
    expect(first).toMatchObject({
      stream: "agent-safe.executor-evidence/1",
      seq: 1,
      caller_principal: "legacy-caller",
    });
    expect(typeof first["hash"]).toBe("string");
    expect(lines.every((line) => line.includes('"caller_principal":"legacy-caller"'))).toBe(true);
  });

  it("never writes a credential, token, or key to an audit or security line", () => {
    const everything = [...lines, ...securityLines].join("\n");
    expect(everything).not.toContain(CALLER_TOKEN);
    expect(everything).not.toContain(DOWNSTREAM_CREDENTIAL);
    expect(everything).not.toContain(LOCAL_AUTHORITY_API_KEY);
    expect(everything).not.toContain("synthetic-wrong-key");
    for (const token of authority.grants.keys()) expect(everything).not.toContain(token);
    expect(lines.filter((line) => line.includes('"EXECUTION_COMPLETED"')).length).toBeGreaterThan(
      0,
    );
  });
});
