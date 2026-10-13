import { generateKeyPairSync } from "node:crypto";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  mintSignedSignal,
  LocalAuthority,
  LocalPresence,
} from "@decionis/agent-safe-pipeline/testing";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cardHandlers } from "../../src/adapters/cards/CardHandlers.js";
import { prepareCardPurchase } from "../../src/adapters/cards/CardEffect.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import type { Principal } from "../../src/identity/PrincipalRegistry.js";
import { HaltSwitch } from "../../src/incident/HaltSwitch.js";
import { InMemoryExecutionJournal } from "../../src/journal/InMemoryExecutionJournal.js";
import type { ActionResponse } from "../../src/service/Requests.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import type { LoadPg, PgPool } from "../../src/edge/EdgeReplay.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { FakeCardHoldsSql } from "../support/FakeCardHoldsSql.js";
import {
  TENANT_ID,
  APPROVER_ID,
  collectedEvents,
  loopbackEnvironment,
  openSecrets,
} from "../support/Environment.js";

/** A cardholder's tap, as the presence provider would sign it; the double accepts only this one. */
const TAPPED =
  "eyJhbGciOiJFZERTQSIsInR5cCI6ImRlY2lvbmlzLXByZXNlbmNlLWF0dGVzdGF0aW9uK2p3dCJ9.dGFwcGVk.c2lnbmVk";
const FORGED = "eyJhbGciOiJFZERTQSJ9.Zm9yZ2Vk.c2lnbmVk";

const authority = new LocalAuthority({
  verifyAttestation: (attestation) => attestation === TAPPED,
});

beforeAll(async () => {
  await authority.start();
});

afterAll(async () => {
  await authority.stop();
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** The issuer's authorization hook: an operator holding `cards.authorize` and nothing else. */
const ISSUER: Principal = {
  id: "synthetic-issuer-hook",
  role: "OPERATOR",
  tenantId: null,
  actor: null,
  allowedActions: new Set(),
  scopes: new Set(["cards.authorize"]),
  credential: { kind: "BEARER", tokenDigest: Buffer.alloc(32) },
  rateLimit: null,
} as unknown as Principal;

interface Built {
  readonly service: TrustedExecutorService;
  readonly halt: HaltSwitch;
  readonly journal: InMemoryExecutionJournal;
  readonly lines: string[];
  readonly securityLines: string[];
}

function build(
  mode: "ENFORCEMENT" | "SHADOW" = "ENFORCEMENT",
  options: {
    readonly env?: Record<string, string>;
    readonly posture?: { degraded: boolean };
    readonly authority?: LocalAuthority;
    readonly presence?: LocalPresence;
    readonly escalation?: "NONE" | "DIRECT";
    readonly loadPg?: LoadPg;
  } = {},
): Built {
  const env: Record<string, string> = {
    ...loopbackEnvironment(
      {
        authority: options.authority ?? authority,
        ...(options.presence === undefined ? {} : { presence: options.presence }),
        providerBaseUrl: "http://127.0.0.1:9",
      },
      mode,
      options.escalation ?? "NONE",
    ),
    DOWNSTREAM_SYSTEM: "synthetic-issuer",
    DOWNSTREAM_OPERATION: "card_purchase",
    EXECUTOR_ACTOR_ID: "synthetic-shopping-agent",
    ...options.env,
  };
  const config = ExecutorConfigLoader.load(env);
  const lines: string[] = [];
  const securityLines: string[] = [];
  const events = collectedEvents(securityLines);
  const halt = new HaltSwitch({ events });
  const journal = new InMemoryExecutionJournal();
  const service = TrustedExecutorService.create(
    config,
    openSecrets(env, config, events),
    cardHandlers(),
    {
      emit: (line) => lines.push(line),
      security: events,
      journal,
      halt,
      ...(options.posture === undefined ? {} : { posture: options.posture }),
      ...(options.loadPg === undefined ? {} : { loadPg: options.loadPg }),
    },
  );
  return { service, halt, journal, lines, securityLines };
}

let sequence = 0;

function purchase(amountMinor = 4_250, overrides: Record<string, unknown> = {}) {
  sequence += 1;
  const parameters = {
    cardTokenRef: `fixture_card_ref_${sequence}`,
    amountMinor,
    currency: "EUR",
    merchantId: "fixture_merchant_17",
    ...overrides,
  };
  return {
    parameters,
    body: {
      proposal: {
        action: "card.purchase",
        target: `card:${String(parameters.cardTokenRef)}`,
        parameters,
      },
      idempotency_key: `fixture-card-purchase-${sequence}`,
    },
  };
}

function authorizationFor(
  parameters: { readonly cardTokenRef: string; readonly amountMinor: number },
  overrides: Record<string, unknown> = {},
) {
  sequence += 1;
  return {
    authorization_id: `fixture_auth_${sequence}`,
    card_token_ref: parameters.cardTokenRef,
    amount_minor: parameters.amountMinor,
    currency: "EUR",
    merchant_id: "fixture_merchant_17",
    ...overrides,
  };
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

const requestsTo = (part: string) =>
  authority.requests.filter((request) => request.path.includes(part));

const parsed = (lines: readonly string[]): Record<string, unknown>[] =>
  lines.map((line) => JSON.parse(line) as Record<string, unknown>);

const auditTypes = (lines: readonly string[]): string[] =>
  parsed(lines).map((line) => String(line["event"]));

describe("a card purchase through the whole boundary", () => {
  it("binds an authorization id before concurrent requests can claim different cards", async () => {
    const { service } = build();
    try {
      const first = purchase();
      const second = purchase();
      await service.propose(first.body);
      await service.propose(second.body);
      const asked = authorizationFor(first.parameters);
      const claims = requestsTo("claim-token").length;
      const [winner, collision] = await Promise.all([
        service.authorizeCard(asked, ISSUER),
        service.authorizeCard(
          authorizationFor(second.parameters, { authorization_id: asked.authorization_id }),
          ISSUER,
        ),
      ]);
      expect(winner.decision).toBe("APPROVE");
      expect(collision).toEqual({ decision: "NO_MATCH", code: "AUTHORIZATION_ID_REUSED" });
      expect(requestsTo("claim-token").length).toBe(claims + 1);
      expect(await service.authorizeCard(asked, ISSUER)).toEqual(winner);
      expect(
        await service.authorizeCard(authorizationFor(second.parameters), ISSUER),
      ).toMatchObject({
        decision: "APPROVE",
      });
    } finally {
      service.close();
    }
  });

  it("joins concurrent retries of the exact authorization and claims once", async () => {
    const { service } = build();
    try {
      const { parameters, body } = purchase();
      await service.propose(body);
      const asked = authorizationFor(parameters);
      const claims = requestsTo("claim-token").length;
      const answers = await Promise.all(
        Array.from({ length: 8 }, () => service.authorizeCard(asked, ISSUER)),
      );
      expect(answers[0]?.decision).toBe("APPROVE");
      expect(answers.every((answer) => JSON.stringify(answer) === JSON.stringify(answers[0]))).toBe(
        true,
      );
      expect(requestsTo("claim-token").length).toBe(claims + 1);
    } finally {
      service.close();
    }
  });

  it("holds the grant on an ALLOW, claims it once on a matching authorization, and finalizes with the effect", async () => {
    const { service, journal, lines, securityLines } = build();
    const { parameters, body } = purchase();
    const claimsBefore = requestsTo("claim-token").length;

    const held = await service.propose(body);

    expect(held).toMatchObject({
      verdict: "ALLOW",
      outcome: "HELD_FOR_AUTHORIZATION",
      executed: false,
      authorization: null,
      finalization: null,
      effect: null,
      result: { status: "HELD_FOR_AUTHORIZATION" },
    });
    const expiresAt = (held.result as { expires_at: string }).expires_at;
    expect(Date.parse(expiresAt)).toBeGreaterThan(Date.now());
    // Nothing is claimed until the issuer asks.
    expect(requestsTo("claim-token").length).toBe(claimsBefore);
    // The grant is bound to the purchase's expected effect.
    const evaluated = requestsTo("enforce-and-bind").at(-1)?.body as Record<string, unknown>;
    expect(evaluated["expected_effect_digest"]).toBe(
      prepareCardPurchase(parameters).expectedEffectDigest,
    );
    expect(auditTypes(lines)).toEqual(["INTENT_CAPTURED", "AUTHORITY_DECISION", "GRANT_HELD"]);
    expect(await journal.openAttempts()).toEqual([]);

    // A second purchase on the same card waits, before the authority is asked.
    const evaluations = requestsTo("enforce-and-bind").length;
    const second = await refusal(
      service.propose({
        ...body,
        idempotency_key: "fixture-card-purchase-again",
      }),
    );
    expect([second.status, second.code]).toEqual([409, "CARD_GRANT_ALREADY_HELD"]);
    expect(requestsTo("enforce-and-bind").length).toBe(evaluations);

    // A purchase on the card that does not match leaves the grant spendable;
    // holds are keyed by the merchant too, so another merchant finds none.
    for (const [overrides, code] of [
      [{ currency: "USD" }, "CURRENCY_MISMATCH"],
      [{ merchant_id: "fixture_merchant_18" }, "NO_GRANT"],
      [{ amount_minor: 4_251 }, "AMOUNT_EXCEEDS_GRANT"],
      [{ card_token_ref: "fixture_card_ref_none" }, "NO_GRANT"],
    ] as const) {
      expect(await service.authorizeCard(authorizationFor(parameters, overrides), ISSUER)).toEqual({
        decision: "NO_MATCH",
        code,
      });
    }
    expect(requestsTo("claim-token").length).toBe(claimsBefore);

    // The authorization the grant was for: claimed once, and approved.
    const asked = authorizationFor(parameters, { amount_minor: 4_000 });
    const approved = await service.authorizeCard(asked, ISSUER);
    expect(approved).toMatchObject({
      decision: "APPROVE",
      authorization_id: asked.authorization_id,
      intent_id: held.intent_id,
      intent_hash: held.intent_hash,
      decision_id: held.decision_id,
      dossier_id: held.dossier_id,
    });
    expect(requestsTo("claim-token").length).toBe(claimsBefore + 1);
    // The issuer retrying the same authorization gets the same answer, and no second claim.
    expect(await service.authorizeCard(asked, ISSUER)).toEqual(approved);
    expect(await service.authorizeCard({ ...asked, amount_minor: 3_000 }, ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "AUTHORIZATION_ID_REUSED",
    });
    // Another authorization for the spent grant is refused, with no claim.
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "GRANT_ALREADY_USED",
    });
    expect(requestsTo("claim-token").length).toBe(claimsBefore + 1);
    expect(await journal.openAttempts()).toMatchObject([
      { intentId: held.intent_id, state: "CLAIMED" },
    ]);

    // The issuer's result: the effect, compared with the grant, finalized once.
    const result = await service.settleCard(
      asked.authorization_id,
      { status: "APPROVED", approved_amount_minor: 4_000, auth_code: "A1B2C3" },
      ISSUER,
    );
    expect(result).toMatchObject({
      authorization_id: asked.authorization_id,
      intent_id: held.intent_id,
      outcome: "COMMITTED",
      executed: true,
      finalization: "RECORDED",
      reason_codes: [],
      effect: {
        outcome: "COMMITTED",
        comparison: "MATCH",
        confirmation: "CONFIRMED",
        observation_method: "EVENT_CONFIRMATION",
        provider_reference: asked.authorization_id,
      },
    });
    const finalized = requestsTo("finalize-token").at(-1);
    expect(finalized?.body).toMatchObject({ outcome: "COMMITTED" });
    expect(finalized?.response?.status).toBe(200);
    expect(await journal.openAttempts()).toEqual([]);
    const again = await refusal(
      service.settleCard(asked.authorization_id, { status: "APPROVED" }, ISSUER),
    );
    expect([again.status, again.code]).toEqual([409, "CARD_RESULT_ALREADY_RECORDED"]);

    expect(auditTypes(lines).slice(3)).toEqual([
      "EXECUTION_BLOCKED",
      "GRANT_CONSUMED",
      "EXECUTION_STARTED",
      "EXECUTION_COMPLETED",
    ]);
    const security = parsed(securityLines).map((line) => line["event"]);
    expect(security).toContain("CARD_GRANT_HELD");
    expect(security).toContain("CARD_AUTHORIZATION_MATCHED");
    expect(security).toContain("CARD_AUTHORIZATION_SETTLED");
    expect(security.filter((event) => event === "CARD_AUTHORIZATION_NO_MATCH")).toHaveLength(6);
    // No card reference, amount or merchant reaches either stream.
    for (const line of [...lines, ...securityLines]) {
      expect(line).not.toContain(parameters.cardTokenRef);
      expect(line).not.toContain("fixture_merchant_17");
    }
    service.close();
  });

  it("finalizes a decline as a refusal, and a result after the lease as indeterminate", async () => {
    const { service, journal, securityLines } = build();
    const declined = purchase();
    await service.propose(declined.body);
    const first = authorizationFor(declined.parameters);
    expect(await service.authorizeCard(first, ISSUER)).toMatchObject({ decision: "APPROVE" });
    expect(
      await service.settleCard(first.authorization_id, { status: "DECLINED" }, ISSUER),
    ).toMatchObject({
      outcome: "FAILED",
      executed: false,
      finalization: "RECORDED",
      reason_codes: ["ISSUER_DECLINED"],
      effect: { outcome: "FAILED", confirmation: "NOT_EFFECTED" },
    });
    expect(requestsTo("finalize-token").at(-1)?.body).toMatchObject({ outcome: "FAILED" });
    expect(parsed(securityLines).map((line) => line["event"])).toContain("PROVIDER_REFUSED");

    const late = purchase();
    await service.propose(late.body);
    const second = authorizationFor(late.parameters);
    const answer = await service.authorizeCard(second, ISSUER);
    if (answer.decision !== "APPROVE") throw new Error("TEST_EXPECTED_APPROVE");
    const leaseEnd = Date.parse(answer.lease_expires_at);
    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(leaseEnd + 1);
    const result = await service.settleCard(
      second.authorization_id,
      { status: "APPROVED" },
      ISSUER,
    );
    vi.spyOn(Date, "now").mockReturnValue(now);
    expect(result).toMatchObject({
      outcome: "INDETERMINATE",
      executed: null,
      finalization: "RECORDED",
      reason_codes: ["CLAIM_LEASE_EXPIRED", "INDETERMINATE_OUTCOME"],
      effect: { outcome: "INDETERMINATE", confirmation: "UNKNOWN" },
    });
    expect(requestsTo("finalize-token").at(-1)?.body).toMatchObject({ outcome: "INDETERMINATE" });
    expect(journal.all.at(-1)).toMatchObject({
      record: "ATTEMPT_CLOSED",
      outcome: "INDETERMINATE_AFTER_LEASE",
      executed: null,
    });
    service.close();
  });

  it("halts on an issuer that approved more than the grant authorised", async () => {
    const { service, halt, securityLines } = build();
    const { parameters, body } = purchase();
    await service.propose(body);
    const asked = authorizationFor(parameters);
    await service.authorizeCard(asked, ISSUER);
    const result = await service.settleCard(
      asked.authorization_id,
      { status: "APPROVED", approved_amount_minor: parameters.amountMinor + 1 },
      ISSUER,
    );
    expect(result).toMatchObject({
      outcome: "COMMITTED",
      reason_codes: ["EFFECT_MISMATCH"],
      effect: { comparison: "MISMATCH", mismatched_fields: ["amount_minor_ceiling"] },
    });
    expect(parsed(securityLines).find((line) => line["event"] === "EFFECT_MISMATCH")).toMatchObject(
      { fields: ["amount_minor_ceiling"] },
    );
    expect(halt.current).toMatchObject({ halted: true, trigger: "EFFECT_MISMATCH" });
    // A halted executor claims nothing.
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "EXECUTOR_HALTED",
    });
    service.close();
  });

  it("answers a grant that expired before the issuer asked, without claiming it", async () => {
    const { service } = build();
    const { parameters, body } = purchase();
    const held = await service.propose(body);
    const expiresAt = Date.parse((held.result as { expires_at: string }).expires_at);
    const claims = requestsTo("claim-token").length;
    vi.spyOn(Date, "now").mockReturnValue(expiresAt);
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "GRANT_EXPIRED",
    });
    expect(requestsTo("claim-token").length).toBe(claims);
    service.close();
  });

  it("refuses a card number before anything is asked or recorded", async () => {
    const { service, lines, securityLines } = build();
    const evaluations = requestsTo("enforce-and-bind").length;
    const pan = "4111111111111111";
    const refused = await refusal(service.propose(purchase(4_250, { cardTokenRef: pan }).body));
    expect([refused.status, refused.code]).toEqual([422, "CARD_PAN_REFUSED"]);
    const mismatched = purchase();
    const target = await refusal(
      service.propose({
        ...mismatched.body,
        proposal: { ...mismatched.body.proposal, target: "card:fixture_card_ref_other" },
      }),
    );
    expect([target.status, target.code]).toEqual([422, "CARD_TARGET_MISMATCH"]);
    const issuer = await refusal(
      service.authorizeCard(
        authorizationFor({ cardTokenRef: "fixture", amountMinor: 1 }, { card_token_ref: pan }),
        ISSUER,
      ),
    );
    expect([issuer.status, issuer.code]).toEqual([422, "CARD_PAN_REFUSED"]);
    const malformed = await refusal(service.authorizeCard({ authorization_id: "x" }, ISSUER));
    expect([malformed.status, malformed.code]).toEqual([400, "CARD_AUTHORIZATION_INVALID"]);
    expect(requestsTo("enforce-and-bind").length).toBe(evaluations);
    expect([...lines, ...securityLines].join("\n")).not.toContain(pan);
    service.close();
  });

  it("keeps the card routes to the issuer's hook and to results it can name", async () => {
    const { service } = build();
    const proposer = await refusal(service.authorizeCard({}, undefined));
    expect([proposer.status, proposer.code]).toEqual([403, "ROLE_FORBIDDEN"]);
    const operator = { ...ISSUER, scopes: new Set(["status"]) } as unknown as Principal;
    const scoped = await refusal(service.settleCard("fixture_auth", {}, operator));
    expect([scoped.status, scoped.code]).toEqual([403, "SCOPE_FORBIDDEN"]);
    const unknown = await refusal(
      service.settleCard("fixture_auth_unknown", { status: "APPROVED" }, ISSUER),
    );
    expect([unknown.status, unknown.code]).toEqual([404, "CARD_AUTHORIZATION_UNKNOWN"]);
    const path = await refusal(service.settleCard("%41", { status: "APPROVED" }, ISSUER));
    expect([path.status, path.code]).toEqual([400, "REQUEST_INVALID"]);
    const body = await refusal(service.settleCard("fixture_auth", { status: "MAYBE" }, ISSUER));
    expect([body.status, body.code]).toEqual([400, "CARD_AUTHORIZATION_RESULT_INVALID"]);
    service.close();
  });

  it("holds nothing in shadow, so nothing can match", async () => {
    const { service } = build("SHADOW");
    const { parameters, body } = purchase();
    expect(await service.propose(body)).toMatchObject({ mode: "SHADOW", outcome: "OBSERVED" });
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "NO_GRANT",
    });
    service.close();
  });
});

describe("a card authorization that cannot be made durable or claimed", () => {
  // The injected journal is the one written to; the directory is only what
  // the configuration requires to be named once the journal is required.
  const required = {
    env: {
      EXECUTOR_JOURNAL_REQUIRED: "true",
      EXECUTOR_JOURNAL_DIR: join(tmpdir(), "agentsafe-cards-journal"),
    },
  };

  it("claims nothing when the attempt cannot be journaled", async () => {
    const { service, journal } = build("ENFORCEMENT", required);
    const { parameters, body } = purchase();
    await service.propose(body);
    const claims = requestsTo("claim-token").length;
    journal.failEvery("ATTEMPT_OPENED");
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "JOURNAL_UNAVAILABLE",
    });
    expect(requestsTo("claim-token").length).toBe(claims);
    // The grant is spent all the same: it is never offered twice.
    journal.failEvery(null);
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "GRANT_ALREADY_USED",
    });
    service.close();
  });

  it("finalizes a claim it cannot make durable as failed, and approves nothing", async () => {
    const { service, journal, securityLines } = build("ENFORCEMENT", required);
    const { parameters, body } = purchase();
    await service.propose(body);
    journal.failEvery("GRANT_CLAIMED");
    const claims = requestsTo("claim-token").length;
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "JOURNAL_UNAVAILABLE",
    });
    expect(requestsTo("claim-token").length).toBe(claims + 1);
    expect(requestsTo("finalize-token").at(-1)?.body).toMatchObject({ outcome: "FAILED" });
    expect(journal.all.at(-1)).toMatchObject({
      record: "ATTEMPT_CLOSED",
      outcome: "DEFINITELY_NOT_EXECUTED",
      executed: false,
    });
    expect(
      parsed(securityLines).find((line) => line["event"] === "JOURNAL_WRITE_FAILED"),
    ).toMatchObject({ record: "GRANT_CLAIMED" });
    service.close();
  });

  it("goes on without the claim record where the journal is not required", async () => {
    const { service, journal } = build();
    const { parameters, body } = purchase();
    await service.propose(body);
    journal.failEvery("GRANT_CLAIMED");
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toMatchObject({
      decision: "APPROVE",
    });
    service.close();
  });

  it("answers no match when the authority refuses the claim", async () => {
    const { service, journal } = build();
    const { parameters, body } = purchase();
    await service.propose(body);
    authority.scriptOnce("claim", { status: 409, body: { valid: false, reason_codes: ["X"] } });
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "GRANT_CLAIM_REFUSED",
    });
    expect(journal.all.at(-1)).toMatchObject({ record: "ATTEMPT_CLOSED", outcome: "BLOCKED" });
    expect(await journal.openAttempts()).toEqual([]);
    service.close();
  });

  it("claims nothing while the host's posture is degraded", async () => {
    const posture = { degraded: false };
    const { service } = build("ENFORCEMENT", { posture });
    const { parameters, body } = purchase();
    await service.propose(body);
    posture.degraded = true;
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "POSTURE_DEGRADED",
    });
    service.close();
  });

  it("holds one of two purchases racing on the same card, and leaves the other's grant to expire", async () => {
    const { service } = build();
    const first = purchase();
    const [a, b] = await Promise.all([
      service.propose(first.body),
      service.propose({ ...first.body, idempotency_key: "fixture-card-race" }),
    ]);
    expect([a.outcome, b.outcome].sort()).toEqual(["BLOCKED", "HELD_FOR_AUTHORIZATION"]);
    const refused = a.outcome === "BLOCKED" ? a : b;
    expect(refused).toMatchObject({ verdict: "ALLOW", executed: false, result: null });
    expect(refused.reason_codes).toContain("CARD_HOLD_UNAVAILABLE");
    service.close();
  });
});

describe("a cardholder's tap resumes an escalated purchase", () => {
  it("hands back the intent, and holds the grant once an attestation the authority verifies is presented", async () => {
    const { service, lines, securityLines, journal } = build();
    const { parameters, body } = purchase(50_000);
    const escalated: ActionResponse = await service.propose(body);
    expect(escalated).toMatchObject({
      verdict: "ESCALATE",
      outcome: "ESCALATE_PENDING",
      executed: false,
      escalation: { mode: "ATTESTATION" },
    });
    const intent = JSON.parse(JSON.stringify(escalated.escalation?.intent)) as Record<
      string,
      unknown
    >;

    // An intent presented back with a card number written into it is refused as one.
    const tampered = {
      ...intent,
      parameters: { ...(intent["parameters"] as object), cardTokenRef: "4111111111111111" },
    };
    const pan = await refusal(
      service.resume({ mode: "ATTESTATION", intent: tampered, attestation: TAPPED }),
    );
    expect([pan.status, pan.code]).toEqual([422, "CARD_PAN_REFUSED"]);

    // A malformed attestation never reaches the authority.
    const evaluations = requestsTo("enforce-and-bind").length;
    for (const attestation of ["not-a-jws", `a.b.${"c".repeat(20_000)}`]) {
      const refused = await refusal(service.resume({ mode: "ATTESTATION", intent, attestation }));
      expect([refused.status, refused.code]).toEqual([400, "REQUEST_INVALID"]);
    }
    expect(requestsTo("enforce-and-bind").length).toBe(evaluations);

    // One the authority cannot verify is a fail-closed refusal.
    const forged = await service.resume({ mode: "ATTESTATION", intent, attestation: FORGED });
    expect(forged).toMatchObject({ verdict: "BLOCK", fail_closed: true, executed: false });

    // The tap the authority verifies: a fresh evaluation of the same intent.
    const resumed = await service.resume({ mode: "ATTESTATION", intent, attestation: TAPPED });
    expect(resumed).toMatchObject({
      intent_id: escalated.intent_id,
      intent_hash: escalated.intent_hash,
      verdict: "ALLOW",
      outcome: "HELD_FOR_AUTHORIZATION",
      reason_codes: ["PRESENCE_ATTESTATION_VERIFIED"],
    });
    const evaluated = requestsTo("enforce-and-bind").at(-1)?.body as Record<string, unknown>;
    expect(evaluated["evidence"]).toEqual({
      humanApproval: { provider: "attestation", attestation: TAPPED },
    });
    expect(evaluated["intent_id"]).toBe(escalated.intent_id);

    // Resuming again while the grant is held is refused before the authority is asked.
    const twice = await refusal(
      service.resume({ mode: "ATTESTATION", intent, attestation: TAPPED }),
    );
    expect([twice.status, twice.code]).toEqual([409, "CARD_GRANT_ALREADY_HELD"]);

    // The issuer's authorization claims it; the claim carries no attestation.
    const asked = authorizationFor(parameters);
    expect(await service.authorizeCard(asked, ISSUER)).toMatchObject({ decision: "APPROVE" });
    expect(JSON.stringify(requestsTo("claim-token").at(-1)?.body)).not.toContain(TAPPED);

    // The attestation is evidence for the authority, and never written down here.
    for (const line of [
      ...lines,
      ...securityLines,
      ...journal.all.map((record) => JSON.stringify(record)),
    ]) {
      expect(line).not.toContain(TAPPED);
      expect(line).not.toContain(FORGED);
    }
    service.close();
  });

  it("accepts an attestation in any enforcing escalation shape, and none in shadow", async () => {
    const shadow = build("SHADOW").service;
    const refused = await refusal(
      shadow.resume({ mode: "ATTESTATION", intent: {}, attestation: TAPPED }),
    );
    expect([refused.status, refused.code]).toEqual([409, "ESCALATION_NOT_CONFIGURED"]);
    shadow.close();
    const { service } = build();
    // Without an escalation shape, a Presence handoff still has nothing to resume.
    const direct = await refusal(
      service.resume({
        mode: "DIRECT",
        intent: {},
        request_id: "synthetic-request-1",
        approval_url: null,
        expires_at: null,
      }),
    );
    expect([direct.status, direct.code]).toEqual([409, "ESCALATION_NOT_CONFIGURED"]);
    const unknownIntent = await refusal(
      service.resume({ mode: "ATTESTATION", intent: {}, attestation: TAPPED }),
    );
    expect([unknownIntent.status, unknownIntent.code]).toEqual([400, "INTENT_INVALID"]);
    service.close();
  });
});

describe("a hold the policy sends to a presence provider", () => {
  const presence = new LocalPresence({ autoComplete: "MANUAL", roles: { [APPROVER_ID]: "CRO" } });
  const routed = new LocalAuthority({
    presence,
    verifyAttestation: (attestation) => attestation === TAPPED,
    escalationRouting: {
      selector: { kind: "ROLE", role_id: "CARDHOLDER" },
      verification: { provider: "koard", methods: ["CARD_TAP"], level: "STANDARD" },
    },
  });
  const routedRequests = (part: string) =>
    routed.requests.filter((request) => request.path.includes(part));

  /** The issuer app's backend, where the cardholder's tap lands: one scope, nothing else. */
  const PRESENTER: Principal = {
    ...ISSUER,
    id: "synthetic-issuer-app",
    scopes: new Set(["escalations.resume"]),
  } as unknown as Principal;

  beforeAll(async () => {
    await presence.start();
    await routed.start();
  });

  afterAll(async () => {
    await routed.stop();
    await presence.stop();
  });

  it("hands the caller where the hold goes, and asks Presence for nothing even in DIRECT", async () => {
    const { service } = build("ENFORCEMENT", { authority: routed, presence, escalation: "DIRECT" });
    const asked = presence.requests.length;
    const { body } = purchase(50_000);
    const escalated = await service.propose(body);
    expect(escalated).toMatchObject({
      verdict: "ESCALATE",
      outcome: "ESCALATE_PENDING",
      executed: false,
      escalation: {
        mode: "ATTESTATION",
        requirement: {
          requirement_id: null,
          selector: { kind: "ROLE", role_id: "CARDHOLDER" },
          verification: { provider: "koard", methods: ["CARD_TAP"], level: "STANDARD" },
        },
      },
    });
    expect(
      Date.parse(
        (escalated.escalation as { requirement: { expires_at: string } }).requirement.expires_at,
      ),
    ).toBeGreaterThan(Date.now());
    expect(presence.requests).toHaveLength(asked);
    service.close();
  });

  it("lets the issuer app's backend present the tap, and refuses it anything else", async () => {
    const { service, lines } = build("ENFORCEMENT", { authority: routed });
    const { body } = purchase(50_000);
    const escalated = await service.propose(body);
    const handoff = JSON.parse(JSON.stringify(escalated.escalation)) as Record<string, unknown>;
    const intent = handoff["intent"] as Record<string, unknown>;

    // Without the scope, nothing is read.
    const unscoped = { ...PRESENTER, scopes: new Set(["status"]) } as unknown as Principal;
    const scoped = await refusal(service.resume({ ...handoff, attestation: TAPPED }, unscoped));
    expect([scoped.status, scoped.code]).toEqual([403, "ROLE_FORBIDDEN"]);
    // A Presence handoff is the proposer's to resume, never an operator's.
    const direct = await refusal(
      service.resume(
        {
          mode: "DIRECT",
          intent,
          request_id: "synthetic-request-1",
          approval_url: null,
          expires_at: null,
        },
        PRESENTER,
      ),
    );
    expect([direct.status, direct.code]).toEqual([403, "ROLE_FORBIDDEN"]);
    // The intent is re-hashed on the way in: a card number written into it is refused.
    const tampered = {
      ...intent,
      parameters: { ...(intent["parameters"] as object), cardTokenRef: "4111111111111111" },
    };
    const pan = await refusal(
      service.resume({ mode: "ATTESTATION", intent: tampered, attestation: TAPPED }, PRESENTER),
    );
    expect([pan.status, pan.code]).toEqual([422, "CARD_PAN_REFUSED"]);

    // The handoff presented whole, with the tap, by the operator: a fresh evaluation.
    const evaluations = routedRequests("enforce-and-bind").length;
    const resumed = await service.resume({ ...handoff, attestation: TAPPED }, PRESENTER);
    expect(resumed).toMatchObject({
      intent_id: escalated.intent_id,
      intent_hash: escalated.intent_hash,
      verdict: "ALLOW",
      outcome: "HELD_FOR_AUTHORIZATION",
      reason_codes: ["PRESENCE_ATTESTATION_VERIFIED"],
    });
    expect(routedRequests("enforce-and-bind")).toHaveLength(evaluations + 1);
    expect(routedRequests("enforce-and-bind").at(-1)?.body).toMatchObject({
      intent_id: escalated.intent_id,
      evidence: { humanApproval: { provider: "attestation", attestation: TAPPED } },
    });
    // Every line the resumption produced names the operator, not the agent.
    expect(parsed(lines).find((line) => line["event"] === "GRANT_HELD")).toMatchObject({
      caller_principal: PRESENTER.id,
    });
    service.close();
  });

  it("tells the authority how busy the card is, in numbers only", async () => {
    const { service } = build("ENFORCEMENT", { authority: routed });
    const { parameters, body } = purchase();
    await service.propose(body);
    const first = routedRequests("enforce-and-bind").at(-1)?.body as {
      context: Record<string, unknown>;
    };
    expect(first.context["card_velocity"]).toEqual({ window_seconds: 600, holds: 0, claims: 0 });
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toMatchObject({
      decision: "APPROVE",
    });
    await service.propose({ ...body, idempotency_key: "fixture-card-purchase-velocity" });
    const second = routedRequests("enforce-and-bind").at(-1)?.body as {
      context: Record<string, unknown>;
    };
    expect(second.context["card_velocity"]).toEqual({ window_seconds: 600, holds: 1, claims: 1 });
    expect(JSON.stringify(second.context)).not.toContain(parameters.cardTokenRef);
    service.close();
  });
});

/** A `pg` pool over the fake client, shared by every replica that loads it. */
function sharedPg(sql: FakeCardHoldsSql): { load: LoadPg; pools: number } {
  const state = { pools: 0 };
  const load: LoadPg = async () => ({
    Pool: class implements PgPool {
      public constructor() {
        state.pools += 1;
      }
      public async query(text: string, values: unknown[]): Promise<{ rowCount: number | null }> {
        return await sql.query(text, values);
      }
      public on(): void {
        return undefined;
      }
      public async end(): Promise<void> {
        return undefined;
      }
    },
  });
  return {
    load,
    get pools() {
      return state.pools;
    },
  };
}

const POSTGRES_HOLDS = (): Record<string, string> => ({
  EXECUTOR_CARD_HOLDS_STORE: "postgres",
  EXECUTOR_CARD_HOLDS_NAMESPACE: "org-synthetic",
  EXECUTOR_CARD_HOLDS_DATABASE_URL: "postgres://executor@db.invalid/cards",
  EXECUTOR_CARD_HOLDS_KEY: randomBytes(32).toString("hex"),
});

describe("holds keyed by the card and the merchant", () => {
  it("holds the same card at two merchants in parallel, and matches each authorization to its merchant's hold", async () => {
    const { service } = build();
    const first = purchase(4_250);
    const second = purchase(1_999, {
      cardTokenRef: first.parameters.cardTokenRef,
      merchantId: "fixture_merchant_18",
    });
    const heldFirst = await service.propose(first.body);
    const heldSecond = await service.propose(second.body);
    expect(heldFirst).toMatchObject({ outcome: "HELD_FOR_AUTHORIZATION" });
    expect(heldSecond).toMatchObject({ outcome: "HELD_FOR_AUTHORIZATION" });
    // The second hold's intent saw the first in the card's velocity.
    const evaluated = requestsTo("enforce-and-bind").at(-1)?.body as {
      context: { card_velocity: { holds: number; claims: number } };
    };
    expect(evaluated.context.card_velocity).toEqual({ window_seconds: 600, holds: 1, claims: 0 });
    // A third purchase at either merchant waits; a third merchant does not.
    const again = await refusal(
      service.propose({ ...second.body, idempotency_key: "fixture-card-purchase-again" }),
    );
    expect([again.status, again.code]).toEqual([409, "CARD_GRANT_ALREADY_HELD"]);
    expect(
      await service.propose(
        purchase(500, {
          cardTokenRef: first.parameters.cardTokenRef,
          merchantId: "fixture_merchant_19",
        }).body,
      ),
    ).toMatchObject({ outcome: "HELD_FOR_AUTHORIZATION" });
    // Each authorization finds its merchant's hold, and only that one.
    const atSecond = await service.authorizeCard(
      authorizationFor(second.parameters, { merchant_id: "fixture_merchant_18" }),
      ISSUER,
    );
    expect(atSecond).toMatchObject({ decision: "APPROVE", intent_id: heldSecond.intent_id });
    const atFirst = await service.authorizeCard(authorizationFor(first.parameters), ISSUER);
    expect(atFirst).toMatchObject({ decision: "APPROVE", intent_id: heldFirst.intent_id });
    expect(
      await service.authorizeCard(
        authorizationFor(first.parameters, { merchant_id: "fixture_merchant_20" }),
        ISSUER,
      ),
    ).toEqual({ decision: "NO_MATCH", code: "NO_GRANT" });
    service.close();
  });

  it("lets an issuer that may increment re-present the same authorization for more, within the ceiling and before the result", async () => {
    const { service, securityLines } = build("ENFORCEMENT", {
      env: { EXECUTOR_CARD_AUTHORIZATIONS: "incremental" },
    });
    const { parameters, body } = purchase(4_250);
    const held = await service.propose(body);
    const asked = authorizationFor(parameters, { amount_minor: 3_000 });
    const approved = await service.authorizeCard(asked, ISSUER);
    expect(approved).toMatchObject({ decision: "APPROVE", intent_id: held.intent_id });
    const claims = requestsTo("claim-token").length;
    // More, inside the ceiling: the same answer, no second claim.
    expect(await service.authorizeCard({ ...asked, amount_minor: 4_000 }, ISSUER)).toEqual(
      approved,
    );
    expect(requestsTo("claim-token").length).toBe(claims);
    expect(parsed(securityLines).map((line) => line["event"])).toContain(
      "CARD_AUTHORIZATION_INCREMENTED",
    );
    // Less than before, more than the ceiling, or another merchant: refused as a reuse.
    for (const change of [
      { amount_minor: 3_500 },
      { amount_minor: 4_251 },
      { amount_minor: 4_100, merchant_id: "fixture_merchant_18" },
    ]) {
      expect(await service.authorizeCard({ ...asked, ...change }, ISSUER)).toEqual({
        decision: "NO_MATCH",
        code: "AUTHORIZATION_ID_REUSED",
      });
    }
    // The result records the final amount against the grant's ceiling.
    const result = await service.settleCard(
      asked.authorization_id,
      { status: "APPROVED", approved_amount_minor: 4_000 },
      ISSUER,
    );
    expect(result).toMatchObject({ outcome: "COMMITTED", effect: { comparison: "MATCH" } });
    // After the result, nothing increments.
    expect(await service.authorizeCard({ ...asked, amount_minor: 4_200 }, ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "AUTHORIZATION_ID_REUSED",
    });
    service.close();
  });

  it("keeps a single-claim issuer to one amount per authorization id", async () => {
    const { service } = build();
    const { parameters, body } = purchase(4_250);
    await service.propose(body);
    const asked = authorizationFor(parameters, { amount_minor: 3_000 });
    await service.authorizeCard(asked, ISSUER);
    expect(await service.authorizeCard({ ...asked, amount_minor: 4_000 }, ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "AUTHORIZATION_ID_REUSED",
    });
    service.close();
  });
});

describe("holds shared across replicas through the Postgres store", () => {
  it("holds on one replica, matches and claims on another, and settles on a third, each adopting what it did not make", async () => {
    const sql = new FakeCardHoldsSql();
    const pg = sharedPg(sql);
    const env = POSTGRES_HOLDS();
    const a = build("ENFORCEMENT", { env, loadPg: pg.load });
    const b = build("ENFORCEMENT", { env, loadPg: pg.load });
    await a.service.startCards();
    await b.service.startCards();
    const { parameters, body } = purchase(4_250);
    const held = await a.service.propose(body);
    expect(held).toMatchObject({ outcome: "HELD_FOR_AUTHORIZATION" });
    expect(sql.holds.size).toBe(1);
    // The row holds no token in clear: a sealed value is the seal's own
    // shape, base64url throughout, and no JSON could survive in it.
    for (const row of sql.holds.values()) {
      expect(row.sealed).toMatch(/^v1(\.[\w-]{16,})+$/);
      expect(row.sealed).not.toMatch(/["{}:]/);
    }
    // B never saw the purchase: the second purchase on the card waits there too.
    const waits = await refusal(
      b.service.propose({ ...body, idempotency_key: "fixture-card-purchase-on-b" }),
    );
    expect([waits.status, waits.code]).toEqual([409, "CARD_GRANT_ALREADY_HELD"]);
    // The authorization reaches B, which admits A's hold through its own executor and claims it.
    const claimsBefore = requestsTo("claim-token").length;
    const asked = authorizationFor(parameters, { amount_minor: 4_000 });
    const approved = await b.service.authorizeCard(asked, ISSUER);
    expect(approved).toMatchObject({
      decision: "APPROVE",
      intent_id: held.intent_id,
      decision_id: held.decision_id,
    });
    expect(requestsTo("claim-token").length).toBe(claimsBefore + 1);
    // B's own record: the refused second purchase, then A's hold admitted
    // here as adopted, then the claim.
    expect(auditTypes(b.lines)).toEqual([
      "EXECUTION_BLOCKED",
      "INTENT_CAPTURED",
      "AUTHORITY_DECISION",
      "GRANT_HELD",
      "GRANT_CONSUMED",
      "EXECUTION_STARTED",
    ]);
    expect(parsed(b.lines)[3]).toMatchObject({ reason_codes: ["HOLD_ADOPTED"] });
    // Spent for everyone: A's own handle is used, and a retry on A is the same answer.
    expect(await a.service.authorizeCard(asked, ISSUER)).toEqual(approved);
    expect(await a.service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "GRANT_ALREADY_USED",
    });
    expect(requestsTo("claim-token").length).toBe(claimsBefore + 1);
    // The result lands on a third replica, started after the claim: it
    // adopts the claim with the material B sealed and finalizes with the authority.
    const c = build("ENFORCEMENT", { env, loadPg: pg.load });
    const finalizedBefore = requestsTo("finalize-token").length;
    const result = await c.service.settleCard(
      asked.authorization_id,
      { status: "APPROVED", approved_amount_minor: 4_000, auth_code: "A1B2C3" },
      ISSUER,
    );
    expect(result).toMatchObject({
      outcome: "COMMITTED",
      executed: true,
      finalization: "RECORDED",
      effect: { comparison: "MATCH" },
    });
    // C finalized A's grant with the claim token B was given: every post names
    // that grant, and the last is recorded. (This loopback authority trusts no
    // effect observer, so the first post, with evidence, is refused and the
    // verifier posts again without it, exactly as on one replica.)
    const granted = (
      requestsTo("enforce-and-bind").at(-1)?.response?.body as { execution_token: string }
    ).execution_token;
    const finalizations = requestsTo("finalize-token").slice(finalizedBefore);
    expect(finalizations.length).toBeGreaterThanOrEqual(1);
    for (const post of finalizations) {
      expect((post.body as { execution_token: string }).execution_token).toBe(granted);
    }
    expect(finalizations.at(-1)?.response).toMatchObject({
      status: 200,
      body: { finalized: true },
    });
    expect(auditTypes(c.lines)).toEqual(["EXECUTION_COMPLETED"]);
    // Settled once, for every replica.
    for (const replica of [a, b, c]) {
      const again = await refusal(
        replica.service.settleCard(asked.authorization_id, { status: "APPROVED" }, ISSUER),
      );
      expect([again.status, again.code]).toEqual([409, "CARD_RESULT_ALREADY_RECORDED"]);
    }
    // No card reference, amount or merchant reaches any stream on any replica.
    for (const replica of [a, b, c]) {
      for (const line of [...replica.lines, ...replica.securityLines]) {
        expect(line).not.toContain(parameters.cardTokenRef);
        expect(line).not.toContain("fixture_merchant_17");
      }
      replica.service.close();
    }
  });

  it("answers the hook with a code, and the result with 503, when the store cannot be reached", async () => {
    const sql = new FakeCardHoldsSql();
    const pg = sharedPg(sql);
    const env = POSTGRES_HOLDS();
    const { service, securityLines } = build("ENFORCEMENT", { env, loadPg: pg.load });
    const { parameters, body } = purchase(4_250);
    await service.propose(body);
    sql.failAll = true;
    expect(await service.authorizeCard(authorizationFor(parameters), ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "CARD_HOLDS_UNAVAILABLE",
    });
    const unavailable = await refusal(
      service.settleCard("fixture_auth_none", { status: "APPROVED" }, ISSUER),
    );
    expect([unavailable.status, unavailable.code]).toEqual([503, "CARD_HOLDS_UNAVAILABLE"]);
    sql.failAll = false;
    sql.failProbe = true;
    await expect(service.startCards()).rejects.toThrow("relation does not exist");
    expect(parsed(securityLines).map((line) => line["event"])).toContain(
      "CARD_AUTHORIZATION_NO_MATCH",
    );
    service.close();
  });
});

/** The issuer app's backend, where a commit-boundary tap lands: it presents, and proposes nothing. */
const PRESENTING_APP: Principal = {
  ...ISSUER,
  id: "synthetic-issuer-app-backend",
  scopes: new Set(["escalations.resume"]),
} as unknown as Principal;

const EVALUATE = (): Record<string, string> => ({
  EXECUTOR_CARD_NO_GRANT: "evaluate",
  EXECUTOR_CARD_COMMIT_TENANT_ID: "00000000-0000-4000-8000-000000000002",
  EXECUTOR_CARD_COMMIT_ACTOR_ID: "synthetic-issuer-commit",
});

describe("an authorization with no hold, evaluated at the commit boundary", () => {
  it("answers NO_GRANT by default, and evaluates, holds and claims in one call when policy allows", async () => {
    const plain = build();
    const unevaluated = authorizationFor({
      cardTokenRef: "fixture_card_ref_none",
      amountMinor: 4_250,
    });
    expect(await plain.service.authorizeCard(unevaluated, ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "NO_GRANT",
    });
    plain.service.close();

    const { service, lines, securityLines, journal } = build("ENFORCEMENT", { env: EVALUATE() });
    const evaluations = requestsTo("enforce-and-bind").length;
    const claims = requestsTo("claim-token").length;
    const asked = authorizationFor({
      cardTokenRef: "fixture_card_ref_commit_1",
      amountMinor: 4_250,
    });
    const approved = await service.authorizeCard(asked, ISSUER);
    expect(approved).toMatchObject({
      decision: "APPROVE",
      authorization_id: asked.authorization_id,
    });
    expect(requestsTo("enforce-and-bind").length).toBe(evaluations + 1);
    expect(requestsTo("claim-token").length).toBe(claims + 1);
    // The intent the authority saw: the authorization as a purchase, by the
    // commit actor, with the hook's principal and the authorization's id in
    // its context, and no card number anywhere.
    const evaluated = requestsTo("enforce-and-bind").at(-1)?.body as {
      actor: { id: string; type: string };
      tenant_id: string;
      action: { type: string; parameters: Record<string, unknown> };
      context: Record<string, unknown>;
    };
    expect(evaluated.actor).toEqual({ id: "synthetic-issuer-commit", type: "SYSTEM" });
    expect(evaluated.tenant_id).toBe("00000000-0000-4000-8000-000000000002");
    expect(evaluated.action.type).toBe("card.purchase");
    expect(evaluated.action.parameters).toEqual({
      cardTokenRef: asked.card_token_ref,
      amountMinor: 4_250,
      currency: "EUR",
      merchantId: "fixture_merchant_17",
    });
    expect(evaluated.context).toMatchObject({
      caller_principal: ISSUER.id,
      commit_boundary: "ISSUER_HOOK",
      card_authorization: { authorization_id: asked.authorization_id },
      card_velocity: { window_seconds: 600, holds: 0, claims: 0 },
    });
    expect(auditTypes(lines)).toEqual([
      "INTENT_CAPTURED",
      "AUTHORITY_DECISION",
      "GRANT_HELD",
      "GRANT_CONSUMED",
      "EXECUTION_STARTED",
    ]);
    // A retry is the same answer; the result settles it like any claim.
    expect(await service.authorizeCard(asked, ISSUER)).toEqual(approved);
    expect(requestsTo("enforce-and-bind").length).toBe(evaluations + 1);
    const result = await service.settleCard(asked.authorization_id, { status: "APPROVED" }, ISSUER);
    expect(result).toMatchObject({
      outcome: "COMMITTED",
      executed: true,
      finalization: "RECORDED",
    });
    expect(await journal.openAttempts()).toEqual([]);
    for (const line of [...lines, ...securityLines]) {
      expect(line).not.toContain(asked.card_token_ref);
      expect(line).not.toContain("fixture_merchant_17");
    }
    service.close();
  });

  it("answers PENDING with the handoff when policy wants the cardholder, and matches once the tap has held the grant", async () => {
    const { service, securityLines } = build("ENFORCEMENT", { env: EVALUATE() });
    const asked = authorizationFor({
      cardTokenRef: "fixture_card_ref_commit_2",
      amountMinor: 50_000,
    });
    const evaluations = requestsTo("enforce-and-bind").length;
    const pending = await service.authorizeCard(asked, ISSUER);
    expect(pending).toMatchObject({
      decision: "PENDING",
      authorization_id: asked.authorization_id,
      escalation: { mode: "ATTESTATION" },
    });
    if (pending.decision !== "PENDING") throw new Error("not pending");
    expect(Date.parse(pending.expires_at)).toBeGreaterThan(Date.now());
    expect(typeof pending.intent_id).toBe("string");
    expect(parsed(securityLines).map((line) => line["event"])).toContain(
      "CARD_AUTHORIZATION_PENDING",
    );
    // Re-presented before the tap: the same answer, and nothing evaluated twice.
    expect(await service.authorizeCard(asked, ISSUER)).toEqual(pending);
    expect(requestsTo("enforce-and-bind").length).toBe(evaluations + 1);
    // The same id for something else is a reuse.
    expect(await service.authorizeCard({ ...asked, amount_minor: 40_000 }, ISSUER)).toEqual({
      decision: "NO_MATCH",
      code: "AUTHORIZATION_ID_REUSED",
    });
    // No claim yet: a result for it is unknown.
    const early = await refusal(
      service.settleCard(asked.authorization_id, { status: "APPROVED" }, ISSUER),
    );
    expect([early.status, early.code]).toEqual([404, "CARD_AUTHORIZATION_UNKNOWN"]);
    // The tap lands through the escalation route with the handoff's intent,
    // and the hold it leaves is what the re-presented authorization matches.
    // No agent proposed this intent, so the tap is presented by the issuer
    // app's backend: an operator holding `escalations.resume`.
    const intent = JSON.parse(JSON.stringify(pending.escalation.intent)) as Record<string, unknown>;
    const resumed = await service.resume(
      { mode: "ATTESTATION", intent, attestation: TAPPED },
      PRESENTING_APP,
    );
    expect(resumed).toMatchObject({
      intent_id: pending.intent_id,
      verdict: "ALLOW",
      outcome: "HELD_FOR_AUTHORIZATION",
    });
    const claims = requestsTo("claim-token").length;
    const approved = await service.authorizeCard(asked, ISSUER);
    expect(approved).toMatchObject({
      decision: "APPROVE",
      authorization_id: asked.authorization_id,
      intent_id: pending.intent_id,
    });
    expect(requestsTo("claim-token").length).toBe(claims + 1);
    expect(requestsTo("enforce-and-bind").length).toBe(evaluations + 2);
    const result = await service.settleCard(
      asked.authorization_id,
      { status: "APPROVED", approved_amount_minor: 50_000 },
      ISSUER,
    );
    expect(result).toMatchObject({ outcome: "COMMITTED", executed: true });
    service.close();
  });

  it("answers a block, a halt and a shadow evaluation as no match with the reason, and forgets a pending answer past its intent", async () => {
    const { service, halt } = build("ENFORCEMENT", { env: EVALUATE() });
    expect(
      await service.authorizeCard(
        authorizationFor({ cardTokenRef: "fixture_card_ref_commit_3", amountMinor: 250_000 }),
        ISSUER,
      ),
    ).toEqual({ decision: "NO_MATCH", code: "POLICY_BLOCK" });
    halt.halt("OPERATOR", "fixture");
    expect(
      await service.authorizeCard(
        authorizationFor({ cardTokenRef: "fixture_card_ref_commit_4", amountMinor: 4_250 }),
        ISSUER,
      ),
    ).toEqual({ decision: "NO_MATCH", code: "EXECUTOR_HALTED" });
    service.close();

    const shadow = build("SHADOW", { env: EVALUATE() });
    const observations = requestsTo("enforce-and-bind").length;
    expect(
      await shadow.service.authorizeCard(
        authorizationFor({ cardTokenRef: "fixture_card_ref_commit_5", amountMinor: 4_250 }),
        ISSUER,
      ),
    ).toEqual({ decision: "NO_MATCH", code: "SHADOW_OBSERVED" });
    expect(requestsTo("enforce-and-bind").length).toBe(observations + 1);
    shadow.service.close();

    // A pending answer lives as long as its intent: past it, the authorization is evaluated afresh.
    const short = build("ENFORCEMENT", {
      env: { ...EVALUATE(), EXECUTOR_INTENT_TTL_SECONDS: "1" },
    });
    const asked = authorizationFor({
      cardTokenRef: "fixture_card_ref_commit_6",
      amountMinor: 50_000,
    });
    const first = await short.service.authorizeCard(asked, ISSUER);
    expect(first.decision).toBe("PENDING");
    const evaluations = requestsTo("enforce-and-bind").length;
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    const again = await short.service.authorizeCard(asked, ISSUER);
    expect(again.decision).toBe("PENDING");
    expect(again).not.toEqual(first);
    expect(requestsTo("enforce-and-bind").length).toBe(evaluations + 1);
    short.service.close();
  });
});

describe("a standing permission: Tap to Authenticate", () => {
  const producer = generateKeyPairSync("ed25519");
  const stranger = generateKeyPairSync("ed25519");
  const seen: unknown[] = [];
  const delegated = new LocalAuthority({
    verifyAttestation: (attestation) => attestation === TAPPED,
    escalationRouting: {
      selector: { kind: "ROLE", role_id: "CARDHOLDER" },
      verification: { provider: "koard", methods: ["CARD_TAP"], level: "STANDARD" },
    },
    // The bank's policy: a purchase the cardholder's standing permission
    // covers is allowed; anything else goes to the cardholder's tap.
    policy: (request) => {
      seen.push(request.signed_signals);
      return request.signed_signals?.["card_delegation"]?.covers_intent === true
        ? "ALLOW"
        : "ESCALATE";
    },
  });
  delegated.registerProviderKey({
    kid: "koard-signal-key-a",
    issuer: "koard",
    publicJwk: producer.publicKey.export({ format: "jwk" }),
    purpose: "signed_signal",
  });
  const delegatedRequests = (part: string) =>
    delegated.requests.filter((request) => request.path.includes(part));

  /** The cardholder's permission as Koard signs it: this agent, card purchases, up to 50 EUR. */
  const permission = (overrides: Partial<Parameters<typeof mintSignedSignal>[0]> = {}) =>
    mintSignedSignal({
      privateKey: producer.privateKey,
      kid: "koard-signal-key-a",
      issuer: "koard",
      audience: TENANT_ID,
      subject: "cardholder-synthetic-7",
      signal: {
        name: "card_delegation",
        method: "card_tap",
        result: "VERIFIED",
        agent: "synthetic-shopping-agent",
        scope: { actions: ["card.purchase"] },
        limits: { currency: "EUR", amount_minor: 5_000 },
      },
      ...overrides,
    });

  beforeAll(async () => {
    await delegated.start();
  });

  afterAll(async () => {
    await delegated.stop();
  });

  it("holds a purchase the permission covers, and keeps nothing of the token", async () => {
    const { service, lines, securityLines, journal } = build("ENFORCEMENT", {
      authority: delegated,
    });
    const token = permission();
    const { body } = purchase(4_250);
    seen.length = 0;
    const held = await service.propose({ ...body, signals: [{ token }] });
    expect(held).toMatchObject({
      verdict: "ALLOW",
      outcome: "HELD_FOR_AUTHORIZATION",
      reason_codes: ["POLICY_AUTONOMOUS_LIMIT"],
    });
    // The authority saw the token as evidence, beside the intent, and the
    // facts it verified: who signed, how, what it covers.
    const evaluated = delegatedRequests("enforce-and-bind").at(-1)?.body as Record<string, unknown>;
    expect(evaluated["evidence"]).toEqual({ signals: [{ token }] });
    expect(JSON.stringify(evaluated["context"])).not.toContain(token);
    expect(seen[0]).toMatchObject({
      card_delegation: {
        verified: true,
        producer: "koard",
        method: "card_tap",
        key_id: "koard-signal-key-a",
        agent: "synthetic-shopping-agent",
        limits: { currency: "EUR", amount_minor: 5_000 },
        covers: { action: true, agent: true, amount: true, currency: true, card: null },
        covers_intent: true,
      },
    });
    // Nothing this process keeps carries the token: not the answer, not the
    // audit or security lines, not the journal.
    const everything = JSON.stringify([held, lines, securityLines, journal.all]);
    expect(everything).not.toContain(token);
    expect(everything).not.toContain(token.split(".")[2]);
    service.close();
  });

  it("sends a purchase the permission does not cover to the cardholder's tap", async () => {
    const { service } = build("ENFORCEMENT", { authority: delegated });
    const { body } = purchase(50_000);
    seen.length = 0;
    const escalated = await service.propose({ ...body, signals: [{ token: permission() }] });
    expect(escalated).toMatchObject({
      verdict: "ESCALATE",
      outcome: "ESCALATE_PENDING",
      executed: false,
      escalation: {
        mode: "ATTESTATION",
        requirement: { verification: { provider: "koard", methods: ["CARD_TAP"] } },
      },
    });
    expect(seen[0]).toMatchObject({
      card_delegation: { covers: { amount: false }, covers_intent: false },
    });
    // A permission for another agent is verified and covers nothing of this
    // intent; it escalates, it is not refused.
    const other = await service.propose({
      ...purchase(4_250).body,
      signals: [
        {
          token: permission({
            signal: {
              name: "card_delegation",
              method: "card_tap",
              result: "VERIFIED",
              agent: "synthetic-other-agent",
            },
          }),
        },
      ],
    });
    expect(other).toMatchObject({ verdict: "ESCALATE", outcome: "ESCALATE_PENDING" });
    service.close();
  });

  it("refuses a forged, expired, mis-addressed or unknown token before any evaluation", async () => {
    const { service } = build("ENFORCEMENT", { authority: delegated });
    const cases: Array<[Partial<Parameters<typeof mintSignedSignal>[0]>, string]> = [
      [{ privateKey: stranger.privateKey }, "SIGNED_SIGNAL_SIGNATURE_INVALID"],
      [{ issuedAtMs: Date.now() - 3 * 24 * 60 * 60 * 1_000 }, "SIGNED_SIGNAL_EXPIRED"],
      [{ audience: "00000000-0000-4000-8000-000000000002" }, "SIGNED_SIGNAL_AUDIENCE_MISMATCH"],
      [{ kid: "koard-signal-key-z" }, "SIGNED_SIGNAL_KEY_UNKNOWN"],
    ];
    for (const [overrides, code] of cases) {
      const refused = await service.propose({
        ...purchase(4_250).body,
        signals: [{ token: permission(overrides) }],
      });
      expect(refused, code).toMatchObject({
        verdict: "BLOCK",
        fail_closed: true,
        executed: false,
        reason_codes: [code],
      });
    }
    service.close();
  });

  it("never sends a malformed signal, or more than eight, to the authority", async () => {
    const { service } = build("ENFORCEMENT", { authority: delegated });
    const evaluations = delegatedRequests("enforce-and-bind").length;
    for (const signals of [
      [{ token: "not-a-jws" }],
      [],
      Array.from({ length: 9 }, () => ({ token: permission() })),
      [{ token: permission(), extra: true }],
    ]) {
      const refused = await refusal(service.propose({ ...purchase(4_250).body, signals }));
      expect([refused.status, refused.code]).toEqual([400, "REQUEST_INVALID"]);
    }
    expect(delegatedRequests("enforce-and-bind").length).toBe(evaluations);
    service.close();
  });

  it("observes the permission in shadow, and holds nothing", async () => {
    const { service } = build("SHADOW", { authority: delegated });
    const token = permission();
    const observed = await service.propose({ ...purchase(4_250).body, signals: [{ token }] });
    expect(observed).toMatchObject({
      mode: "SHADOW",
      verdict: "ALLOW",
      executed: false,
      authorization: null,
    });
    const evaluated = delegatedRequests("enforce-and-bind").at(-1)?.body as Record<string, unknown>;
    expect(evaluated["mode"]).toBe("SHADOW");
    expect(evaluated["evidence"]).toEqual({ signals: [{ token }] });
    service.close();
  });
});
