import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cardHandlers } from "../../src/adapters/cards/CardHandlers.js";
import { prepareCardPurchase } from "../../src/adapters/cards/CardEffect.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import type { Principal } from "../../src/identity/PrincipalRegistry.js";
import { HaltSwitch } from "../../src/incident/HaltSwitch.js";
import { InMemoryExecutionJournal } from "../../src/journal/InMemoryExecutionJournal.js";
import type { ActionResponse } from "../../src/service/Requests.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { collectedEvents, loopbackEnvironment, openSecrets } from "../support/Environment.js";

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
  options: { readonly env?: Record<string, string>; readonly posture?: { degraded: boolean } } = {},
): Built {
  const env: Record<string, string> = {
    ...loopbackEnvironment({ authority, providerBaseUrl: "http://127.0.0.1:9" }, mode),
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

    // A purchase on the card that does not match leaves the grant spendable.
    for (const [overrides, code] of [
      [{ currency: "USD" }, "CURRENCY_MISMATCH"],
      [{ merchant_id: "fixture_merchant_18" }, "MERCHANT_MISMATCH"],
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
