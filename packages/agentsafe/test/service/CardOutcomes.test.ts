import { existsSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cardHandlers } from "../../src/adapters/cards/CardHandlers.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import type { Principal } from "../../src/identity/PrincipalRegistry.js";
import { HaltSwitch } from "../../src/incident/HaltSwitch.js";
import { InMemoryExecutionJournal } from "../../src/journal/InMemoryExecutionJournal.js";
import type { CardOutcomeFact } from "../../src/outcomes/CardOutcomeFact.js";
import {
  CardOutcomeLedgerError,
  InMemoryCardOutcomeLedger,
  type CardOutcomeLedger,
} from "../../src/outcomes/CardOutcomeLedger.js";
import {
  OutcomeEvidenceRefusal,
  type OutcomeEvidenceSink,
} from "../../src/outcomes/CoreOutcomeEvidenceClient.js";
import {
  OutcomeEvidenceSubmissionSchema,
  type OutcomeEvidence,
  type OutcomeEvidenceSubmission,
} from "../../src/outcomes/OutcomeEvidence.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { ORG_ID, PRODUCER_TOKEN, coreClassification } from "../support/CardOutcomeFacts.js";
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

/** The issuer app's backend, where a tap lands for an authorization no agent proposed. */
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

/** Core's evidence resource as a double: every submission, checked against the contract. */
class CoreDouble implements OutcomeEvidenceSink {
  public readonly received: OutcomeEvidenceSubmission[] = [];
  public refuse: OutcomeEvidenceRefusal | null = null;

  public async submit(
    submission: OutcomeEvidenceSubmission,
  ): Promise<{ accepted: number; duplicates: number }> {
    await Promise.resolve();
    OutcomeEvidenceSubmissionSchema.parse(submission);
    if (this.refuse !== null) throw this.refuse;
    this.received.push(submission);
    return { accepted: submission.evidence.length, duplicates: 0 };
  }
}

interface Built {
  readonly service: TrustedExecutorService;
  readonly ledger: CardOutcomeLedger;
  readonly core: CoreDouble;
  readonly securityLines: string[];
  readonly lines: string[];
  readonly dir: string;
}

function build(
  outcomes: "off" | "record" | "publish",
  options: {
    readonly mode?: "ENFORCEMENT" | "SHADOW";
    readonly env?: Record<string, string>;
    readonly ledger?: CardOutcomeLedger | "file";
  } = {},
): Built {
  const dir = mkdtempSync(join(tmpdir(), "agentsafe-card-outcomes-"));
  const outcomeEnv: Record<string, string> =
    outcomes === "off"
      ? {}
      : outcomes === "record"
        ? { EXECUTOR_CARD_OUTCOMES: "record", EXECUTOR_CARD_OUTCOMES_DIR: dir }
        : {
            EXECUTOR_CARD_OUTCOMES: "publish",
            EXECUTOR_CARD_OUTCOMES_DIR: dir,
            EXECUTOR_CARD_OUTCOMES_ORG_ID: ORG_ID,
            DECIONIS_PRODUCER_TOKEN: PRODUCER_TOKEN,
          };
  const env: Record<string, string> = {
    ...loopbackEnvironment(
      { authority, providerBaseUrl: "http://127.0.0.1:9" },
      options.mode ?? "ENFORCEMENT",
      "NONE",
    ),
    DOWNSTREAM_SYSTEM: "synthetic-issuer",
    DOWNSTREAM_OPERATION: "card_purchase",
    EXECUTOR_ACTOR_ID: "synthetic-shopping-agent",
    ...outcomeEnv,
    ...options.env,
  };
  const config = ExecutorConfigLoader.load(env);
  const lines: string[] = [];
  const securityLines: string[] = [];
  const events = collectedEvents(securityLines);
  const ledger =
    options.ledger === "file" ? null : (options.ledger ?? new InMemoryCardOutcomeLedger());
  const core = new CoreDouble();
  const service = TrustedExecutorService.create(
    config,
    openSecrets(env, config, events),
    cardHandlers(),
    {
      emit: (line) => lines.push(line),
      security: events,
      journal: new InMemoryExecutionJournal(),
      halt: new HaltSwitch({ events }),
      outcomeSink: core,
      ...(ledger === null ? {} : { cardOutcomeLedger: ledger }),
    },
  );
  return {
    service,
    ledger: ledger ?? new InMemoryCardOutcomeLedger(),
    core,
    securityLines,
    lines,
    dir,
  };
}

let sequence = 0;

function purchase(amountMinor: number) {
  sequence += 1;
  const parameters = {
    cardTokenRef: `fixture_card_ref_outcome_${sequence}`,
    amountMinor,
    currency: "EUR",
    merchantId: `fixture_merchant_outcome_${sequence}`,
  };
  return {
    parameters,
    body: {
      proposal: {
        action: "card.purchase",
        target: `card:${parameters.cardTokenRef}`,
        parameters,
      },
      idempotency_key: `fixture-card-outcome-${sequence}`,
    },
  };
}

function authorizationFor(parameters: {
  readonly cardTokenRef: string;
  readonly amountMinor: number;
  readonly merchantId?: string;
}) {
  sequence += 1;
  return {
    authorization_id: `fixture_auth_outcome_${sequence}`,
    card_token_ref: parameters.cardTokenRef,
    amount_minor: parameters.amountMinor,
    currency: "EUR",
    merchant_id: parameters.merchantId ?? `fixture_merchant_outcome_${sequence}`,
  };
}

const events = (lines: readonly string[]): Record<string, unknown>[] =>
  lines.map((line) => JSON.parse(line) as Record<string, unknown>);

const ALL_TIME = new Date(0);

/** A scripted morning at the issuer: an allowed purchase, a tapped one, a forged tap and a block. */
async function morning(service: TrustedExecutorService) {
  const allowed = purchase(4_250);
  const held = await service.propose(allowed.body);
  const asked = authorizationFor(allowed.parameters);
  const approved = await service.authorizeCard(asked, ISSUER);
  const result = await service.settleCard(
    asked.authorization_id,
    { status: "APPROVED", approved_amount_minor: 4_000, auth_code: "A1B2C3" },
    ISSUER,
  );

  const tapped = purchase(50_000);
  const escalated = await service.propose(tapped.body);
  const intent = JSON.parse(JSON.stringify(escalated.escalation?.intent)) as Record<
    string,
    unknown
  >;
  const resumed = await service.resume({ mode: "ATTESTATION", intent, attestation: TAPPED });
  const tappedAsk = authorizationFor(tapped.parameters);
  const tappedApproved = await service.authorizeCard(tappedAsk, ISSUER);
  const tappedResult = await service.settleCard(
    tappedAsk.authorization_id,
    { status: "APPROVED" },
    ISSUER,
  );

  const forgedPurchase = purchase(50_000);
  const unanswered = await service.propose(forgedPurchase.body);
  const forgedIntent = JSON.parse(JSON.stringify(unanswered.escalation?.intent)) as Record<
    string,
    unknown
  >;
  const forged = await service.resume({
    mode: "ATTESTATION",
    intent: forgedIntent,
    attestation: FORGED,
  });

  const blocked = await service.propose(purchase(250_000).body);
  return {
    answers: [
      held,
      approved,
      result,
      escalated,
      resumed,
      tappedApproved,
      tappedResult,
      unanswered,
      forged,
      blocked,
    ],
    secrets: [
      allowed.parameters.cardTokenRef,
      allowed.parameters.merchantId,
      asked.authorization_id,
      tapped.parameters.cardTokenRef,
      tappedAsk.authorization_id,
      forgedPurchase.parameters.cardTokenRef,
      "A1B2C3",
      TAPPED,
      FORGED,
    ],
  };
}

/** What an answer says, without the identifiers and times that differ between two runs. */
function shape(answer: unknown): unknown {
  if (Array.isArray(answer)) return answer.map(shape);
  if (answer === null || typeof answer !== "object") return answer;
  const kept: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(answer as Record<string, unknown>)) {
    if (/(?:_id|_hash|_at|^expires|^intent|digest|reference|Id|Hash|At)$/.test(key)) continue;
    kept[key] = shape(value);
  }
  return kept;
}

describe("card purchases' outcome evidence, kept and stated after the fact", () => {
  it("records what each purchase came to, and states it to Decionis without a card reference, a merchant, an authorization id or a tap", async () => {
    const { service, ledger, core, securityLines, lines } = build("publish");
    const { answers, secrets } = await morning(service);
    expect(answers.map((answer) => ("verdict" in answer ? answer.verdict : null))).toEqual([
      "ALLOW",
      null,
      null,
      "ESCALATE",
      "ALLOW",
      null,
      null,
      "ESCALATE",
      "BLOCK",
      "BLOCK",
    ]);
    await service.cardOutcomes?.flush();
    const facts = await ledger.since(ALL_TIME);
    const byIntent = new Map<string, string[]>();
    for (const fact of facts) {
      byIntent.set(fact.intent_id, [...(byIntent.get(fact.intent_id) ?? []), fact.kind]);
    }
    expect([...byIntent.values()]).toEqual([
      ["DECIDED", "CLAIMED", "SETTLED"],
      ["DECIDED", "RESUMED", "CLAIMED", "SETTLED"],
      ["DECIDED", "RESUMED"],
      ["DECIDED"],
    ]);
    const first = facts[0] as Extract<CardOutcomeFact, { kind: "DECIDED" }>;
    expect(first).toMatchObject({
      mode: "ENFORCEMENT",
      verdict: "ALLOW",
      currency: "EUR",
      amount_minor: 4_250,
    });
    expect(first.held_until).not.toBeNull();

    const summary = await service.cardOutcomes?.publish();
    expect(summary).toMatchObject({ collected: 4, submitted: 4, accepted: 4, refused: null });
    expect(core.received).toHaveLength(1);
    const submission = core.received[0] as OutcomeEvidenceSubmission;
    expect(submission).toMatchObject({ producer: "agentsafe", org_id: ORG_ID });
    const evidence = [...submission.evidence].sort((a, b) =>
      a.occurred_at.localeCompare(b.occurred_at),
    );
    expect(evidence.map((item: OutcomeEvidence) => coreClassification(item))).toEqual([
      "GOVERNED/EXECUTED_WITH_PERMIT",
      "FALSE_HOLD/RELEASED_AS_LEGITIMATE",
      // The forged tap is no one's answer: the hold waits for the cardholder.
      "PENDING/AWAITING_REVIEW",
      "HELD_UNCONFIRMED/BLOCKED_WITHOUT_REVIEW",
    ]);
    expect(evidence[0]).toMatchObject({
      platform: "card-authorization",
      action_type: "CARD_PURCHASE",
      amount: { currency: "EUR", scale: 2, amount_minor: 4_250 },
      execution: { status: "COMMITTED" },
      financial: null,
    });
    expect(evidence[1]?.review).toMatchObject({ outcome: "RELEASED", reviewer: "CUSTOMER" });
    expect(evidence[2]?.review).toBeNull();

    // Nothing the producer keeps or states carries the card, the merchant, the issuer's
    // references or the tap, and the streams still carry none of them either.
    const written = [
      ...facts.map((fact) => JSON.stringify(fact)),
      JSON.stringify(core.received),
      ...lines,
      ...securityLines,
    ].join("\n");
    for (const secret of secrets) expect(written).not.toContain(secret);
    expect(events(securityLines)).toContainEqual(
      expect.objectContaining({
        event: "CARD_OUTCOMES_PUBLISHED",
        submitted: 4,
        accepted: 4,
        duplicates: 0,
        conflicts: 0,
      }),
    );

    // A second run states the same evidence, and sends nothing.
    expect(await service.cardOutcomes?.publish()).toMatchObject({ submitted: 0, unchanged: 4 });
    expect(core.received).toHaveLength(1);
    service.close();
  });

  it("answers every request exactly as it does with outcomes off", async () => {
    const off = build("off");
    const on = build("publish");
    expect(off.service.cardOutcomes).toBeNull();
    const plain = await morning(off.service);
    const recorded = await morning(on.service);
    expect(shape(recorded.answers)).toEqual(shape(plain.answers));
    await on.service.cardOutcomes?.flush();
    expect((await on.ledger.since(ALL_TIME)).length).toBeGreaterThan(0);
    off.service.close();
    on.service.close();
  });

  it("never lets a ledger that fails touch an authorization, and counts what it lost", async () => {
    const failing: CardOutcomeLedger = {
      append: async () => {
        await Promise.resolve();
        throw new CardOutcomeLedgerError("CARD_OUTCOMES_UNWRITABLE");
      },
      since: async () => await Promise.resolve([]),
    };
    const { service, securityLines } = build("publish", { ledger: failing });
    const { answers } = await morning(service);
    expect(answers[0]).toMatchObject({ verdict: "ALLOW", outcome: "HELD_FOR_AUTHORIZATION" });
    expect(answers[2]).toMatchObject({ outcome: "COMMITTED", executed: true });
    await service.cardOutcomes?.flush();
    const dropped = events(securityLines).filter(
      (event) => event["event"] === "CARD_OUTCOMES_DROPPED",
    );
    expect(dropped.length).toBeGreaterThan(0);
    expect(dropped.every((event) => event["code"] === "CARD_OUTCOMES_UNWRITABLE")).toBe(true);
    service.close();
  });

  it("records a shadow evaluation as what would have been decided, at the proposal and at the issuer's hook", async () => {
    const { service, ledger } = build("record", { mode: "SHADOW", env: EVALUATE() });
    const observed = await service.propose(purchase(50_000).body);
    expect(observed).toMatchObject({ mode: "SHADOW", verdict: "ESCALATE" });
    expect(
      await service.authorizeCard(
        authorizationFor({ cardTokenRef: "fixture_card_ref_outcome_hook", amountMinor: 4_250 }),
        ISSUER,
      ),
    ).toEqual({ decision: "NO_MATCH", code: "SHADOW_OBSERVED" });
    await service.cardOutcomes?.flush();
    const facts = await ledger.since(ALL_TIME);
    expect(facts).toMatchObject([
      { kind: "DECIDED", mode: "SHADOW", verdict: "ESCALATE", held_until: null },
      { kind: "DECIDED", mode: "SHADOW", verdict: "ALLOW", held_until: null },
    ]);
    // Recording only: nothing is stated to Decionis.
    expect(await service.cardOutcomes?.publish()).toBeNull();
    service.close();
  });

  it("records a flagged authorization held at the issuer's hook, tapped, re-presented and settled", async () => {
    const { service, ledger } = build("record", { env: EVALUATE() });
    const asked = authorizationFor({
      cardTokenRef: "fixture_card_ref_outcome_flagged",
      amountMinor: 50_000,
    });
    const pending = await service.authorizeCard(asked, ISSUER);
    if (pending.decision !== "PENDING") throw new Error("not pending");
    await service.resume(
      {
        mode: "ATTESTATION",
        intent: JSON.parse(JSON.stringify(pending.escalation.intent)) as Record<string, unknown>,
        attestation: TAPPED,
      },
      PRESENTING_APP,
    );
    expect(await service.authorizeCard(asked, ISSUER)).toMatchObject({ decision: "APPROVE" });
    await service.settleCard(asked.authorization_id, { status: "DECLINED" }, ISSUER);
    // An allowed authorization at the hook is decided, held and claimed in one call.
    const direct = authorizationFor({
      cardTokenRef: "fixture_card_ref_outcome_direct",
      amountMinor: 4_250,
    });
    expect(await service.authorizeCard(direct, ISSUER)).toMatchObject({ decision: "APPROVE" });
    await service.cardOutcomes?.flush();
    const facts = await ledger.since(ALL_TIME);
    expect(facts.map((fact) => fact.kind)).toEqual([
      "DECIDED",
      "RESUMED",
      "CLAIMED",
      "SETTLED",
      "DECIDED",
      "CLAIMED",
    ]);
    expect(facts[0]).toMatchObject({
      verdict: "ESCALATE",
      tenant_id: "00000000-0000-4000-8000-000000000002",
    });
    expect(facts[3]).toMatchObject({ outcome: "FAILED" });
    expect(JSON.stringify(facts)).not.toContain(asked.authorization_id);
    service.close();
  });

  it("keeps the evidence owed when Decionis refuses the producer, and says so", async () => {
    const { service, core, securityLines } = build("publish");
    await service.propose(purchase(250_000).body);
    await service.cardOutcomes?.flush();
    core.refuse = new OutcomeEvidenceRefusal("OUTCOME_PRODUCER_NOT_ALLOWED", true);
    expect(await service.cardOutcomes?.publish()).toMatchObject({
      refused: "OUTCOME_PRODUCER_NOT_ALLOWED",
      retry: false,
    });
    expect(events(securityLines)).toContainEqual(
      expect.objectContaining({
        event: "CARD_OUTCOMES_REFUSED",
        code: "OUTCOME_PRODUCER_NOT_ALLOWED",
        retry: false,
      }),
    );
    // Authorizations go on as before.
    expect(await service.propose(purchase(4_250).body)).toMatchObject({ verdict: "ALLOW" });
    await service.cardOutcomes?.flush();
    core.refuse = null;
    expect(await service.cardOutcomes?.publish()).toMatchObject({ submitted: 2, refused: null });
    service.close();
  });

  it("keeps the facts and the publisher's state in the configured directory, and publishes on its own timer", async () => {
    const { service, core, dir } = build("publish", { ledger: "file" });
    await service.propose(purchase(4_250).body);
    await service.cardOutcomes?.flush();
    await service.startCards();
    // The first run starts at once, off the request path.
    for (let attempt = 0; attempt < 50 && core.received.length === 0; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(core.received).toHaveLength(1);
    const files = readdirSync(dir).sort();
    expect(
      files.some((file) => /^card-outcomes-\d{4}-\d{2}-\d{2}\.[a-z0-9-]+\.jsonl$/.test(file)),
    ).toBe(true);
    expect(existsSync(join(dir, "card-outcomes-state.json"))).toBe(true);
    expect(readFileSync(join(dir, "card-outcomes-state.json"), "utf8")).not.toContain(
      "fixture_card_ref",
    );
    service.close();
  });
});
