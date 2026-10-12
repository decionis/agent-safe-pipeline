import { randomBytes } from "node:crypto";
import type {
  CapturedIntent,
  DecisionGate,
  HeldExecution,
  JsonObject,
  SafeExecutor,
  SqlClient,
  VerifiedAuthorization,
} from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { prepareCardPurchase } from "../../../src/adapters/cards/CardEffect.js";
import { CardHoldSeal } from "../../../src/adapters/cards/CardHoldSeal.js";
import type {
  CardClaimInput,
  CardHoldAdoption,
  HeldCardGrant,
} from "../../../src/adapters/cards/CardHoldStore.js";
import {
  CardHoldStoreError,
  DEFAULT_CARD_HOLDS_TABLE,
  PostgresCardHolds,
} from "../../../src/adapters/cards/PostgresCardHolds.js";
import { FakeCardHoldsSql } from "../../support/FakeCardHoldsSql.js";

const NOW = Date.parse("2026-10-12T12:00:00.000Z");
const KEY = randomBytes(32);

let intents = 0;

function captured(intentId: string): CapturedIntent {
  return {
    intent: { intentId, action: "card.purchase", expiresAt: new Date(NOW + 120_000).toISOString() },
    intentHash: `sha256:${"a".repeat(64)}`,
    canonicalIntent: "{}",
    byteLength: 2,
  } as unknown as CapturedIntent;
}

function decision(expiresAtMs = NOW + 60_000): DecisionGate {
  return {
    verdict: "ALLOW",
    decisionId: "decision-1",
    dossierId: "dossier-1",
    intentHash: `sha256:${"a".repeat(64)}`,
    reasonCodes: [],
    authorization: { token: "grant-token-secret", expiresAt: new Date(expiresAtMs).toISOString() },
    failClosed: false,
  } as unknown as DecisionGate;
}

function grant(
  executor: SafeExecutor,
  overrides: { cardTokenRef?: string; merchantId?: string; expiresAtMs?: number } = {},
): HeldCardGrant {
  intents += 1;
  const intentId = `fixture_intent_${intents}`;
  const purchase = {
    cardTokenRef: overrides.cardTokenRef ?? "fixture_card_1",
    amountMinor: 4_250,
    currency: "EUR",
    merchantId: overrides.merchantId ?? "fixture_m",
  };
  const expiresAtMs = overrides.expiresAtMs ?? NOW + 60_000;
  const held = {
    captured: captured(intentId),
    decision: decision(expiresAtMs),
    expiresAt: new Date(expiresAtMs).toISOString(),
  } as HeldExecution;
  return {
    ...purchase,
    mcc: null,
    expiresAtMs,
    used: false,
    purchase,
    prepared: prepareCardPurchase(purchase),
    held,
    executor,
  };
}

const authorization: VerifiedAuthorization = Object.freeze({
  decisionId: "decision-1",
  dossierId: "dossier-1",
  grantId: "grant-1",
  intentHash: `sha256:${"a".repeat(64)}`,
  expiresAt: new Date(NOW + 60_000).toISOString(),
  leaseExpiresAt: new Date(NOW + 30_000).toISOString(),
});

function claimInput(held: HeldCardGrant, material: JsonObject | null): CardClaimInput {
  return {
    grant: held,
    request: {
      authorization_id: "fixture_auth_1",
      card_token_ref: held.cardTokenRef,
      amount_minor: 4_000,
      currency: "EUR",
      merchant_id: held.merchantId,
    },
    authorization,
    leaseExpiresAtMs: NOW + 30_000,
    answer: {
      decision: "APPROVE",
      authorization_id: "fixture_auth_1",
      intent_id: held.held.captured.intent.intentId,
      intent_hash: authorization.intentHash,
      decision_id: "decision-1",
      dossier_id: "dossier-1",
      grant_id: "grant-1",
      lease_expires_at: authorization.leaseExpiresAt as string,
    },
    material,
  };
}

/** A replica: its own executor identity, and a record of what it was asked to adopt. */
function replica(
  client: SqlClient,
  options: {
    seal?: CardHoldSeal;
    refuseHold?: boolean;
    refuseClaim?: boolean;
    clock?: () => number;
  } = {},
) {
  const executor = { name: randomBytes(4).toString("hex") } as unknown as SafeExecutor;
  const adoptedHolds: { captured: CapturedIntent; decision: DecisionGate }[] = [];
  const adoptedClaims: { authorization: VerifiedAuthorization; material: JsonObject | null }[] = [];
  const adopt: CardHoldAdoption = {
    hold: async (c, d) => {
      adoptedHolds.push({ captured: c, decision: d });
      if (options.refuseHold === true) return null;
      return {
        held: {
          captured: c,
          decision: d,
          expiresAt: d.authorization?.expiresAt ?? "",
        } as HeldExecution,
        executor,
      };
    },
    claim: (c, d, a, material) => {
      adoptedClaims.push({ authorization: a, material });
      if (options.refuseClaim === true) return null;
      return {
        held: { captured: c, decision: d, expiresAt: a.expiresAt } as HeldExecution,
        executor,
      };
    },
  };
  const store = new PostgresCardHolds({
    client,
    namespace: "org-synthetic",
    seal: options.seal ?? CardHoldSeal.fromKey(KEY),
    adopt,
    clock: options.clock ?? (() => NOW),
  });
  return { store, executor, adoptedHolds, adoptedClaims };
}

describe("the shared card hold store", () => {
  it("holds one grant per card and merchant across replicas, and the database decides the race", async () => {
    const sql = new FakeCardHoldsSql();
    const a = replica(sql);
    const b = replica(sql);
    const first = grant(a.executor);
    expect(await a.store.hold(first)).toBe(true);
    expect(
      await b.store.spendable({ cardTokenRef: "fixture_card_1", merchantId: "fixture_m" }),
    ).toBe(true);
    expect(await b.store.hold(grant(b.executor))).toBe(false);
    // Another merchant holds in parallel on the same card.
    expect(await b.store.hold(grant(b.executor, { merchantId: "fixture_m2" }))).toBe(true);
    // Two replicas racing for the same key: the fake answers in order, one wins.
    const [x, y] = await Promise.all([
      a.store.hold(grant(a.executor, { cardTokenRef: "fixture_card_9" })),
      b.store.hold(grant(b.executor, { cardTokenRef: "fixture_card_9" })),
    ]);
    expect([x, y].filter(Boolean)).toHaveLength(1);
    // Spent on A, the key is free for a new hold on B; expired, likewise.
    expect(await a.store.spend(first)).toBe(true);
    expect(await b.store.hold(grant(b.executor))).toBe(true);
    const lapsed = replica(sql, { clock: () => NOW + 120_000 });
    expect(await lapsed.store.hold(grant(lapsed.executor))).toBe(true);
    // Nothing in the rows is the grant's token in clear.
    for (const row of sql.holds.values()) expect(row.sealed).not.toContain("grant-token-secret");
  });

  it("lets any replica match and spend a hold, admitting it there first, once", async () => {
    const sql = new FakeCardHoldsSql();
    const a = replica(sql);
    const b = replica(sql);
    const held = grant(a.executor);
    await a.store.hold(held);
    const key = { cardTokenRef: "fixture_card_1", merchantId: "fixture_m" };
    const onB = await b.store.grant(key);
    expect(onB).toMatchObject({
      ...key,
      amountMinor: 4_250,
      currency: "EUR",
      mcc: null,
      expiresAtMs: NOW + 60_000,
      used: false,
      intentId: held.held.captured.intent.intentId,
    });
    const opened = await onB!.open();
    expect(opened?.executor).toBe(b.executor);
    expect(opened?.held.captured.intent.intentId).toBe(held.held.captured.intent.intentId);
    expect(b.adoptedHolds).toHaveLength(1);
    expect(b.adoptedHolds[0]?.decision.authorization?.token).toBe("grant-token-secret");
    // Admitted once: a second look on B reuses the handle.
    expect(await (await b.store.grant(key))!.open()).toBe(opened);
    expect(b.adoptedHolds).toHaveLength(1);
    // On A the handle is A's own, never adopted.
    expect(await (await a.store.grant(key))!.open()).toBe(held);
    expect(a.adoptedHolds).toHaveLength(0);
    // Spent once, whichever replica asks first.
    expect(await b.store.spend(opened!)).toBe(true);
    expect(opened!.used).toBe(true);
    expect(await a.store.spend(held)).toBe(false);
    expect(held.used).toBe(true);
    expect((await a.store.grant(key))?.used).toBe(true);
    // A hold this process cannot admit opens to nothing, and nothing is spent.
    const refusing = replica(sql, { refuseHold: true });
    await a.store.hold(grant(a.executor, { cardTokenRef: "fixture_card_2" }));
    const refused = await refusing.store.grant({
      cardTokenRef: "fixture_card_2",
      merchantId: "fixture_m",
    });
    expect(await refused!.open()).toBeNull();
    expect(
      await a.store.spendable({ cardTokenRef: "fixture_card_2", merchantId: "fixture_m" }),
    ).toBe(true);
  });

  it("keeps a claim for any replica to settle, with the material the claiming replica sealed", async () => {
    const sql = new FakeCardHoldsSql();
    const a = replica(sql);
    const b = replica(sql);
    const held = grant(a.executor);
    await a.store.hold(held);
    await a.store.spend(held);
    const material: JsonObject = {
      kind: "decionis",
      claim_token: "c".repeat(43),
      execution_token: "e",
    };
    const recorded = await a.store.recordClaim("fixture_auth_1", claimInput(held, material));
    expect(recorded).toMatchObject({ settled: false, retainUntilMs: NOW + 15 * 60_000 });
    for (const row of sql.claims.values()) {
      expect(row.sealed).not.toContain("c".repeat(43));
      expect(row.sealed).not.toContain("grant-token-secret");
    }
    // Read on B: adopted with the sealed material, settled there, once.
    const onB = await b.store.claimed("fixture_auth_1");
    expect(onB).toMatchObject({
      request: recorded.request,
      answer: recorded.answer,
      leaseExpiresAtMs: NOW + 30_000,
      settled: false,
    });
    expect(onB?.grant).toMatchObject({
      cardTokenRef: "fixture_card_1",
      amountMinor: 4_250,
      used: true,
    });
    expect(onB?.grant.executor).toBe(b.executor);
    expect(b.adoptedClaims).toEqual([{ authorization, material }]);
    expect(await b.store.claimed("fixture_auth_1")).toBe(onB);
    expect(b.adoptedClaims).toHaveLength(1);
    expect(await a.store.claimed("fixture_auth_1")).toBe(recorded);
    // An increment on A re-seals the claim with its material, which a third replica reads.
    const more = { ...recorded.request, amount_minor: 4_250 };
    expect(await a.store.amend("fixture_auth_1", more)).toBe(true);
    expect(recorded.request).toEqual(more);
    const c = replica(sql);
    expect((await c.store.claimed("fixture_auth_1"))?.request).toEqual(more);
    expect(c.adoptedClaims[0]?.material).toEqual(material);
    expect(await b.store.settle("fixture_auth_1")).toBe(true);
    expect(await a.store.settle("fixture_auth_1")).toBe(false);
    expect(await a.store.amend("fixture_auth_1", more)).toBe(false);
    expect((await a.store.claimed("fixture_auth_1"))?.settled).toBe(true);
    expect(await a.store.claimed("fixture_auth_unknown")).toBeUndefined();
    expect(await a.store.settle("fixture_auth_unknown")).toBe(false);
    // A claim this process cannot adopt is an error, never a quiet miss.
    const refusing = replica(sql, { refuseClaim: true });
    await expect(refusing.store.claimed("fixture_auth_1")).rejects.toThrow(CardHoldStoreError);
  });

  it("counts a card's activity across replicas and sweeps what lapsed", async () => {
    const sql = new FakeCardHoldsSql();
    const a = replica(sql);
    const b = replica(sql);
    const held = grant(a.executor);
    await a.store.hold(held);
    await b.store.hold(grant(b.executor, { merchantId: "fixture_m2" }));
    await a.store.spend(held);
    await a.store.recordClaim("fixture_auth_1", claimInput(held, null));
    expect(await b.store.velocity("fixture_card_1")).toEqual({
      window_seconds: 600,
      holds: 2,
      claims: 1,
    });
    expect(await b.store.velocity("fixture_card_1", 1)).toEqual({
      window_seconds: 0,
      holds: 2,
      claims: 1,
    });
    expect(await b.store.velocity("fixture_card_2")).toEqual({
      window_seconds: 600,
      holds: 0,
      claims: 0,
    });
    const later = replica(sql, { clock: () => NOW + 2 * 86_400_000 });
    await later.store.cleanup();
    expect(sql.holds.size).toBe(0);
    expect(sql.claims.size).toBe(0);
    expect(sql.activity).toHaveLength(0);
    await expect(a.store.ready()).resolves.toBeUndefined();
    sql.failProbe = true;
    await expect(a.store.ready()).rejects.toThrow("relation does not exist");
    sql.failAll = true;
    await expect(a.store.spendable({ cardTokenRef: "x", merchantId: "y" })).rejects.toThrow(
      "connection refused",
    );
  });

  it("treats a row sealed under another key as absent, and refuses to adopt a claim it cannot open", async () => {
    const sql = new FakeCardHoldsSql();
    const a = replica(sql);
    const held = grant(a.executor);
    await a.store.hold(held);
    await a.store.recordClaim("fixture_auth_1", claimInput(held, null));
    const other = replica(sql, { seal: CardHoldSeal.fromKey(randomBytes(32)) });
    expect(
      await other.store.grant({ cardTokenRef: "fixture_card_1", merchantId: "fixture_m" }),
    ).toBeUndefined();
    await expect(other.store.claimed("fixture_auth_1")).rejects.toMatchObject({
      code: "CLAIM_NOT_ADOPTED",
    });
  });

  it("validates its names and prints the DDL an operator runs once", () => {
    const client = new FakeCardHoldsSql();
    const seal = CardHoldSeal.fromKey(KEY);
    const adopt = replica(client).store as unknown as { adopt: CardHoldAdoption };
    const base = { client, seal, adopt: adopt as unknown as CardHoldAdoption, namespace: "org" };
    expect(() => new PostgresCardHolds({ ...base, table: "Bad-Name" })).toThrow(
      "CARD_HOLDS_TABLE_INVALID",
    );
    expect(() => new PostgresCardHolds({ ...base, namespace: "" })).toThrow(
      "CARD_HOLDS_NAMESPACE_INVALID",
    );
    expect(() => new PostgresCardHolds({ ...base, claimRetentionMs: -1 })).toThrow(
      "CARD_HOLDS_RETENTION_INVALID",
    );
    expect(() => PostgresCardHolds.schema("1bad")).toThrow("CARD_HOLDS_TABLE_INVALID");
    const ddl = PostgresCardHolds.schema();
    for (const table of ["_holds", "_claims", "_activity"]) {
      expect(ddl).toContain(`CREATE TABLE IF NOT EXISTS ${DEFAULT_CARD_HOLDS_TABLE}${table} (`);
    }
    expect(ddl).toContain("PRIMARY KEY (namespace, card_token_ref, merchant_id)");
    expect(ddl).toContain("PRIMARY KEY (namespace, authorization_id)");
    expect(PostgresCardHolds.schema("bank.cards")).toContain(
      "CREATE INDEX IF NOT EXISTS bank_cards_holds_expires_at ON bank.cards_holds",
    );
  });
});
