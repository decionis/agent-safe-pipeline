import { randomBytes } from "node:crypto";
import type {
  CapturedIntent,
  DecisionGate,
  JsonObject,
  SqlClient,
  VerifiedAuthorization,
} from "@decionis/agent-safe-pipeline";
import { prepareCardPurchase } from "./CardEffect.js";
import type { CardHoldSeal } from "./CardHoldSeal.js";
import {
  CARD_KEY_SEPARATOR,
  CARD_VELOCITY_WINDOW_MS,
  cardHoldKey,
  type CardApproval,
  type CardClaimInput,
  type CardHoldAdoption,
  type CardHoldKey,
  type CardHoldStore,
  type CardVelocity,
  type ClaimedCardAuthorization,
  type HeldCardGrant,
  type HeldCardGrantRecord,
} from "./CardHoldStore.js";
import type { CardAuthorizationRequest, CardPurchase } from "./CardPurchase.js";

export const DEFAULT_CARD_HOLDS_TABLE = "agentsafe_card";

/** What a sealed hold's and a sealed claim's identities begin with, so neither opens as the other. */
const HOLD_IDENTITY = "agentsafe-card-hold";
const CLAIM_IDENTITY = "agentsafe-card-claim";
const CLAIM_NOT_ADOPTED = "CLAIM_NOT_ADOPTED";

/** A lowercase SQL identifier prefix, or `schema.prefix`, short enough for its three suffixes. */
const TABLE = /^[a-z_][a-z0-9_]{0,53}(?:\.[a-z_][a-z0-9_]{0,53})?$/;
const DAY_MS = 86_400_000;

export class CardHoldStoreError extends Error {
  public constructor(public readonly code: typeof CLAIM_NOT_ADOPTED | "CARD_HOLDS_UNAVAILABLE") {
    super(code);
    this.name = "CardHoldStoreError";
  }
}

export interface PostgresCardHoldsOptions {
  readonly client: SqlClient;
  /** Whose holds these are: one deployment. Two deployments on one database never see each other's. */
  readonly namespace: string;
  /** The tables' prefix, optionally schema-qualified; `agentsafe_card` by default. */
  readonly table?: string;
  /** Seals what the rows keep of a grant and a claim; the key stays in the process. */
  readonly seal: CardHoldSeal;
  /** How this process admits a hold or a claim another replica made. */
  readonly adopt: CardHoldAdoption;
  /** This replica's name in a row, for an operator reading the table; random when absent. */
  readonly replica?: string;
  /** How long a claimed authorization waits for its result before it is forgotten. */
  readonly claimRetentionMs?: number;
  readonly clock?: () => number;
}

interface SealedHold {
  readonly captured: CapturedIntent;
  readonly decision: DecisionGate;
  readonly purchase: CardPurchase;
}

interface SealedClaim extends SealedHold {
  readonly authorization: VerifiedAuthorization;
  readonly request: CardAuthorizationRequest;
  readonly answer: CardApproval;
  readonly material: JsonObject | null;
}

interface HoldRow {
  readonly intentId: string;
  readonly used: boolean;
  readonly expiresAtMs: number;
  readonly sealed: string;
}

interface ClaimRow {
  readonly intentId: string;
  readonly leaseExpiresAtMs: number;
  readonly retainUntilMs: number;
  readonly settled: boolean;
  readonly sealed: string;
}

const column = (row: unknown, name: string): unknown =>
  row !== null && typeof row === "object" ? (row as Record<string, unknown>)[name] : undefined;

/**
 * Holds and claims shared by every replica, and kept across a restart. A
 * hold is one row, unique on the card and the merchant; `hold` takes the
 * key when its row is absent, spent or expired, in one statement, so of two
 * purchases racing for the same card at the same merchant the database lets
 * one hold. `spend` sets `used` on the row that is still unspent and
 * unexpired, in one statement, so of two authorizations racing for the
 * same hold the database lets one claim: the same race rule as in memory,
 * decided by the database instead of by one process's memory.
 *
 * What a row keeps of the grant, and later of the claim, is sealed under
 * the deployment's hold key, so the database holds no bearer credential in
 * clear; the columns outside the seal are references, times and flags. A
 * hold another replica made is admitted here on first use, through the
 * executor's own checks, and a claim another replica made is finalized here
 * with the material that replica sealed. The operator creates the tables
 * (`PostgresCardHolds.schema()`); the executor's role needs SELECT, INSERT,
 * UPDATE and DELETE on them and nothing else.
 */
export class PostgresCardHolds implements CardHoldStore {
  public readonly kind = "postgres" as const;
  private readonly client: SqlClient;
  private readonly namespace: string;
  private readonly holds: string;
  private readonly claims: string;
  private readonly activity: string;
  private readonly seal: CardHoldSeal;
  private readonly adopt: CardHoldAdoption;
  private readonly replica: string;
  private readonly claimRetentionMs: number;
  private readonly clock: () => number;
  /** The handles this process holds, by key, each valid for the intent it was made for. */
  private readonly localHolds = new Map<string, HeldCardGrant>();
  private readonly localClaims = new Map<string, ClaimedCardAuthorization>();
  /** The claim material each claim was recorded with here, for re-sealing an amendment. */
  private readonly materials = new Map<
    string,
    { readonly intentId: string; readonly material: JsonObject | null }
  >();

  public constructor(options: PostgresCardHoldsOptions) {
    const table = options.table ?? DEFAULT_CARD_HOLDS_TABLE;
    if (!TABLE.test(table)) throw new Error("CARD_HOLDS_TABLE_INVALID");
    if (options.namespace.length === 0 || options.namespace.length > 200) {
      throw new Error("CARD_HOLDS_NAMESPACE_INVALID");
    }
    const retention = options.claimRetentionMs ?? 15 * 60_000;
    if (!Number.isSafeInteger(retention) || retention < 0) {
      throw new Error("CARD_HOLDS_RETENTION_INVALID");
    }
    this.client = options.client;
    this.namespace = options.namespace;
    this.holds = `${table}_holds`;
    this.claims = `${table}_claims`;
    this.activity = `${table}_activity`;
    this.seal = options.seal;
    this.adopt = options.adopt;
    this.replica = options.replica ?? randomBytes(8).toString("hex");
    this.claimRetentionMs = retention;
    this.clock = options.clock ?? Date.now;
  }

  /** The DDL an operator runs once, before the first replica starts. */
  public static schema(table = DEFAULT_CARD_HOLDS_TABLE): string {
    if (!TABLE.test(table)) throw new Error("CARD_HOLDS_TABLE_INVALID");
    const plain = table.replace(".", "_");
    return [
      `CREATE TABLE IF NOT EXISTS ${table}_holds (`,
      "  namespace text NOT NULL,",
      "  card_token_ref text NOT NULL,",
      "  merchant_id text NOT NULL,",
      "  intent_id text NOT NULL,",
      "  expires_at timestamptz NOT NULL,",
      "  held_at timestamptz NOT NULL,",
      "  used boolean NOT NULL DEFAULT false,",
      "  used_at timestamptz,",
      "  replica text NOT NULL,",
      "  sealed text NOT NULL,",
      "  PRIMARY KEY (namespace, card_token_ref, merchant_id)",
      ");",
      `CREATE INDEX IF NOT EXISTS ${plain}_holds_expires_at ON ${table}_holds (expires_at);`,
      `CREATE TABLE IF NOT EXISTS ${table}_claims (`,
      "  namespace text NOT NULL,",
      "  authorization_id text NOT NULL,",
      "  intent_id text NOT NULL,",
      "  claimed_at timestamptz NOT NULL,",
      "  lease_expires_at timestamptz NOT NULL,",
      "  retain_until timestamptz NOT NULL,",
      "  settled boolean NOT NULL DEFAULT false,",
      "  settled_at timestamptz,",
      "  replica text NOT NULL,",
      "  sealed text NOT NULL,",
      "  PRIMARY KEY (namespace, authorization_id)",
      ");",
      `CREATE INDEX IF NOT EXISTS ${plain}_claims_retain_until ON ${table}_claims (retain_until);`,
      `CREATE TABLE IF NOT EXISTS ${table}_activity (`,
      "  namespace text NOT NULL,",
      "  card_token_ref text NOT NULL,",
      "  kind text NOT NULL,",
      "  at timestamptz NOT NULL",
      ");",
      `CREATE INDEX IF NOT EXISTS ${plain}_activity_card ON ${table}_activity (namespace, card_token_ref, at);`,
      "",
    ].join("\n");
  }

  public async spendable(key: CardHoldKey): Promise<boolean> {
    const result = await this.client.query(
      `SELECT 1 FROM ${this.holds} WHERE namespace = $1 AND card_token_ref = $2 AND merchant_id = $3 AND used = false AND expires_at > $4`,
      [this.namespace, key.cardTokenRef, key.merchantId, this.iso(this.clock())],
    );
    return result.rowCount === 1;
  }

  public async hold(grant: HeldCardGrant): Promise<boolean> {
    const intentId = grant.held.captured.intent.intentId;
    const now = this.clock();
    const sealed = this.seal.seal(
      JSON.stringify({
        captured: grant.held.captured,
        decision: grant.held.decision,
        purchase: grant.purchase,
      } satisfies SealedHold),
      this.holdIdentity(grant, intentId),
    );
    const result = await this.client.query(
      `INSERT INTO ${this.holds} (namespace, card_token_ref, merchant_id, intent_id, expires_at, held_at, used, used_at, replica, sealed) VALUES ($1, $2, $3, $4, $5, $6, false, NULL, $7, $8) ON CONFLICT (namespace, card_token_ref, merchant_id) DO UPDATE SET intent_id = EXCLUDED.intent_id, expires_at = EXCLUDED.expires_at, held_at = EXCLUDED.held_at, used = false, used_at = NULL, replica = EXCLUDED.replica, sealed = EXCLUDED.sealed WHERE ${this.holds}.used = true OR ${this.holds}.expires_at <= EXCLUDED.held_at`,
      [
        this.namespace,
        grant.cardTokenRef,
        grant.merchantId,
        intentId,
        this.iso(grant.expiresAtMs),
        this.iso(now),
        this.replica,
        sealed,
      ],
    );
    if (result.rowCount !== 1) return false;
    this.localHolds.set(cardHoldKey(grant), grant);
    await this.note(grant.cardTokenRef, "hold", now);
    return true;
  }

  public async grant(key: CardHoldKey): Promise<HeldCardGrantRecord | undefined> {
    const result = await this.client.query(
      `SELECT intent_id, used, (extract(epoch FROM expires_at) * 1000)::bigint AS expires_at_ms, sealed FROM ${this.holds} WHERE namespace = $1 AND card_token_ref = $2 AND merchant_id = $3`,
      [this.namespace, key.cardTokenRef, key.merchantId],
    );
    const row = PostgresCardHolds.holdRow(result.rows?.[0]);
    if (row === null) return undefined;
    const opened = this.seal.open(row.sealed, this.holdIdentity(key, row.intentId));
    if (opened === null) return undefined;
    const { captured, decision, purchase } = JSON.parse(opened) as SealedHold;
    const view = {
      cardTokenRef: key.cardTokenRef,
      merchantId: key.merchantId,
      amountMinor: purchase.amountMinor,
      currency: purchase.currency,
      mcc: purchase.mcc ?? null,
      expiresAtMs: row.expiresAtMs,
    };
    const localKey = cardHoldKey(key);
    return {
      ...view,
      used: row.used,
      intentId: row.intentId,
      open: async () => {
        const local = this.localHolds.get(localKey);
        if (local !== undefined && local.held.captured.intent.intentId === row.intentId) {
          local.used = row.used;
          return local;
        }
        const admitted = await this.adopt.hold(captured, decision);
        if (admitted === null) return null;
        const adopted: HeldCardGrant = {
          ...view,
          used: row.used,
          purchase,
          prepared: prepareCardPurchase(purchase),
          held: admitted.held,
          executor: admitted.executor,
        };
        this.localHolds.set(localKey, adopted);
        return adopted;
      },
    };
  }

  public async spend(grant: HeldCardGrant): Promise<boolean> {
    const now = this.clock();
    const result = await this.client.query(
      `UPDATE ${this.holds} SET used = true, used_at = $5, replica = $6 WHERE namespace = $1 AND card_token_ref = $2 AND merchant_id = $3 AND intent_id = $4 AND used = false AND expires_at > $5`,
      [
        this.namespace,
        grant.cardTokenRef,
        grant.merchantId,
        grant.held.captured.intent.intentId,
        this.iso(now),
        this.replica,
      ],
    );
    grant.used = true;
    return result.rowCount === 1;
  }

  public async claimed(authorizationId: string): Promise<ClaimedCardAuthorization | undefined> {
    const result = await this.client.query(
      `SELECT intent_id, settled, (extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, (extract(epoch FROM retain_until) * 1000)::bigint AS retain_until_ms, sealed FROM ${this.claims} WHERE namespace = $1 AND authorization_id = $2`,
      [this.namespace, authorizationId],
    );
    const row = PostgresCardHolds.claimRow(result.rows?.[0]);
    if (row === null) return undefined;
    const local = this.localClaims.get(authorizationId);
    if (local !== undefined && local.grant.held.captured.intent.intentId === row.intentId) {
      local.settled = row.settled;
      return local;
    }
    const opened = this.seal.open(row.sealed, this.claimIdentity(authorizationId, row.intentId));
    if (opened === null) throw new CardHoldStoreError(CLAIM_NOT_ADOPTED);
    const sealed = JSON.parse(opened) as SealedClaim;
    const admitted = this.adopt.claim(
      sealed.captured,
      sealed.decision,
      sealed.authorization,
      sealed.material,
    );
    if (admitted === null) throw new CardHoldStoreError(CLAIM_NOT_ADOPTED);
    const grant: HeldCardGrant = {
      cardTokenRef: sealed.purchase.cardTokenRef,
      merchantId: sealed.purchase.merchantId,
      amountMinor: sealed.purchase.amountMinor,
      currency: sealed.purchase.currency,
      mcc: sealed.purchase.mcc ?? null,
      expiresAtMs: Date.parse(
        sealed.decision.authorization?.expiresAt ?? sealed.authorization.expiresAt,
      ),
      used: true,
      purchase: sealed.purchase,
      prepared: prepareCardPurchase(sealed.purchase),
      held: admitted.held,
      executor: admitted.executor,
    };
    const claim: ClaimedCardAuthorization = {
      grant,
      request: sealed.request,
      authorization: sealed.authorization,
      leaseExpiresAtMs: row.leaseExpiresAtMs,
      answer: sealed.answer,
      retainUntilMs: row.retainUntilMs,
      settled: row.settled,
    };
    this.localClaims.set(authorizationId, claim);
    this.materials.set(authorizationId, { intentId: row.intentId, material: sealed.material });
    return claim;
  }

  public async recordClaim(
    authorizationId: string,
    claim: CardClaimInput,
  ): Promise<ClaimedCardAuthorization> {
    const now = this.clock();
    const retainUntilMs = now + this.claimRetentionMs;
    const intentId = claim.grant.held.captured.intent.intentId;
    const record: ClaimedCardAuthorization = {
      grant: claim.grant,
      request: claim.request,
      authorization: claim.authorization,
      leaseExpiresAtMs: claim.leaseExpiresAtMs,
      answer: claim.answer,
      retainUntilMs,
      settled: false,
    };
    await this.client.query(
      `INSERT INTO ${this.claims} (namespace, authorization_id, intent_id, claimed_at, lease_expires_at, retain_until, settled, settled_at, replica, sealed) VALUES ($1, $2, $3, $4, $5, $6, false, NULL, $7, $8) ON CONFLICT (namespace, authorization_id) DO NOTHING`,
      [
        this.namespace,
        authorizationId,
        intentId,
        this.iso(now),
        this.iso(claim.leaseExpiresAtMs),
        this.iso(retainUntilMs),
        this.replica,
        this.sealClaim(authorizationId, intentId, record, claim.material),
      ],
    );
    this.localClaims.set(authorizationId, record);
    this.materials.set(authorizationId, { intentId, material: claim.material });
    await this.note(claim.grant.cardTokenRef, "claim", now);
    return record;
  }

  public async amend(authorizationId: string, request: CardAuthorizationRequest): Promise<boolean> {
    const claim = await this.claimed(authorizationId);
    if (claim === undefined || claim.settled) return false;
    const intentId = claim.grant.held.captured.intent.intentId;
    const amended: ClaimedCardAuthorization = { ...claim, request };
    const material = this.materialOf(authorizationId, intentId);
    const result = await this.client.query(
      `UPDATE ${this.claims} SET sealed = $3 WHERE namespace = $1 AND authorization_id = $2 AND settled = false`,
      [
        this.namespace,
        authorizationId,
        this.sealClaim(authorizationId, intentId, amended, material),
      ],
    );
    if (result.rowCount !== 1) return false;
    claim.request = request;
    return true;
  }

  public async settle(authorizationId: string): Promise<boolean> {
    const result = await this.client.query(
      `UPDATE ${this.claims} SET settled = true, settled_at = $3 WHERE namespace = $1 AND authorization_id = $2 AND settled = false`,
      [this.namespace, authorizationId, this.iso(this.clock())],
    );
    const local = this.localClaims.get(authorizationId);
    if (local !== undefined) local.settled = true;
    return result.rowCount === 1;
  }

  public async velocity(
    cardTokenRef: string,
    windowMs = CARD_VELOCITY_WINDOW_MS,
  ): Promise<CardVelocity> {
    const result = await this.client.query(
      `SELECT kind, count(*)::int AS n FROM ${this.activity} WHERE namespace = $1 AND card_token_ref = $2 AND at > $3 GROUP BY kind`,
      [this.namespace, cardTokenRef, this.iso(this.clock() - windowMs)],
    );
    let holds = 0;
    let claims = 0;
    for (const row of result.rows ?? []) {
      const n = Number(column(row, "n"));
      if (!Number.isFinite(n)) continue;
      if (column(row, "kind") === "hold") holds += n;
      if (column(row, "kind") === "claim") claims += n;
    }
    return { window_seconds: Math.round(windowMs / 1_000), holds, claims };
  }

  /** Throws unless every table exists with the columns this store uses. */
  public async ready(): Promise<void> {
    await this.client.query(
      `SELECT namespace, card_token_ref, merchant_id, intent_id, expires_at, held_at, used, used_at, replica, sealed FROM ${this.holds} LIMIT 0`,
      [],
    );
    await this.client.query(
      `SELECT namespace, authorization_id, intent_id, claimed_at, lease_expires_at, retain_until, settled, settled_at, replica, sealed FROM ${this.claims} LIMIT 0`,
      [],
    );
    await this.client.query(
      `SELECT namespace, card_token_ref, kind, at FROM ${this.activity} LIMIT 0`,
      [],
    );
  }

  /**
   * Forgets what lapsed: a hold a claim's retention after its expiry (so a
   * late authorization is still told its grant expired), a claim after its
   * retention, and activity older than the velocity window plus a day.
   */
  public async cleanup(): Promise<void> {
    const now = this.clock();
    await this.client.query(`DELETE FROM ${this.holds} WHERE expires_at <= $1`, [
      this.iso(now - this.claimRetentionMs),
    ]);
    await this.client.query(`DELETE FROM ${this.claims} WHERE retain_until <= $1`, [this.iso(now)]);
    await this.client.query(`DELETE FROM ${this.activity} WHERE at <= $1`, [
      this.iso(now - CARD_VELOCITY_WINDOW_MS - DAY_MS),
    ]);
    for (const [key, grant] of this.localHolds) {
      if (grant.expiresAtMs + this.claimRetentionMs <= now) this.localHolds.delete(key);
    }
    for (const [key, claim] of this.localClaims) {
      if (claim.retainUntilMs <= now) {
        this.localClaims.delete(key);
        this.materials.delete(key);
      }
    }
  }

  public async close(): Promise<void> {
    return undefined;
  }

  private async note(cardTokenRef: string, kind: "hold" | "claim", at: number): Promise<void> {
    await this.client.query(
      `INSERT INTO ${this.activity} (namespace, card_token_ref, kind, at) VALUES ($1, $2, $3, $4)`,
      [this.namespace, cardTokenRef, kind, this.iso(at)],
    );
  }

  private sealClaim(
    authorizationId: string,
    intentId: string,
    claim: ClaimedCardAuthorization,
    material: JsonObject | null,
  ): string {
    return this.seal.seal(
      JSON.stringify({
        captured: claim.grant.held.captured,
        decision: claim.grant.held.decision,
        purchase: claim.grant.purchase,
        authorization: claim.authorization,
        request: claim.request,
        answer: claim.answer,
        material,
      } satisfies SealedClaim),
      this.claimIdentity(authorizationId, intentId),
    );
  }

  /** The material a claim was recorded with here, kept only in the row; re-read for an amendment. */
  private materialOf(authorizationId: string, intentId: string): JsonObject | null {
    const material = this.materials.get(authorizationId);
    return material === undefined || material.intentId !== intentId ? null : material.material;
  }

  private holdIdentity(key: CardHoldKey, intentId: string): string {
    return [HOLD_IDENTITY, this.namespace, key.cardTokenRef, key.merchantId, intentId].join(
      CARD_KEY_SEPARATOR,
    );
  }

  private claimIdentity(authorizationId: string, intentId: string): string {
    return [CLAIM_IDENTITY, this.namespace, authorizationId, intentId].join(CARD_KEY_SEPARATOR);
  }

  private iso(ms: number): string {
    return new Date(ms).toISOString();
  }

  private static holdRow(row: unknown): HoldRow | null {
    const intentId = column(row, "intent_id");
    const sealed = column(row, "sealed");
    const expiresAtMs = Number(column(row, "expires_at_ms"));
    if (
      typeof intentId !== "string" ||
      typeof sealed !== "string" ||
      !Number.isFinite(expiresAtMs)
    ) {
      return null;
    }
    return { intentId, used: column(row, "used") === true, expiresAtMs, sealed };
  }

  private static claimRow(row: unknown): ClaimRow | null {
    const intentId = column(row, "intent_id");
    const sealed = column(row, "sealed");
    const leaseExpiresAtMs = Number(column(row, "lease_expires_at_ms"));
    const retainUntilMs = Number(column(row, "retain_until_ms"));
    if (
      typeof intentId !== "string" ||
      typeof sealed !== "string" ||
      !Number.isFinite(leaseExpiresAtMs) ||
      !Number.isFinite(retainUntilMs)
    ) {
      return null;
    }
    return {
      intentId,
      leaseExpiresAtMs,
      retainUntilMs,
      settled: column(row, "settled") === true,
      sealed,
    };
  }
}
