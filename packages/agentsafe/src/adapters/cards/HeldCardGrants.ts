import {
  CARD_VELOCITY_WINDOW_MS,
  cardHoldKey,
  type CardClaimInput,
  type CardHoldKey,
  type CardHoldStore,
  type CardVelocity,
  type ClaimedCardAuthorization,
  type HeldCardGrant,
  type HeldCardGrantRecord,
} from "./CardHoldStore.js";
import type { CardAuthorizationRequest } from "./CardPurchase.js";

export type {
  CardApproval,
  CardVelocity,
  ClaimedCardAuthorization,
  HeldCardGrant,
} from "./CardHoldStore.js";
export { CARD_VELOCITY_WINDOW_MS } from "./CardHoldStore.js";

export interface HeldCardGrantsOptions {
  /** Entries of each kind this process keeps at most; a hold beyond it is refused. */
  readonly maxEntries?: number;
  /** How long a claimed authorization waits for its result before it is forgotten. */
  readonly claimRetentionMs?: number;
  readonly clock?: () => number;
}

/**
 * Grants held for a card authorization that has not happened yet, keyed by
 * the card and the merchant, and the authorizations that claimed one, keyed
 * by the issuer's authorization id. In memory and bounded on purpose: a hold
 * lives no longer than its grant, which the authority caps in minutes, and a
 * restart that loses one loses only a grant nobody claimed, which expires
 * with no effect. A claimed authorization is already in the journal. A
 * deployment with more than one replica, or one that must keep its holds
 * across a restart, uses the shared store instead.
 *
 * One card has at most one spendable hold per merchant. An agent that wants
 * a second purchase at the same merchant on the same card waits for the
 * first to be authorised or to expire, so an authorization can never be
 * matched to the wrong one of two; purchases at different merchants hold in
 * parallel, because the authorization names its merchant.
 */
export class HeldCardGrants implements CardHoldStore {
  public readonly kind = "memory" as const;
  private static readonly MAX_ACTIVITY_PER_CARD = 100;
  private readonly holds = new Map<string, HeldCardGrant>();
  private readonly claims = new Map<string, ClaimedCardAuthorization>();
  /** When each card was last held for and claimed, most recently touched card last. */
  private readonly activity = new Map<
    string,
    Array<{ readonly at: number; readonly kind: "hold" | "claim" }>
  >();
  private readonly maxEntries: number;
  private readonly claimRetentionMs: number;
  private readonly clock: () => number;

  public constructor(options: HeldCardGrantsOptions = {}) {
    this.maxEntries = options.maxEntries ?? 10_000;
    this.claimRetentionMs = options.claimRetentionMs ?? 15 * 60_000;
    this.clock = options.clock ?? ((): number => Date.now());
  }

  public async spendable(key: CardHoldKey): Promise<boolean> {
    return this.spendableNow(key);
  }

  public async hold(grant: HeldCardGrant): Promise<boolean> {
    const key = cardHoldKey(grant);
    if (this.spendableNow(grant)) return false;
    this.holds.delete(key);
    if (this.holds.size >= this.maxEntries) return false;
    this.holds.set(key, grant);
    this.note(grant.cardTokenRef, "hold");
    return true;
  }

  public async grant(key: CardHoldKey): Promise<HeldCardGrantRecord | undefined> {
    this.sweep();
    const grant = this.holds.get(cardHoldKey(key));
    if (grant === undefined) return undefined;
    return {
      cardTokenRef: grant.cardTokenRef,
      merchantId: grant.merchantId,
      amountMinor: grant.amountMinor,
      currency: grant.currency,
      mcc: grant.mcc,
      expiresAtMs: grant.expiresAtMs,
      used: grant.used,
      intentId: grant.held.captured.intent.intentId,
      open: async () => grant,
    };
  }

  /** Spent before anything is awaited by the caller: the first to ask gets it, later askers find it used. */
  public async spend(grant: HeldCardGrant): Promise<boolean> {
    if (grant.used || this.holds.get(cardHoldKey(grant)) !== grant) return false;
    grant.used = true;
    return true;
  }

  public async claimed(authorizationId: string): Promise<ClaimedCardAuthorization | undefined> {
    this.sweep();
    return this.claims.get(authorizationId);
  }

  /** Remembers a claim for its result; a full store forgets the oldest, which the journal still holds. */
  public async recordClaim(
    authorizationId: string,
    claim: CardClaimInput,
  ): Promise<ClaimedCardAuthorization> {
    // The claim material is the shared store's concern; here the claim stays in the process.
    const record: ClaimedCardAuthorization = {
      grant: claim.grant,
      request: claim.request,
      authorization: claim.authorization,
      leaseExpiresAtMs: claim.leaseExpiresAtMs,
      answer: claim.answer,
      retainUntilMs: this.clock() + this.claimRetentionMs,
      settled: false,
    };
    if (this.claims.size >= this.maxEntries) {
      const oldest = this.claims.keys().next().value as string;
      this.claims.delete(oldest);
    }
    this.claims.set(authorizationId, record);
    this.note(claim.grant.cardTokenRef, "claim");
    return record;
  }

  public async amend(authorizationId: string, request: CardAuthorizationRequest): Promise<boolean> {
    const claim = this.claims.get(authorizationId);
    if (claim === undefined || claim.settled) return false;
    claim.request = request;
    return true;
  }

  public async settle(authorizationId: string): Promise<boolean> {
    const claim = this.claims.get(authorizationId);
    if (claim === undefined || claim.settled) return false;
    claim.settled = true;
    return true;
  }

  /**
   * The burst a policy wants to see: how many purchases were held for this
   * card and how many authorizations claimed one, over the window. The
   * policy language counts nothing over time, so the executor counts here
   * and puts the numbers in the intent's context; a card reference never
   * leaves with them.
   */
  public async velocity(
    cardTokenRef: string,
    windowMs = CARD_VELOCITY_WINDOW_MS,
  ): Promise<CardVelocity> {
    const since = this.clock() - windowMs;
    const recent = (this.activity.get(cardTokenRef) ?? []).filter((entry) => entry.at > since);
    const holds = recent.filter((entry) => entry.kind === "hold").length;
    return { window_seconds: Math.round(windowMs / 1_000), holds, claims: recent.length - holds };
  }

  public async ready(): Promise<void> {
    return undefined;
  }

  public async cleanup(): Promise<void> {
    this.sweep();
  }

  public async close(): Promise<void> {
    return undefined;
  }

  public get size(): { readonly holds: number; readonly claims: number } {
    return { holds: this.holds.size, claims: this.claims.size };
  }

  private spendableNow(key: CardHoldKey): boolean {
    this.sweep();
    const grant = this.holds.get(cardHoldKey(key));
    return grant !== undefined && !grant.used && grant.expiresAtMs > this.clock();
  }

  /** Remembers one hold or claim on a card, bounded per card and across cards. */
  private note(cardTokenRef: string, kind: "hold" | "claim"): void {
    const now = this.clock();
    const entries = (this.activity.get(cardTokenRef) ?? []).filter(
      (entry) => entry.at > now - CARD_VELOCITY_WINDOW_MS,
    );
    entries.push({ at: now, kind });
    if (entries.length > HeldCardGrants.MAX_ACTIVITY_PER_CARD) {
      entries.splice(0, entries.length - HeldCardGrants.MAX_ACTIVITY_PER_CARD);
    }
    // Re-inserted so the map's order is recency, and the stalest card goes first.
    this.activity.delete(cardTokenRef);
    this.activity.set(cardTokenRef, entries);
    if (this.activity.size > this.maxEntries) {
      this.activity.delete(this.activity.keys().next().value as string);
    }
  }

  private sweep(): void {
    const now = this.clock();
    // An expired hold is kept as long as a claim would be, so an authorization
    // that arrives late is told its grant expired rather than that none existed.
    for (const [key, grant] of this.holds) {
      if (grant.expiresAtMs + this.claimRetentionMs <= now) this.holds.delete(key);
    }
    for (const [key, claim] of this.claims) {
      if (claim.retainUntilMs <= now) this.claims.delete(key);
    }
  }
}
