import type {
  HeldExecution,
  SafeExecutor,
  VerifiedAuthorization,
} from "@decionis/agent-safe-pipeline";
import type { CardAuthorizationAnswer } from "../../service/Requests.js";
import type { PreparedAction } from "../EffectAdapter.js";
import type { HeldCardGrantView } from "./CardAuthorizationMatcher.js";
import type { CardAuthorizationRequest, CardPurchase } from "./CardPurchase.js";

/** One held grant: the purchase, the executor's handle on it, and whether it is spent. */
export interface HeldCardGrant extends HeldCardGrantView {
  readonly purchase: CardPurchase;
  readonly prepared: PreparedAction;
  readonly held: HeldExecution;
  /** The executor that issued the hold; only it can claim it. */
  readonly executor: SafeExecutor;
  used: boolean;
}

/** What the issuer was answered when an authorization matched, kept for a retry of the same one. */
export type CardApproval = Extract<CardAuthorizationAnswer, { readonly decision: "APPROVE" }>;

/** An authorization that claimed a grant, until its result is recorded or it is forgotten. */
export interface ClaimedCardAuthorization {
  readonly grant: HeldCardGrant;
  readonly request: CardAuthorizationRequest;
  readonly authorization: VerifiedAuthorization;
  readonly leaseExpiresAtMs: number;
  readonly answer: CardApproval;
  readonly retainUntilMs: number;
  settled: boolean;
}

export interface HeldCardGrantsOptions {
  /** Entries of each kind this process keeps at most; a hold beyond it is refused. */
  readonly maxEntries?: number;
  /** How long a claimed authorization waits for its result before it is forgotten. */
  readonly claimRetentionMs?: number;
  readonly clock?: () => number;
}

/**
 * Grants held for a card authorization that has not happened yet, keyed by
 * the card token reference, and the authorizations that claimed one, keyed
 * by the issuer's authorization id. In memory and bounded on purpose: a hold
 * lives no longer than its grant, which the authority caps in minutes, and a
 * restart that loses one loses only a grant nobody claimed, which expires
 * with no effect. A claimed authorization is already in the journal.
 *
 * One card has at most one spendable hold. An agent that wants a second
 * purchase on the same card waits for the first to be authorised or to
 * expire, so an authorization can never be matched to the wrong one of two.
 */
export class HeldCardGrants {
  private readonly holds = new Map<string, HeldCardGrant>();
  private readonly claims = new Map<string, ClaimedCardAuthorization>();
  private readonly maxEntries: number;
  private readonly claimRetentionMs: number;
  private readonly clock: () => number;

  public constructor(options: HeldCardGrantsOptions = {}) {
    this.maxEntries = options.maxEntries ?? 10_000;
    this.claimRetentionMs = options.claimRetentionMs ?? 15 * 60_000;
    this.clock = options.clock ?? ((): number => Date.now());
  }

  /** Whether the card has a hold an authorization could still match. */
  public spendable(cardTokenRef: string): boolean {
    const grant = this.grant(cardTokenRef);
    return grant !== undefined && !grant.used && grant.expiresAtMs > this.clock();
  }

  /** The hold for a card, spent, expired or neither, until it is forgotten. */
  public grant(cardTokenRef: string): HeldCardGrant | undefined {
    this.sweep();
    return this.holds.get(cardTokenRef);
  }

  /** Keeps a hold; false when the card already has a spendable one or the store is full. */
  public hold(grant: HeldCardGrant): boolean {
    if (this.spendable(grant.cardTokenRef)) return false;
    this.holds.delete(grant.cardTokenRef);
    if (this.holds.size >= this.maxEntries) return false;
    this.holds.set(grant.cardTokenRef, grant);
    return true;
  }

  public claimed(authorizationId: string): ClaimedCardAuthorization | undefined {
    this.sweep();
    return this.claims.get(authorizationId);
  }

  /** Remembers a claim for its result; a full store forgets the oldest, which the journal still holds. */
  public recordClaim(
    authorizationId: string,
    claim: Omit<ClaimedCardAuthorization, "retainUntilMs" | "settled">,
  ): ClaimedCardAuthorization {
    const record: ClaimedCardAuthorization = {
      ...claim,
      retainUntilMs: this.clock() + this.claimRetentionMs,
      settled: false,
    };
    if (this.claims.size >= this.maxEntries) {
      const oldest = this.claims.keys().next().value as string;
      this.claims.delete(oldest);
    }
    this.claims.set(authorizationId, record);
    return record;
  }

  public get size(): { readonly holds: number; readonly claims: number } {
    return { holds: this.holds.size, claims: this.claims.size };
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
