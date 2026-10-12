import type {
  CapturedIntent,
  DecisionGate,
  HeldExecution,
  JsonObject,
  SafeExecutor,
  VerifiedAuthorization,
} from "@decionis/agent-safe-pipeline";
import type { CardAuthorizationAnswer } from "../../service/Requests.js";
import type { PreparedAction } from "../EffectAdapter.js";
import type { HeldCardGrantView } from "./CardAuthorizationMatcher.js";
import type { CardAuthorizationRequest, CardPurchase } from "./CardPurchase.js";

/** What a hold is keyed by: one card at one merchant. A burst across merchants holds in parallel. */
export interface CardHoldKey {
  readonly cardTokenRef: string;
  readonly merchantId: string;
}

/** Between the parts of a key or a row's identity: a character no reference can contain. */
export const CARD_KEY_SEPARATOR = "\u0000";

/** The key as one string. */
export function cardHoldKey(key: CardHoldKey): string {
  return `${key.cardTokenRef}${CARD_KEY_SEPARATOR}${key.merchantId}`;
}

/** One held grant: the purchase, the executor's handle on it, and whether it is spent. */
export interface HeldCardGrant extends HeldCardGrantView {
  readonly purchase: CardPurchase;
  readonly prepared: PreparedAction;
  readonly held: HeldExecution;
  /** The executor that holds the handle; only it can claim and settle it. */
  readonly executor: SafeExecutor;
  used: boolean;
}

/**
 * A hold as the store finds it: what the matcher reads, the intent it was
 * made for, and `open`, which yields the grant with a handle this process
 * can claim, admitting it here first when another replica made it. Null
 * from `open` means this process cannot admit it, and nothing was spent.
 */
export interface HeldCardGrantRecord extends HeldCardGrantView {
  readonly intentId: string;
  open(): Promise<HeldCardGrant | null>;
}

/** What the issuer was answered when an authorization matched, kept for a retry of the same one. */
export type CardApproval = Extract<CardAuthorizationAnswer, { readonly decision: "APPROVE" }>;

/** An authorization that claimed a grant, until its result is recorded or it is forgotten. */
export interface ClaimedCardAuthorization {
  readonly grant: HeldCardGrant;
  request: CardAuthorizationRequest;
  readonly authorization: VerifiedAuthorization;
  readonly leaseExpiresAtMs: number;
  readonly answer: CardApproval;
  readonly retainUntilMs: number;
  settled: boolean;
}

/** What `recordClaim` is given: the claim, and what a replica needs to finalize it elsewhere. */
export interface CardClaimInput extends Omit<
  ClaimedCardAuthorization,
  "retainUntilMs" | "settled"
> {
  /** The verifier's claim material, sealed by a shared store and never written in clear. */
  readonly material: JsonObject | null;
}

/** How far back a card's holds and claims are counted for policy. */
export const CARD_VELOCITY_WINDOW_MS = 10 * 60_000;

/** How often one card was held for and claimed lately: counts for policy, never a reference. */
export interface CardVelocity {
  readonly window_seconds: number;
  readonly holds: number;
  readonly claims: number;
}

/** What a store needs from the process to admit a hold or a claim another replica made. */
export interface CardHoldAdoption {
  hold(
    captured: CapturedIntent,
    decision: DecisionGate,
  ): Promise<{ readonly held: HeldExecution; readonly executor: SafeExecutor } | null>;
  claim(
    captured: CapturedIntent,
    decision: DecisionGate,
    authorization: VerifiedAuthorization,
    material: JsonObject | null,
  ): { readonly held: HeldExecution; readonly executor: SafeExecutor } | null;
}

/**
 * Where held grants and the authorizations that claimed them live. One key
 * (a card at a merchant) has at most one spendable hold, and a hold is spent
 * once, whichever replica the authorization reaches: `spend` is the race
 * rule, and it is the same rule in memory and in the shared store.
 */
export interface CardHoldStore {
  readonly kind: "memory" | "postgres";
  /** Whether the key has a hold an authorization could still match. */
  spendable(key: CardHoldKey): Promise<boolean>;
  /** Keeps a hold; false when the key already has a spendable one or the store is full. */
  hold(grant: HeldCardGrant): Promise<boolean>;
  /** The hold for a key, spent, expired or neither, until it is forgotten. */
  grant(key: CardHoldKey): Promise<HeldCardGrantRecord | undefined>;
  /** Spends a hold once: true for the one caller that did, false for every other. */
  spend(grant: HeldCardGrant): Promise<boolean>;
  claimed(authorizationId: string): Promise<ClaimedCardAuthorization | undefined>;
  /** Remembers a claim for its result. */
  recordClaim(authorizationId: string, claim: CardClaimInput): Promise<ClaimedCardAuthorization>;
  /** An incremental authorization: the same claim, re-presented for more; false when unknown. */
  amend(authorizationId: string, request: CardAuthorizationRequest): Promise<boolean>;
  /** Marks a claim settled once: false when it was already, or is unknown. */
  settle(authorizationId: string): Promise<boolean>;
  velocity(cardTokenRef: string, windowMs?: number): Promise<CardVelocity>;
  /** Throws unless the store can be used; for the shared store, the tables are reachable. */
  ready(): Promise<void>;
  /** Forgets what lapsed; nothing to do in memory, which sweeps as it goes. */
  cleanup(): Promise<void>;
  close(): Promise<void>;
}
