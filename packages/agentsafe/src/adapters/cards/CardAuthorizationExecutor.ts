import type {
  AuthorityEffectEvidence,
  ClaimedExecution,
  EffectObservation,
  EffectPreparedAction,
  ExecutionCapability,
  ExecutionEffect,
  JsonObject,
  NativeExecutor,
  PreparedAction,
  ReconcileResult,
} from "@decionis/agent-safe-pipeline";
import { authorityEffectEvidence } from "../EffectEvidenceBuilder.js";
import type { RegisteredEffect } from "../EffectEvidenceRegister.js";
import { cardResultRecord, prepareCardPurchase } from "./CardEffect.js";
import {
  CARD_PURCHASE_ACTION,
  cardTarget,
  type CardAuthorizationRequest,
  type CardAuthorizationResult,
  type CardPurchase,
} from "./CardPurchase.js";

export const CARD_ISSUER_PLATFORM = "card-issuer";

/**
 * What the issuer reported about an authorization it was told to approve,
 * with the attempt it belongs to: the purchase and the projection its grant
 * was bound to, the issuer's request and result, and whether the claim's
 * lease had closed by the time the result arrived.
 */
export interface CardAuthorizationReceipt {
  readonly purchase: CardPurchase;
  readonly prepared: EffectPreparedAction;
  readonly request: CardAuthorizationRequest;
  readonly result: CardAuthorizationResult;
  readonly leaseExpired: boolean;
  readonly correlationId: string;
  readonly idempotencyKey: string;
}

export interface CardAuthorizationExecutorOptions {
  /** The observer the effect record and the authority name. */
  readonly observer: { readonly id: string; readonly version: string };
  readonly clock?: () => Date;
}

/**
 * The cards family on `agent-safe.executors.native/1`, permit style: the
 * issuer performs the effect, when its real-time authorization hook asks, so
 * this executor never writes anything. The grant is held when the purchase
 * is decided; the issuer's authorization request presents it, which claims
 * it once; the permit is the approval the issuer is answered with; and the
 * issuer's result is the receipt that settles it.
 *
 * - `observe` reads the result into the family's effect record: an approval
 *   within the ceiling is the authorised effect, a decline is a refusal, and
 *   a result after the claim's lease is indeterminate whatever it says.
 * - `reconcile` has no one to ask: the issuer is the system of record and
 *   this boundary has no read path into it, so an authorization whose result
 *   never arrived stays unknown until someone who can see the issuer's ledger
 *   says.
 */
export class CardAuthorizationExecutor implements NativeExecutor<
  CardPurchase,
  CardAuthorizationReceipt,
  RegisteredEffect
> {
  public readonly platform = CARD_ISSUER_PLATFORM;
  public readonly style = "permit" as const;
  public readonly actionTypes: readonly string[] = [CARD_PURCHASE_ACTION];
  public readonly version: string;
  private readonly observer: { readonly id: string; readonly version: string };
  private readonly clock: () => Date;

  public constructor(options: CardAuthorizationExecutorOptions) {
    this.observer = options.observer;
    this.version = options.observer.version;
    this.clock = options.clock ?? ((): Date => new Date());
  }

  public async capabilities(): Promise<readonly ExecutionCapability[]> {
    return await Promise.resolve([
      {
        platform: this.platform,
        actionType: CARD_PURCHASE_ACTION,
        enabled: true,
        scopeGranted: true,
        connected: true,
        requirement: "",
      },
    ]);
  }

  /**
   * The purchase as an intent: this card, at this merchant, for at most this
   * amount, bound to the projection the issuer's result is later compared
   * with. The retry identity is the purchase's own digest, so the same
   * purchase proposed twice is one purchase.
   */
  public async prepare(purchase: CardPurchase): Promise<PreparedAction> {
    const effect = prepareCardPurchase(purchase);
    return await Promise.resolve({
      actionType: CARD_PURCHASE_ACTION,
      proposal: {
        action: CARD_PURCHASE_ACTION,
        target: cardTarget(purchase),
        parameters: purchase as JsonObject,
      },
      downstreamTarget: { system: CARD_ISSUER_PLATFORM, operation: "authorize" },
      idempotencyKey: `card-purchase:${effect.intentDigest}`,
      expectedEffectDigest: effect.expectedEffectDigest,
      requestDigest: effect.requestDigest,
      facts: {},
    });
  }

  /** The permit the issuer is answered with: this grant, for this intent, until it expires. */
  public async execute(
    run: ClaimedExecution<CardPurchase>,
  ): Promise<ExecutionEffect<CardAuthorizationReceipt>> {
    return await Promise.resolve({
      kind: "PERMIT",
      permit: {
        permitId: run.authorization.grantId,
        intentHash: run.intent.intentHash,
        expiresAt: run.authorization.expiresAt,
        ...(run.authorization.claimAttestation === undefined
          ? {}
          : { claimAttestation: run.authorization.claimAttestation }),
      },
    });
  }

  /** The issuer's result as the family's effect record; anything but a receipt is unknown. */
  public async observe(
    effect: ExecutionEffect<CardAuthorizationReceipt>,
  ): Promise<EffectObservation<RegisteredEffect>> {
    if (effect.kind !== "RECEIPT") {
      return await Promise.resolve({ status: "INDETERMINATE", reason: null, result: null });
    }
    const receipt = effect.receipt;
    const record = cardResultRecord({
      purchase: receipt.purchase,
      prepared: receipt.prepared,
      authorization: receipt.request,
      result: receipt.result,
      leaseExpired: receipt.leaseExpired,
      observer: this.observer,
      correlationId: receipt.correlationId,
      idempotencyKey: receipt.idempotencyKey,
      observedAt: this.clock().toISOString(),
    });
    const evidence: AuthorityEffectEvidence = authorityEffectEvidence(
      record,
      receipt.correlationId,
      this.observer,
    );
    if (record.outcome === "INDETERMINATE") {
      return { status: "INDETERMINATE", reason: null, result: record, evidence };
    }
    if (record.outcome === "FAILED") {
      return {
        status: "FAILED",
        reason: record.reasonCodes[0] ?? "ISSUER_DECLINED",
        result: record,
        evidence,
      };
    }
    return { status: "COMMITTED", reason: null, result: record, evidence };
  }

  public async reconcile(): Promise<ReconcileResult<RegisteredEffect>> {
    return await Promise.resolve({ status: "UNKNOWN" });
  }
}
