import type { CardAuthorizationRequest, CardAuthorizationResult } from "../cards/CardPurchase.js";
import {
  cardAuthorizationFromStripe,
  cardResultFromStripe,
  STRIPE_AUTHORIZATION_CREATED,
  STRIPE_AUTHORIZATION_REQUEST,
  stripeAuthorizationOf,
  StripeEventError,
  type StripeAuthorizationView,
} from "./StripeIssuingEvent.js";
import { StripeSignatureError, verifyStripeSignature } from "./StripeSignature.js";

/**
 * - `shadow` (the default): the bridge never answers an authorization. It reads what Stripe
 *   already decided (`issuing_authorization.created`) and has the executor evaluate it, so the
 *   policy's verdict is recorded beside what happened. Nothing it does can decline a card.
 * - `enforce`: the bridge is Stripe's real-time authorization endpoint and the policy answers.
 */
export type StripeBridgeMode = "shadow" | "enforce";

/**
 * What the real-time endpoint does when it cannot get a verdict in time, or cannot form the
 * question: `stand_in` answers with an error so Stripe applies the account's own timeout
 * setting (or Autopilot), the issuer's stand-in decision the plan defaults card authorization
 * to; `decline` answers `approved: false`.
 */
export type StripeUndecidedRule = "stand_in" | "decline";

export interface StripeBridgeConfig {
  readonly mode: StripeBridgeMode;
  /** Which Stripe mode's events this bridge serves; the other mode's are refused. */
  readonly livemode: boolean;
  /** Sent as `Stripe-Version` on every real-time answer, as Stripe requires. */
  readonly stripeVersion: string;
  /** Signing secrets of the endpoints that post here (real-time and events), any one may match. */
  readonly secrets: readonly string[];
  /** The bridge's own budget for a real-time answer, inside Stripe's two seconds. */
  readonly deadlineMs: number;
  readonly onUndecided: StripeUndecidedRule;
}

/** The executor's card hook, as the bridge calls it: an operator holding `cards.authorize`. */
export interface ExecutorCardHook {
  authorize(
    request: CardAuthorizationRequest,
    signal: AbortSignal,
  ): Promise<{ readonly status: number; readonly body: unknown }>;
  settle(
    authorizationId: string,
    result: CardAuthorizationResult,
    signal: AbortSignal,
  ): Promise<{ readonly status: number; readonly body: unknown }>;
}

export interface BridgeReply {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

type HookAnswer =
  | {
      readonly decision: "APPROVE";
      readonly intent_id?: string;
      readonly decision_id?: string;
      readonly dossier_id?: string;
    }
  | {
      readonly decision: "PENDING";
      readonly intent_id?: string;
      readonly decision_id?: string | null;
    }
  | { readonly decision: "NO_MATCH"; readonly code?: string };

const JSON_TYPE = { "content-type": "application/json" } as const;
/** How long an ordinary event may wait on the executor; Stripe retries a failed delivery. */
const EVENT_TIMEOUT_MS = 10_000;

/**
 * Stripe Issuing in front of the executor's card hook (docs/banking/stripe-issuing.md).
 *
 * The bridge decides nothing. It proves an event is Stripe's, keeps only the references and
 * amounts the hook needs, asks the hook, and answers Stripe in Stripe's shape. The policy's
 * verdict, the grant and the evidence are the executor's and the authority's, exactly as for
 * any issuer that posts to `POST /v1/card-authorizations`.
 */
export class StripeIssuingBridge {
  public constructor(
    private readonly config: StripeBridgeConfig,
    private readonly hook: ExecutorCardHook,
    private readonly dependencies: {
      readonly nowMs: () => number;
      readonly log: (line: Readonly<Record<string, unknown>>) => void;
    },
  ) {}

  /** Stripe's real-time authorization endpoint. Only served in `enforce`. */
  public async authorizationRequest(
    body: Buffer,
    signature: string | undefined,
  ): Promise<BridgeReply> {
    const started = this.dependencies.nowMs();
    if (this.config.mode !== "enforce") {
      // Answering here would decide a real card. Shadow never sits in the authorization path.
      this.dependencies.log({ event: "STRIPE_REALTIME_REFUSED_IN_SHADOW" });
      return StripeIssuingBridge.refusal(404, "STRIPE_REALTIME_NOT_ENABLED");
    }
    const view = this.admit(body, signature, STRIPE_AUTHORIZATION_REQUEST);
    if ("refusal" in view) return this.undecided(view.refusal, null, started);

    let request: CardAuthorizationRequest;
    try {
      request = cardAuthorizationFromStripe(view.view, "pending");
    } catch (error) {
      if (error instanceof StripeEventError) return this.undecided(error.code, view.view, started);
      throw error;
    }

    const remaining = this.config.deadlineMs - (this.dependencies.nowMs() - started);
    if (remaining <= 0) return this.undecided("BRIDGE_DEADLINE", view.view, started);
    let answer: { readonly status: number; readonly body: unknown };
    try {
      answer = await this.hook.authorize(request, AbortSignal.timeout(remaining));
    } catch (error) {
      const code =
        error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")
          ? "EXECUTOR_TIMEOUT"
          : "EXECUTOR_UNAVAILABLE";
      return this.undecided(code, view.view, started);
    }
    if (answer.status !== 200) {
      return this.undecided(
        `EXECUTOR_${StripeIssuingBridge.code(answer.body)}`,
        view.view,
        started,
      );
    }
    const decided = answer.body as HookAnswer;
    switch (decided.decision) {
      case "APPROVE":
        return this.answer(view.view, true, started, {
          decionis_decision: "APPROVE",
          ...StripeIssuingBridge.references(decided),
        });
      case "PENDING":
        // Stripe cannot pend. The hold the approver's answer leaves is keyed by card and
        // merchant, so the cardholder's retry, a new authorization, matches it.
        return this.answer(view.view, false, started, {
          decionis_decision: "PENDING",
          decionis_code: "ESCALATION_PENDING",
          ...StripeIssuingBridge.references(decided),
        });
      case "NO_MATCH":
        return this.answer(view.view, false, started, {
          decionis_decision: "NO_MATCH",
          decionis_code: StripeIssuingBridge.code(decided),
        });
      default:
        return this.undecided("EXECUTOR_ANSWER_INVALID", view.view, started);
    }
  }

  /**
   * Stripe's ordinary events. `issuing_authorization.created` says what Stripe did with an
   * authorization, whoever decided it (the policy, a timeout, Autopilot, spending controls):
   * in `enforce` it settles the claim the hook made; in `shadow` it has the hook evaluate what
   * already happened. Every other event is acknowledged and ignored.
   */
  public async event(body: Buffer, signature: string | undefined): Promise<BridgeReply> {
    const admitted = this.admit(body, signature, null);
    if ("refusal" in admitted) return StripeIssuingBridge.refusal(400, admitted.refusal);
    const view = admitted.view;
    if (view.type !== STRIPE_AUTHORIZATION_CREATED)
      return StripeIssuingBridge.ok({ ignored: true });
    if (view.lastRequest !== null && view.lastRequest.reason.startsWith("webhook_")) {
      // The answer was Stripe's stand-in, not the policy's: worth watching before enforcement.
      this.dependencies.log({
        event: "STRIPE_STAND_IN_DECIDED",
        authorization_id: view.authorizationId,
        reason: view.lastRequest.reason,
        approved: view.approved,
      });
    }
    return this.config.mode === "enforce" ? this.settle(view) : this.observe(view);
  }

  private async settle(view: StripeAuthorizationView): Promise<BridgeReply> {
    let settled: { readonly status: number; readonly body: unknown };
    try {
      settled = await this.hook.settle(
        view.authorizationId,
        cardResultFromStripe(view),
        AbortSignal.timeout(EVENT_TIMEOUT_MS),
      );
    } catch {
      // Stripe retries a failed delivery; the result is recorded once whenever it lands.
      return StripeIssuingBridge.refusal(503, "EXECUTOR_UNAVAILABLE");
    }
    const code = StripeIssuingBridge.code(settled.body);
    if (settled.status === 200 || code === "CARD_RESULT_ALREADY_RECORDED") {
      this.dependencies.log({
        event: "STRIPE_AUTHORIZATION_SETTLED",
        authorization_id: view.authorizationId,
        approved: view.approved,
        replayed: settled.status !== 200,
      });
      return StripeIssuingBridge.ok({ settled: true });
    }
    // Nothing was claimed for it: declined before the endpoint was asked, or answered no.
    if (code === "CARD_AUTHORIZATION_UNKNOWN") return StripeIssuingBridge.ok({ settled: false });
    return StripeIssuingBridge.refusal(503, `EXECUTOR_${code}`);
  }

  private async observe(view: StripeAuthorizationView): Promise<BridgeReply> {
    let request: CardAuthorizationRequest;
    try {
      request = cardAuthorizationFromStripe(view, "history");
    } catch (error) {
      if (!(error instanceof StripeEventError)) throw error;
      this.dependencies.log({
        event: "STRIPE_SHADOW_SKIPPED",
        authorization_id: view.authorizationId,
        code: error.code,
      });
      return StripeIssuingBridge.ok({ observed: false });
    }
    let answer: { readonly status: number; readonly body: unknown };
    try {
      answer = await this.hook.authorize(request, AbortSignal.timeout(EVENT_TIMEOUT_MS));
    } catch {
      return StripeIssuingBridge.refusal(503, "EXECUTOR_UNAVAILABLE");
    }
    if (answer.status !== 200) {
      return StripeIssuingBridge.refusal(503, `EXECUTOR_${StripeIssuingBridge.code(answer.body)}`);
    }
    const decided = answer.body as HookAnswer;
    if (decided.decision === "APPROVE") {
      // The executor enforces while the bridge shadows: a grant was claimed for a purchase
      // that already happened. Settle it with what Stripe did, and say so loudly.
      this.dependencies.log({
        event: "STRIPE_SHADOW_EXECUTOR_ENFORCING",
        authorization_id: view.authorizationId,
      });
      return this.settle(view);
    }
    this.dependencies.log({
      event: "STRIPE_SHADOW_OBSERVED",
      authorization_id: view.authorizationId,
      stripe_approved: view.approved,
      decision: decided.decision,
      code: decided.decision === "NO_MATCH" ? StripeIssuingBridge.code(decided) : null,
    });
    return StripeIssuingBridge.ok({ observed: true });
  }

  /** Signature first, then the event's shape, its mode and, when one is expected, its type. */
  private admit(
    body: Buffer,
    signature: string | undefined,
    type: string | null,
  ): { readonly view: StripeAuthorizationView } | { readonly refusal: string } {
    try {
      verifyStripeSignature({
        body,
        header: signature,
        secrets: this.config.secrets,
        nowSeconds: Math.floor(this.dependencies.nowMs() / 1000),
      });
    } catch (error) {
      if (error instanceof StripeSignatureError) {
        this.dependencies.log({ event: "STRIPE_SIGNATURE_REFUSED", code: error.code });
        return { refusal: error.code };
      }
      throw error;
    }
    let view: StripeAuthorizationView;
    try {
      view = stripeAuthorizationOf(body);
    } catch (error) {
      if (error instanceof StripeEventError) return { refusal: error.code };
      throw error;
    }
    if (view.livemode !== this.config.livemode) return { refusal: "STRIPE_LIVEMODE_MISMATCH" };
    if (type !== null && view.type !== type) return { refusal: "STRIPE_EVENT_UNEXPECTED" };
    return { view };
  }

  private answer(
    view: StripeAuthorizationView,
    approved: boolean,
    started: number,
    metadata: Readonly<Record<string, string>>,
  ): BridgeReply {
    this.dependencies.log({
      event: "STRIPE_AUTHORIZATION_ANSWERED",
      authorization_id: view.authorizationId,
      approved,
      decision: metadata.decionis_decision,
      code: metadata.decionis_code ?? null,
      elapsed_ms: this.dependencies.nowMs() - started,
    });
    return {
      status: 200,
      headers: { ...JSON_TYPE, "stripe-version": this.config.stripeVersion },
      body: JSON.stringify({ approved, metadata }),
    };
  }

  private undecided(
    code: string,
    view: StripeAuthorizationView | null,
    started: number,
  ): BridgeReply {
    this.dependencies.log({
      event: "STRIPE_AUTHORIZATION_UNDECIDED",
      authorization_id: view?.authorizationId ?? null,
      code,
      rule: this.config.onUndecided,
      elapsed_ms: this.dependencies.nowMs() - started,
    });
    if (this.config.onUndecided === "decline" && view !== null) {
      return this.answer(view, false, started, {
        decionis_decision: "UNDECIDED",
        decionis_code: code,
      });
    }
    // No answer Stripe can act on: it applies the account's timeout setting or Autopilot.
    return StripeIssuingBridge.refusal(view === null ? 400 : 503, code);
  }

  private static references(answer: {
    readonly intent_id?: string;
    readonly decision_id?: string | null;
  }): Record<string, string> {
    return {
      ...(typeof answer.intent_id === "string" ? { decionis_intent_id: answer.intent_id } : {}),
      ...(typeof answer.decision_id === "string"
        ? { decionis_decision_id: answer.decision_id }
        : {}),
    };
  }

  /** A refusal code from an executor body, bounded to what Stripe metadata may hold. */
  private static code(body: unknown): string {
    const code = (body as { readonly code?: unknown } | null)?.code;
    return typeof code === "string" && /^[A-Z0-9_]{1,80}$/.test(code) ? code : "UNKNOWN";
  }

  private static ok(body: Readonly<Record<string, unknown>>): BridgeReply {
    return { status: 200, headers: JSON_TYPE, body: JSON.stringify(body) };
  }

  private static refusal(status: number, code: string): BridgeReply {
    return { status, headers: JSON_TYPE, body: JSON.stringify({ code }) };
  }
}
