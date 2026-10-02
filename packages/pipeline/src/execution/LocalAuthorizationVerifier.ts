import { randomBytes } from "node:crypto";
import type { GateDecision } from "../decision/DecisionAuthority.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type {
  AuthorizationFinalizationInput,
  AuthorizationVerifier,
  ExecutionCommitOutcome,
  VerifiedAuthorization,
} from "./AuthorizationVerifier.js";
import type { ReplayStore } from "./ReplayStore.js";

/** What an in-process authority decided, held until the executor consumes it. */
export interface LocalGrant {
  readonly intentId: string;
  readonly intentHash: string;
  readonly decisionId: string;
  readonly dossierId: string;
  readonly expiresAt: string;
}

/**
 * Authorizations issued in this process. A token is 256 random bits that
 * never leave the process except inside the decision the executor is handed,
 * and it names nothing: what it authorizes is held here, so a token cannot be
 * forged, edited, or carried to another process. A token is taken at most
 * once.
 */
export class LocalGrants {
  private readonly grants = new Map<string, LocalGrant>();

  public constructor(
    private readonly clock: () => number = Date.now,
    private readonly maxEntries = 10_000,
  ) {}

  /** Holds `grant` and returns the token that names it. Lapsed grants are dropped first. */
  public issue(grant: LocalGrant): string {
    const now = this.clock();
    for (const [token, held] of this.grants) {
      if (Date.parse(held.expiresAt) <= now) this.grants.delete(token);
    }
    if (this.grants.size >= this.maxEntries) throw new Error("LOCAL_GRANTS_CAPACITY_EXCEEDED");
    const token = randomBytes(32).toString("base64url");
    this.grants.set(token, Object.freeze({ ...grant }));
    return token;
  }

  /** The grant `token` names, removed so that no second caller can take it. */
  public take(token: string): LocalGrant | undefined {
    const grant = this.grants.get(token);
    this.grants.delete(token);
    return grant;
  }
}

/** What the local finalization writes: the outcome against the local decision, nothing else. */
export interface LocalFinalizationRecord {
  readonly event: "EDGE_EXECUTION_FINALIZED";
  readonly intent_id: string;
  readonly intent_hash: string;
  readonly decision_id: string;
  readonly outcome: ExecutionCommitOutcome;
}

export interface LocalAuthorizationVerifierOptions {
  readonly grants: LocalGrants;
  /** Single use, keyed by `intent_id`, for local and delegated grants alike. */
  readonly replay: ReplayStore;
  /** The verifier for every authorization this process did not issue: the hosted one. */
  readonly delegate?: AuthorizationVerifier;
  readonly clock?: () => number;
  /** Where a local attempt's outcome is recorded; it is the only record the outcome has. */
  readonly record: (record: LocalFinalizationRecord) => void;
}

/**
 * The `AuthorizationVerifier` for an executor whose authority decides
 * locally. An authorization this process issued is checked against the grant
 * it names and consumed here, once: the grant is taken from the store, and
 * the intent is claimed in the replay store, so neither the same token nor a
 * second decision about the same intent can run it again. Anything else is
 * handed to the delegate unchanged, and a delegated authorization claims the
 * intent too, so an intent is executable once whichever path allowed it.
 */
export class LocalAuthorizationVerifier implements AuthorizationVerifier {
  private readonly clock: () => number;
  private readonly local = new WeakSet<VerifiedAuthorization>();

  public constructor(private readonly options: LocalAuthorizationVerifierOptions) {
    this.clock = options.clock ?? Date.now;
  }

  public async verifyAndConsume(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<VerifiedAuthorization | null> {
    if (decision.authorization === null) return null;
    const grant = this.options.grants.take(decision.authorization.token);
    if (grant === undefined) return await this.delegated(captured, decision);
    if (
      decision.verdict !== "ALLOW" ||
      decision.failClosed ||
      decision.decisionId !== grant.decisionId ||
      decision.dossierId !== grant.dossierId ||
      decision.intentHash !== grant.intentHash ||
      decision.authorization.expiresAt !== grant.expiresAt ||
      captured.intentHash !== grant.intentHash ||
      captured.intent.intentId !== grant.intentId ||
      Date.parse(grant.expiresAt) <= this.clock()
    ) {
      return null;
    }
    if (!(await this.options.replay.claim(grant.intentId, new Date(grant.expiresAt)))) return null;
    const authorization: VerifiedAuthorization = Object.freeze({
      decisionId: grant.decisionId,
      dossierId: grant.dossierId,
      grantId: `edge:${grant.intentId}`,
      intentHash: grant.intentHash,
      expiresAt: grant.expiresAt,
    });
    this.local.add(authorization);
    return authorization;
  }

  /**
   * A local attempt's outcome is recorded where its decision was: in this
   * process's evidence. A delegated one is finalized by its own verifier.
   */
  public async finalize(input: AuthorizationFinalizationInput): Promise<"RECORDED" | "PENDING"> {
    if (!this.local.has(input.authorization)) {
      const finalize = this.options.delegate?.finalize;
      if (finalize === undefined) return "PENDING";
      return await finalize.call(this.options.delegate, input);
    }
    try {
      this.options.record({
        event: "EDGE_EXECUTION_FINALIZED",
        intent_id: input.captured.intent.intentId,
        intent_hash: input.authorization.intentHash,
        decision_id: input.authorization.decisionId,
        outcome: input.outcome,
      });
      return "RECORDED";
    } catch {
      return "PENDING";
    }
  }

  private async delegated(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<VerifiedAuthorization | null> {
    const delegate = this.options.delegate;
    if (delegate === undefined) return null;
    const authorization = await delegate.verifyAndConsume(captured, decision);
    if (authorization === null) return null;
    const claimed = await this.options.replay.claim(
      captured.intent.intentId,
      new Date(authorization.expiresAt),
    );
    return claimed ? authorization : null;
  }
}
