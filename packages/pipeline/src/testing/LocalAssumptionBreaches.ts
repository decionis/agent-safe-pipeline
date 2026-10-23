import { createHash, randomUUID } from "node:crypto";

/**
 * The hosted authority's assumption breaches, as `LocalAuthority` models them
 * (Decionis `docs/architecture/assumption-breaches.md`): an observed outcome
 * that contradicts what a grant was bound to holds that grant's scope, the
 * action type at its target, until a governed release or recovery review
 * cites it and every piece of its evidence.
 *
 * Hosted, the breach is a fact policy reads (`history.assumption_breach`) and
 * the starter policy's rule ESCALATEs on it; this double has a policy hook
 * instead of rules, so it applies that rule's effect itself: an autonomous
 * ALLOW in a held scope becomes ESCALATE, and a grant issued autonomously
 * fails at claim with `POLICY_STATE_CHANGED`, the code the hosted claim's
 * policy re-run answers. An ALLOW a person approved is that person's
 * decision and goes through, as it would under a policy whose approval rule
 * sits above the hold.
 */

/** Why a breach opened. The double opens the two a finalization can. */
export type LocalAssumptionBreachTrigger = "EFFECT_MISMATCH" | "EFFECT_RECEIPT_CONTRADICTION";

/** Where a breach holds: the action type at one target, as the hosted scope names it. */
export interface LocalAssumptionBreachScope {
  readonly tenantId: string;
  readonly actionType: string;
  readonly system: string;
  readonly environment: string;
  readonly resource: string;
}

export interface LocalAssumptionBreach {
  readonly breachId: string;
  readonly trigger: LocalAssumptionBreachTrigger;
  readonly scope: LocalAssumptionBreachScope;
  readonly grantJti: string;
  readonly dossierId: string;
  /** What a clearance must cite, exactly. */
  readonly evidenceIds: readonly string[];
  status: "OPEN" | "CLEARED";
}

/** What a governed release or recovery review cites to clear a breach. */
export interface LocalAssumptionBreachCitation {
  readonly breachId: string;
  readonly evidenceIds: readonly string[];
}

/** One grant, as the breach model needs it. */
interface GrantSubject {
  readonly scope: LocalAssumptionBreachScope;
  /** Issued on the policy's own ALLOW, with no person's approval. */
  readonly autonomous: boolean;
}

export class LocalAssumptionBreaches {
  /** Every breach opened, oldest first. */
  public readonly all: LocalAssumptionBreach[] = [];
  private readonly subjects = new Map<string, GrantSubject>();

  /** The scope of an intent: the hosted binding's target, environment defaulting to production. */
  public static scopeOf(request: {
    readonly tenant_id: string;
    readonly action: { readonly type: string; readonly resource: string };
    readonly downstream_target: {
      readonly system: string;
      readonly environment?: string | undefined;
    };
  }): LocalAssumptionBreachScope {
    return {
      tenantId: request.tenant_id,
      actionType: request.action.type,
      system: request.downstream_target.system,
      environment: request.downstream_target.environment ?? "production",
      resource: request.action.resource,
    };
  }

  /** The breaches still holding a scope. */
  public openIn(scope: LocalAssumptionBreachScope): readonly LocalAssumptionBreach[] {
    const key = scopeKey(scope);
    return this.all.filter((breach) => breach.status === "OPEN" && scopeKey(breach.scope) === key);
  }

  /** Remembers what a grant was issued for, so its finalization and its claim are scoped. */
  public granted(token: string, scope: LocalAssumptionBreachScope, autonomous: boolean): void {
    this.subjects.set(token, { scope, autonomous });
  }

  /** Whether a claim of this grant is refused: an autonomous grant in a held scope. */
  public holdsClaim(token: string): boolean {
    const subject = this.subjects.get(token);
    return subject !== undefined && subject.autonomous && this.openIn(subject.scope).length > 0;
  }

  /**
   * Opens a breach when a finalization contradicts its binding: a verified
   * receipt that effected another effect, effected what the executor reports
   * FAILED, or refused what it reports COMMITTED; or the executor's own
   * observation of another effect. One per grant, whatever it is retried as.
   */
  public finalized(input: {
    readonly token: string;
    readonly grantJti: string;
    readonly dossierId: string;
    readonly outcome: "COMMITTED" | "FAILED" | "INDETERMINATE";
    readonly expectedEffectDigest: string | null;
    readonly observedEffectDigest: string | null;
    readonly evidenceDigest: string | null;
    readonly receipt: {
      readonly verified: boolean;
      readonly token: string;
      readonly effect_status: "EFFECTED" | "REFUSED" | "INDETERMINATE" | null;
      readonly effect_digest: string | null;
    } | null;
  }): {
    readonly breach_id: string;
    readonly trigger: LocalAssumptionBreachTrigger;
    readonly created: boolean;
  } | null {
    const subject = this.subjects.get(input.token);
    if (subject === undefined) return null;
    const expected = input.expectedEffectDigest;
    const receipt = input.receipt?.verified === true ? input.receipt : null;
    const receiptContradicts =
      receipt !== null &&
      ((receipt.effect_status === "EFFECTED" &&
        ((expected !== null &&
          receipt.effect_digest !== null &&
          receipt.effect_digest !== expected) ||
          input.outcome === "FAILED")) ||
        (receipt.effect_status === "REFUSED" && input.outcome === "COMMITTED"));
    const observationContradicts =
      expected !== null &&
      input.observedEffectDigest !== null &&
      input.observedEffectDigest !== expected;
    if (!receiptContradicts && !observationContradicts) return null;
    const existing = this.all.find((breach) => breach.grantJti === input.grantJti);
    if (existing !== undefined) {
      return { breach_id: existing.breachId, trigger: existing.trigger, created: false };
    }
    const breach: LocalAssumptionBreach = {
      breachId: randomUUID(),
      trigger: receiptContradicts ? "EFFECT_RECEIPT_CONTRADICTION" : "EFFECT_MISMATCH",
      scope: subject.scope,
      grantJti: input.grantJti,
      dossierId: input.dossierId,
      evidenceIds: [
        `grant:${input.grantJti}`,
        `dossier:${input.dossierId}`,
        ...(receiptContradicts && receipt !== null
          ? [`receipt:sha256:${createHash("sha256").update(receipt.token, "utf8").digest("hex")}`]
          : []),
        ...(observationContradicts && input.evidenceDigest !== null
          ? [`effect:${input.evidenceDigest}`]
          : []),
      ].sort(),
      status: "OPEN",
    };
    this.all.push(breach);
    return { breach_id: breach.breachId, trigger: breach.trigger, created: true };
  }

  /**
   * What a governed release or recovery review that cites the breaches does
   * hosted: each must be open and cited with every evidence id it was opened
   * on, or none clears.
   */
  public clear(citations: readonly LocalAssumptionBreachCitation[]): void {
    const found = citations.map((citation) => {
      const breach = this.all.find((one) => one.breachId === citation.breachId);
      if (breach === undefined) throw new Error("POLICY_BREACH_NOT_FOUND");
      if (breach.status !== "OPEN") throw new Error("POLICY_BREACH_NOT_OPEN");
      if ([...citation.evidenceIds].sort().join("\n") !== breach.evidenceIds.join("\n")) {
        throw new Error("POLICY_BREACH_EVIDENCE_MISMATCH");
      }
      return breach;
    });
    for (const breach of found) breach.status = "CLEARED";
  }
}

function scopeKey(scope: LocalAssumptionBreachScope): string {
  return JSON.stringify([
    scope.tenantId,
    scope.actionType,
    scope.system,
    scope.environment,
    scope.resource,
  ]);
}
