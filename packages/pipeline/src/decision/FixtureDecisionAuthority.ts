import { createPublicKey, generateKeyPairSync, randomUUID, type KeyObject } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type {
  AuthorizationFinalizationInput,
  AuthorizationVerifier,
  ExecutionCommitOutcome,
  VerifiedAuthorization,
} from "../execution/AuthorizationVerifier.js";
import type { ReplayStore } from "../execution/ReplayStore.js";
import { InMemoryReplayStore } from "../execution/ReplayStore.js";
import type {
  DecisionAuthority,
  DecisionEvidence,
  DecisionVerdict,
  GateDecision,
} from "./DecisionAuthority.js";
import { immutableGateDecision } from "./ImmutableGateDecision.js";

export type FixtureVerdictResolver = (
  intent: CapturedIntent,
  evidence?: DecisionEvidence,
) => DecisionVerdict;

export interface FixtureAuthorityPair {
  readonly authority: FixtureDecisionAuthority;
  readonly verifier: FixtureAuthorizationVerifier;
}

export interface UnsafeFixtureAuthorityOptions {
  readonly unsafeAllowDevelopmentFixture: true;
  readonly privateKey?: KeyObject;
  readonly keyId?: string;
  readonly replayStore?: ReplayStore;
}

export class FixtureDecisionAuthority implements DecisionAuthority {
  private readonly privateKey: KeyObject;
  private readonly keyId: string;

  public constructor(
    private readonly resolveVerdict: FixtureVerdictResolver,
    options: UnsafeFixtureAuthorityOptions,
  ) {
    assertDevelopmentFixtureAllowed(options.unsafeAllowDevelopmentFixture);
    this.privateKey = options.privateKey ?? generateKeyPairSync("ed25519").privateKey;
    this.keyId = options.keyId ?? "agent-safe-fixture";
  }

  public publicKey(): KeyObject {
    return createPublicKey(this.privateKey);
  }

  public async evaluate(
    intent: CapturedIntent,
    evidence?: DecisionEvidence,
  ): Promise<GateDecision> {
    const verdict = this.resolveVerdict(intent, evidence);
    const decisionId = `fixture_${randomUUID()}`;
    const dossierId = `fixture_dossier_${randomUUID()}`;
    const evidenceField = evidence === undefined ? {} : { evidence };
    if (verdict !== "ALLOW") {
      return immutableGateDecision({
        verdict,
        decisionId,
        dossierId,
        intentHash: intent.intentHash,
        reasonCodes: [`FIXTURE_${verdict}`],
        authorization: null,
        failClosed: false,
        ...evidenceField,
      });
    }
    const issuedAt = Math.floor(Date.now() / 1_000);
    const expiresAt = Math.min(
      issuedAt + 60,
      Math.floor(new Date(intent.intent.expiresAt).valueOf() / 1_000),
    );
    const token = await new SignJWT({
      decision_id: decisionId,
      dossier_id: dossierId,
      decision: "allow",
      scope: "execute",
      binding: { intent_hash: intent.intentHash },
    })
      .setProtectedHeader({ alg: "EdDSA", kid: this.keyId, typ: "JWT" })
      .setIssuer("agent-safe-fixture")
      .setAudience(
        `${intent.intent.downstreamTarget.system}:${intent.intent.downstreamTarget.operation}`,
      )
      .setJti(randomUUID())
      .setIssuedAt(issuedAt)
      .setNotBefore(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(this.privateKey);
    return immutableGateDecision({
      verdict,
      decisionId,
      dossierId,
      intentHash: intent.intentHash,
      reasonCodes: ["FIXTURE_ALLOW"],
      authorization: { token, expiresAt: new Date(expiresAt * 1_000).toISOString() },
      failClosed: false,
      ...evidenceField,
    });
  }
}

/** One claimed fixture grant and, once finalized, the commit outcome recorded for it. */
export interface FixtureCommitRecord {
  readonly grantId: string;
  readonly decisionId: string;
  readonly dossierId: string;
  readonly intentHash: string;
  readonly claimedAt: string;
  readonly outcome: ExecutionCommitOutcome | null;
  readonly finalizedAt: string | null;
}

/**
 * Development verifier. It verifies the fixture authority's signed grant,
 * claims it once through the replay store, and keeps an inspectable commit
 * ledger: `finalize` records the attempt outcome exactly once per claimed
 * grant, so `RECORDED` from this verifier means the entry exists in
 * `ledger()`, never that anything was sent anywhere.
 */
export class FixtureAuthorizationVerifier implements AuthorizationVerifier {
  private readonly commits = new Map<string, FixtureCommitRecord>();

  public constructor(
    private readonly publicKey: KeyObject,
    private readonly replayStore: ReplayStore,
    unsafeAllowDevelopmentFixture: true,
  ) {
    assertDevelopmentFixtureAllowed(unsafeAllowDevelopmentFixture);
  }

  /** Every claimed grant with its recorded outcome, oldest first. */
  public ledger(): readonly FixtureCommitRecord[] {
    return [...this.commits.values()];
  }

  public commitOf(grantId: string): FixtureCommitRecord | null {
    return this.commits.get(grantId) ?? null;
  }

  /**
   * Records the outcome for an authorization this verifier claimed. Unknown,
   * foreign, or already finalized grants stay `PENDING`; nothing throws.
   */
  public async finalize(input: AuthorizationFinalizationInput): Promise<"RECORDED" | "PENDING"> {
    const entry = this.commits.get(input.authorization.grantId);
    if (
      entry === undefined ||
      entry.outcome !== null ||
      entry.decisionId !== input.authorization.decisionId ||
      entry.dossierId !== input.authorization.dossierId ||
      entry.intentHash !== input.authorization.intentHash
    ) {
      return "PENDING";
    }
    this.commits.set(
      entry.grantId,
      Object.freeze({
        ...entry,
        outcome: input.outcome,
        finalizedAt: new Date().toISOString(),
      }),
    );
    return "RECORDED";
  }

  public async verifyAndConsume(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<VerifiedAuthorization | null> {
    if (decision.authorization === null || decision.dossierId === null) return null;
    try {
      const audience = `${captured.intent.downstreamTarget.system}:${captured.intent.downstreamTarget.operation}`;
      const { payload } = await jwtVerify(decision.authorization.token, this.publicKey, {
        algorithms: ["EdDSA"],
        issuer: "agent-safe-fixture",
        audience,
      });
      const binding = payload.binding as { intent_hash?: unknown } | undefined;
      if (
        payload.decision !== "allow" ||
        payload.scope !== "execute" ||
        payload.decision_id !== decision.decisionId ||
        payload.dossier_id !== decision.dossierId ||
        binding?.intent_hash !== captured.intentHash ||
        typeof payload.jti !== "string" ||
        typeof payload.exp !== "number"
      ) {
        return null;
      }
      const expiresAt = new Date(payload.exp * 1_000);
      if (!(await this.replayStore.claim(payload.jti, expiresAt))) return null;
      this.commits.set(
        payload.jti,
        Object.freeze({
          grantId: payload.jti,
          decisionId: decision.decisionId,
          dossierId: decision.dossierId,
          intentHash: captured.intentHash,
          claimedAt: new Date().toISOString(),
          outcome: null,
          finalizedAt: null,
        }),
      );
      return Object.freeze({
        decisionId: decision.decisionId,
        dossierId: decision.dossierId,
        grantId: payload.jti,
        intentHash: captured.intentHash,
        expiresAt: expiresAt.toISOString(),
      });
    } catch {
      return null;
    }
  }
}

export function createFixtureAuthorityPair(
  resolver: FixtureVerdictResolver,
  options: UnsafeFixtureAuthorityOptions,
): FixtureAuthorityPair {
  const authority = new FixtureDecisionAuthority(resolver, options);
  return {
    authority,
    verifier: new FixtureAuthorizationVerifier(
      authority.publicKey(),
      options.replayStore ?? new InMemoryReplayStore(),
      true,
    ),
  };
}

function assertDevelopmentFixtureAllowed(explicitlyAllowed: boolean): void {
  if (!explicitlyAllowed || process.env.NODE_ENV === "production") {
    throw new Error("FIXTURE_AUTHORITY_FORBIDDEN");
  }
}
