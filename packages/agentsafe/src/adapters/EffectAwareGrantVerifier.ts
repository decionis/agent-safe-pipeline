import type {
  AuthorizationFinalizationInput,
  AuthorizationVerifier,
  CapturedIntent,
  GateDecision,
  VerifiedAuthorization,
} from "@decionis/agent-safe-pipeline";
import { authorityEffectEvidence } from "./EffectEvidenceBuilder.js";
import type { EffectEvidenceRegister } from "./EffectEvidenceRegister.js";

export interface EffectAwareGrantVerifierOptions {
  readonly verifier: AuthorizationVerifier;
  readonly register: EffectEvidenceRegister;
  readonly observer: { readonly id: string; readonly version: string };
}

/**
 * The verifier the executor runs, wrapped so that the observation the
 * handler made reaches the authority with the commit it belongs to. It adds
 * nothing to the claim: `verifyAndConsume` is the delegate's, unchanged, and
 * the grant is still consumed once by whoever the adopter configured.
 *
 * On `finalize` it attaches the effect record the handler registered for
 * this exact authorization. The authority binds evidence by the
 * expected-effect digest and the commit correlation id and refuses a
 * finalization whose evidence it cannot bind, which would lose the commit
 * outcome with it; so the delegate's own drop rule applies and an attempt
 * with no registered observation finalizes exactly as it did before.
 */
export class EffectAwareGrantVerifier implements AuthorizationVerifier {
  public constructor(private readonly options: EffectAwareGrantVerifierOptions) {}

  public async verifyAndConsume(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<VerifiedAuthorization | null> {
    return await this.options.verifier.verifyAndConsume(captured, decision);
  }

  public async finalize(input: AuthorizationFinalizationInput): Promise<"RECORDED" | "PENDING"> {
    const finalize = this.options.verifier.finalize?.bind(this.options.verifier);
    if (finalize === undefined) return "PENDING";
    const effect = this.options.register.take(input.authorization);
    if (effect === null) return await finalize(input);
    // The authority's binding is the commit correlation id, which this
    // repository's verifier takes from the intent's own id.
    return await finalize({
      ...input,
      effectEvidence: authorityEffectEvidence(
        effect,
        input.captured.intent.intentId,
        this.options.observer,
      ),
    });
  }
}
