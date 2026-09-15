import type { JsonObject } from "@decionis/agent-safe-pipeline";
import type { DownstreamConfig } from "../../config/ExecutorConfig.js";
import type { PrincipalActor } from "../../identity/PrincipalRegistry.js";
import {
  BankingActionWireSchema,
  transportActionName,
  transportTarget,
  type BankingAction,
} from "./BankingAction.js";

export class BindingError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "BindingError";
  }
}

export interface BindingInput {
  /** The action and target the caller proposed, over the transport. */
  readonly action: string;
  readonly target: string;
  readonly parameters: JsonObject;
  readonly idempotencyKey: string;
  readonly downstream: DownstreamConfig;
  readonly actor: PrincipalActor;
}

export interface BoundBankingAction {
  readonly action: BankingAction;
  /** The trusted context the executor computes; never anything the caller sent. */
  readonly context: JsonObject;
  readonly expectedEffectDigest: string;
  readonly intentDigest: string;
}

/**
 * The gate between the transport and the profile. A BEAP action arrives as
 * the canonical `BankingAction` in the proposal's parameters, and the
 * transport's own action name and target are derived from it rather than
 * trusted: if they disagree, the caller is describing one thing and asking
 * for another, and the proposal is refused before the authority is asked.
 *
 * The same rule covers the request id, which must be the idempotency key the
 * attempt is bound to; the downstream, which must be the one this process is
 * configured for and not a provider the caller named; and the actor, which
 * must be the principal the door authenticated. Every one of these is a
 * `422` refusal, and none of them costs a dossier.
 *
 * What the executor adds is the trusted context: the profile, the intent
 * digest and the expected-effect digest, computed here from the action
 * itself. The proposal schema already refuses a caller-supplied context, so
 * these cannot be presented from outside.
 */
export function bindBankingAction(
  input: BindingInput,
  digests: (action: BankingAction) => {
    readonly intentDigest: string;
    readonly expectedEffectDigest: string;
  },
): BoundBankingAction {
  const parsed = BankingActionWireSchema.safeParse(input.parameters);
  if (!parsed.success) throw new BindingError("BANKING_ACTION_INVALID");
  const action = parsed.data;
  if (transportActionName(action) !== input.action) {
    throw new BindingError("BANKING_ACTION_NAME_MISMATCH");
  }
  if (transportTarget(action) !== input.target) throw new BindingError("BANKING_TARGET_MISMATCH");
  if (action.action.request_id !== input.idempotencyKey) {
    throw new BindingError("BANKING_REQUEST_ID_MISMATCH");
  }
  if (
    action.downstream.provider !== input.downstream.system.toUpperCase() ||
    action.downstream.operation !== input.downstream.operation.toUpperCase() ||
    (action.downstream.environment !== undefined &&
      action.downstream.environment !== input.downstream.environment.toUpperCase())
  ) {
    throw new BindingError("BANKING_DOWNSTREAM_MISMATCH");
  }
  if (action.actor.id !== input.actor.id) throw new BindingError("BANKING_ACTOR_MISMATCH");
  const { intentDigest, expectedEffectDigest } = digests(action);
  return {
    action,
    context: {
      beap_profile: action.profile,
      beap_intent_digest: intentDigest,
      beap_expected_effect_digest: expectedEffectDigest,
      ...(action.batch === undefined
        ? {}
        : { beap_batch_manifest_digest: action.batch.manifest_digest }),
    },
    expectedEffectDigest,
    intentDigest,
  };
}
