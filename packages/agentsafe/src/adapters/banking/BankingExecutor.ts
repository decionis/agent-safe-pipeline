import { createHash } from "node:crypto";
import type {
  EffectPreparedAction,
  ExecutionCapability,
  ExecutorScope,
  JsonObject,
} from "@decionis/agent-safe-pipeline";
import { EffectAdapterExecutor, type ActionDescription } from "../EffectAdapterExecutor.js";
import { transportActionName, transportTarget, type BankingAction } from "./BankingAction.js";
import type { BankingAdapter } from "./BankingAdapter.js";

export const CORE_BANKING_PLATFORM = "core-banking";

/** The longest idempotency key an intent carries; a longer request id is carried by its digest. */
const MAX_IDEMPOTENCY_KEY = 180;

export interface BankingExecutorOptions {
  readonly adapter: BankingAdapter;
  /** What the connection can execute; absent, every registered action is stated as live. */
  readonly capabilities?: (scope: ExecutorScope) => Promise<readonly ExecutionCapability[]>;
  readonly clock?: () => Date;
}

/**
 * The banking family on `agent-safe.executors.native/1`, dispatch style: the
 * BEAP adapter performs the write against the core, once, inside the
 * dispatch the runner opens. Everything the family does — the profile's
 * arithmetic, the projection, the comparison, the effect record — is the
 * adapter's, unchanged; this class says how a BEAP action reads as an
 * intent:
 *
 * - the action is the transport name the profile assigns
 *   (`beap.<domain>.<type>`) and the resource its target;
 * - the system of record is the downstream provider and operation the
 *   action names;
 * - the retry identity is the action's own `request_id`, which the core
 *   holds as its idempotency key (by digest when it is longer than an
 *   intent carries);
 * - the facts the authority decides with are the domain, the action type and
 *   the registered effect, never an amount or an account.
 */
export class BankingExecutor extends EffectAdapterExecutor<BankingAction> {
  public constructor(options: BankingExecutorOptions) {
    super({
      adapter: options.adapter,
      platform: CORE_BANKING_PLATFORM,
      describe: describeBankingAction,
      ...(options.capabilities === undefined ? {} : { capabilities: options.capabilities }),
      ...(options.clock === undefined ? {} : { clock: options.clock }),
    });
  }
}

/** How a BEAP action reads as an `agent-safe.intent/1` binding. */
export function describeBankingAction(
  action: BankingAction,
  prepared: EffectPreparedAction,
): ActionDescription {
  const requestId = action.action.request_id;
  return {
    proposal: {
      action: transportActionName(action),
      target: transportTarget(action),
      parameters: action as unknown as JsonObject,
    },
    downstreamTarget: {
      system: action.downstream.provider,
      operation: action.downstream.operation,
      ...(action.downstream.environment === undefined
        ? {}
        : { environment: action.downstream.environment }),
    },
    idempotencyKey:
      requestId.length <= MAX_IDEMPOTENCY_KEY
        ? requestId
        : `sha256:${createHash("sha256").update(requestId, "utf8").digest("hex")}`,
    facts: {
      beap: {
        domain: action.domain,
        action_type: action.action.type,
        effect_type: prepared.effectType,
      },
    },
  };
}
