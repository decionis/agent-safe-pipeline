import { createHash } from "node:crypto";
import {
  ActionRegistry,
  CanonicalIntentHasher,
  type ActionExecutionContext,
  type ActionHandler,
  type JsonObject,
  type JsonValue,
} from "@decionis/agent-safe-pipeline";
import type { ExecutionJournal } from "../journal/ExecutionJournal.js";
import { RequestContext } from "../http/RequestContext.js";

/** The digest of what the handler is about to send: the canonical parameters. */
export function requestDigest(parameters: unknown): `sha256:${string}` {
  const canonical = CanonicalIntentHasher.stringify((parameters ?? {}) as JsonValue);
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

/**
 * The decorator that makes a claimed grant durable before anything can be
 * dispatched. It runs inside the handler, after `SafeExecutor` consumed the
 * grant and before the handler's own body, which is where the verified
 * authorization exists and where a failure is still a failure *before*
 * dispatch. A journal that cannot take the record throws here, the registry
 * reports `FAILED_BEFORE_DISPATCH`, and `SafeExecutor` finalizes the attempt
 * as `FAILED`: there is no side effect without a durable record of the claim,
 * and the authority is told the attempt failed rather than being left to a
 * lease timeout.
 */
export function journaledActionHandler<TParameters, TResult>(
  handler: ActionHandler<TParameters, TResult>,
  journal: () => ExecutionJournal | null,
): ActionHandler<TParameters, TResult> {
  const execute = async (context: ActionExecutionContext<TParameters>): Promise<TResult> => {
    const target = journal();
    if (target !== null) {
      await target.append({
        record: "GRANT_CLAIMED",
        at: new Date().toISOString(),
        intent_id: context.intent.intent.intentId,
        intent_hash: context.intent.intentHash,
        idempotency_key: context.dispatch.idempotencyKey,
        grant_id: context.authorization.grantId,
        expires_at: context.authorization.expiresAt,
        request_digest: requestDigest(context.parameters),
      });
    }
    return await handler.execute(context);
  };
  return {
    parametersSchema: handler.parametersSchema,
    execute,
    ...(handler.reconcile === undefined ? {} : { reconcile: handler.reconcile.bind(handler) }),
  };
}

/**
 * The registry the adopter's registration fills. Every handler it accepts is
 * wrapped, so the durable claim is not something a registration can forget:
 * an adopter writes an ordinary handler and the journal record happens
 * anyway. `SafeExecutor` and the pipeline's own registry are untouched.
 */
export class JournaledRegistry extends ActionRegistry {
  public constructor(private readonly journal: () => ExecutionJournal | null) {
    super();
  }

  public override register<TParameters, TResult>(
    action: string,
    handler: ActionHandler<TParameters, TResult>,
  ): this {
    return super.register(action, journaledActionHandler(handler, this.journal));
  }
}

/** The principal a journal record names, when one is in scope. */
export function callerPrincipal(): string | null {
  return RequestContext.current()?.principal ?? null;
}

export type { JsonObject };
