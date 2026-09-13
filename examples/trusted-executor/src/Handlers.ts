import {
  JsonObjectSchema,
  type ActionHandler,
  type ActionRegistry,
  type JsonObject,
} from "@decionis/agent-safe-pipeline";
import type { DownstreamConfig } from "./Config.js";

/**
 * The seam an adopter edits. Everything registered here runs only behind a
 * claimed single-use grant, with the parameters the authority evaluated and
 * nothing the agent could add afterwards. The one handler that ships forwards
 * the verified parameters to a configured downstream endpoint, carrying the
 * downstream credential the executor holds and the intent-bound idempotency
 * key; replace it with the handler for your own provider, keeping the shape:
 * a strict parameter schema, the side effect inside `dispatch.run`, and a
 * read-only `reconcile`.
 */
export const FORWARD_REQUEST_ACTION = "forward_request";

/** Every action this process registers, in the order `/ready` reports them. */
export const REGISTERED_ACTIONS: readonly string[] = [FORWARD_REQUEST_ACTION];

/** What the executor reports about the downstream attempt: a status, never a body. */
export interface DownstreamResult {
  readonly status: number;
  readonly accepted: boolean;
}

export type FetchLike = typeof fetch;

type ForwardHandler = ActionHandler<JsonObject, DownstreamResult>;

export function registerHandlers(
  registry: ActionRegistry,
  downstream: DownstreamConfig,
  fetchImpl: FetchLike = fetch,
): ActionRegistry {
  const headers = (extra: Readonly<Record<string, string>>): Record<string, string> => ({
    // The credential exists only here, on the trusted side of the boundary.
    [downstream.credentialHeader]: downstream.credential,
    ...extra,
  });

  const execute: ForwardHandler["execute"] = async ({
    intent,
    parameters,
    authorization,
    dispatch,
  }) =>
    await dispatch.run(async (idempotencyKey) => {
      // Everything after this line is the point of no return: a transport
      // failure here is an unknown outcome, never a failure to retry.
      const response = await fetchImpl(downstream.url, {
        method: "POST",
        headers: headers({
          "content-type": "application/json",
          "idempotency-key": idempotencyKey,
          "x-agent-safe-intent-hash": intent.intentHash,
          "x-agent-safe-decision-id": authorization.decisionId,
          "x-agent-safe-dossier-id": authorization.dossierId,
        }),
        body: JSON.stringify(parameters),
        signal: AbortSignal.timeout(downstream.timeoutMs),
      });
      await response.body?.cancel();
      return { status: response.status, accepted: response.ok };
    });

  // Read-only: asks the downstream what it did with this idempotency key.
  // It never sends the request again.
  const reconcile: NonNullable<ForwardHandler["reconcile"]> = async ({ idempotencyKey }) => {
    const url = (downstream.lookupUrl ?? "").replace(
      "{idempotency_key}",
      encodeURIComponent(idempotencyKey),
    );
    const response = await fetchImpl(url, {
      method: "GET",
      headers: headers({}),
      signal: AbortSignal.timeout(downstream.timeoutMs),
    });
    await response.body?.cancel();
    if (response.status === 404) return { status: "NOT_EXECUTED" };
    if (response.ok) {
      return { status: "COMPLETED", result: { status: response.status, accepted: true } };
    }
    return { status: "UNKNOWN" };
  };

  const handler: ForwardHandler = {
    parametersSchema: JsonObjectSchema,
    execute,
    ...(downstream.lookupUrl === null ? {} : { reconcile }),
  };
  registry.register(FORWARD_REQUEST_ACTION, handler);
  return registry;
}
