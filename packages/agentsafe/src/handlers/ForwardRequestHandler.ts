import {
  JsonObjectSchema,
  type ActionHandler,
  type ActionRegistry,
  type JsonObject,
} from "@decionis/agent-safe-pipeline";
import type { DownstreamConfig } from "../config/ExecutorConfig.js";
import type { DownstreamCredential } from "../credential/DownstreamCredential.js";
import { dispatchBudgetMs, MonotonicDeadline } from "../time/MonotonicClock.js";
import type { FetchLike, HandlerRegistration } from "./HandlerRegistration.js";

/**
 * The reference handler. Everything registered here runs only behind a
 * claimed single-use grant, with the parameters the authority evaluated and
 * nothing the agent could add afterwards. It forwards the verified parameters
 * to a configured downstream endpoint, carrying the headers the credential
 * resolves at dispatch and the intent-bound idempotency key; an adopter
 * replaces it with the handlers for their own provider, keeping the shape: a
 * strict parameter schema, the side effect inside `dispatch.run`, and a
 * read-only `reconcile`.
 */
export const FORWARD_REQUEST_ACTION = "forward_request";

/** Every action the reference registration registers, in the order `/ready` reports them. */
export const REGISTERED_ACTIONS: readonly string[] = [FORWARD_REQUEST_ACTION];

/** What the executor reports about the downstream attempt: a status, never a body. */
export interface DownstreamResult {
  readonly status: number;
  readonly accepted: boolean;
}

type ForwardHandler = ActionHandler<JsonObject, DownstreamResult>;

export function registerHandlers(
  registry: ActionRegistry,
  downstream: DownstreamConfig,
  credential: DownstreamCredential,
  fetchImpl: FetchLike = fetch,
): ActionRegistry {
  const execute: ForwardHandler["execute"] = async ({
    intent,
    parameters,
    authorization,
    dispatch,
  }) => {
    const body = JSON.stringify(parameters);
    // The credential is resolved before the point of no return, so a token
    // that cannot be obtained or a key that cannot sign is a failure before
    // dispatch, never an unknown outcome; it exists only here, on the
    // trusted side of the boundary, and only for this request.
    const credentialHeaders = await credential.headersFor({
      method: "POST",
      url: downstream.url,
      body,
      idempotencyKey: dispatch.idempotencyKey,
      intentHash: intent.intentHash,
    });
    // The provider is never given more time than the authorization has left:
    // a slow call cannot outlive the permission it was made under, and the
    // budget is monotonic, so correcting the wall clock cannot extend it.
    const deadline = MonotonicDeadline.after(dispatchBudgetMs(downstream.timeoutMs, authorization));
    return await dispatch.run(async (idempotencyKey) => {
      // Everything after this line is the point of no return: a transport
      // failure here is an unknown outcome, never a failure to retry.
      const response = await fetchImpl(downstream.url, {
        method: "POST",
        headers: {
          ...credentialHeaders,
          "content-type": "application/json",
          "idempotency-key": idempotencyKey,
          "x-agent-safe-intent-hash": intent.intentHash,
          "x-agent-safe-decision-id": authorization.decisionId,
          "x-agent-safe-dossier-id": authorization.dossierId,
        },
        body,
        signal: deadline.signal(),
      });
      await response.body?.cancel();
      return { status: response.status, accepted: response.ok };
    });
  };

  // Read-only: asks the downstream what it did with this idempotency key.
  // It never sends the request again.
  const reconcile: NonNullable<ForwardHandler["reconcile"]> = async ({
    intent,
    idempotencyKey,
  }) => {
    const url = (downstream.lookupUrl ?? "").replace(
      "{idempotency_key}",
      encodeURIComponent(idempotencyKey),
    );
    const response = await fetchImpl(url, {
      method: "GET",
      headers: await credential.headersFor({
        method: "GET",
        url,
        body: null,
        idempotencyKey,
        intentHash: intent.intentHash,
      }),
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

/** The reference registration: the one forwarding handler, as a seam the executor accepts. */
export function forwardRequestHandlers(): HandlerRegistration {
  return ({ registry, downstream, credential, fetch: fetchImpl }) => {
    registerHandlers(registry, downstream, credential, fetchImpl);
    return REGISTERED_ACTIONS;
  };
}
