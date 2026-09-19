import { z } from "zod";
import {
  JsonValueSchema,
  ProviderRefusal,
  type ActionHandler,
  type ActionRegistry,
} from "@decionis/agent-safe-pipeline";
import { EFFECT_RECEIPT_HEADER } from "../verify/EffectReceipt.js";
import { dispatchBudgetMs, MonotonicDeadline } from "../time/MonotonicClock.js";
import { CONSEQUENTIAL_METHODS } from "./GatewayConfig.js";
import {
  bodyDigest,
  type HttpActionParameters,
  type InterceptedRequest,
} from "./InterceptedRequest.js";
import type { Upstream, UpstreamResult } from "./Upstream.js";

/** The parameters an HTTP action carries; anything else the registry refuses before a grant is spent. */
export const HttpActionParametersSchema = z.strictObject({
  method: z.enum(CONSEQUENTIAL_METHODS),
  path: z.string().min(1).max(500),
  query: z.record(z.string(), z.union([z.string(), z.array(z.string())])),
  body: JsonValueSchema.optional(),
});

/** What the handler leaves behind for the relay, whichever way the attempt ended. */
export interface ForwardOutcome {
  readonly response: UpstreamResult | null;
  /** Why the upstream's answer was not a commit, when it was not. */
  readonly failure:
    "UPSTREAM_REFUSED" | "UPSTREAM_ERROR" | "TRANSPORT" | "RESPONSE_TOO_LARGE" | null;
}

/** Thrown after dispatch when the upstream answered with a server error: the effect is unknown. */
class UpstreamIndeterminate extends Error {
  public constructor() {
    super("UPSTREAM_STATUS_5XX");
    this.name = "UpstreamIndeterminate";
  }
}

interface Held {
  readonly request: InterceptedRequest;
  readonly extraHeaders: Readonly<Record<string, string>>;
  outcome: ForwardOutcome;
}

/**
 * The bytes and headers of each request in flight, keyed by intent id. The
 * intent carries the digest of the bytes and never the bytes, so the handler
 * looks them up here; nothing about a request outlives its run.
 */
export class RequestHolder {
  private readonly held = new Map<string, Held>();

  public hold(
    intentId: string,
    request: InterceptedRequest,
    extraHeaders: Readonly<Record<string, string>>,
  ): void {
    this.held.set(intentId, { request, extraHeaders, outcome: { response: null, failure: null } });
  }

  /** @internal */
  public get(intentId: string): Held | undefined {
    return this.held.get(intentId);
  }

  /** The outcome the handler recorded, and the end of the hold. */
  public release(intentId: string): ForwardOutcome {
    const held = this.held.get(intentId);
    this.held.delete(intentId);
    return held?.outcome ?? { response: null, failure: null };
  }
}

/**
 * The one handler every HTTP action runs through. It runs only behind a
 * claimed single-use grant, with the parameters the authority evaluated.
 * Before the point of no return it recomputes the digest of the bytes it is
 * about to send and refuses if they are not the bytes the intent bound; the
 * request forwarded is therefore the request authorized, and a payload that
 * changed between the two is a failure before dispatch, not an execution.
 * The upstream's status is the attempt's outcome: `2xx` and `3xx` commit,
 * `4xx` is the provider's own refusal, `5xx` and a lost connection are
 * unknown.
 */
export function httpForwardHandler(
  upstream: Upstream,
  holder: RequestHolder,
): ActionHandler<HttpActionParameters, UpstreamResult> {
  return {
    parametersSchema: HttpActionParametersSchema as z.ZodType<HttpActionParameters>,
    execute: async ({ intent, parameters, authorization, dispatch }) => {
      const held = holder.get(intent.intent.intentId);
      if (held === undefined) throw new Error("REQUEST_NOT_HELD");
      const request = held.request;
      const context = intent.intent.context;
      if (
        request.method.toUpperCase() !== parameters.method ||
        request.path !== parameters.path ||
        context["body_bytes"] !== request.body.length ||
        context["body_sha256"] !== bodyDigest(request.body)
      ) {
        throw new Error("PAYLOAD_BINDING_MISMATCH");
      }
      const headers = upstream.headersFor(request, {
        ...held.extraHeaders,
        "x-agent-safe-intent-hash": intent.intentHash,
        "x-agent-safe-decision-id": authorization.decisionId,
        "x-agent-safe-dossier-id": authorization.dossierId,
      });
      // The upstream is never given more time than the authorization has
      // left, and the budget is monotonic, so a clock change cannot extend it.
      const deadline = MonotonicDeadline.after(dispatchBudgetMs(upstream.timeoutMs, authorization));
      return await dispatch.run(async () => {
        // Everything after this line is the point of no return.
        let response: UpstreamResult;
        try {
          response = await upstream.send(
            parameters.method,
            parameters.path,
            request.search,
            headers,
            request.body,
            upstream.signal(deadline.remainingMs),
          );
        } catch (error) {
          held.outcome = {
            response: null,
            failure:
              error instanceof Error && error.name === "UpstreamResponseTooLarge"
                ? "RESPONSE_TOO_LARGE"
                : "TRANSPORT",
          };
          throw error;
        }
        // The upstream's signed receipt of the effect, when it is a verifying
        // provider, whichever way it answered: it accompanies the finalization
        // and the authority verifies it. The relay carries it to the caller
        // like any other upstream header.
        const receipt = response.headers.find(([name]) => name === EFFECT_RECEIPT_HEADER);
        if (receipt !== undefined) dispatch.receipt(receipt[1]);
        if (response.status >= 500) {
          held.outcome = { response, failure: "UPSTREAM_ERROR" };
          throw new UpstreamIndeterminate();
        }
        if (response.status >= 400) {
          held.outcome = { response, failure: "UPSTREAM_REFUSED" };
          throw new ProviderRefusal(`UPSTREAM_STATUS_${response.status}`);
        }
        held.outcome = { response, failure: null };
        return response;
      });
    },
  };
}

/** Registers the one handler under every name the route table can produce, then seals. */
export function registerHttpActions(
  registry: ActionRegistry,
  actions: readonly string[],
  handler: ActionHandler<HttpActionParameters, UpstreamResult>,
): ActionRegistry {
  for (const action of actions) registry.register(action, handler);
  return registry.seal();
}
