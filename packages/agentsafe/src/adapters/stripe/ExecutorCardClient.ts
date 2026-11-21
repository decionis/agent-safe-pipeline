import type { CardAuthorizationRequest, CardAuthorizationResult } from "../cards/CardPurchase.js";
import type { ExecutorCardHook } from "./StripeIssuingBridge.js";

/**
 * The executor's card hook over HTTP, as an `OPERATOR` principal holding only `cards.authorize`
 * (its bearer token). The bridge never holds a proposer's credential, so it cannot propose a
 * purchase, only ask about an authorization and report what became of it.
 */
export class ExecutorCardClient implements ExecutorCardHook {
  private readonly base: URL;

  public constructor(
    executorUrl: string,
    private readonly token: () => string,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    this.base = new URL(executorUrl);
    if (this.base.protocol !== "https:" && !ExecutorCardClient.loopback(this.base.hostname)) {
      // The operator token crosses this link: in clear only on the same host.
      throw new Error("EXECUTOR_URL_NOT_HTTPS");
    }
  }

  public authorize(request: CardAuthorizationRequest, signal: AbortSignal) {
    return this.post("/v1/card-authorizations", request, signal);
  }

  public settle(authorizationId: string, result: CardAuthorizationResult, signal: AbortSignal) {
    return this.post(
      `/v1/card-authorizations/${encodeURIComponent(authorizationId)}/result`,
      result,
      signal,
    );
  }

  private async post(path: string, body: unknown, signal: AbortSignal) {
    const response = await this.fetcher(new URL(path, this.base), {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.token()}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
      signal,
      redirect: "error",
    });
    let parsed: unknown = null;
    try {
      parsed = await response.json();
    } catch {
      parsed = null;
    }
    return { status: response.status, body: parsed };
  }

  private static loopback(hostname: string): boolean {
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
  }
}
