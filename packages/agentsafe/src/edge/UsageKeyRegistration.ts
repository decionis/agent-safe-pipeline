import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { withoutTrailingSlash } from "./Entitlement.js";
import type { UsageSigningKey } from "./UsageReport.js";

/** What registering an installation's usage-report key came to. */
export type UsageKeyRegistration =
  | { readonly result: "REGISTERED" }
  /** The kid is registered to another installation; nothing was changed. */
  | { readonly result: "KEY_ID_IN_USE"; readonly issuer: string }
  | { readonly result: "FAILED"; readonly code: string };

interface RegisteredKey {
  readonly kid?: unknown;
  readonly issuer?: unknown;
  readonly revoked_at?: unknown;
}

/**
 * Registers an installation's usage-report key with Decionis
 * (`POST /v1/execution/provider-keys`, purpose `usage_report`, `issuer` the
 * installation id). Decionis keeps one key per kid and a registration under a
 * kid it already holds re-points that kid to the new issuer, which would make
 * the first installation's reports fail `USAGE_REPORT_ISSUER_MISMATCH`. So a
 * kid already registered, unrevoked, to another installation is refused here
 * and left alone: replicas sharing one key file each need their own kid.
 *
 * The API key needs `policy:write`; it is an operator's, used for this call
 * only, never the executor's runtime key.
 */
export async function registerUsageKey(options: {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly fetch: FetchLike;
  readonly key: UsageSigningKey;
  readonly installationId: string;
}): Promise<UsageKeyRegistration> {
  const url = `${withoutTrailingSlash(options.baseUrl)}/v1/execution/provider-keys`;
  const headers = {
    authorization: `Bearer ${options.apiKey}`,
    accept: "application/json",
  };
  const listed = await call(options.fetch, url, { method: "GET", headers });
  if (!listed.ok) return { result: "FAILED", code: listed.code };
  const keys = (listed.body as { keys?: unknown }).keys;
  const holder = Array.isArray(keys)
    ? (keys as RegisteredKey[]).find(
        // Revoked means a revocation time; anything else holds the kid.
        (entry) => entry.kid === options.key.kid && typeof entry.revoked_at !== "string",
      )
    : undefined;
  if (typeof holder?.issuer === "string" && holder.issuer !== options.installationId) {
    return { result: "KEY_ID_IN_USE", issuer: holder.issuer };
  }
  const registered = await call(options.fetch, url, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({
      kid: options.key.kid,
      issuer: options.installationId,
      algorithm: "EdDSA",
      public_jwk: options.key.publicJwk,
      purpose: "usage_report",
    }),
  });
  return registered.ok ? { result: "REGISTERED" } : { result: "FAILED", code: registered.code };
}

async function call(
  fetch: FetchLike,
  url: string,
  init: RequestInit,
): Promise<{ ok: true; body: unknown } | { ok: false; code: string }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      // A body that is not JSON carries no code.
    }
    if (response.ok) return { ok: true, body };
    const error = (body as { error?: unknown } | null)?.error;
    return {
      ok: false,
      code:
        typeof error === "string" && /^[A-Z_]{1,60}$/.test(error)
          ? error
          : `USAGE_KEY_HTTP_${response.status}`,
    };
  } catch {
    return { ok: false, code: "USAGE_KEY_SEND_FAILED" };
  } finally {
    clearTimeout(timeout);
  }
}
