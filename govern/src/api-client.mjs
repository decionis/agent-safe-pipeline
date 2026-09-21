// @ts-check
// Decionis API client — the only module that talks to the Decionis backend.
// Extracted from index.mjs so the blocking path and the background
// (speculative / notarization) pipeline share one implementation.

/**
 * POST /v1/protocol/evaluate-decision.
 *
 * Returns `{ ok: true, status, data }` on 2xx and
 * `{ ok: false, status, bodyText }` on any other HTTP status.
 * Throws on network errors, the internal timeout, or an external abort —
 * the caller decides fail-open vs fail-closed per mode.
 *
 * @param {{ apiBaseUrl: string, apiKey: string, body: object,
 *           timeoutMs: number, signal?: AbortSignal }} options
 */
export async function evaluateDecision({ apiBaseUrl, apiKey, body, timeoutMs, signal }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onExternalAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) {
      clearTimeout(timer);
      throw new Error("Decionis evaluate-decision aborted before the request started");
    }
    signal.addEventListener("abort", onExternalAbort, { once: true });
  }
  try {
    const res = await fetch(`${apiBaseUrl}/v1/protocol/evaluate-decision`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        accept: "application/json",
        "x-decionis-source": "github_actions",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) {
      const bodyText = await res.text().catch(() => "");
      return { ok: false, status: res.status, bodyText };
    }
    return { ok: true, status: res.status, data: await res.json() };
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener("abort", onExternalAbort);
  }
}

/**
 * Map the protocol's outcome vocabulary (APPROVE / REJECT / REVIEW / ESCALATE,
 * plus rule-action forms) onto the verdict vocabulary the gate logic consumes
 * (allow / block / review / escalate). Unmapped strings pass through — the
 * downstream sets already understand deny/denied/restrain/etc.
 */
const VERDICT_ALIASES = {
  approve: "allow",
  approved: "allow",
  auto_approve: "allow",
  reject: "block",
  rejected: "block",
  auto_reject: "block",
  require_review: "review",
  request_info: "review",
};

export function normalizeVerdict(raw) {
  const d = String(raw ?? "")
    .trim()
    .toLowerCase();
  return VERDICT_ALIASES[d] ?? d;
}

/**
 * Extract the verdict fields from an evaluate-decision response body.
 * Pure + testable. Tolerates both top-level and dossier-nested shapes.
 * `decision` is normalized (e.g. the protocol's APPROVE → allow) so
 * shouldExecute/shouldFail work against the live API; `rawDecision`
 * preserves the wire value for logs.
 */
export function parseDecisionResponse(data) {
  const rawDecision = String(data?.decision ?? data?.outcome ?? "").toLowerCase();
  const decision = normalizeVerdict(rawDecision);
  const dossierId = String(data?.dossier_id ?? data?.dossier?.dossier_id ?? "");
  const signature = data?.verification?.signature ?? data?.signature ?? null;
  const policyVersion = data?.policy_version ?? data?.dossier?.policy_version ?? null;
  const reasonCode =
    (Array.isArray(data?.reason_codes) ? data.reason_codes[0] : undefined) ??
    data?.reason_code ??
    null;
  return { decision, rawDecision, dossierId, signature, policyVersion, reasonCode };
}

/** Request a signed execution grant from Decionis (returns null on any failure). */
export async function fetchExecutionGrant({ apiBaseUrl, apiKey, body, timeoutMs, logNotice }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${apiBaseUrl}/v1/protocol/execution-grants/issue`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        accept: "application/json",
        "x-decionis-source": "github_actions",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) {
      logNotice(`Execution grant not issued (HTTP ${res.status}).`);
      return null;
    }
    return await res.json();
  } catch (err) {
    logNotice(`Execution grant request failed: ${err instanceof Error ? err.message : err}`);
    return null;
  } finally {
    clearTimeout(timer);
  }
}
