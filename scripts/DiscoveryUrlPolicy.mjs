// Reviewed public origins the link probe may contact (discovery.rules.md §3).
// banking.decionis.com and commerce.decionis.com joined on 2026-09-12: both
// are Decionis-operated properties of the same protocol — the banking
// profile whose reference runtime builds on this package, and the Commerce
// Gate whose MCP server lives in packages/commerce-mcp — and both answered
// 200 on that day.
const allowedHostnames = new Set([
  "github.com",
  "decionis.com",
  "presence.decionis.com",
  "banking.decionis.com",
  "commerce.decionis.com",
]);
const maxRedirects = 5;

export class DiscoveryUrlPolicyError extends Error {
  constructor(code) {
    super(code);
    this.name = "DiscoveryUrlPolicyError";
    this.code = code;
  }
}

export function assertAllowedDiscoveryUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new DiscoveryUrlPolicyError("DISCOVERY_URL_INVALID");
  }
  if (url.protocol !== "https:") {
    throw new DiscoveryUrlPolicyError("DISCOVERY_URL_MUST_USE_HTTPS");
  }
  if (url.username || url.password) {
    throw new DiscoveryUrlPolicyError("DISCOVERY_URL_MUST_NOT_CONTAIN_CREDENTIALS");
  }
  if (url.port && url.port !== "443") {
    throw new DiscoveryUrlPolicyError("DISCOVERY_URL_PORT_FORBIDDEN");
  }
  if (!allowedHostnames.has(url.hostname.toLowerCase())) {
    throw new DiscoveryUrlPolicyError("DISCOVERY_URL_HOST_FORBIDDEN");
  }
  return url;
}

export async function probeAllowedDiscoveryUrl(
  value,
  method,
  { fetchImpl = globalThis.fetch } = {},
) {
  if (method !== "HEAD" && method !== "GET") {
    throw new DiscoveryUrlPolicyError("DISCOVERY_URL_METHOD_FORBIDDEN");
  }
  let url = assertAllowedDiscoveryUrl(value);
  for (let redirectCount = 0; redirectCount <= maxRedirects; redirectCount += 1) {
    const response = await fetchImpl(url, {
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(20_000),
      headers: { "user-agent": "agent-safe-discovery-check" },
    });
    const location = response.headers.get("location");
    if (response.status < 300 || response.status >= 400 || location === null) {
      await response.body?.cancel().catch(() => undefined);
      return response.status;
    }

    await response.body?.cancel().catch(() => undefined);
    if (redirectCount === maxRedirects) {
      throw new DiscoveryUrlPolicyError("DISCOVERY_URL_REDIRECT_LIMIT_EXCEEDED");
    }
    url = assertAllowedDiscoveryUrl(new URL(location, url).href);
  }
  throw new DiscoveryUrlPolicyError("DISCOVERY_URL_REDIRECT_LIMIT_EXCEEDED");
}
