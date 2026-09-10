import { CommerceGateError } from "./Errors.js";

export const DEFAULT_DECIONIS_API_BASE = "https://api.decionis.com";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface ApiConnection {
  apiBaseUrl: string;
  apiKey: string;
}

export interface TenantConnection extends ApiConnection {
  orgId: string;
}

export interface PublicConfiguration {
  api_base: string;
  connected: boolean;
  erp_guard_ready: boolean;
  protocol_tools_ready: boolean;
  protocol_organization_bound_by_environment: true;
  api_key_configured: boolean;
  org_id_configured: boolean;
  configuration_issues: string[];
}

function normalizeApiBase(rawValue: string | undefined): {
  value: string;
  issue: string | null;
} {
  const raw = rawValue?.trim() || DEFAULT_DECIONIS_API_BASE;
  try {
    const parsed = new URL(raw);
    const isLocal =
      parsed.hostname === "localhost" ||
      parsed.hostname === "127.0.0.1" ||
      parsed.hostname === "[::1]";
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLocal)) {
      return {
        value: DEFAULT_DECIONIS_API_BASE,
        issue: "DECIONIS_API_BASE must use HTTPS (HTTP is allowed only for loopback development).",
      };
    }
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      return {
        value: DEFAULT_DECIONIS_API_BASE,
        issue: "DECIONIS_API_BASE must not contain credentials, query parameters, or fragments.",
      };
    }
    if (parsed.pathname !== "/") {
      return {
        value: DEFAULT_DECIONIS_API_BASE,
        issue: "DECIONIS_API_BASE must be an origin without a path.",
      };
    }
    return { value: parsed.origin, issue: null };
  } catch {
    return {
      value: DEFAULT_DECIONIS_API_BASE,
      issue: "DECIONIS_API_BASE is not a valid absolute URL.",
    };
  }
}

/** Immutable, fail-closed CommerceGate runtime configuration. */
export class CommerceGateConfiguration {
  readonly apiBaseUrl: string;
  private readonly apiKey: string | null;
  private readonly orgId: string | null;
  private readonly apiIssues: string[];
  private readonly tenantIssues: string[];

  constructor(environment: Record<string, string | undefined> = process.env) {
    const apiBase = normalizeApiBase(environment.DECIONIS_API_BASE);
    this.apiBaseUrl = apiBase.value;
    this.apiKey = environment.DECIONIS_API_KEY?.trim() || null;
    this.orgId = environment.DECIONIS_ORG_ID?.trim() || null;
    this.apiIssues = [];
    this.tenantIssues = [];
    if (apiBase.issue) this.apiIssues.push(apiBase.issue);
    if (this.orgId && !UUID_PATTERN.test(this.orgId)) {
      this.tenantIssues.push("DECIONIS_ORG_ID must be a UUID.");
    }
  }

  /** Safe to expose to agents: values that could identify or authorize a tenant are omitted. */
  describe(): PublicConfiguration {
    const apiKeyConfigured = this.apiKey !== null;
    const orgIdConfigured = this.orgId !== null;
    const apiReady = apiKeyConfigured && this.apiIssues.length === 0;
    const protocolReady = apiReady && orgIdConfigured && this.tenantIssues.length === 0;
    return {
      api_base: this.apiBaseUrl,
      connected: protocolReady,
      erp_guard_ready: apiReady,
      protocol_tools_ready: protocolReady,
      protocol_organization_bound_by_environment: true,
      api_key_configured: apiKeyConfigured,
      org_id_configured: orgIdConfigured,
      configuration_issues: [...this.apiIssues, ...this.tenantIssues],
    };
  }

  /** Resolve the shared API credential only at the network boundary; never serialize it. */
  requireApiConnection(): ApiConnection {
    if (this.apiIssues.length > 0) {
      throw new CommerceGateError(
        "CONFIGURATION_INVALID",
        "CommerceGate configuration is invalid. Run commercegate_describe_capabilities for safe diagnostics.",
      );
    }
    if (!this.apiKey) {
      throw new CommerceGateError(
        "CONFIGURATION_REQUIRED",
        "CommerceGate is not connected. Configure DECIONIS_API_KEY; no downstream action was executed.",
      );
    }
    return {
      apiBaseUrl: this.apiBaseUrl,
      apiKey: this.apiKey,
    };
  }

  /** Resolve Protocol tenant credentials only at the network boundary; never serialize this value. */
  requireTenantConnection(): TenantConnection {
    const api = this.requireApiConnection();
    if (this.tenantIssues.length > 0) {
      throw new CommerceGateError(
        "CONFIGURATION_INVALID",
        "CommerceGate Protocol tenant configuration is invalid. Run commercegate_describe_capabilities for safe diagnostics.",
      );
    }
    if (!this.orgId) {
      throw new CommerceGateError(
        "CONFIGURATION_REQUIRED",
        "CommerceGate Protocol tools require DECIONIS_ORG_ID; no downstream action was executed.",
      );
    }
    return {
      ...api,
      orgId: this.orgId,
    };
  }
}
