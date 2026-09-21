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

export type AccessPurpose = "shadow" | "read" | "erp";
export interface ResolvedAccess extends TenantConnection {
  provisional: boolean;
}
export interface AccessOptions {
  source: "local_trial" | "aws_secret";
  canProvision?: boolean;
  configurationIssue?: string;
  resolve(purpose: AccessPurpose): Promise<ResolvedAccess | null>;
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
  access?: {
    source: "local_trial" | "aws_secret";
    provisional: boolean | null;
    first_shadow_call_can_provision: boolean;
    claim_instructions: string | null;
  };
}

export function normalizeApiBase(rawValue: string | undefined): {
  value: string;
  issue: string | null;
} {
  const raw = rawValue?.trim() || DEFAULT_DECIONIS_API_BASE;
  try {
    if (raw.length > 2_048 || raw.includes("\\") || !/^https?:\/\//i.test(raw)) throw new Error();
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
    // Only the deployed Marketplace gateway prefix is accepted. Check the raw
    // spelling too: URL normalization must not conceal dot or encoded segments.
    const rawPath = raw.slice(raw.indexOf("://") + 3).replace(/^[^/]+/, "");
    if (!["", "/", "/aws", "/aws/"].includes(rawPath)) {
      return {
        value: DEFAULT_DECIONIS_API_BASE,
        issue: "DECIONIS_API_BASE must be an origin or use the exact /aws gateway path.",
      };
    }
    return {
      value: parsed.origin + (parsed.pathname.startsWith("/aws") ? "/aws" : ""),
      issue: null,
    };
  } catch {
    return {
      value: DEFAULT_DECIONIS_API_BASE,
      issue: "DECIONIS_API_BASE is not a valid absolute URL.",
    };
  }
}

/** Fail-closed configuration; lazy access is resolved only at an explicit tool boundary. */
export class CommerceGateConfiguration {
  readonly apiBaseUrl: string;
  private readonly apiKey: string | null;
  private readonly orgId: string | null;
  private readonly apiIssues: string[];
  private readonly tenantIssues: string[];
  private access: ResolvedAccess | null = null;

  constructor(
    environment: Record<string, string | undefined> = process.env,
    private readonly accessOptions?: AccessOptions,
  ) {
    const apiBase = normalizeApiBase(environment.DECIONIS_API_BASE);
    this.apiBaseUrl = apiBase.value;
    this.apiKey = environment.DECIONIS_API_KEY?.trim() || null;
    this.orgId = environment.DECIONIS_ORG_ID?.trim() || null;
    this.apiIssues = [];
    this.tenantIssues = [];
    if (apiBase.issue) this.apiIssues.push(apiBase.issue);
    if (accessOptions?.configurationIssue) this.apiIssues.push(accessOptions.configurationIssue);
    if (this.orgId && !UUID_PATTERN.test(this.orgId)) {
      this.tenantIssues.push("DECIONIS_ORG_ID must be a UUID.");
    }
  }

  /** Safe to expose to agents: values that could identify or authorize a tenant are omitted. */
  describe(): PublicConfiguration {
    const apiKeyConfigured = this.apiKey !== null || this.access !== null;
    const orgIdConfigured = this.orgId !== null || this.access !== null;
    const apiReady = apiKeyConfigured && this.apiIssues.length === 0;
    const protocolReady = apiReady && orgIdConfigured && this.tenantIssues.length === 0;
    return {
      api_base: this.access?.apiBaseUrl ?? this.apiBaseUrl,
      connected: protocolReady,
      erp_guard_ready: apiReady && this.access?.provisional !== true,
      protocol_tools_ready: protocolReady,
      protocol_organization_bound_by_environment: true,
      api_key_configured: apiKeyConfigured,
      org_id_configured: orgIdConfigured,
      configuration_issues: [...this.apiIssues, ...this.tenantIssues],
      ...(this.accessOptions
        ? {
            access: {
              source: this.accessOptions.source,
              provisional: this.access?.provisional ?? null,
              first_shadow_call_can_provision:
                this.accessOptions.source === "local_trial" &&
                this.accessOptions.canProvision !== false &&
                this.access === null,
              claim_instructions: this.access?.provisional
                ? "This is a provisional Shadow workspace. Contact commerce@decionis.com to claim it and retain its evidence. Do not share its API key; owned access is required for ERP enforcement."
                : null,
            },
          }
        : {}),
    };
  }

  async resolveAccess(purpose: AccessPurpose): Promise<void> {
    if (this.apiIssues.length) this.requireApiConnection();
    if (purpose !== "erp" && this.tenantIssues.length) this.requireTenantConnection();
    // An explicitly supplied key or tenant must never fall back to a new identity.
    if (!this.apiKey && !this.orgId && this.access === null && this.accessOptions) {
      const candidate = await this.accessOptions.resolve(purpose);
      if (candidate !== null) {
        const checked = new CommerceGateConfiguration({
          DECIONIS_API_BASE: candidate.apiBaseUrl,
          DECIONIS_API_KEY: candidate.apiKey,
          DECIONIS_ORG_ID: candidate.orgId,
        }).requireTenantConnection();
        this.access = { ...checked, provisional: candidate.provisional };
      }
    }
    if (purpose === "erp" && this.access?.provisional) {
      throw new CommerceGateError(
        "AUTHORIZATION_FAILED",
        "Provisional access supports Shadow evaluation only. Configure owned access for ERP authorization.",
      );
    }
  }

  /** Resolve the shared API credential only at the network boundary; never serialize it. */
  requireApiConnection(): ApiConnection {
    if (this.apiIssues.length > 0) {
      throw new CommerceGateError(
        "CONFIGURATION_INVALID",
        "CommerceGate configuration is invalid. Run commercegate_describe_capabilities for safe diagnostics.",
      );
    }
    const apiKey = this.apiKey ?? this.access?.apiKey;
    if (!apiKey) {
      throw new CommerceGateError(
        "CONFIGURATION_REQUIRED",
        "CommerceGate is not connected. Configure DECIONIS_API_KEY; no downstream action was executed.",
      );
    }
    return {
      apiBaseUrl: this.access?.apiBaseUrl ?? this.apiBaseUrl,
      apiKey,
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
    const orgId = this.orgId ?? this.access?.orgId;
    if (!orgId) {
      throw new CommerceGateError(
        "CONFIGURATION_REQUIRED",
        "CommerceGate Protocol tools require DECIONIS_ORG_ID; no downstream action was executed.",
      );
    }
    return {
      ...api,
      orgId,
    };
  }
}
