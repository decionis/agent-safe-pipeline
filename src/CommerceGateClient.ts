import { CommerceGateConfiguration } from "./Configuration.js";
import { CommerceGateError } from "./Errors.js";
import { MCP_SERVER_VERSION } from "./Version.js";

export const SUPPORTED_ACTION_TYPES = ["ORDER_ACCEPTANCE", "PRICE_CHANGE"] as const;
export const COMMERCEGATE_API_OPERATIONS = [
  {
    operationId: "evaluateCommerceDecision",
    method: "POST",
    path: "/v1/protocol/evaluate-decision",
  },
  {
    operationId: "getDecisionDossier",
    method: "GET",
    path: "/v1/protocol/dossiers/{dossierId}",
  },
  {
    operationId: "getDecisionProofPacket",
    method: "GET",
    path: "/v1/protocol/dossiers/{dossierId}/proof-packet",
  },
  {
    operationId: "listCommerceShadowReports",
    method: "GET",
    path: "/v1/protocol/shadow-reports",
  },
] as const;

const [EVALUATE_OPERATION, DOSSIER_OPERATION, PROOF_PACKET_OPERATION, SHADOW_REPORT_OPERATION] =
  COMMERCEGATE_API_OPERATIONS;
export type SupportedActionType = (typeof SUPPORTED_ACTION_TYPES)[number];
export type ActorType = "HUMAN" | "ERP" | "REPRICER" | "WORKFLOW" | "AGENT" | "UNKNOWN";

export interface CommerceActor {
  type: ActorType;
  id: string;
}

interface ActionBase {
  actor: CommerceActor;
  platform: string;
  idempotency_key: string;
}

export interface OrderAcceptanceAction extends ActionBase {
  action_type: "ORDER_ACCEPTANCE";
  payload: {
    order_id: string;
    gross_amount: number;
    discount_amount: number;
    estimated_cost: number;
    currency: string;
  };
}

export interface PriceChangeAction extends ActionBase {
  action_type: "PRICE_CHANGE";
  payload: {
    sku: string;
    from_price: number | null;
    to_price: number;
    estimated_cost: number;
    currency: string;
  };
}

export type CommerceAction = OrderAcceptanceAction | PriceChangeAction;

export interface EvaluateActionInput {
  action: CommerceAction;
  policy_version?: string;
}

export interface ShadowReportQuery {
  days?: number;
  limit?: number;
}

export interface CommerceGateApi {
  evaluateAction(input: EvaluateActionInput): Promise<unknown>;
  getDossier(dossierId: string): Promise<unknown>;
  getProofPacket(dossierId: string): Promise<unknown>;
  listShadowReports(query: ShadowReportQuery): Promise<unknown>;
  summarizeShadowReports(query: ShadowReportQuery): Promise<unknown>;
}

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

function responseTooLarge(): CommerceGateError {
  return new CommerceGateError(
    "INVALID_UPSTREAM_RESPONSE",
    "The Decionis API response exceeded the CommerceGate safety limit.",
  );
}

async function readBoundedResponse(
  response: Response,
  controller: AbortController,
): Promise<string> {
  const contentLength = Number.parseInt(response.headers.get("content-length") ?? "0", 10);
  if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
    controller.abort();
    try {
      await response.body?.cancel();
    } catch {
      // The abort can make cancellation reject; the response is already unusable.
    }
    throw responseTooLarge();
  }

  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;

      totalBytes += value.byteLength;
      if (totalBytes > MAX_RESPONSE_BYTES) {
        controller.abort();
        try {
          await reader.cancel();
        } catch {
          // The abort can make cancellation reject; the size failure remains authoritative.
        }
        throw responseTooLarge();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  if (chunks.length === 0) return "";
  const buffers = chunks.map((chunk) =>
    Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength),
  );
  return Buffer.concat(buffers, totalBytes).toString("utf8");
}

function rounded(value: number): number {
  return Number.parseFloat(value.toFixed(6));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function marginSignal(revenue: number, estimatedCost: number): Record<string, number | null> {
  const netMarginAmount = revenue - estimatedCost;
  return {
    net_revenue: rounded(revenue),
    estimated_cost: rounded(estimatedCost),
    net_margin_amount: rounded(netMarginAmount),
    net_margin_fraction: revenue > 0 ? rounded(netMarginAmount / revenue) : null,
  };
}

function buildEvaluationRequest(input: EvaluateActionInput): Record<string, unknown> {
  const { action } = input;
  if (action.action_type === "ORDER_ACCEPTANCE") {
    const netRevenue = action.payload.gross_amount - action.payload.discount_amount;
    const economics = marginSignal(netRevenue, action.payload.estimated_cost);
    return {
      org_id: null,
      decision_type: action.action_type,
      transaction_type: "order_acceptance",
      workflow_key: "commerce_order_acceptance",
      amount: action.payload.gross_amount,
      channel: "mcp",
      source: "commercegate-mcp",
      mode: "SHADOW",
      idempotency_key: action.idempotency_key,
      ...(input.policy_version
        ? { policy_version: input.policy_version, require_exact_policy_version: true }
        : {}),
      context: {
        action_type: action.action_type,
        actor_type: action.actor.type,
        actor_id: action.actor.id,
        platform: action.platform,
        ...action.payload,
        ...economics,
        commerce_action: action,
      },
    };
  }

  const economics = marginSignal(action.payload.to_price, action.payload.estimated_cost);
  return {
    org_id: null,
    decision_type: action.action_type,
    transaction_type: "price_change",
    workflow_key: "commerce_price_change",
    amount: action.payload.to_price,
    channel: "mcp",
    source: "commercegate-mcp",
    mode: "SHADOW",
    idempotency_key: action.idempotency_key,
    ...(input.policy_version
      ? { policy_version: input.policy_version, require_exact_policy_version: true }
      : {}),
    context: {
      action_type: action.action_type,
      actor_type: action.actor.type,
      actor_id: action.actor.id,
      platform: action.platform,
      ...action.payload,
      price_change_amount:
        action.payload.from_price === null
          ? null
          : rounded(action.payload.to_price - action.payload.from_price),
      ...economics,
      commerce_action: action,
    },
  };
}

function upstreamError(status: number): CommerceGateError {
  if (status === 401) {
    return new CommerceGateError(
      "AUTHENTICATION_FAILED",
      "The Decionis API rejected the configured credential.",
      { status },
    );
  }
  if (status === 403) {
    return new CommerceGateError(
      "AUTHORIZATION_FAILED",
      "The configured credential is not authorized for this environment-bound organization.",
      { status },
    );
  }
  if (status === 404) {
    return new CommerceGateError(
      "NOT_FOUND",
      "The requested CommerceGate evidence was not found.",
      {
        status,
      },
    );
  }
  if (status === 409) {
    return new CommerceGateError(
      "CONFLICT",
      "The CommerceGate request conflicted with existing state.",
      {
        status,
      },
    );
  }
  if (status === 429) {
    return new CommerceGateError("RATE_LIMITED", "The Decionis API rate limit was reached.", {
      status,
      retryable: true,
    });
  }
  if (status >= 500) {
    return new CommerceGateError(
      "UPSTREAM_UNAVAILABLE",
      "The Decionis API is temporarily unavailable. CommerceGate failed closed.",
      { status, retryable: true },
    );
  }
  return new CommerceGateError(
    "REQUEST_REJECTED",
    "The Decionis API rejected the CommerceGate request. Review the action fields and policy configuration.",
    { status },
  );
}

/** Tenant-bound HTTP client for the narrow CommerceGate Protocol surface. */
export class CommerceGateClient implements CommerceGateApi {
  constructor(
    private readonly configuration: CommerceGateConfiguration,
    private readonly fetchImpl: FetchLike = fetch,
    private readonly timeoutMs: number = DEFAULT_TIMEOUT_MS,
  ) {}

  private async request(
    path: string,
    options: {
      method?: "GET" | "POST";
      body?: Record<string, unknown>;
      idempotencyKey?: string;
    } = {},
  ): Promise<unknown> {
    const tenant = this.configuration.requireTenantConnection();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    const body = options.body ? { ...options.body, org_id: tenant.orgId } : undefined;

    try {
      const response = await this.fetchImpl(new URL(path, `${tenant.apiBaseUrl}/`), {
        method: options.method ?? "GET",
        headers: {
          authorization: `Bearer ${tenant.apiKey}`,
          accept: "application/json",
          ...(body ? { "content-type": "application/json" } : {}),
          ...(options.idempotencyKey ? { "idempotency-key": options.idempotencyKey } : {}),
          "user-agent": `decionis-commercegate-mcp/${MCP_SERVER_VERSION}`,
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        redirect: "error",
        signal: controller.signal,
      });

      const responseText = await readBoundedResponse(response, controller);
      if (!response.ok) throw upstreamError(response.status);
      if (!responseText) return {};
      try {
        return JSON.parse(responseText) as unknown;
      } catch {
        throw new CommerceGateError(
          "INVALID_UPSTREAM_RESPONSE",
          "The Decionis API returned an invalid JSON response. CommerceGate failed closed.",
        );
      }
    } catch (error) {
      if (error instanceof CommerceGateError) throw error;
      if (controller.signal.aborted) {
        throw new CommerceGateError(
          "UPSTREAM_TIMEOUT",
          "The Decionis API timed out. CommerceGate failed closed.",
          { retryable: true },
        );
      }
      throw new CommerceGateError(
        "UPSTREAM_UNREACHABLE",
        "The Decionis API could not be reached. CommerceGate failed closed.",
        { retryable: true },
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  async evaluateAction(input: EvaluateActionInput): Promise<unknown> {
    const request = buildEvaluationRequest(input);
    const response = await this.request(EVALUATE_OPERATION.path, {
      method: "POST",
      body: request,
      idempotencyKey: input.action.idempotency_key,
    });
    if (!isRecord(response) || response.mode !== "SHADOW") {
      throw new CommerceGateError(
        "INVALID_UPSTREAM_RESPONSE",
        "The Decionis API did not confirm a SHADOW evaluation. CommerceGate failed closed.",
      );
    }
    return response;
  }

  async getDossier(dossierId: string): Promise<unknown> {
    const tenant = this.configuration.requireTenantConnection();
    const query = new URLSearchParams({ org_id: tenant.orgId });
    const path = DOSSIER_OPERATION.path.replace("{dossierId}", encodeURIComponent(dossierId));
    return this.request(`${path}?${query}`);
  }

  async getProofPacket(dossierId: string): Promise<unknown> {
    const tenant = this.configuration.requireTenantConnection();
    const query = new URLSearchParams({ org_id: tenant.orgId });
    const path = PROOF_PACKET_OPERATION.path.replace("{dossierId}", encodeURIComponent(dossierId));
    return this.request(`${path}?${query}`);
  }

  async listShadowReports(queryInput: ShadowReportQuery): Promise<unknown> {
    return this.shadowReportsRequest(SHADOW_REPORT_OPERATION.path, queryInput);
  }

  async summarizeShadowReports(queryInput: ShadowReportQuery): Promise<unknown> {
    return this.shadowReportsRequest(SHADOW_REPORT_OPERATION.path, queryInput);
  }

  private async shadowReportsRequest(path: string, input: ShadowReportQuery): Promise<unknown> {
    const tenant = this.configuration.requireTenantConnection();
    const query = new URLSearchParams({ org_id: tenant.orgId });
    if (input.days) query.set("days", String(input.days));
    if (input.limit) query.set("limit", String(input.limit));
    return this.request(`${path}?${query}`);
  }
}

export const CommerceGateRequestMapping = { buildEvaluationRequest, marginSignal };
