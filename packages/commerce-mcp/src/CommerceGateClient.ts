import type { CommerceGateConfiguration } from "./Configuration.js";
import { CommerceGateError } from "./Errors.js";
import { MCP_SERVER_VERSION } from "./Version.js";

export const SUPPORTED_ACTION_TYPES = [
  "PRICE_CHANGE",
  "INVENTORY_MUTATION",
  "ORDER_ACCEPTANCE",
  "FULFILLMENT_ACTION",
  "PROMOTION_CHANGE",
  "REFUND_REQUEST",
  "RETURN_AUTHORIZATION",
] as const;
export const COMMERCEGATE_API_OPERATIONS = [
  {
    operationId: "validateErpTransaction",
    method: "POST",
    path: "/v1/guard/validate",
  },
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

const [
  ERP_GUARD_OPERATION,
  EVALUATE_OPERATION,
  DOSSIER_OPERATION,
  PROOF_PACKET_OPERATION,
  SHADOW_REPORT_OPERATION,
] = COMMERCEGATE_API_OPERATIONS;
export type SupportedActionType = (typeof SUPPORTED_ACTION_TYPES)[number];
export type ActorType = "HUMAN" | "ERP" | "REPRICER" | "WORKFLOW" | "AGENT" | "UNKNOWN";
export type ErpType = "D365_BC" | "D365_FSCM";

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
    order_id: string | null;
    gross_amount: number;
    discount_amount: number;
    estimated_cost: number;
    currency?: string;
  };
}

export interface PriceChangeAction extends ActionBase {
  action_type: "PRICE_CHANGE";
  payload: {
    sku: string;
    from_price: number | null;
    to_price: number;
    estimated_cost?: number | null;
    currency?: string;
  };
}

export interface InventoryMutationAction extends ActionBase {
  action_type: "INVENTORY_MUTATION";
  payload: {
    sku: string;
    from: number | null;
    to: number;
    location_id?: string | null;
  };
}

export interface FulfillmentAction extends ActionBase {
  action_type: "FULFILLMENT_ACTION";
  payload: {
    order_id: string;
    action: "acknowledge" | "ship" | "cancel" | "hold";
  };
}

export interface PromotionChangeAction extends ActionBase {
  action_type: "PROMOTION_CHANGE";
  payload: {
    promotion_id: string | null;
    percentage_fraction: number | null;
    ends_at: string | null;
    status: string | null;
    combines_with: {
      order_discounts: boolean;
      product_discounts: boolean;
      shipping_discounts: boolean;
    } | null;
  };
}

export interface RefundRequestAction extends ActionBase {
  action_type: "REFUND_REQUEST";
  payload: {
    order_id: string;
    amount: number;
    currency?: string;
    reason_code?: string | null;
  };
}

export interface ReturnAuthorizationAction extends ActionBase {
  action_type: "RETURN_AUTHORIZATION";
  payload: {
    order_id: string;
    rma_id?: string | null;
    amount?: number | null;
  };
}

export type CommerceAction =
  | PriceChangeAction
  | InventoryMutationAction
  | OrderAcceptanceAction
  | FulfillmentAction
  | PromotionChangeAction
  | RefundRequestAction
  | ReturnAuthorizationAction;

export interface EvaluateActionInput {
  action: CommerceAction;
  policy_version?: string;
}

export interface ErpGuardLine {
  line_id: number;
  sku: string;
  quantity: number;
  unit_price: number;
  cost_base: number;
}

export interface ErpGuardRequest {
  transaction_id: string;
  erp_type: ErpType;
  tenant_id: string;
  timestamp: string;
  agent_id: string;
  currency: string;
  lines: ErpGuardLine[];
}

export interface ValidateErpTransactionInput {
  erp_region: string;
  request: ErpGuardRequest;
}

export interface ErpGuardResponse {
  decision: "ALLOW" | "BLOCK";
  transaction_id: string;
  execution_time_ms: number;
  reason_code: string;
  message: string;
}

export interface ShadowReportQuery {
  days?: number;
  limit?: number;
}

export interface CommerceGateApi {
  validateErpTransaction(input: ValidateErpTransactionInput): Promise<ErpGuardResponse>;
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

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EVALUATION_OUTCOMES = new Set(["APPROVE", "ESCALATE", "REJECT", "REVIEW"]);
const GOVERNANCE_METRICS = [
  "override_drift_rate",
  "governance_tension_index",
  "boundary_volatility_score",
  "decision_volume_under_governance",
] as const;
const ERP_GUARD_RESPONSE_KEYS = new Set([
  "decision",
  "transaction_id",
  "execution_time_ms",
  "reason_code",
  "message",
]);

function invalidUpstreamResponse(message: string): CommerceGateError {
  return new CommerceGateError(
    "INVALID_UPSTREAM_RESPONSE",
    `${message} CommerceGate failed closed.`,
  );
}

function finiteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function boundedResponseText(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function validateEvaluationResponse(
  response: unknown,
  requestedPolicyVersion: string | undefined,
): Record<string, unknown> {
  if (!isRecord(response) || response.mode !== "SHADOW") {
    throw invalidUpstreamResponse("The Decionis API did not confirm a SHADOW evaluation.");
  }
  const governanceMetrics = response.governance_metrics;
  const reasonCodes = response.reason_codes;
  const valid =
    typeof response.outcome === "string" &&
    EVALUATION_OUTCOMES.has(response.outcome) &&
    finiteNumber(response.confidence) &&
    response.confidence >= 0 &&
    response.confidence <= 1 &&
    boundedResponseText(response.policy_version, 120) &&
    typeof response.objective_profile === "string" &&
    UUID_PATTERN.test(typeof response.dossier_id === "string" ? response.dossier_id : "") &&
    UUID_PATTERN.test(typeof response.evaluation_id === "string" ? response.evaluation_id : "") &&
    typeof response.fallback_to_legacy === "boolean" &&
    typeof response.idempotent_replay === "boolean" &&
    isRecord(governanceMetrics) &&
    GOVERNANCE_METRICS.every((metric) => finiteNumber(governanceMetrics[metric])) &&
    (reasonCodes === undefined ||
      (Array.isArray(reasonCodes) &&
        reasonCodes.every((reasonCode) => boundedResponseText(reasonCode, 500))));
  if (!valid) {
    throw invalidUpstreamResponse(
      "The Decionis API returned an incomplete or malformed evaluation response.",
    );
  }
  if (requestedPolicyVersion && response.policy_version !== requestedPolicyVersion) {
    throw invalidUpstreamResponse(
      "The Decionis API did not evaluate the exact requested policy version.",
    );
  }
  return response;
}

function validateErpGuardResponse(
  response: unknown,
  expectedTransactionId: string,
): ErpGuardResponse {
  if (
    !isRecord(response) ||
    Object.keys(response).some((key) => !ERP_GUARD_RESPONSE_KEYS.has(key)) ||
    (response.decision !== "ALLOW" && response.decision !== "BLOCK") ||
    !boundedResponseText(response.transaction_id, 160) ||
    response.transaction_id !== expectedTransactionId ||
    !finiteNumber(response.execution_time_ms) ||
    response.execution_time_ms < 0 ||
    !boundedResponseText(response.reason_code, 100) ||
    !boundedResponseText(response.message, 500)
  ) {
    throw invalidUpstreamResponse(
      "The Decionis API returned an incomplete, malformed, or mismatched ERP guard response.",
    );
  }
  return {
    decision: response.decision,
    transaction_id: response.transaction_id,
    execution_time_ms: response.execution_time_ms,
    reason_code: response.reason_code,
    message: response.message,
  };
}

function marginSignal(
  revenue: number,
  estimatedCost: number | null | undefined,
): Record<string, number | null> {
  const hasCost = estimatedCost !== null && estimatedCost !== undefined;
  const netMarginAmount = hasCost ? revenue - estimatedCost : null;
  const rawNetMarginFraction =
    netMarginAmount === null
      ? null
      : revenue > 0
        ? netMarginAmount / revenue
        : (estimatedCost as number) > 0
          ? -1
          : null;
  return {
    net_revenue: rounded(revenue),
    estimated_cost: hasCost ? rounded(estimatedCost) : null,
    net_margin_amount: netMarginAmount === null ? null : rounded(netMarginAmount),
    net_margin_fraction: rawNetMarginFraction === null ? null : rounded(rawNetMarginFraction),
    // Protocol commerce policies use percentage points (12 means 12%), while
    // net_margin_fraction remains at the legacy 0-1 scale for compatibility.
    // A known positive cost against zero revenue is a total loss, matching the
    // native CommerceGate margin evaluator's fail-closed -100% convention.
    net_margin_percent: rawNetMarginFraction === null ? null : rounded(rawNetMarginFraction * 100),
  };
}

interface EvaluationFacts {
  amount?: number;
  derived: Record<string, unknown>;
  signals: Record<string, unknown>;
}

function evaluationFacts(action: CommerceAction): EvaluationFacts {
  switch (action.action_type) {
    case "ORDER_ACCEPTANCE": {
      const netRevenue = action.payload.gross_amount - action.payload.discount_amount;
      const economics = marginSignal(netRevenue, action.payload.estimated_cost);
      return {
        amount: action.payload.gross_amount,
        derived: economics,
        signals: {
          order_id: action.payload.order_id,
          gross_amount: action.payload.gross_amount,
          discount_amount: action.payload.discount_amount,
          ...(action.payload.currency ? { currency: action.payload.currency } : {}),
          ...economics,
        },
      };
    }
    case "PRICE_CHANGE": {
      const economics = marginSignal(action.payload.to_price, action.payload.estimated_cost);
      const priceChangeAmount =
        action.payload.from_price === null
          ? null
          : rounded(action.payload.to_price - action.payload.from_price);
      return {
        amount: action.payload.to_price,
        derived: { price_change_amount: priceChangeAmount, ...economics },
        signals: {
          ...action.payload,
          price_change_amount: priceChangeAmount,
          ...economics,
        },
      };
    }
    case "INVENTORY_MUTATION": {
      const inventory = {
        current_inventory: action.payload.from,
        proposed_inventory: action.payload.to,
        available_inventory: action.payload.to,
      };
      return {
        derived: inventory,
        signals: { ...action.payload, ...inventory },
      };
    }
    case "FULFILLMENT_ACTION": {
      const fulfillment = { fulfillment_action: action.payload.action };
      return {
        derived: fulfillment,
        signals: { ...action.payload, ...fulfillment },
      };
    }
    case "PROMOTION_CHANGE": {
      const combines = action.payload.combines_with;
      const promotion = {
        discount_percent:
          action.payload.percentage_fraction === null
            ? null
            : rounded(action.payload.percentage_fraction * 100),
        combines_with_order_discounts: combines?.order_discounts ?? null,
        combines_with_product_discounts: combines?.product_discounts ?? null,
        combines_with_shipping_discounts: combines?.shipping_discounts ?? null,
      };
      return {
        derived: promotion,
        // Preserve exactly the supplied promotion facts. In particular, do not
        // infer a discount count from combines_with flags.
        signals: { ...action.payload, ...promotion },
      };
    }
    case "REFUND_REQUEST": {
      const refund = { refund_amount: action.payload.amount };
      return {
        amount: action.payload.amount,
        derived: refund,
        signals: { ...action.payload, ...refund },
      };
    }
    case "RETURN_AUTHORIZATION": {
      const returnFacts = { return_amount: action.payload.amount ?? null };
      return {
        ...(action.payload.amount === null || action.payload.amount === undefined
          ? {}
          : { amount: action.payload.amount }),
        derived: returnFacts,
        signals: { ...action.payload, ...returnFacts },
      };
    }
  }
}

function buildEvaluationRequest(input: EvaluateActionInput): Record<string, unknown> {
  const { action } = input;
  const transactionType = action.action_type.toLowerCase();
  const facts = evaluationFacts(action);
  return {
    org_id: null,
    decision_type: action.action_type,
    transaction_type: transactionType,
    workflow_key: `commerce_${transactionType}`,
    ...(facts.amount === undefined ? {} : { amount: facts.amount }),
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
      actor: action.actor,
      platform: action.platform,
      payload: action.payload,
      ...action.payload,
      // Existing consumers read derived facts at context.*. Keep those fields
      // while policy rules consume the canonical context.signals namespace.
      ...facts.derived,
      signals: {
        action_type: action.action_type,
        actor_type: action.actor.type,
        actor_id: action.actor.id,
        platform: action.platform,
        ...facts.signals,
      },
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
      "The configured credential is not authorized for this CommerceGate request.",
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

/** HTTP client for the public CommerceGate guard, Protocol, and evidence surface. */
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
      authentication?: { type: "bearer" } | { type: "erp_guard"; region: string };
      bindOrganization?: boolean;
    } = {},
  ): Promise<unknown> {
    const authentication = options.authentication ?? { type: "bearer" as const };
    const connection =
      authentication.type === "erp_guard"
        ? this.configuration.requireApiConnection()
        : this.configuration.requireTenantConnection();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    const orgId = "orgId" in connection ? connection.orgId : null;
    const body = options.body
      ? {
          ...options.body,
          ...(options.bindOrganization === false || orgId === null ? {} : { org_id: orgId }),
        }
      : undefined;
    const authenticationHeaders: Record<string, string> =
      authentication.type === "erp_guard"
        ? {
            "X-Decionis-API-Key": connection.apiKey,
            "X-ERP-Region": authentication.region,
          }
        : { authorization: `Bearer ${connection.apiKey}` };

    try {
      const response = await this.fetchImpl(new URL(path, `${connection.apiBaseUrl}/`), {
        method: options.method ?? "GET",
        headers: {
          ...authenticationHeaders,
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
    return validateEvaluationResponse(response, input.policy_version);
  }

  async validateErpTransaction(input: ValidateErpTransactionInput): Promise<ErpGuardResponse> {
    const response = await this.request(ERP_GUARD_OPERATION.path, {
      method: "POST",
      body: { ...input.request },
      authentication: { type: "erp_guard", region: input.erp_region },
      bindOrganization: false,
    });
    return validateErpGuardResponse(response, input.request.transaction_id);
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

export const CommerceGateRequestMapping = { buildEvaluationRequest, evaluationFacts, marginSignal };
