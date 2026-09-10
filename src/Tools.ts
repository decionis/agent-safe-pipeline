import type {
  ActorType,
  CommerceAction,
  CommerceGateApi,
  ErpGuardResponse,
  ErpType,
  EvaluateActionInput,
  ShadowReportQuery,
  ValidateErpTransactionInput,
} from "./CommerceGateClient.js";
import { SUPPORTED_ACTION_TYPES } from "./CommerceGateClient.js";
import type { CommerceGateConfiguration } from "./Configuration.js";
import { CommerceGateError, toSafeFailure } from "./Errors.js";

export interface ToolContent {
  type: "text";
  text: string;
}

export interface ToolInvocationResult {
  content: ToolContent[];
  structuredContent: Record<string, unknown>;
  isError?: boolean;
}

export interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: {
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
  handler: (args: Record<string, unknown>) => Promise<ToolInvocationResult>;
}

export const COMMERCEGATE_TOOL_NAMES = [
  "commercegate_describe_capabilities",
  "commercegate_validate_erp_transaction",
  "commercegate_evaluate_action",
  "commercegate_get_dossier",
  "commercegate_get_proof_packet",
  "commercegate_list_shadow_reports",
  "commercegate_summarize_shadow_reports",
] as const;

export const COMMERCEGATE_OUTCOME_MAP = {
  APPROVE: "PROCEED",
  REJECT: "BLOCK",
  REVIEW: "HOLD",
  ESCALATE: "HOLD",
} as const;

export const COMMERCEGATE_ACTION_SUPPORT = {
  native_margin_mapping: ["ORDER_ACCEPTANCE", "PRICE_CHANGE"],
  generic_protocol_shadow: [
    "INVENTORY_MUTATION",
    "FULFILLMENT_ACTION",
    "PROMOTION_CHANGE",
    "REFUND_REQUEST",
    "RETURN_AUTHORIZATION",
  ],
  connector_execution: {
    exposed_by_this_mcp: false,
    connected_status_alone_is_sufficient: false,
    required_evidence: [
      "marketplace_api_support",
      "merchant_granted_scope",
      "implemented_connector_path",
      "enabled_connector_path",
      "explicit_execution_authority",
    ],
  },
} as const;

const ACTOR_TYPES: ActorType[] = ["HUMAN", "ERP", "REPRICER", "WORKFLOW", "AGENT", "UNKNOWN"];
const ERP_TYPES: ErpType[] = ["D365_BC", "D365_FSCM"];
const ISO_4217_CODES = Intl.supportedValuesOf("currency");
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RFC_3339_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/;
const BOUNDED_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,179}$/;
const POLICY_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$/;

const annotations = (readOnlyHint: boolean, openWorldHint: boolean) => ({
  readOnlyHint,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint,
});

const actorSchema = {
  type: "object",
  required: ["type", "id"],
  properties: {
    type: {
      type: "string",
      enum: ACTOR_TYPES,
      description: "The class of human or system proposing the commerce action.",
    },
    id: {
      type: "string",
      minLength: 1,
      maxLength: 200,
      description: "A stable, non-secret actor identifier.",
    },
  },
  additionalProperties: false,
} as const;

const actionBaseProperties = {
  actor: actorSchema,
  platform: {
    type: "string",
    minLength: 1,
    maxLength: 120,
    description: "Target commerce platform, such as shopify or walmart-marketplace.",
  },
  idempotency_key: {
    type: "string",
    minLength: 1,
    maxLength: 180,
    pattern: BOUNDED_KEY_PATTERN.source,
    description: "Stable key reused for retries of this same proposed action.",
  },
} as const;

const boundedIdentifierSchema = {
  type: "string",
  minLength: 1,
  maxLength: 200,
} as const;

const nullableIdentifierSchema = {
  anyOf: [boundedIdentifierSchema, { type: "null" }],
} as const;

const nullableNonNegativeNumberSchema = {
  anyOf: [{ type: "number", minimum: 0 }, { type: "null" }],
} as const;

const currencySchema = {
  type: "string",
  enum: ISO_4217_CODES,
  description: "ISO-4217 alpha-3 currency code.",
} as const;

const erpGuardSchema = {
  type: "object",
  required: ["erp_region", "request"],
  properties: {
    erp_region: {
      type: "string",
      minLength: 1,
      maxLength: 50,
      description: "ERP deployment region sent as X-ERP-Region.",
    },
    request: {
      type: "object",
      required: [
        "transaction_id",
        "erp_type",
        "tenant_id",
        "timestamp",
        "agent_id",
        "currency",
        "lines",
      ],
      properties: {
        transaction_id: { type: "string", minLength: 1, maxLength: 160 },
        erp_type: { type: "string", enum: ["D365_BC", "D365_FSCM"] },
        tenant_id: { type: "string", format: "uuid" },
        timestamp: { type: "string", format: "date-time" },
        agent_id: { type: "string", minLength: 1, maxLength: 160 },
        currency: { type: "string", pattern: "^[A-Z]{3}$" },
        lines: {
          type: "array",
          minItems: 1,
          maxItems: 200,
          items: {
            type: "object",
            required: ["line_id", "sku", "quantity", "unit_price", "cost_base"],
            properties: {
              line_id: { type: "integer", minimum: 1, maximum: 2_147_483_647 },
              sku: { type: "string", minLength: 1, maxLength: 100 },
              quantity: { type: "number", exclusiveMinimum: 0, maximum: 1_000_000_000 },
              unit_price: { type: "number", minimum: 0, maximum: 1_000_000_000_000 },
              cost_base: { type: "number", minimum: 0, maximum: 1_000_000_000_000 },
            },
            additionalProperties: false,
          },
        },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
} as const;

const orderAcceptanceActionSchema = {
  title: "Order acceptance preflight",
  description:
    "Evaluate whether a proposed order acceptance clears the supplied gross revenue, seller-funded discount, and landed-cost economics.",
  type: "object",
  required: ["action_type", "actor", "platform", "idempotency_key", "payload"],
  properties: {
    action_type: { type: "string", const: "ORDER_ACCEPTANCE" },
    ...actionBaseProperties,
    payload: {
      type: "object",
      required: ["order_id", "gross_amount", "discount_amount", "estimated_cost"],
      properties: {
        order_id: nullableIdentifierSchema,
        gross_amount: { type: "number", minimum: 0 },
        discount_amount: {
          type: "number",
          minimum: 0,
          description: "Seller-funded discount; must not exceed gross_amount.",
        },
        estimated_cost: { type: "number", minimum: 0 },
        currency: currencySchema,
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
  examples: [
    {
      action_type: "ORDER_ACCEPTANCE",
      actor: { type: "AGENT", id: "order-agent" },
      platform: "shopify",
      idempotency_key: "order:1001:accept:v1",
      payload: {
        order_id: "1001",
        gross_amount: 125,
        discount_amount: 10,
        estimated_cost: 72,
        currency: "USD",
      },
    },
  ],
} as const;

const priceChangeActionSchema = {
  title: "Price change preflight",
  description:
    "Evaluate a proposed SKU price, with optional landed cost for a native CommerceGate margin-floor calculation.",
  type: "object",
  required: ["action_type", "actor", "platform", "idempotency_key", "payload"],
  properties: {
    action_type: { type: "string", const: "PRICE_CHANGE" },
    ...actionBaseProperties,
    payload: {
      type: "object",
      required: ["sku", "from_price", "to_price"],
      properties: {
        sku: boundedIdentifierSchema,
        from_price: nullableNonNegativeNumberSchema,
        to_price: { type: "number", minimum: 0 },
        estimated_cost: nullableNonNegativeNumberSchema,
        currency: currencySchema,
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
  examples: [
    {
      action_type: "PRICE_CHANGE",
      actor: { type: "REPRICER", id: "marketplace-repricer" },
      platform: "walmart-marketplace",
      idempotency_key: "sku:SKU-1001:price:v3",
      payload: {
        sku: "SKU-1001",
        from_price: 99,
        to_price: 89,
        estimated_cost: 61,
        currency: "USD",
      },
    },
  ],
} as const;

const inventoryMutationActionSchema = {
  title: "Inventory mutation or oversell preflight",
  description:
    "Evaluate a proposed inventory quantity change or an inventory-floor signal before a separate connector writes stock or releases an order.",
  type: "object",
  required: ["action_type", "actor", "platform", "idempotency_key", "payload"],
  properties: {
    action_type: { type: "string", const: "INVENTORY_MUTATION" },
    ...actionBaseProperties,
    payload: {
      type: "object",
      required: ["sku", "from", "to"],
      properties: {
        sku: boundedIdentifierSchema,
        from: nullableNonNegativeNumberSchema,
        to: { type: "number", minimum: 0 },
        location_id: nullableIdentifierSchema,
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
  examples: [
    {
      action_type: "INVENTORY_MUTATION",
      actor: { type: "ERP", id: "inventory-sync" },
      platform: "shopify",
      idempotency_key: "sku:SKU-1001:inventory:v8",
      payload: { sku: "SKU-1001", from: 18, to: 7, location_id: "stockholm" },
    },
  ],
} as const;

const fulfillmentActionSchema = {
  title: "Fulfillment action preflight",
  description:
    "Evaluate a proposed order acknowledgment, shipment, cancellation, or hold without performing that marketplace action.",
  type: "object",
  required: ["action_type", "actor", "platform", "idempotency_key", "payload"],
  properties: {
    action_type: { type: "string", const: "FULFILLMENT_ACTION" },
    ...actionBaseProperties,
    payload: {
      type: "object",
      required: ["order_id", "action"],
      properties: {
        order_id: boundedIdentifierSchema,
        action: {
          type: "string",
          enum: ["acknowledge", "ship", "cancel", "hold"],
        },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
  examples: [
    {
      action_type: "FULFILLMENT_ACTION",
      actor: { type: "WORKFLOW", id: "warehouse-flow" },
      platform: "walmart-marketplace",
      idempotency_key: "order:1001:fulfillment:hold:v1",
      payload: { order_id: "1001", action: "hold" },
    },
  ],
} as const;

const promotionChangeActionSchema = {
  title: "Promotion change preflight",
  description:
    "Evaluate proposed promotion percentage, lifecycle, and discount-combination facts against the active tenant policy.",
  type: "object",
  required: ["action_type", "actor", "platform", "idempotency_key", "payload"],
  properties: {
    action_type: { type: "string", const: "PROMOTION_CHANGE" },
    ...actionBaseProperties,
    payload: {
      type: "object",
      required: ["promotion_id", "percentage_fraction", "ends_at", "status", "combines_with"],
      properties: {
        promotion_id: nullableIdentifierSchema,
        percentage_fraction: {
          anyOf: [{ type: "number", minimum: 0, maximum: 1 }, { type: "null" }],
          description: "Promotion percentage as a fraction, where 0.2 means 20%.",
        },
        ends_at: {
          anyOf: [{ type: "string", minLength: 1, maxLength: 100 }, { type: "null" }],
        },
        status: {
          anyOf: [{ type: "string", minLength: 1, maxLength: 120 }, { type: "null" }],
        },
        combines_with: {
          anyOf: [
            {
              type: "object",
              required: ["order_discounts", "product_discounts", "shipping_discounts"],
              properties: {
                order_discounts: { type: "boolean" },
                product_discounts: { type: "boolean" },
                shipping_discounts: { type: "boolean" },
              },
              additionalProperties: false,
            },
            { type: "null" },
          ],
        },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
  examples: [
    {
      action_type: "PROMOTION_CHANGE",
      actor: { type: "HUMAN", id: "merchandising-operator" },
      platform: "shopify",
      idempotency_key: "promotion:summer-20:update:v2",
      payload: {
        promotion_id: "summer-20",
        percentage_fraction: 0.2,
        ends_at: "2026-09-30T23:59:59Z",
        status: "ACTIVE",
        combines_with: {
          order_discounts: false,
          product_discounts: false,
          shipping_discounts: true,
        },
      },
    },
  ],
} as const;

const refundRequestActionSchema = {
  title: "Refund request preflight",
  description:
    "Evaluate a proposed refund amount and reason before any connector-specific lifecycle, balance, scope, and confirmation checks execute it.",
  type: "object",
  required: ["action_type", "actor", "platform", "idempotency_key", "payload"],
  properties: {
    action_type: { type: "string", const: "REFUND_REQUEST" },
    ...actionBaseProperties,
    payload: {
      type: "object",
      required: ["order_id", "amount"],
      properties: {
        order_id: boundedIdentifierSchema,
        amount: { type: "number", minimum: 0 },
        currency: currencySchema,
        reason_code: nullableIdentifierSchema,
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
  examples: [
    {
      action_type: "REFUND_REQUEST",
      actor: { type: "AGENT", id: "support-agent" },
      platform: "walmart-marketplace",
      idempotency_key: "order:1001:refund:v1",
      payload: {
        order_id: "1001",
        amount: 90,
        currency: "USD",
        reason_code: "CUSTOMER_RETURN",
      },
    },
  ],
} as const;

const returnAuthorizationActionSchema = {
  title: "Return authorization preflight",
  description:
    "Evaluate a proposed return or RMA authorization without creating the return in a marketplace or ERP.",
  type: "object",
  required: ["action_type", "actor", "platform", "idempotency_key", "payload"],
  properties: {
    action_type: { type: "string", const: "RETURN_AUTHORIZATION" },
    ...actionBaseProperties,
    payload: {
      type: "object",
      required: ["order_id"],
      properties: {
        order_id: boundedIdentifierSchema,
        rma_id: nullableIdentifierSchema,
        amount: nullableNonNegativeNumberSchema,
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
  examples: [
    {
      action_type: "RETURN_AUTHORIZATION",
      actor: { type: "HUMAN", id: "returns-operator" },
      platform: "shopify",
      idempotency_key: "order:1001:return:v1",
      payload: { order_id: "1001", rma_id: "RMA-1001", amount: 90 },
    },
  ],
} as const;

const evaluateActionSchema = {
  type: "object",
  required: ["action"],
  properties: {
    action: {
      oneOf: [
        priceChangeActionSchema,
        inventoryMutationActionSchema,
        orderAcceptanceActionSchema,
        fulfillmentActionSchema,
        promotionChangeActionSchema,
        refundRequestActionSchema,
        returnAuthorizationActionSchema,
      ],
      description: "The complete, normalized commerce action proposed for shadow evaluation.",
    },
    policy_version: {
      type: "string",
      minLength: 1,
      maxLength: 120,
      pattern: POLICY_VERSION_PATTERN.source,
      description: "Optional exact Decionis policy version. Omit to use the tenant default.",
    },
  },
  additionalProperties: false,
} as const;

const dossierSchema = {
  type: "object",
  required: ["dossier_id"],
  properties: {
    dossier_id: {
      type: "string",
      pattern: UUID_PATTERN.source,
      description: "UUID returned by commercegate_evaluate_action or a shadow report.",
    },
  },
  additionalProperties: false,
} as const;

const reportSchema = {
  type: "object",
  properties: {
    days: {
      type: "integer",
      minimum: 1,
      maximum: 365,
      description: "Report window in days. The API default is 30.",
    },
    limit: {
      type: "integer",
      minimum: 1,
      maximum: 100,
      description: "Maximum report rows to inspect. The API default is 20.",
    },
  },
  additionalProperties: false,
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertAllowedKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const unexpected = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unexpected.length > 0) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      `${label} contains unsupported field '${unexpected[0]}'.`,
    );
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new CommerceGateError("INVALID_INPUT", `${label} must be a JSON object.`);
  }
  return value;
}

function boundedText(value: unknown, label: string, maximum: number): string {
  const hasControlCharacter =
    typeof value === "string" &&
    Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 31 || codePoint === 127;
    });
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    value.trim() !== value ||
    hasControlCharacter
  ) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      `${label} must be a non-empty string of at most ${maximum} characters without control characters or surrounding whitespace.`,
    );
  }
  return value;
}

function nonNegativeNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      `${label} must be a finite number greater than or equal to zero.`,
    );
  }
  return value;
}

function nullableNonNegativeNumber(value: unknown, label: string): number | null {
  return value === null ? null : nonNegativeNumber(value, label);
}

function optionalNullableNonNegativeNumber(
  value: unknown,
  label: string,
): number | null | undefined {
  return value === undefined ? undefined : nullableNonNegativeNumber(value, label);
}

function fractionOrNull(value: unknown, label: string): number | null {
  if (value === null) return null;
  const result = nonNegativeNumber(value, label);
  if (result > 1) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      `${label} must be a fraction from zero through one, or null.`,
    );
  }
  return result;
}

function boundedTextOrNull(value: unknown, label: string, maximum: number): string | null {
  return value === null ? null : boundedText(value, label, maximum);
}

function optionalBoundedTextOrNull(
  value: unknown,
  label: string,
  maximum: number,
): string | null | undefined {
  return value === undefined ? undefined : boundedTextOrNull(value, label, maximum);
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new CommerceGateError("INVALID_INPUT", `${label} must be a boolean.`);
  }
  return value;
}

function currency(value: unknown): string {
  if (typeof value !== "string" || !ISO_4217_CODES.includes(value)) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "action.payload.currency must be an uppercase ISO-4217 alpha-3 code.",
    );
  }
  return value;
}

function optionalCurrency(value: unknown): string | undefined {
  return value === undefined ? undefined : currency(value);
}

function boundedNumber(
  value: unknown,
  label: string,
  options: { maximum: number; exclusiveMinimum?: number },
): number {
  const result = nonNegativeNumber(value, label);
  if (
    result > options.maximum ||
    (options.exclusiveMinimum !== undefined && result <= options.exclusiveMinimum)
  ) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      `${label} is outside the supported CommerceGate ERP guard range.`,
    );
  }
  return result;
}

function boundedInteger(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      `${label} must be an integer from ${minimum} through ${maximum}.`,
    );
  }
  return value as number;
}

function erpCurrency(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Z]{3}$/.test(value)) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "request.currency must contain exactly three uppercase letters.",
    );
  }
  return value;
}

function rfc3339Timestamp(value: unknown): string {
  const result = boundedText(value, "request.timestamp", 100);
  const match = RFC_3339_PATTERN.exec(result);
  if (!match) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "request.timestamp must be an RFC 3339 date-time.",
    );
  }
  const [
    ,
    rawYear,
    rawMonth,
    rawDay,
    rawHour,
    rawMinute,
    rawSecond,
    rawOffsetHour,
    rawOffsetMinute,
  ] = match;
  const year = Number(rawYear);
  const month = Number(rawMonth);
  const day = Number(rawDay);
  const maximumDay =
    month >= 1 && month <= 12 ? new Date(Date.UTC(year, month, 0)).getUTCDate() : 0;
  const valid =
    day >= 1 &&
    day <= maximumDay &&
    Number(rawHour) <= 23 &&
    Number(rawMinute) <= 59 &&
    Number(rawSecond) <= 59 &&
    (rawOffsetHour === undefined || Number(rawOffsetHour) <= 23) &&
    (rawOffsetMinute === undefined || Number(rawOffsetMinute) <= 59) &&
    Number.isFinite(Date.parse(result));
  if (!valid) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "request.timestamp must be a valid RFC 3339 date-time.",
    );
  }
  return result;
}

function parseErpGuardInput(args: Record<string, unknown>): ValidateErpTransactionInput {
  assertAllowedKeys(args, ["erp_region", "request"], "commercegate_validate_erp_transaction input");
  const request = record(args.request, "request");
  assertAllowedKeys(
    request,
    ["transaction_id", "erp_type", "tenant_id", "timestamp", "agent_id", "currency", "lines"],
    "request",
  );
  if (typeof request.erp_type !== "string" || !ERP_TYPES.includes(request.erp_type as ErpType)) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      `request.erp_type must be one of ${ERP_TYPES.join(", ")}.`,
    );
  }
  const tenantId = boundedText(request.tenant_id, "request.tenant_id", 36);
  if (!UUID_PATTERN.test(tenantId)) {
    throw new CommerceGateError("INVALID_INPUT", "request.tenant_id must be a UUID.");
  }
  if (!Array.isArray(request.lines) || request.lines.length < 1 || request.lines.length > 200) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "request.lines must contain from 1 through 200 lines.",
    );
  }
  const lines = request.lines.map((value, index) => {
    const line = record(value, `request.lines[${index}]`);
    assertAllowedKeys(
      line,
      ["line_id", "sku", "quantity", "unit_price", "cost_base"],
      `request.lines[${index}]`,
    );
    return {
      line_id: boundedInteger(line.line_id, `request.lines[${index}].line_id`, 1, 2_147_483_647),
      sku: boundedText(line.sku, `request.lines[${index}].sku`, 100),
      quantity: boundedNumber(line.quantity, `request.lines[${index}].quantity`, {
        maximum: 1_000_000_000,
        exclusiveMinimum: 0,
      }),
      unit_price: boundedNumber(line.unit_price, `request.lines[${index}].unit_price`, {
        maximum: 1_000_000_000_000,
      }),
      cost_base: boundedNumber(line.cost_base, `request.lines[${index}].cost_base`, {
        maximum: 1_000_000_000_000,
      }),
    };
  });
  return {
    erp_region: boundedText(args.erp_region, "erp_region", 50),
    request: {
      transaction_id: boundedText(request.transaction_id, "request.transaction_id", 160),
      erp_type: request.erp_type as ErpType,
      tenant_id: tenantId,
      timestamp: rfc3339Timestamp(request.timestamp),
      agent_id: boundedText(request.agent_id, "request.agent_id", 160),
      currency: erpCurrency(request.currency),
      lines,
    },
  };
}

function actor(value: unknown): { type: ActorType; id: string } {
  const item = record(value, "action.actor");
  assertAllowedKeys(item, ["type", "id"], "action.actor");
  if (typeof item.type !== "string" || !ACTOR_TYPES.includes(item.type as ActorType)) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      `action.actor.type must be one of ${ACTOR_TYPES.join(", ")}.`,
    );
  }
  return {
    type: item.type as ActorType,
    id: boundedText(item.id, "action.actor.id", 200),
  };
}

function parseAction(value: unknown): CommerceAction {
  const item = record(value, "action");
  assertAllowedKeys(
    item,
    ["action_type", "actor", "platform", "idempotency_key", "payload"],
    "action",
  );
  if (
    typeof item.action_type !== "string" ||
    !SUPPORTED_ACTION_TYPES.includes(item.action_type as (typeof SUPPORTED_ACTION_TYPES)[number])
  ) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      `action.action_type must be one of ${SUPPORTED_ACTION_TYPES.join(", ")}.`,
    );
  }
  const actionType = item.action_type as (typeof SUPPORTED_ACTION_TYPES)[number];
  const shared = {
    actor: actor(item.actor),
    platform: boundedText(item.platform, "action.platform", 120),
    idempotency_key: boundedText(item.idempotency_key, "action.idempotency_key", 180),
  };
  if (!BOUNDED_KEY_PATTERN.test(shared.idempotency_key)) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "action.idempotency_key may contain only letters, digits, dot, underscore, colon, slash, and hyphen.",
    );
  }

  const payload = record(item.payload, "action.payload");
  switch (actionType) {
    case "ORDER_ACCEPTANCE": {
      assertAllowedKeys(
        payload,
        ["order_id", "gross_amount", "discount_amount", "estimated_cost", "currency"],
        "action.payload",
      );
      const grossAmount = nonNegativeNumber(payload.gross_amount, "action.payload.gross_amount");
      const discountAmount = nonNegativeNumber(
        payload.discount_amount,
        "action.payload.discount_amount",
      );
      if (discountAmount > grossAmount) {
        throw new CommerceGateError(
          "INVALID_INPUT",
          "action.payload.discount_amount must not exceed action.payload.gross_amount.",
        );
      }
      const currencyCode = optionalCurrency(payload.currency);
      return {
        action_type: "ORDER_ACCEPTANCE",
        ...shared,
        payload: {
          order_id: boundedTextOrNull(payload.order_id, "action.payload.order_id", 200),
          gross_amount: grossAmount,
          discount_amount: discountAmount,
          estimated_cost: nonNegativeNumber(
            payload.estimated_cost,
            "action.payload.estimated_cost",
          ),
          ...(currencyCode ? { currency: currencyCode } : {}),
        },
      };
    }
    case "PRICE_CHANGE": {
      assertAllowedKeys(
        payload,
        ["sku", "from_price", "to_price", "estimated_cost", "currency"],
        "action.payload",
      );
      const estimatedCost = optionalNullableNonNegativeNumber(
        payload.estimated_cost,
        "action.payload.estimated_cost",
      );
      const currencyCode = optionalCurrency(payload.currency);
      return {
        action_type: "PRICE_CHANGE",
        ...shared,
        payload: {
          sku: boundedText(payload.sku, "action.payload.sku", 200),
          from_price: nullableNonNegativeNumber(payload.from_price, "action.payload.from_price"),
          to_price: nonNegativeNumber(payload.to_price, "action.payload.to_price"),
          ...(estimatedCost !== undefined ? { estimated_cost: estimatedCost } : {}),
          ...(currencyCode ? { currency: currencyCode } : {}),
        },
      };
    }
    case "INVENTORY_MUTATION": {
      assertAllowedKeys(payload, ["sku", "from", "to", "location_id"], "action.payload");
      const locationId = optionalBoundedTextOrNull(
        payload.location_id,
        "action.payload.location_id",
        200,
      );
      return {
        action_type: "INVENTORY_MUTATION",
        ...shared,
        payload: {
          sku: boundedText(payload.sku, "action.payload.sku", 200),
          from: nullableNonNegativeNumber(payload.from, "action.payload.from"),
          to: nonNegativeNumber(payload.to, "action.payload.to"),
          ...(locationId !== undefined ? { location_id: locationId } : {}),
        },
      };
    }
    case "FULFILLMENT_ACTION": {
      assertAllowedKeys(payload, ["order_id", "action"], "action.payload");
      const fulfillmentActions = ["acknowledge", "ship", "cancel", "hold"] as const;
      if (
        typeof payload.action !== "string" ||
        !fulfillmentActions.includes(payload.action as (typeof fulfillmentActions)[number])
      ) {
        throw new CommerceGateError(
          "INVALID_INPUT",
          `action.payload.action must be one of ${fulfillmentActions.join(", ")}.`,
        );
      }
      return {
        action_type: "FULFILLMENT_ACTION",
        ...shared,
        payload: {
          order_id: boundedText(payload.order_id, "action.payload.order_id", 200),
          action: payload.action as (typeof fulfillmentActions)[number],
        },
      };
    }
    case "PROMOTION_CHANGE": {
      assertAllowedKeys(
        payload,
        ["promotion_id", "percentage_fraction", "ends_at", "status", "combines_with"],
        "action.payload",
      );
      let combinesWith: {
        order_discounts: boolean;
        product_discounts: boolean;
        shipping_discounts: boolean;
      } | null = null;
      if (payload.combines_with !== null) {
        const combines = record(payload.combines_with, "action.payload.combines_with");
        assertAllowedKeys(
          combines,
          ["order_discounts", "product_discounts", "shipping_discounts"],
          "action.payload.combines_with",
        );
        combinesWith = {
          order_discounts: booleanValue(
            combines.order_discounts,
            "action.payload.combines_with.order_discounts",
          ),
          product_discounts: booleanValue(
            combines.product_discounts,
            "action.payload.combines_with.product_discounts",
          ),
          shipping_discounts: booleanValue(
            combines.shipping_discounts,
            "action.payload.combines_with.shipping_discounts",
          ),
        };
      }
      return {
        action_type: "PROMOTION_CHANGE",
        ...shared,
        payload: {
          promotion_id: boundedTextOrNull(payload.promotion_id, "action.payload.promotion_id", 200),
          percentage_fraction: fractionOrNull(
            payload.percentage_fraction,
            "action.payload.percentage_fraction",
          ),
          ends_at: boundedTextOrNull(payload.ends_at, "action.payload.ends_at", 100),
          status: boundedTextOrNull(payload.status, "action.payload.status", 120),
          combines_with: combinesWith,
        },
      };
    }
    case "REFUND_REQUEST": {
      assertAllowedKeys(
        payload,
        ["order_id", "amount", "currency", "reason_code"],
        "action.payload",
      );
      const currencyCode = optionalCurrency(payload.currency);
      const reasonCode = optionalBoundedTextOrNull(
        payload.reason_code,
        "action.payload.reason_code",
        200,
      );
      return {
        action_type: "REFUND_REQUEST",
        ...shared,
        payload: {
          order_id: boundedText(payload.order_id, "action.payload.order_id", 200),
          amount: nonNegativeNumber(payload.amount, "action.payload.amount"),
          ...(currencyCode ? { currency: currencyCode } : {}),
          ...(reasonCode !== undefined ? { reason_code: reasonCode } : {}),
        },
      };
    }
    case "RETURN_AUTHORIZATION": {
      assertAllowedKeys(payload, ["order_id", "rma_id", "amount"], "action.payload");
      const rmaId = optionalBoundedTextOrNull(payload.rma_id, "action.payload.rma_id", 200);
      const amount = optionalNullableNonNegativeNumber(payload.amount, "action.payload.amount");
      return {
        action_type: "RETURN_AUTHORIZATION",
        ...shared,
        payload: {
          order_id: boundedText(payload.order_id, "action.payload.order_id", 200),
          ...(rmaId !== undefined ? { rma_id: rmaId } : {}),
          ...(amount !== undefined ? { amount } : {}),
        },
      };
    }
  }
}

function parseEvaluationInput(args: Record<string, unknown>): EvaluateActionInput {
  assertAllowedKeys(args, ["action", "policy_version"], "commercegate_evaluate_action input");
  const policyVersion =
    args.policy_version === undefined
      ? undefined
      : boundedText(args.policy_version, "policy_version", 120);
  if (policyVersion && !POLICY_VERSION_PATTERN.test(policyVersion)) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "policy_version may contain only letters, digits, dot, underscore, colon, slash, and hyphen.",
    );
  }
  return {
    action: parseAction(args.action),
    ...(policyVersion ? { policy_version: policyVersion } : {}),
  };
}

function parseDossierId(args: Record<string, unknown>): string {
  assertAllowedKeys(args, ["dossier_id"], "dossier input");
  const id = boundedText(args.dossier_id, "dossier_id", 36);
  if (!UUID_PATTERN.test(id)) {
    throw new CommerceGateError("INVALID_INPUT", "dossier_id must be a UUID.");
  }
  return id;
}

function parseReportQuery(args: Record<string, unknown>): ShadowReportQuery {
  assertAllowedKeys(args, ["days", "limit"], "shadow report input");
  let days: number | undefined;
  if (args.days !== undefined) {
    if (!Number.isInteger(args.days) || (args.days as number) < 1 || (args.days as number) > 365) {
      throw new CommerceGateError("INVALID_INPUT", "days must be an integer from 1 to 365.");
    }
    days = args.days as number;
  }
  let limit: number | undefined;
  if (args.limit !== undefined) {
    if (
      !Number.isInteger(args.limit) ||
      (args.limit as number) < 1 ||
      (args.limit as number) > 100
    ) {
      throw new CommerceGateError("INVALID_INPUT", "limit must be an integer from 1 to 100.");
    }
    limit = args.limit as number;
  }
  return { ...(days ? { days } : {}), ...(limit ? { limit } : {}) };
}

function toolResult(payload: Record<string, unknown>, isError = false): ToolInvocationResult {
  return {
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
    ...(isError ? { isError: true } : {}),
  };
}

async function safeCall(
  operation: () => Promise<Record<string, unknown>>,
): Promise<ToolInvocationResult> {
  try {
    return toolResult(await operation());
  } catch (error) {
    return toolResult(toSafeFailure(error) as unknown as Record<string, unknown>, true);
  }
}

function outcomeGuidance(response: unknown): string {
  if (!isRecord(response) || typeof response.outcome !== "string") {
    return "The response did not contain a recognized outcome. Fail closed and ask an operator to inspect the dossier.";
  }
  if (response.outcome === "REJECT") return "STOP. Do not execute the proposed commerce action.";
  if (response.outcome === "REVIEW" || response.outcome === "ESCALATE") {
    return "HOLD. Do not execute; route the action to an authorized human reviewer.";
  }
  if (response.outcome === "APPROVE") {
    return "Shadow evidence indicates approval, but this is not user consent and does not execute the action.";
  }
  return "Unknown outcome. Fail closed and do not execute the proposed commerce action.";
}

function commerceGateDisposition(response: unknown): "PROCEED" | "HOLD" | "BLOCK" {
  if (!isRecord(response) || typeof response.outcome !== "string") return "HOLD";
  return (
    COMMERCEGATE_OUTCOME_MAP[response.outcome as keyof typeof COMMERCEGATE_OUTCOME_MAP] ?? "HOLD"
  );
}

function erpGuardDisposition(response: ErpGuardResponse): "PROCEED" | "BLOCK" {
  return response.decision === "ALLOW" ? "PROCEED" : "BLOCK";
}

function erpBudgetAuthorizationStatus(
  response: ErpGuardResponse,
): "AUTHORIZED" | "DENIED" | "NOT_REACHED" {
  if (response.decision === "ALLOW") return "AUTHORIZED";
  return response.reason_code === "AGENT_BUDGET_EXCEEDED" ? "DENIED" : "NOT_REACHED";
}

function erpGuardGuidance(response: ErpGuardResponse): string {
  return response.decision === "ALLOW"
    ? "The central ERP guard authorized this exact transaction against policy and the agent budget. This does not execute the ERP write or replace current user intent."
    : "STOP. The central ERP guard blocked this transaction; do not write it to the ERP.";
}

function shadowReportListView(response: unknown): Record<string, unknown> {
  if (!isRecord(response) || !Array.isArray(response.recent_evaluations)) {
    throw new CommerceGateError(
      "INVALID_UPSTREAM_RESPONSE",
      "The Decionis API returned an invalid Shadow Report document. CommerceGate failed closed.",
    );
  }
  return {
    service: response.service ?? null,
    generated_at: response.generated_at ?? null,
    window_days: response.window_days ?? null,
    since: response.since ?? null,
    candidate_enforcement_paths: Array.isArray(response.candidate_enforcement_paths)
      ? response.candidate_enforcement_paths
      : [],
    near_misses: Array.isArray(response.near_misses) ? response.near_misses : [],
    recent_evaluations: response.recent_evaluations,
  };
}

function shadowReportSummaryView(response: unknown): Record<string, unknown> {
  if (!isRecord(response) || !isRecord(response.summary)) {
    throw new CommerceGateError(
      "INVALID_UPSTREAM_RESPONSE",
      "The Decionis API returned an invalid Shadow Report summary. CommerceGate failed closed.",
    );
  }
  return {
    service: response.service ?? null,
    generated_at: response.generated_at ?? null,
    window_days: response.window_days ?? null,
    since: response.since ?? null,
    summary: response.summary,
    cards: Array.isArray(response.cards) ? response.cards : [],
    reason_breakdown: Array.isArray(response.reason_breakdown) ? response.reason_breakdown : [],
  };
}

/** Build the operations-facing CommerceGate MCP tool catalog. */
export class CommerceGateTools {
  constructor(
    private readonly configuration: CommerceGateConfiguration,
    private readonly api: CommerceGateApi,
  ) {}

  build(): ToolDefinition[] {
    return [
      {
        name: COMMERCEGATE_TOOL_NAMES[0],
        title: "Describe CommerceGate Capabilities",
        description:
          "Use this first, or when someone asks 'can you check prices, orders or refunds against our policy?'. It lists the seven kinds of commerce action CommerceGate can check in Shadow Mode: price changes, inventory updates, order acceptance, fulfillment steps, promotion changes, refund requests, and return authorizations. It also explains PROCEED, HOLD, and BLOCK, tenant connection state, and available evidence tools. This local diagnostic never calls the Decionis API, reveals credentials, or claims that a platform connector can execute an action.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
        annotations: annotations(true, false),
        handler: async (args) =>
          safeCall(async () => {
            assertAllowedKeys(args, [], "commercegate_describe_capabilities input");
            const connection = this.configuration.describe();
            return {
              ok: true,
              server: "CommerceGate MCP",
              identity: "com.decionis/commerce-gate",
              connection,
              supported_action_types: SUPPORTED_ACTION_TYPES,
              evaluation_mode: "SHADOW",
              erp_guard: {
                mode: "ENFORCED",
                decisions: ["ALLOW", "BLOCK"],
                agent_budget_authorization_after_policy_approval: true,
                configuration_ready: connection.erp_guard_ready,
                erp_writes: false,
              },
              outcome_mapping: COMMERCEGATE_OUTCOME_MAP,
              action_support: COMMERCEGATE_ACTION_SUPPORT,
              guarantees: {
                marketplace_writes: false,
                erp_writes: false,
                evaluates_authority: true,
                evaluation_may_create_dossier: true,
                approve_is_not_execution_consent: true,
                protocol_tenant_org_is_environment_bound: true,
                credential_values_are_never_returned: true,
              },
              tools: COMMERCEGATE_TOOL_NAMES,
              configuration: {
                required_for_erp_guard: ["DECIONIS_API_KEY"],
                required_for_protocol_calls: ["DECIONIS_API_KEY", "DECIONIS_ORG_ID"],
                optional: ["DECIONIS_API_BASE"],
              },
            };
          }),
      },
      {
        name: COMMERCEGATE_TOOL_NAMES[1],
        title: "Validate an ERP Transaction",
        description:
          "Use this for a fully formed Dynamics 365 Business Central or Finance and Supply Chain Management transaction that needs central enforced authorization. CommerceGate evaluates line economics first and, only after policy clears, atomically authorizes the agent budget before returning the binary ALLOW or BLOCK decision used by the ERP enforcement shell. The tool can reserve budget and returns a reason-coded validation response; unlike the Shadow evaluator, it does not promise a retrievable dossier. It never writes, posts, releases, or modifies the ERP transaction itself. ALLOW is authorization evidence for the exact transaction, not user consent to perform the ERP write.",
        inputSchema: erpGuardSchema,
        annotations: annotations(false, true),
        handler: async (args) =>
          safeCall(async () => {
            const input = parseErpGuardInput(args);
            const validation = await this.api.validateErpTransaction(input);
            return {
              ok: true,
              mode: "ENFORCED",
              budget_authorization_status: erpBudgetAuthorizationStatus(validation),
              no_erp_write_executed: true,
              allow_is_not_execution_consent: true,
              commercegate_disposition: erpGuardDisposition(validation),
              agent_guidance: erpGuardGuidance(validation),
              validation,
            };
          }),
      },
      {
        name: COMMERCEGATE_TOOL_NAMES[2],
        title: "Evaluate a Commerce Action in Shadow Mode",
        description:
          "Use this as the default preflight before a price, inventory, order-acceptance, fulfillment, promotion, refund, or return proposal, for questions like 'would repricing this SKU to $89 on Walmart still clear our margin floor after the referral fee?', 'is it safe to accept this 40-unit order with the stock we have left?', or 'can the support bot refund $2,850 on this order?'. It sends the bounded canonical action and policy signals to Decionis in SHADOW mode and may persist a signed Decision Dossier. This is a generic Protocol evaluation: it never calls a marketplace API, executes the proposal, or confirms that a connector exposes the required write path. The result maps to PROCEED, HOLD, or BLOCK: APPROVE is evidence, not consent to execute; REJECT means stop; REVIEW or ESCALATE means hold for a human.",
        inputSchema: evaluateActionSchema,
        annotations: annotations(false, true),
        handler: async (args) =>
          safeCall(async () => {
            const input = parseEvaluationInput(args);
            const evaluation = await this.api.evaluateAction(input);
            return {
              ok: true,
              mode: "SHADOW",
              action_type: input.action.action_type,
              idempotency_key: input.action.idempotency_key,
              no_downstream_action_executed: true,
              approve_is_not_execution_consent: true,
              commercegate_disposition: commerceGateDisposition(evaluation),
              agent_guidance: outcomeGuidance(evaluation),
              evaluation,
            };
          }),
      },
      {
        name: COMMERCEGATE_TOOL_NAMES[3],
        title: "Get a CommerceGate Decision Dossier",
        description:
          "Use this to answer 'why was that order held?' or 'what policy version decided that price change?' by reading the signed Decision Dossier for a known dossier UUID within the environment-bound organization. This is a tenant read; it never executes or modifies a commerce action and it fails closed when credentials are absent or invalid.",
        inputSchema: dossierSchema,
        annotations: annotations(true, true),
        handler: async (args) =>
          safeCall(async () => ({
            ok: true,
            organization_scope: "environment-bound",
            dossier: await this.api.getDossier(parseDossierId(args)),
          })),
      },
      {
        name: COMMERCEGATE_TOOL_NAMES[4],
        title: "Get a CommerceGate Proof Packet",
        description:
          "Use this when finance or an auditor asks for signed evidence by fetching the proof packet for a known dossier UUID in the environment-bound organization. The tool is read-only, performs no marketplace action, and never treats successful verification as permission to execute.",
        inputSchema: dossierSchema,
        annotations: annotations(true, true),
        handler: async (args) =>
          safeCall(async () => ({
            ok: true,
            organization_scope: "environment-bound",
            proof_packet: await this.api.getProofPacket(parseDossierId(args)),
          })),
      },
      {
        name: COMMERCEGATE_TOOL_NAMES[5],
        title: "List CommerceGate Shadow Reports",
        description:
          "Use this to answer 'what would Shadow Mode have held recently?' by listing recent SHADOW evaluations in the environment-bound organization across price, inventory, order, fulfillment, promotion, refund, and return proposals. Results describe what policy would have done; they do not report marketplace execution and must not be interpreted as authority to mutate commerce state.",
        inputSchema: reportSchema,
        annotations: annotations(true, true),
        handler: async (args) =>
          safeCall(async () => {
            const report = await this.api.listShadowReports(parseReportQuery(args));
            return {
              ok: true,
              mode: "SHADOW",
              organization_scope: "environment-bound",
              reports: shadowReportListView(report),
            };
          }),
      },
      {
        name: COMMERCEGATE_TOOL_NAMES[6],
        title: "Summarize CommerceGate Shadow Reports",
        description:
          "Use this for 'how much would we have caught this month?' style questions: aggregate SHADOW outcomes, near misses, and policy mismatches for the environment-bound organization, so an operator can judge whether to turn enforcement on. It is a read-only operational summary; it neither changes enforcement mode nor executes any commerce action.",
        inputSchema: reportSchema,
        annotations: annotations(true, true),
        handler: async (args) =>
          safeCall(async () => {
            const report = await this.api.summarizeShadowReports(parseReportQuery(args));
            return {
              ok: true,
              mode: "SHADOW",
              organization_scope: "environment-bound",
              summary: shadowReportSummaryView(report),
            };
          }),
      },
    ];
  }
}

export const CommerceGateToolParsing = {
  parseAction,
  parseDossierId,
  parseErpGuardInput,
  parseEvaluationInput,
  parseReportQuery,
};
