import type {
  ActorType,
  CommerceAction,
  CommerceGateApi,
  EvaluateActionInput,
  ShadowReportQuery,
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

const ACTOR_TYPES: ActorType[] = ["HUMAN", "ERP", "REPRICER", "WORKFLOW", "AGENT", "UNKNOWN"];
const ISO_4217_CODES = Intl.supportedValuesOf("currency");
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BOUNDED_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;
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
    maxLength: 200,
    pattern: BOUNDED_KEY_PATTERN.source,
    description: "Stable key reused for retries of this same proposed action.",
  },
} as const;

const orderAcceptanceActionSchema = {
  type: "object",
  required: ["action_type", "actor", "platform", "idempotency_key", "payload"],
  properties: {
    action_type: { type: "string", const: "ORDER_ACCEPTANCE" },
    ...actionBaseProperties,
    payload: {
      type: "object",
      required: ["order_id", "gross_amount", "discount_amount", "estimated_cost", "currency"],
      properties: {
        order_id: { type: "string", minLength: 1, maxLength: 200 },
        gross_amount: { type: "number", minimum: 0 },
        discount_amount: {
          type: "number",
          minimum: 0,
          description: "Seller-funded discount; must not exceed gross_amount.",
        },
        estimated_cost: { type: "number", minimum: 0 },
        currency: {
          type: "string",
          enum: ISO_4217_CODES,
          description: "ISO-4217 alpha-3 currency code.",
        },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
} as const;

const priceChangeActionSchema = {
  type: "object",
  required: ["action_type", "actor", "platform", "idempotency_key", "payload"],
  properties: {
    action_type: { type: "string", const: "PRICE_CHANGE" },
    ...actionBaseProperties,
    payload: {
      type: "object",
      required: ["sku", "from_price", "to_price", "estimated_cost", "currency"],
      properties: {
        sku: { type: "string", minLength: 1, maxLength: 200 },
        from_price: { anyOf: [{ type: "number", minimum: 0 }, { type: "null" }] },
        to_price: { type: "number", minimum: 0 },
        estimated_cost: { type: "number", minimum: 0 },
        currency: {
          type: "string",
          enum: ISO_4217_CODES,
          description: "ISO-4217 alpha-3 currency code.",
        },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
} as const;

const evaluateActionSchema = {
  type: "object",
  required: ["action"],
  properties: {
    action: {
      oneOf: [orderAcceptanceActionSchema, priceChangeActionSchema],
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

function currency(value: unknown): string {
  if (typeof value !== "string" || !ISO_4217_CODES.includes(value)) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "action.payload.currency must be an uppercase ISO-4217 alpha-3 code.",
    );
  }
  return value;
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
  const shared = {
    actor: actor(item.actor),
    platform: boundedText(item.platform, "action.platform", 120),
    idempotency_key: boundedText(item.idempotency_key, "action.idempotency_key", 200),
  };
  if (!BOUNDED_KEY_PATTERN.test(shared.idempotency_key)) {
    throw new CommerceGateError(
      "INVALID_INPUT",
      "action.idempotency_key may contain only letters, digits, dot, underscore, colon, slash, and hyphen.",
    );
  }

  const payload = record(item.payload, "action.payload");
  if (item.action_type === "ORDER_ACCEPTANCE") {
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
    return {
      action_type: "ORDER_ACCEPTANCE",
      ...shared,
      payload: {
        order_id: boundedText(payload.order_id, "action.payload.order_id", 200),
        gross_amount: grossAmount,
        discount_amount: discountAmount,
        estimated_cost: nonNegativeNumber(payload.estimated_cost, "action.payload.estimated_cost"),
        currency: currency(payload.currency),
      },
    };
  }

  assertAllowedKeys(
    payload,
    ["sku", "from_price", "to_price", "estimated_cost", "currency"],
    "action.payload",
  );
  const fromPrice =
    payload.from_price === null
      ? null
      : nonNegativeNumber(payload.from_price, "action.payload.from_price");
  return {
    action_type: "PRICE_CHANGE",
    ...shared,
    payload: {
      sku: boundedText(payload.sku, "action.payload.sku", 200),
      from_price: fromPrice,
      to_price: nonNegativeNumber(payload.to_price, "action.payload.to_price"),
      estimated_cost: nonNegativeNumber(payload.estimated_cost, "action.payload.estimated_cost"),
      currency: currency(payload.currency),
    },
  };
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

/** Build the narrow, operations-facing CommerceGate MCP tool catalog. */
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
          "Use this first to understand CommerceGate's supported commerce actions, shadow-only safety boundary, tenant connection state, and available evidence tools. This local diagnostic never calls the Decionis API and never reveals credentials or the organization identifier.",
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
              outcome_mapping: COMMERCEGATE_OUTCOME_MAP,
              guarantees: {
                marketplace_writes: false,
                evaluates_authority: true,
                evaluation_may_create_dossier: true,
                approve_is_not_execution_consent: true,
                tenant_org_is_environment_bound: true,
                credential_values_are_never_returned: true,
              },
              tools: COMMERCEGATE_TOOL_NAMES,
              configuration: {
                required_for_tenant_calls: ["DECIONIS_API_KEY", "DECIONIS_ORG_ID"],
                optional: ["DECIONIS_API_BASE"],
              },
            };
          }),
      },
      {
        name: COMMERCEGATE_TOOL_NAMES[1],
        title: "Evaluate a Commerce Action in Shadow Mode",
        description:
          "Use this as the default preflight before an order-acceptance or price-change operation. It sends a normalized action to Decionis in SHADOW mode and may persist a signed Decision Dossier, but it never writes to a marketplace, changes a price, or accepts an order. APPROVE is evidence, not consent to execute; REJECT means stop; REVIEW or ESCALATE means hold for a human.",
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
        name: COMMERCEGATE_TOOL_NAMES[2],
        title: "Get a CommerceGate Decision Dossier",
        description:
          "Use this to inspect the signed decision record for a known dossier UUID within the environment-bound organization. This is a tenant read; it never executes or modifies a commerce action and it fails closed when credentials are absent or invalid.",
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
        name: COMMERCEGATE_TOOL_NAMES[3],
        title: "Get a CommerceGate Proof Packet",
        description:
          "Use this when an operator or auditor needs the proof packet for a known dossier UUID in the environment-bound organization. The tool is read-only, performs no marketplace action, and never treats successful verification as permission to execute.",
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
        name: COMMERCEGATE_TOOL_NAMES[4],
        title: "List CommerceGate Shadow Reports",
        description:
          "Use this for operations triage of recent SHADOW evaluations in the environment-bound organization. Results describe what policy would have done; they do not report marketplace execution and must not be interpreted as authority to mutate commerce state.",
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
        name: COMMERCEGATE_TOOL_NAMES[5],
        title: "Summarize CommerceGate Shadow Reports",
        description:
          "Use this to review aggregate SHADOW outcomes, near misses, and policy mismatches for the environment-bound organization. It is a read-only operational summary; it neither changes enforcement mode nor executes any commerce action.",
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
  parseEvaluationInput,
  parseReportQuery,
};
