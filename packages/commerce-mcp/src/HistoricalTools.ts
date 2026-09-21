import { toSafeFailure } from "./Errors.js";
import type { HistoricalApi } from "./HistoricalClient.js";
import {
  historicalAssessmentId,
  historicalEmptyInput,
  historicalStartInput,
} from "./HistoricalContract.js";
import type { ToolDefinition, ToolInvocationResult } from "./Tools.js";

export const HISTORICAL_TOOL_NAMES = [
  "commercegate_list_history_sources",
  "commercegate_start_historical_assessment",
  "commercegate_get_historical_assessment",
] as const;
export const HISTORICAL_MCP_INSTRUCTIONS =
  "The additional history tools assess the previous 90 days of transactions from a synthetic dataset or an already connected store. Dates, workspace, policy and source transactions are server-bound. The 14-day trial uses synthetic history and requires a server-verified AWS entitlement; the client never provisions anonymous HTTP access or determines license expiry. Historical results describe past transactions and are not authorization for a future action. These tools do not replace the separate proposal evaluation or ERP authorization contracts. Missing costs and evaluation failures remain visible. A null proof_ref means no signed proof is available; do not claim otherwise.";

const emptySchema = { type: "object", properties: {}, additionalProperties: false };
async function result(work: () => Promise<Record<string, unknown>>): Promise<ToolInvocationResult> {
  try {
    const value = await work();
    return { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value };
  } catch (error) {
    const value = toSafeFailure(error);
    return {
      content: [{ type: "text", text: JSON.stringify(value) }],
      structuredContent: { ...value },
      isError: true,
    };
  }
}
const annotations = (readOnlyHint: boolean, openWorldHint = true) => ({
  readOnlyHint,
  openWorldHint,
  destructiveHint: false,
  idempotentHint: true,
});

export class HistoricalTools {
  constructor(private readonly api: HistoricalApi) {}

  build(): ToolDefinition[] {
    return [
      {
        name: HISTORICAL_TOOL_NAMES[0],
        title: "List Historical Data Sources",
        description:
          "List the synthetic dataset and existing connected stores authorized for the buyer's Commerce Gate workspace. Real data requires a verified store connection established outside this tool. No raw transactions or connection credentials are returned.",
        inputSchema: emptySchema,
        annotations: annotations(true),
        handler: (args) =>
          result(async () => {
            historicalEmptyInput(args);
            return { ok: true, history: await this.api.sources() };
          }),
      },
      {
        name: HISTORICAL_TOOL_NAMES[1],
        title: "Assess the Previous 90 Days",
        description:
          "Start and persist an idempotent historical assessment of the previous 90 days using synthetic history or an authorized connected store. The service fixes dates, policy and tenant; callers cannot upload transactions, set policy, or evaluate future actions. A verified AWS grant is required, including during the 14-day synthetic trial. Results include provenance, missing costs, summaries and bounded evidence; a null proof reference is not signed proof.",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          required: ["source", "idempotency_key"],
          properties: {
            source: {
              oneOf: [
                {
                  type: "object",
                  additionalProperties: false,
                  required: ["kind"],
                  properties: { kind: { const: "synthetic" } },
                },
                {
                  type: "object",
                  additionalProperties: false,
                  required: ["kind", "connection_id"],
                  properties: {
                    kind: { const: "connected_store" },
                    connection_id: { type: "string", format: "uuid" },
                  },
                },
              ],
            },
            idempotency_key: {
              type: "string",
              minLength: 1,
              maxLength: 200,
              pattern: "^[A-Za-z0-9._:-]+$",
            },
          },
        },
        annotations: annotations(false),
        handler: (args) =>
          result(async () => ({
            ok: true,
            no_downstream_action_executed: true,
            assessment: await this.api.start(historicalStartInput(args)),
          })),
      },
      {
        name: HISTORICAL_TOOL_NAMES[2],
        title: "Read a Historical Assessment and Evidence",
        description:
          "Read an immutable assessment by UUID within the buyer's credential-bound workspace. Evidence remains bound to the historical source and 90-day window. PROCEED is a retrospective classification, never authorization to execute. Missing proof references do not imply signed evidence.",
        inputSchema: {
          type: "object",
          additionalProperties: false,
          required: ["assessment_id"],
          properties: { assessment_id: { type: "string", format: "uuid" } },
        },
        annotations: annotations(true),
        handler: (args) =>
          result(async () => ({
            ok: true,
            no_downstream_action_executed: true,
            assessment: await this.api.assessment(historicalAssessmentId(args)),
          })),
      },
    ];
  }
}
