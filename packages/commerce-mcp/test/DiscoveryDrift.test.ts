import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import type {
  CommerceGateApi,
  EvaluateActionInput,
  ShadowReportQuery,
} from "../src/CommerceGateClient.js";
import { COMMERCEGATE_API_OPERATIONS, SUPPORTED_ACTION_TYPES } from "../src/CommerceGateClient.js";
import { CommerceGateConfiguration } from "../src/Configuration.js";
import { COMMERCEGATE_TOOL_NAMES, CommerceGateTools } from "../src/Tools.js";

interface JsonSchema {
  type?: string | string[];
  const?: unknown;
  description?: string;
  enum?: unknown[];
  format?: string;
  minimum?: number;
  maximum?: number;
  maxLength?: number;
  exclusiveMinimum?: number;
  minItems?: number;
  maxItems?: number;
  required?: string[];
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema;
  $ref?: string;
}

interface CommerceOpenApi {
  paths: Record<
    string,
    Record<
      string,
      {
        operationId?: string;
        "x-commercegate-mcp"?: boolean;
        "x-commercegate-tools"?: string[];
      }
    >
  >;
  components: { schemas: Record<string, JsonSchema> };
}

function namesIn(text: string): string[] {
  return Array.from(
    new Set(Array.from(text.matchAll(/["`](commercegate_[a-z0-9_]+)["`]/g), (match) => match[1])),
  ).sort();
}

const expectedNames = [...COMMERCEGATE_TOOL_NAMES].sort();
const expectedNameSet = new Set<string>(expectedNames);

/**
 * The vendored copy of https://commerce.decionis.com/.well-known/openapi.json.
 * Refresh with `pnpm contract:sync`; `pnpm contract:check` compares it with
 * the published contract. Tests never reach the network.
 */
async function readPublishedOpenApi(): Promise<CommerceOpenApi> {
  return JSON.parse(
    await readFile(new URL("../contract/CommerceGateOpenApi.json", import.meta.url), "utf8"),
  ) as CommerceOpenApi;
}

function schemaRequired(schema: JsonSchema): string[] {
  return [...(schema.required ?? [])].sort();
}

function objectKeys(value: unknown): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected an object while checking the CommerceGate response projection");
  }
  return Object.keys(value).sort();
}

describe("CommerceGate discovery drift", () => {
  it("set-compares registered tools with the README, registry manifest and desktop-extension manifest", async () => {
    const [readme, serverManifest, mcpbManifest] = await Promise.all([
      readFile(new URL("../README.md", import.meta.url), "utf8"),
      readFile(new URL("../server.json", import.meta.url), "utf8"),
      readFile(new URL("../manifest.json", import.meta.url), "utf8"),
    ]);
    const mcpb = JSON.parse(mcpbManifest) as { tools: Array<{ name: string }> };

    expect(namesIn(readme)).toEqual(expectedNames);
    expect(mcpb.tools.map((tool) => tool.name).sort()).toEqual(expectedNames);
    // server.json carries no tool list by design; it must at least not name a tool we do not ship.
    expect(namesIn(serverManifest).every((name) => expectedNameSet.has(name))).toBe(true);
  });

  it("keeps the MCPB desktop-extension manifest in step with the package and the privacy policy", async () => {
    const [manifestText, packageText, readme] = await Promise.all([
      readFile(new URL("../manifest.json", import.meta.url), "utf8"),
      readFile(new URL("../package.json", import.meta.url), "utf8"),
      readFile(new URL("../README.md", import.meta.url), "utf8"),
    ]);
    const manifest = JSON.parse(manifestText) as {
      manifest_version: string;
      version: string;
      tools: Array<{ name: string; description: string }>;
      privacy_policies: string[];
      server: { type: string; entry_point: string; mcp_config: { env: Record<string, string> } };
      user_config: Record<string, { sensitive?: boolean }>;
      compatibility: { runtimes: { node: string } };
    };
    const packageManifest = JSON.parse(packageText) as {
      version: string;
      bin: Record<string, string>;
      engines: { node: string };
    };

    expect(Number(manifest.manifest_version)).toBeGreaterThanOrEqual(0.2);
    expect(manifest.version).toBe(packageManifest.version);
    expect(manifest.tools.map((tool) => tool.name).sort()).toEqual(expectedNames);
    for (const tool of manifest.tools) expect(tool.description.length).toBeGreaterThan(20);
    expect(manifest.server.type).toBe("node");
    expect(Object.values(packageManifest.bin)).toContain(manifest.server.entry_point);
    expect(Object.keys(manifest.server.mcp_config.env).sort()).toEqual([
      "DECIONIS_API_BASE",
      "DECIONIS_API_KEY",
      "DECIONIS_ORG_ID",
    ]);
    expect(manifest.user_config.decionis_api_key.sensitive).toBe(true);
    expect(manifest.compatibility.runtimes.node).toBe(`${packageManifest.engines.node}.0.0`);

    // Anthropic rejects desktop extensions without a privacy policy in both places.
    expect(manifest.privacy_policies.length).toBeGreaterThan(0);
    for (const url of manifest.privacy_policies) expect(url).toMatch(/^https:\/\//);
    expect(readme).toMatch(/^## Privacy Policy$/m);
    for (const topic of [
      "collect",
      "stor",
      "Third parties",
      "retention",
      "commerce@decionis.com",
    ]) {
      expect(readme.slice(readme.indexOf("## Privacy Policy"))).toMatch(new RegExp(topic, "i"));
    }
  });

  it("derives every public package entry point from the npm package manifest", async () => {
    const [packageManifest, readme, serverManifest, smitheryManifest] = await Promise.all([
      readFile(new URL("../package.json", import.meta.url), "utf8"),
      readFile(new URL("../README.md", import.meta.url), "utf8"),
      readFile(new URL("../server.json", import.meta.url), "utf8"),
      readFile(new URL("../smithery.yaml", import.meta.url), "utf8"),
    ]);
    const packageDocument = JSON.parse(packageManifest) as {
      name: string;
      version: string;
      mcpName: string;
    };
    const server = JSON.parse(serverManifest);
    const stablePackage = `${packageDocument.name}@${packageDocument.version}`;
    const npmUrl = `https://www.npmjs.com/package/${packageDocument.name}`;

    expect(server.name).toBe(packageDocument.mcpName);
    expect(server.version).toBe(packageDocument.version);
    expect(server.packages).toEqual([
      expect.objectContaining({
        registryType: "npm",
        identifier: packageDocument.name,
        version: packageDocument.version,
        runtimeHint: "npx",
        transport: { type: "stdio" },
      }),
    ]);
    expect(readme).toContain(`npx -y ${stablePackage}`);
    expect(readme).toContain('command = "npx"');
    expect(readme).toContain(`args = ["-y", "${stablePackage}"]`);
    expect(readme).toContain(npmUrl);
    expect(smitheryManifest).toContain('command: "npx"');
    expect(smitheryManifest).toContain(`args: ["-y", "${stablePackage}"]`);

    const repository = server.repository as { url: string; source: string; subfolder?: string };
    expect(repository).toEqual({
      url: "https://github.com/decionis/agent-safe-pipeline",
      source: "github",
      subfolder: "packages/commerce-mcp",
    });
  });

  it("pins every client route and operationId to the published OpenAPI contract", async () => {
    const document = await readPublishedOpenApi();

    const publishedOperations = Object.entries(document.paths).flatMap(([path, pathItem]) =>
      Object.entries(pathItem)
        .filter(([, operation]) => operation["x-commercegate-mcp"] === true)
        .map(([method, operation]) => ({
          operationId: operation.operationId,
          method: method.toUpperCase(),
          path,
        })),
    );
    const publishedTools = Object.values(document.paths)
      .flatMap((pathItem) => Object.values(pathItem))
      .filter((operation) => operation["x-commercegate-mcp"] === true)
      .flatMap((operation) => operation["x-commercegate-tools"] ?? [])
      .sort();

    expect(publishedOperations).toEqual(COMMERCEGATE_API_OPERATIONS);
    expect(publishedTools).toEqual(
      expectedNames.filter((name) => name !== "commercegate_describe_capabilities"),
    );
  });

  it("publishes the response fields and bounds required by the CommerceGate client", async () => {
    const { schemas } = (await readPublishedOpenApi()).components;
    const evaluation = schemas.CommerceEvaluationResponse;
    const dossier = schemas.DecisionDossier;
    const dossierRecord = schemas.DecisionDossierRecord;
    const proofPacket = schemas.DecisionProofPacket;
    const proofVerification = schemas.DecisionProofVerification;
    const shadowReport = schemas.ShadowReportDocument;
    const shadowSummary = schemas.ShadowReportSummary;
    const shadowEvaluation = schemas.ShadowReportEvaluation;
    const guardRequest = schemas.GuardRequest;
    const guardResponse = schemas.GuardResponse;

    expect(schemaRequired(evaluation)).toEqual(
      [
        "confidence",
        "dossier_id",
        "evaluation_id",
        "fallback_to_legacy",
        "governance_metrics",
        "idempotent_replay",
        "mode",
        "objective_profile",
        "outcome",
        "policy_version",
      ].sort(),
    );
    expect(evaluation.properties?.mode?.const).toBe("SHADOW");
    expect(evaluation.properties?.outcome?.enum).toEqual([
      "APPROVE",
      "REJECT",
      "REVIEW",
      "ESCALATE",
    ]);
    expect(evaluation.properties?.dossier_id?.format).toBe("uuid");
    expect(evaluation.properties?.evaluation_id?.format).toBe("uuid");
    expect(evaluation.properties?.confidence).toMatchObject({ minimum: 0, maximum: 1 });

    expect(schemaRequired(guardRequest)).toEqual(
      [
        "agent_id",
        "currency",
        "erp_type",
        "lines",
        "tenant_id",
        "timestamp",
        "transaction_id",
      ].sort(),
    );
    expect(schemaRequired(guardResponse)).toEqual(
      ["decision", "execution_time_ms", "message", "reason_code", "transaction_id"].sort(),
    );
    expect(guardResponse.properties?.decision?.enum).toEqual(["ALLOW", "BLOCK"]);

    expect(schemaRequired(dossier)).toEqual(["dossier", "protocol_version", "service"]);
    expect(schemaRequired(dossierRecord)).toEqual(
      [
        "created_at",
        "decision_evaluation_id",
        "dossier_id",
        "dossier_payload",
        "evidence_hashes",
        "org_id",
        "updated_at",
      ].sort(),
    );
    expect(dossierRecord.properties?.dossier_id?.format).toBe("uuid");
    expect(dossierRecord.properties?.decision_evaluation_id?.format).toBe("uuid");

    expect(schemaRequired(proofPacket)).toEqual(
      [
        "dossier",
        "issued_at",
        "ledger_anchor",
        "packet_type",
        "packet_version",
        "policy_snapshot",
        "proof_artifact_results",
        "proof_bundle",
        "protocol_version",
        "service",
        "subject",
        "verification",
        "verify_instructions",
      ].sort(),
    );
    expect(proofPacket.properties?.packet_type?.const).toBe(
      "decionis.decision_dossier.proof_packet",
    );
    expect(proofVerification.properties?.overall?.enum).toEqual([
      "VERIFIED",
      "PARTIAL",
      "UNVERIFIED",
    ]);
    expect(proofVerification.properties?.checks).toMatchObject({ minItems: 4, maxItems: 4 });

    expect(schemaRequired(shadowReport)).toEqual(
      [
        "candidate_enforcement_paths",
        "cards",
        "generated_at",
        "near_misses",
        "org_id",
        "reason_breakdown",
        "recent_evaluations",
        "service",
        "since",
        "summary",
        "window_days",
      ].sort(),
    );
    expect(shadowReport.properties?.window_days).toMatchObject({ minimum: 1, maximum: 365 });
    expect(shadowReport.properties?.reason_breakdown?.maxItems).toBe(8);
    expect(shadowReport.properties?.candidate_enforcement_paths?.maxItems).toBe(100);
    expect(shadowReport.properties?.near_misses?.maxItems).toBe(100);
    expect(shadowReport.properties?.recent_evaluations?.maxItems).toBe(100);
    expect(shadowSummary.properties?.non_allow_rate).toMatchObject({ minimum: 0, maximum: 1 });
    expect(shadowSummary.properties?.near_miss_rate).toMatchObject({ minimum: 0, maximum: 1 });
    expect(shadowEvaluation.properties?.confidence).toMatchObject({ minimum: 0, maximum: 1 });
    expect(shadowEvaluation.properties?.reason_codes?.maxItems).toBe(20);
  });

  it("publishes every canonical commerce action accepted by the MCP request contract", async () => {
    const request = (await readPublishedOpenApi()).components.schemas.CommerceEvaluationRequest;
    const actionTypes = [...SUPPORTED_ACTION_TYPES];
    const transactionTypes = actionTypes.map((actionType) => actionType.toLowerCase());
    const workflowKeys = transactionTypes.map((transactionType) => `commerce_${transactionType}`);

    expect(schemaRequired(request)).toEqual(
      [
        "channel",
        "context",
        "decision_type",
        "idempotency_key",
        "mode",
        "org_id",
        "source",
        "transaction_type",
        "workflow_key",
      ].sort(),
    );
    expect(request.properties?.decision_type?.enum).toEqual(actionTypes);
    expect(request.properties?.transaction_type?.enum).toEqual(transactionTypes);
    expect(request.properties?.workflow_key?.enum).toEqual(workflowKeys);
    expect(request.properties?.mode?.const).toBe("SHADOW");
    expect(request.properties?.idempotency_key?.maxLength).toBe(180);
    expect(request.properties?.context?.description).toContain(
      "does not assert that a connected platform can execute the action",
    );
  });

  it("keeps both Shadow Report tool projections inside the published response contract", async () => {
    const shadowReport = {
      service: "decionis",
      generated_at: "2026-09-09T00:00:00.000Z",
      org_id: "11111111-1111-4111-8111-111111111111",
      window_days: 30,
      since: "2026-08-10T00:00:00.000Z",
      summary: {
        shadow_evaluations: 1,
        would_allow: 0,
        would_block: 1,
        would_escalate: 0,
        review_required: 0,
        non_allow_count: 1,
        non_allow_rate: 1,
        policy_drift_count: 0,
        policy_drift_rate: 0,
        near_miss_count: 1,
        near_miss_rate: 1,
        candidate_enforcement_path_count: 0,
      },
      cards: [
        { key: "would_block", label: "Would block", value: 1, rate: 1, severity: "high" },
        { key: "would_escalate", label: "Would escalate", value: 0, rate: 0, severity: "low" },
        { key: "policy_drift", label: "Policy drift", value: 0, rate: 0, severity: "low" },
        { key: "near_misses", label: "Near misses", value: 1, rate: 1, severity: "medium" },
        {
          key: "candidate_enforcement_paths",
          label: "Candidate enforcement paths",
          value: 0,
          rate: null,
          severity: "medium",
        },
      ],
      reason_breakdown: [{ reason_code: "MARGIN_FLOOR", count: 1 }],
      candidate_enforcement_paths: [
        {
          path_key: "commerce_order_acceptance",
          workflow_key: "commerce_order_acceptance",
          decision_type: "ORDER_ACCEPTANCE",
          total: 1,
          would_allow: 0,
          would_block: 1,
          would_escalate: 0,
          review_required: 0,
          near_miss_count: 1,
          non_allow_rate: 1,
          near_miss_rate: 1,
          last_seen_at: "2026-09-09T00:00:00.000Z",
          recommendation: "COLLECT_MORE_TRAFFIC",
        },
      ],
      near_misses: [],
      recent_evaluations: [
        {
          evaluation_id: "22222222-2222-4222-8222-222222222222",
          dossier_id: "33333333-3333-4333-8333-333333333333",
          decision_type: "ORDER_ACCEPTANCE",
          workflow_key: "commerce_order_acceptance",
          outcome: "REJECT",
          execution_action: "STOP",
          confidence: 0.9,
          risk_score: null,
          policy_version: "commerce-v1",
          reason_codes: ["MARGIN_FLOOR"],
          created_at: "2026-09-09T00:00:00.000Z",
          dossier_api_path:
            "/v1/protocol/dossiers/33333333-3333-4333-8333-333333333333?org_id=11111111-1111-4111-8111-111111111111",
        },
      ],
    };
    const api: CommerceGateApi = {
      validateErpTransaction: async () => ({
        decision: "ALLOW",
        transaction_id: "sales-order:1001",
        execution_time_ms: 1,
        reason_code: "AGENT_BUDGET_PASSED",
        message: "Allowed.",
      }),
      evaluateAction: async (_input: EvaluateActionInput) => ({}),
      getDossier: async (_dossierId: string) => ({}),
      getProofPacket: async (_dossierId: string) => ({}),
      listShadowReports: async (_query: ShadowReportQuery) => shadowReport,
      summarizeShadowReports: async (_query: ShadowReportQuery) => shadowReport,
    };
    const tools = new CommerceGateTools(new CommerceGateConfiguration({}), api).build();
    const listResult = await tools
      .find(({ name }) => name === "commercegate_list_shadow_reports")!
      .handler({});
    const summaryResult = await tools
      .find(({ name }) => name === "commercegate_summarize_shadow_reports")!
      .handler({});
    const listProjection = listResult.structuredContent.reports as Record<string, unknown>;
    const summaryProjection = summaryResult.structuredContent.summary as Record<string, unknown>;
    const { schemas } = (await readPublishedOpenApi()).components;
    const reportProperties = Object.keys(schemas.ShadowReportDocument.properties ?? {});
    const reportRequired = schemaRequired(schemas.ShadowReportDocument);

    expect(listResult.isError).toBeUndefined();
    expect(summaryResult.isError).toBeUndefined();
    expect(objectKeys(listProjection)).toEqual(
      [
        "candidate_enforcement_paths",
        "generated_at",
        "near_misses",
        "recent_evaluations",
        "service",
        "since",
        "window_days",
      ].sort(),
    );
    expect(objectKeys(summaryProjection)).toEqual(
      [
        "cards",
        "generated_at",
        "reason_breakdown",
        "service",
        "since",
        "summary",
        "window_days",
      ].sort(),
    );
    expect(objectKeys(listProjection).every((key) => reportProperties.includes(key))).toBe(true);
    expect(objectKeys(summaryProjection).every((key) => reportProperties.includes(key))).toBe(true);
    expect(objectKeys(listProjection).every((key) => reportRequired.includes(key))).toBe(true);
    expect(objectKeys(summaryProjection).every((key) => reportRequired.includes(key))).toBe(true);
    expect(schemas.ShadowReportDocument.properties?.recent_evaluations?.type).toBe("array");
    expect(schemas.ShadowReportDocument.properties?.summary?.$ref).toBe(
      "#/components/schemas/ShadowReportSummary",
    );

    const recentEvaluation = (listProjection.recent_evaluations as unknown[])[0];
    const candidatePath = (listProjection.candidate_enforcement_paths as unknown[])[0];
    const summary = summaryProjection.summary;
    const card = (summaryProjection.cards as unknown[])[0];
    const reason = (summaryProjection.reason_breakdown as unknown[])[0];

    expect(objectKeys(recentEvaluation)).toEqual(schemaRequired(schemas.ShadowReportEvaluation));
    expect(objectKeys(candidatePath)).toEqual(schemaRequired(schemas.ShadowReportPath));
    expect(objectKeys(summary)).toEqual(schemaRequired(schemas.ShadowReportSummary));
    expect(objectKeys(card)).toEqual(schemaRequired(schemas.ShadowReportCard));
    expect(objectKeys(reason)).toEqual(schemaRequired(schemas.ShadowReportReason));
  });
});
