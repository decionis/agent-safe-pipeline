import { readdir, readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  COMMERCEGATE_NPM_INSTALL_COMMAND,
  COMMERCEGATE_NPM_PACKAGE,
  COMMERCEGATE_NPM_SPECIFIER,
  COMMERCEGATE_NPM_URL,
  COMMERCEGATE_NPM_VERSION,
  buildLlmsFullText,
  buildLlmsText,
  commerceGateMcpCard,
} from "../../commerce-dashboard/app/discovery/MachineDiscovery.js";
import type {
  CommerceGateApi,
  EvaluateActionInput,
  ShadowReportQuery,
} from "../src/CommerceGateClient.js";
import { COMMERCEGATE_API_OPERATIONS } from "../src/CommerceGateClient.js";
import { CommerceGateConfiguration } from "../src/Configuration.js";
import { COMMERCEGATE_TOOL_NAMES, CommerceGateTools } from "../src/Tools.js";

interface JsonSchema {
  type?: string | string[];
  const?: unknown;
  enum?: unknown[];
  format?: string;
  minimum?: number;
  maximum?: number;
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

async function readPublishedOpenApi(): Promise<CommerceOpenApi> {
  return JSON.parse(
    await readFile(
      new URL(
        "../../commerce-dashboard/app/discovery/CommerceGateErpOpenApi.generated.json",
        import.meta.url,
      ),
      "utf8",
    ),
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
  it("set-compares registered tools with the public card, README, and root agent allowlist", async () => {
    const [dashboardDiscovery, readme, codexConfig] = await Promise.all([
      readFile(
        new URL("../../commerce-dashboard/app/discovery/MachineDiscovery.ts", import.meta.url),
        "utf8",
      ),
      readFile(new URL("../README.md", import.meta.url), "utf8"),
      readFile(new URL("../../../.codex/config.toml", import.meta.url), "utf8"),
    ]);

    expect(namesIn(dashboardDiscovery)).toEqual(expectedNames);
    expect(namesIn(readme)).toEqual(expectedNames);
    expect(namesIn(codexConfig)).toEqual(expectedNames);
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

    expect(COMMERCEGATE_NPM_PACKAGE).toBe(packageDocument.name);
    expect(COMMERCEGATE_NPM_VERSION).toBe(packageDocument.version);
    expect(COMMERCEGATE_NPM_SPECIFIER).toBe(stablePackage);
    expect(COMMERCEGATE_NPM_URL).toBe(npmUrl);
    expect(COMMERCEGATE_NPM_INSTALL_COMMAND).toBe(`npx -y ${stablePackage}`);

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

    const card = commerceGateMcpCard();
    expect(card).toMatchObject({
      name: packageDocument.mcpName,
      version: packageDocument.version,
      distribution: {
        npm: {
          identifier: packageDocument.name,
          version: packageDocument.version,
          url: npmUrl,
          install: `npx -y ${stablePackage}`,
        },
      },
      transports: [{ type: "stdio", command: "npx", args: ["-y", stablePackage] }],
    });

    const llmsText = buildLlmsText();
    const llmsFullText = buildLlmsFullText();
    for (const machineText of [llmsText, llmsFullText]) {
      expect(machineText).toContain(stablePackage);
      expect(machineText).toContain(npmUrl);
      expect(machineText).toContain(`npx -y ${stablePackage}`);
    }
    expect(llmsFullText).toContain(`MCP identity: ${packageDocument.mcpName}`);
  });

  it("keeps repository agent configuration on local pnpm dogfooding", async () => {
    const codexConfig = await readFile(
      new URL("../../../.codex/config.toml", import.meta.url),
      "utf8",
    );
    const localArgs = 'args = ["--silent", "--filter", "@decionis/commerce", "mcp"]';

    expect(codexConfig).toContain('command = "pnpm"');
    expect(codexConfig).toContain(localArgs);
  });

  it("keeps every specialist allowlist inside the registered catalog", async () => {
    const agentsDirectory = new URL("../../../.codex/agents/", import.meta.url);
    const files = (await readdir(agentsDirectory)).filter((file) => file.endsWith(".toml"));
    const byFile = new Map<string, string[]>();

    for (const file of files) {
      const contents = await readFile(new URL(file, agentsDirectory), "utf8");
      const names = namesIn(contents);
      expect(names.every((name) => expectedNameSet.has(name))).toBe(true);
      expect(contents).toContain('command = "pnpm"');
      expect(contents).toContain('args = ["--silent", "--filter", "@decionis/commerce", "mcp"]');
      byFile.set(file, names);
    }

    expect(byFile.get("CommerceOperator.toml")).toEqual(expectedNames);
    expect(byFile.get("CommerceIntegrationEngineer.toml")).toEqual(expectedNames);
    expect(Array.from(new Set([...byFile.values()].flat())).sort()).toEqual(expectedNames);
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
