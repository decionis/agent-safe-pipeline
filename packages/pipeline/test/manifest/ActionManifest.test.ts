import { createHash } from "node:crypto";
import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import {
  ACTION_MANIFEST_CONTRACT,
  ActionManifest,
  ActionManifestError,
  ActionManifestSchema,
  type ActionManifestEntry,
} from "../../src/manifest/ActionManifest.js";
import { ApiProfile } from "../../src/profile/ApiProfile.js";
import { ApiProfiles } from "../../src/profile/ApiProfiles.js";
import { McpToolProfile } from "../../src/profile/McpToolProfile.js";

/** A synthetic MCP profile in the shape the specification's vectors use. */
const mcp = McpToolProfile.parse({
  profile: "agent-safe.profile.mcp/1",
  id: "erp/mcp/v1",
  title: "Synthetic ERP MCP server",
  system: "erp.example",
  tools: [
    {
      tool: "update_credit_limit",
      action: "customer.credit_limit.update",
      operation: "customers.updateCreditLimit",
      summary: "Set a customer's credit limit.",
      target: "erp:customer:{customerNumber}",
      subject: "customerNumber",
      consequential: ["customerNumber", "creditLimit"],
      arguments: {
        customerNumber: { type: "string", required: true, maxLength: 50 },
        creditLimit: { type: "number", required: true },
      },
    },
    {
      tool: "refresh_exchange_rates",
      action: "currency.rates.refresh",
      operation: "currencies.refreshRates",
      summary: "Refresh exchange rates from the bank feed.",
      target: "erp:currencies",
      consequential: [],
      arguments: { currencies: { type: "array" } },
    },
  ],
});

function entry(action: string, overrides: Partial<ActionManifestEntry> = {}): ActionManifestEntry {
  return {
    action,
    source: { kind: "registry", family: "synthetic" },
    parameters: { type: "object" },
    targets: [],
    effect_type: null,
    ...overrides,
  };
}

function refusal(work: () => unknown): string {
  try {
    work();
  } catch (error) {
    return error instanceof ActionManifestError ? `${error.code} ${error.detail}` : String(error);
  }
  return "no refusal";
}

describe("agent-safe.actions/1", () => {
  it("states a parameters schema as its input JSON Schema, open where zod cannot say", () => {
    const schema = z
      .strictObject({ amount: z.number().positive(), when: z.date().optional() })
      .refine(() => true);
    expect(ActionManifest.parametersJsonSchema(schema)).toEqual({
      type: "object",
      properties: { amount: { type: "number", exclusiveMinimum: 0 }, when: {} },
      required: ["amount"],
      additionalProperties: false,
    });
    expect(ActionManifest.parametersJsonSchema(z.custom<string>(() => true))).toEqual({});
  });

  it("describes a sealed registry's actions under their family, annotated by it", () => {
    const registry = new ActionRegistry()
      .register("payment.send", {
        parametersSchema: z.strictObject({ amount: z.number() }),
        execute: vi.fn(),
      })
      .register("payment.cancel", { parametersSchema: z.strictObject({}), execute: vi.fn() })
      .seal();
    const annotate = vi.fn((action: string) => ({
      targets: [`payment:{${action === "payment.send" ? "payee" : "payment"}}`],
      effectType: action === "payment.send" ? "PAYMENT_SENT" : null,
    }));
    expect(ActionManifest.fromRegistry(registry, "payments", annotate)).toEqual([
      {
        action: "payment.send",
        source: { kind: "registry", family: "payments" },
        parameters: {
          type: "object",
          properties: { amount: { type: "number" } },
          required: ["amount"],
          additionalProperties: false,
        },
        targets: ["payment:{payee}"],
        effect_type: "PAYMENT_SENT",
      },
      {
        action: "payment.cancel",
        source: { kind: "registry", family: "payments" },
        parameters: { type: "object", properties: {}, additionalProperties: false },
        targets: ["payment:{payment}"],
        effect_type: null,
      },
    ]);
    expect(() => ActionManifest.fromRegistry(new ActionRegistry(), "payments", annotate)).toThrow(
      "ACTION_REGISTRY_NOT_SEALED",
    );
  });

  it("lists an API profile's writes, each with every operation that becomes it, and no reads", () => {
    const parameters = z.strictObject({ method: z.string() });
    const entries = ActionManifest.fromApiProfile(
      ApiProfiles.get("businesscentral/api/v2")!,
      parameters,
    );
    const post = entries.find((found) => found.action === "sales.post");
    expect(post).toEqual({
      action: "sales.post",
      source: {
        kind: "api",
        profile: "businesscentral/api/v2",
        operations: [
          "salesInvoices.post",
          "salesInvoices.postAndSend",
          "salesOrders.shipAndInvoice",
        ],
      },
      parameters: ActionManifest.parametersJsonSchema(parameters),
      targets: [
        "POST /companies({companyId})/salesInvoices({salesInvoiceId})/Microsoft.NAV.post",
        "POST /companies({companyId})/salesInvoices({salesInvoiceId})/Microsoft.NAV.postAndSend",
        "POST /companies({companyId})/salesOrders({salesOrderId})/Microsoft.NAV.shipAndInvoice",
      ],
      effect_type: null,
    });
    expect(entries.map((found) => found.action)).not.toContain("customer.read");
    expect(entries.map((found) => found.action)).toEqual(
      ApiProfiles.get("businesscentral/api/v2")!.actions(),
    );
  });

  it("names a target once when two operations of one action share a method and path", () => {
    const profile = ApiProfiles.get("walmart/api/v3")!;
    const overloaded = {
      ...profile.definition,
      id: "walmart/api/v9",
      operations: [
        { ...profile.definition.operations[0]!, id: "a.first" },
        {
          ...profile.definition.operations[0]!,
          id: "a.second",
          query: { mode: "second" },
        },
      ],
    };
    const [only] = ActionManifest.fromApiProfile(ApiProfile.parse(overloaded), z.strictObject({}));
    expect(only!.source).toEqual({
      kind: "api",
      profile: "walmart/api/v9",
      operations: ["a.first", "a.second"],
    });
    expect(only!.targets).toHaveLength(1);
  });

  it("lists an MCP profile's tools, admitted against their declared arguments", () => {
    expect(ActionManifest.fromMcpProfile(mcp)).toEqual([
      {
        action: "customer.credit_limit.update",
        source: { kind: "mcp", profile: "erp/mcp/v1", tool: "update_credit_limit" },
        parameters: {
          type: "object",
          properties: {
            customerNumber: { type: "string", maxLength: 50 },
            creditLimit: { type: "number" },
          },
          required: ["customerNumber", "creditLimit"],
          additionalProperties: false,
        },
        targets: ["erp:customer:{customerNumber}"],
        effect_type: null,
      },
      expect.objectContaining({
        action: "currency.rates.refresh",
        source: { kind: "mcp", profile: "erp/mcp/v1", tool: "refresh_exchange_rates" },
        targets: ["erp:currencies"],
      }),
    ]);
  });

  it("orders the document by action in code-point order and holds it to the contract", () => {
    const document = ActionManifest.document([
      entry("zeta.run"),
      entry("alpha.run"),
      entry("beta.run"),
      ...ActionManifest.fromMcpProfile(mcp),
    ]);
    expect(document.manifest).toBe(ACTION_MANIFEST_CONTRACT);
    expect(document.actions.map((found) => found.action)).toEqual([
      "alpha.run",
      "beta.run",
      "currency.rates.refresh",
      "customer.credit_limit.update",
      "zeta.run",
    ]);
    expect(ActionManifestSchema.safeParse(document).success).toBe(true);
  });

  it("refuses an action two sources both produce, by name", () => {
    expect(refusal(() => ActionManifest.document([entry("a.run"), entry("a.run")]))).toBe(
      "ACTION_MANIFEST_DUPLICATE_ACTION a.run",
    );
  });

  it("refuses a document the contract does not allow, saying where", () => {
    expect(refusal(() => ActionManifest.document([]))).toMatch(
      /^ACTION_MANIFEST_INVALID actions: /,
    );
    expect(
      refusal(() => ActionManifest.document([entry("a.run", { effect_type: "sent" })])),
    ).toMatch(/^ACTION_MANIFEST_INVALID actions\.0\.effect_type: /);
    expect(refusal(() => ActionManifest.document([entry("A.run")]))).toMatch(
      /^ACTION_MANIFEST_INVALID actions\.0\.action: /,
    );
    expect(
      refusal(() =>
        ActionManifest.document([
          entry("a.run", { source: { kind: "registry", family: "two-words" } }),
        ]),
      ),
    ).toMatch(/^ACTION_MANIFEST_INVALID actions\.0\.source\.family: /);
    expect(
      refusal(() => ActionManifest.document([entry("a.run", { targets: Array(65).fill("t") })])),
    ).toMatch(/^ACTION_MANIFEST_INVALID actions\.0\.targets: /);
  });

  it("refuses a parsed document listed out of order, or listing an action twice", () => {
    const unsorted = {
      manifest: ACTION_MANIFEST_CONTRACT,
      actions: [entry("b.run"), entry("a.run")],
    };
    const twice = { manifest: ACTION_MANIFEST_CONTRACT, actions: [entry("a.run"), entry("a.run")] };
    for (const document of [unsorted, twice]) {
      const parsed = ActionManifestSchema.safeParse(document);
      expect(parsed.success).toBe(false);
      expect(parsed.error?.issues[0]?.path).toEqual(["actions", 1, "action"]);
    }
  });

  it("digests the RFC 8785 form, whatever order the keys were written in", () => {
    const document = ActionManifest.document([
      entry("a.run", { targets: ["a:{id}"], effect_type: "RAN" }),
    ]);
    const canonical =
      '{"actions":[{"action":"a.run","effect_type":"RAN","parameters":{"type":"object"},' +
      '"source":{"family":"synthetic","kind":"registry"},"targets":["a:{id}"]}],' +
      '"manifest":"agent-safe.actions/1"}';
    const expected = `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
    expect(ActionManifest.digest(document)).toBe(expected);
    const reordered = JSON.parse(
      '{"manifest":"agent-safe.actions/1","actions":[{"targets":["a:{id}"],"source":{"kind":"registry","family":"synthetic"},"parameters":{"type":"object"},"effect_type":"RAN","action":"a.run"}]}',
    ) as typeof document;
    expect(ActionManifest.digest(reordered)).toBe(expected);
  });
});
