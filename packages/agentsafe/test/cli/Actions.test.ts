import { describe, expect, it } from "vitest";
import {
  ActionManifest,
  ApiProfiles,
  JsonObjectSchema,
  type ActionManifestDocument,
} from "@decionis/agent-safe-pipeline";
import { registeredActionNames } from "../../src/adapters/banking/BankingAdapter.js";
import { ACTIONS_COMMANDS, runActions } from "../../src/cli/Actions.js";
import { usage } from "../../src/cli/Help.js";
import { HttpParametersSchema } from "../../src/gateway/ForwardHandler.js";
import { GatewayConfigLoader } from "../../src/gateway/GatewayConfig.js";
import { deploymentFingerprint } from "../../src/posture/DeploymentFingerprint.js";
import { packageVersion } from "../../src/Version.js";
import { fakeProcess } from "../support/GatewayHarness.js";

/** A synthetic MCP tool profile, as an operator would keep it beside the server it governs. */
function mcpProfile(id: string, tools: readonly { tool: string; action: string }[]): string {
  return JSON.stringify({
    profile: "agent-safe.profile.mcp/1",
    id,
    title: "Synthetic CRM MCP server",
    system: "crm.example",
    tools: tools.map(({ tool, action }) => ({
      tool,
      action,
      operation: `customers.${tool}`,
      summary: "A synthetic tool.",
      target: "crm:customer:{customerId}",
      subject: "customerId",
      consequential: ["customerId"],
      arguments: { customerId: { type: "string", required: true, maxLength: 64 } },
    })),
  });
}

const CRM = mcpProfile("crm/mcp/v1", [{ tool: "update_customer", action: "customer.update" }]);

function run(argv: readonly string[], files: Record<string, string> = {}) {
  const io = fakeProcess({ files });
  runActions(io, argv);
  return io;
}

function manifest(argv: readonly string[], files?: Record<string, string>): ActionManifestDocument {
  const io = run(["manifest", ...argv], files);
  expect(io.exits).toEqual([]);
  return JSON.parse(io.out.join("")) as ActionManifestDocument;
}

function refusal(argv: readonly string[], files?: Record<string, string>) {
  const io = run(argv, files);
  expect(io.exits).toEqual([2]);
  expect(io.out).toEqual([]);
  return JSON.parse(io.err.join("")) as Record<string, unknown>;
}

describe("agentsafe actions manifest", () => {
  it("is in the usage", () => {
    expect(usage("1")).toContain("actions manifest");
  });

  it("describes the forwarding family as its registry admits it: whatever the proposal targets", () => {
    expect(manifest(["--family", "forward"])).toEqual({
      manifest: "agent-safe.actions/1",
      actions: [
        {
          action: "forward_request",
          source: { kind: "registry", family: "forward" },
          parameters: ActionManifest.parametersJsonSchema(JsonObjectSchema),
          targets: [],
          effect_type: null,
        },
      ],
    });
  });

  it("describes every banking action this build registers, with the effect each produces", () => {
    const { actions } = manifest(["--family", "banking"]);
    expect(actions.map((entry) => entry.action)).toEqual([...registeredActionNames()].sort());
    expect(Object.fromEntries(actions.map((entry) => [entry.action, entry.effect_type]))).toEqual({
      "beap.account_origination.create_account": "ACCOUNT_CREATED",
      "beap.corporate_payments.send_payment": "PAYMENT_SENT",
      "beap.credit_limits.set_credit_limit": "CREDIT_LIMIT_SET",
      "beap.loan_disbursement.disburse_loan": "LOAN_DISBURSEMENT",
    });
    for (const entry of actions) {
      expect(entry.source).toEqual({ kind: "registry", family: "banking" });
      expect(entry.targets).toEqual(["{target.type}:{target.ref}"]);
      expect(entry.parameters["type"]).toBe("object");
    }
  });

  it("describes a card purchase by the card it spends from, a field of its parameters", () => {
    const [purchase] = manifest(["--family", "cards"]).actions;
    expect(purchase!.parameters["required"]).toContain("cardTokenRef");
    expect(purchase).toMatchObject({
      action: "card.purchase",
      source: { kind: "registry", family: "cards" },
      targets: ["card:{cardTokenRef}"],
      effect_type: "CARD_PURCHASE_AUTHORIZATION",
    });
  });

  it("describes a shipped API profile's writes with the parameters the gateway admits", () => {
    const profile = ApiProfiles.get("businesscentral/api/v2")!;
    const { actions } = manifest(["--api", "businesscentral/api/v2"]);
    expect(actions).toEqual(
      ActionManifest.document(ActionManifest.fromApiProfile(profile, HttpParametersSchema)).actions,
    );
    expect(actions.find((entry) => entry.action === "customer.update")).toEqual({
      action: "customer.update",
      source: {
        kind: "api",
        profile: "businesscentral/api/v2",
        operations: ["customers.update"],
      },
      parameters: ActionManifest.parametersJsonSchema(HttpParametersSchema),
      targets: ["PATCH /companies({companyId})/customers({customerId})"],
      effect_type: null,
    });
  });

  it("describes an MCP profile file's tools, read from the working directory", () => {
    expect(manifest(["--mcp", "crm.json"], { "/work/crm.json": CRM }).actions).toEqual([
      {
        action: "customer.update",
        source: { kind: "mcp", profile: "crm/mcp/v1", tool: "update_customer" },
        parameters: {
          type: "object",
          properties: { customerId: { type: "string", maxLength: 64 } },
          required: ["customerId"],
          additionalProperties: false,
        },
        targets: ["crm:customer:{customerId}"],
        effect_type: null,
      },
    ]);
  });

  it("puts every source named into one document, in action order", () => {
    const document = manifest(
      [
        "--family",
        "cards",
        "--api=walmart/api/v3",
        "--family",
        "forward",
        "--mcp",
        "/profiles/crm.json",
      ],
      { "/profiles/crm.json": CRM },
    );
    const names = document.actions.map((entry) => entry.action);
    expect(names).toEqual([...names].sort());
    expect(names).toEqual(expect.arrayContaining(["card.purchase", "forward_request"]));
    expect(names).toContain("customer.update");
    expect(names).toContain("price.change");
    expect(names).toHaveLength(2 + 1 + ApiProfiles.get("walmart/api/v3")!.actions().length);
  });

  it("prints the digest the signed release manifest records, instead of the document", () => {
    const document = manifest(["--family", "cards", "--family", "forward"]);
    const io = run(["manifest", "--family", "forward", "--family", "cards", "--digest"]);
    expect(io.exits).toEqual([]);
    expect(JSON.parse(io.out.join(""))).toEqual({
      manifest: "agent-safe.actions/1",
      digest: ActionManifest.digest(document),
      actions: 2,
    });
  });

  it("describes what a gateway with this configuration loads, as its fingerprint digests it", () => {
    const yaml = [
      "version: 1",
      "gateway:",
      "  upstream: http://127.0.0.1:3000",
      "interception:",
      "  profile: walmart/api/v3",
      "  routes:",
      "    - path: /refunds",
      "      action: refund.create",
      "      methods: [POST]",
    ].join("\n");
    const files = { "/work/agentsafe.yaml": yaml };
    const document = manifest(["--gateway", "--config", "agentsafe.yaml"], files);
    expect(document.actions.map((entry) => entry.action)).toEqual(
      [
        ...ApiProfiles.get("walmart/api/v3")!.actions(),
        "http.delete",
        "http.patch",
        "http.post",
        "http.put",
        "refund.create",
      ].sort(),
    );
    const io = run(["manifest", "--gateway", "--config", "agentsafe.yaml", "--digest"], files);
    const printed = JSON.parse(io.out.join("")) as { digest: string };
    // The digest a running gateway with this file reports in its fingerprint.
    const config = GatewayConfigLoader.load({
      env: {},
      file: {
        version: 1,
        gateway: { upstream: "http://127.0.0.1:3000" },
        interception: {
          profile: "walmart/api/v3",
          routes: [{ path: "/refunds", action: "refund.create", methods: ["POST"] }],
        },
      },
      credentials: null,
      version: packageVersion(),
    });
    expect(printed.digest).toBe(
      deploymentFingerprint(config, { version: packageVersion(), imageDigest: null }).document
        .action_manifest_digest,
    );
    // The flags `agentsafe proxy` takes resolve it the same way; a source beside it joins it.
    const combined = manifest(
      ["--gateway", "--upstream", "http://127.0.0.1:3000", "--mcp", "crm.json"],
      { "/work/crm.json": CRM },
    );
    expect(combined.actions.map((entry) => entry.action)).toEqual([
      "customer.update",
      "http.delete",
      "http.patch",
      "http.post",
      "http.put",
    ]);
  });

  it("refuses a gateway configuration it cannot resolve, naming the setting", () => {
    expect(refusal(["manifest", "--gateway"])).toEqual({
      event: "ACTIONS_GATEWAY_CONFIG_INVALID",
      detail: expect.stringContaining("CONFIG_MISSING: upstream"),
    });
    // A gateway that governs nothing (its file read from the working directory) has no action space.
    expect(
      refusal(["manifest", "--gateway", "--upstream", "http://127.0.0.1:3000"], {
        "/work/agentsafe.yaml": "version: 1\ninterception:\n  unmatched: passthrough\n",
      }),
    ).toMatchObject({ event: "ACTION_MANIFEST_INVALID" });
  });

  it("refuses without the manifest command, naming the commands", () => {
    for (const argv of [[], ["list"]]) {
      expect(refusal(argv)).toEqual({
        event: "ACTIONS_COMMAND_REQUIRED",
        commands: ACTIONS_COMMANDS,
      });
    }
  });

  it("refuses arguments it does not take, and a manifest of nothing", () => {
    expect(refusal(["manifest", "--profile", "x"])).toEqual({
      event: "ACTIONS_ARGUMENTS_INVALID",
      detail: "UNKNOWN_OPTION: profile",
    });
    expect(refusal(["manifest", "--family"])).toEqual({
      event: "ACTIONS_ARGUMENTS_INVALID",
      detail: "VALUE_REQUIRED: family",
    });
    expect(refusal(["manifest", "forward"])).toEqual({
      event: "ACTIONS_ARGUMENTS_INVALID",
      detail: "VALUE_INVALID: forward",
    });
    expect(refusal(["manifest", "--digest"])).toMatchObject({ event: "ACTIONS_SOURCE_REQUIRED" });
  });

  it("refuses a family, a profile or a file it cannot find, by name", () => {
    for (const family of ["payments", "toString", "__proto__"]) {
      expect(refusal(["manifest", "--family", family])).toEqual({
        event: "ACTIONS_FAMILY_UNKNOWN",
        family,
        families: ["forward", "banking", "cards"],
      });
    }
    expect(refusal(["manifest", "--api", "walmart/api/v9"])).toEqual({
      event: "PROFILE_UNKNOWN",
      profile: "walmart/api/v9",
      profiles: ApiProfiles.ids(),
    });
    expect(refusal(["manifest", "--mcp", "missing.json"])).toEqual({
      event: "MCP_PROFILE_UNREADABLE",
      file: "missing.json",
    });
  });

  it("refuses an MCP profile file that is not JSON, or not a profile", () => {
    expect(refusal(["manifest", "--mcp", "a.json"], { "/work/a.json": "{" })).toEqual({
      event: "MCP_PROFILE_INVALID",
      file: "a.json",
      detail: "not JSON",
    });
    expect(
      refusal(["manifest", "--mcp", "b.json"], { "/work/b.json": '{"profile":"x"}' }),
    ).toMatchObject({ event: "MCP_PROFILE_INVALID", file: "b.json", detail: expect.any(String) });
  });

  it("refuses an action two sources both produce, since one grant can run one handler", () => {
    expect(refusal(["manifest", "--family", "cards", "--family", "cards"])).toEqual({
      event: "ACTION_MANIFEST_DUPLICATE_ACTION",
      detail: "card.purchase",
    });
    const priced = mcpProfile("shop/mcp/v1", [{ tool: "set_price", action: "price.change" }]);
    expect(
      refusal(["manifest", "--api", "walmart/api/v3", "--mcp", "shop.json"], {
        "/work/shop.json": priced,
      }),
    ).toEqual({ event: "ACTION_MANIFEST_DUPLICATE_ACTION", detail: "price.change" });
  });

  it("refuses more actions than one manifest lists", () => {
    const files: Record<string, string> = {};
    const argv = ["manifest"];
    for (const part of [1, 2, 3]) {
      files[`/work/p${part}.json`] = mcpProfile(
        `part${part}/mcp/v1`,
        Array.from({ length: 200 }, (_, index) => ({
          tool: `tool_${index}`,
          action: `part${part}.tool${index}`,
        })),
      );
      argv.push("--mcp", `p${part}.json`);
    }
    expect(refusal(argv, files)).toMatchObject({
      event: "ACTION_MANIFEST_INVALID",
      detail: expect.stringMatching(/^actions: /),
    });
  });
});
