import { describe, expect, it } from "vitest";
import { ApiProfiles } from "@decionis/agent-safe-pipeline";
import { PROFILE_COMMANDS, profileOpenApi, runProfile } from "../../src/cli/Profile.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const lastJson = (lines: readonly string[]): Record<string, unknown> =>
  JSON.parse(lines.join("")) as Record<string, unknown>;

type Operation = {
  operationId: string;
  parameters: Array<{ name: string; in: string; required: boolean; schema: { enum?: string[] } }>;
  requestBody?: { required: boolean };
  "x-agentsafe-actions": Array<{ operation: string; action: string; query?: object }>;
};

describe("agentsafe profile", () => {
  it("lists the profiles this build governs by", () => {
    const io = fakeProcess();
    runProfile(io, ["list"]);
    expect(lastJson(io.out)).toEqual({
      profiles: [
        {
          id: "businesscentral/api/v2",
          platform: "business-central",
          title: ApiProfiles.get("businesscentral/api/v2")!.definition.title,
          operations: 22,
          reads: 12,
          subject_scoped: 13,
        },
        {
          id: "walmart/api/v3",
          platform: "walmart-marketplace",
          title: ApiProfiles.get("walmart/api/v3")!.definition.title,
          operations: 8,
          reads: 0,
          subject_scoped: 0,
        },
      ],
    });
  });

  it("writes a profile as an OpenAPI target whose one server is the gateway", () => {
    const io = fakeProcess();
    runProfile(io, ["openapi", "walmart/api/v3", "--server", "https://agentsafe.example/"]);
    const document = lastJson(io.out) as {
      openapi: string;
      servers: Array<{ url: string }>;
      paths: Record<string, Record<string, Operation>>;
    };
    expect(document.openapi).toBe("3.0.3");
    expect(document.servers).toEqual([{ url: "https://agentsafe.example" }]);
    const acknowledge = document.paths["/v3/orders/{purchaseOrderId}/acknowledge"]!["post"]!;
    expect(acknowledge.operationId).toBe("orders_acknowledge");
    expect(acknowledge.parameters).toEqual([
      { name: "purchaseOrderId", in: "path", required: true, schema: { type: "string" } },
    ]);
    // One OpenAPI operation for the overloaded path; the gateway still tells them apart.
    const price = document.paths["/v3/price"]!["put"]!;
    expect(price.operationId).toBe("prices_update");
    expect(price.parameters).toEqual([
      { name: "promo", in: "query", required: false, schema: { type: "string", enum: ["true"] } },
    ]);
    expect(price.requestBody?.required).toBe(true);
    expect(price["x-agentsafe-actions"]).toEqual([
      { operation: "prices.promotion", action: "promotion.change", query: { promo: "true" } },
      { operation: "prices.update", action: "price.change" },
    ]);
  });

  it("uses a profile's first prefix unless another is named, and asks for no body it does not read", () => {
    const profile = ApiProfiles.get("businesscentral/api/v2")!;
    const prefixed = profileOpenApi(
      profile,
      "https://agentsafe.example",
      profile.definition.prefixes[0]!,
    ) as {
      paths: Record<string, Record<string, Operation>>;
    };
    const post =
      prefixed.paths[
        "/v2.0/{tenantId}/{environment}/api/v2.0/companies({companyId})/salesInvoices({salesInvoiceId})/Microsoft.NAV.post"
      ]!["post"]!;
    expect(post.parameters.map((parameter) => parameter.name)).toEqual([
      "tenantId",
      "environment",
      "companyId",
      "salesInvoiceId",
    ]);
    expect(post.requestBody?.required).toBe(false);
    const io = fakeProcess();
    runProfile(io, [
      "openapi",
      "businesscentral/api/v2",
      "--server",
      "http://127.0.0.1:8080",
      "--prefix",
      "",
    ]);
    const bare = lastJson(io.out) as {
      paths: Record<string, Record<string, Operation & { description: string }>>;
    };
    expect(Object.keys(bare.paths)).toContain(
      "/companies({companyId})/salesInvoices({salesInvoiceId})/Microsoft.NAV.post",
    );
    // A read is checked, never governed, and takes no body.
    const read = bare.paths["/companies({companyId})/customers"]!["get"]!;
    expect(read.operationId).toBe("customers_list");
    expect(read.requestBody).toBeUndefined();
    expect(read.description).toContain("Checked as customer.read");
    expect(read.description).toContain("refused whole");
    // A read and a write on one path are two OpenAPI operations.
    expect(Object.keys(bare.paths["/companies({companyId})/salesOrders"]!).sort()).toEqual([
      "get",
      "post",
    ]);
  });

  it.each([
    [["openapi"], "PROFILE_UNKNOWN"],
    [["openapi", "walmart/api/v9", "--server", "https://agentsafe.example"], "PROFILE_UNKNOWN"],
    [["openapi", "walmart/api/v3"], "PROFILE_SERVER_REQUIRED"],
    [
      ["openapi", "walmart/api/v3", "--server", "http://agentsafe.example"],
      "PROFILE_SERVER_REQUIRED",
    ],
    [
      ["openapi", "walmart/api/v3", "--server", "https://agentsafe.example", "--prefix", "/x"],
      "PROFILE_PREFIX_UNKNOWN",
    ],
    [["openapi", "walmart/api/v3", "--server"], "PROFILE_ARGUMENTS_INVALID"],
    [[], "PROFILE_COMMAND_REQUIRED"],
  ])("refuses %j as %s", (argv, event) => {
    const io = fakeProcess();
    runProfile(io, argv);
    expect(JSON.parse(io.err.at(-1) ?? "null")).toMatchObject({ event });
    expect(io.exits).toEqual([2]);
    expect(io.out).toEqual([]);
  });

  it("names its commands", () => {
    expect(PROFILE_COMMANDS).toEqual(["list", "openapi"]);
  });
});
