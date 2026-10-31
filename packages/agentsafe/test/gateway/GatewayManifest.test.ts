import { describe, expect, it } from "vitest";
import { ActionManifest, ApiProfiles } from "@decionis/agent-safe-pipeline";
import { HttpParametersSchema } from "../../src/gateway/ForwardHandler.js";
import { GATEWAY_FAMILY, gatewayManifest } from "../../src/gateway/GatewayManifest.js";
import { RouteTable } from "../../src/gateway/RouteTable.js";

const walmart = ApiProfiles.get("walmart/api/v3")!;
const parameters = ActionManifest.parametersJsonSchema(HttpParametersSchema);

describe("the action space a gateway loads", () => {
  it("is the profile's own manifest when the profile alone names what is governed", () => {
    const table = new RouteTable([], "GOVERN", true, walmart, "FACTS");
    const profileOnly = ActionManifest.document(
      ActionManifest.fromApiProfile(walmart, HttpParametersSchema),
    );
    // What `agentsafe actions manifest --api walmart/api/v3` writes, byte for byte.
    expect(gatewayManifest(table)).toEqual(profileOnly);
    expect(ActionManifest.digest(gatewayManifest(table))).toBe(ActionManifest.digest(profileOnly));
  });

  it("describes each other governed action once, with every method and path that produces it", () => {
    const table = new RouteTable(
      [
        { path: "/refunds", action: "refund.create", methods: ["POST", "PUT"] },
        { path: "/refunds/*/retry", action: "refund.create", methods: ["POST"] },
        // A route that names one of the profile's actions adds nothing of its own.
        { path: "/acknowledge", action: "order.acknowledge", methods: ["POST"] },
      ],
      "PASSTHROUGH",
      true,
      walmart,
    );
    const document = gatewayManifest(table);
    expect(document.actions.map((entry) => entry.action)).toEqual(
      [...walmart.actions(), "refund.create"].sort(),
    );
    expect(document.actions.find((entry) => entry.action === "refund.create")).toEqual({
      action: "refund.create",
      source: { kind: "registry", family: GATEWAY_FAMILY },
      parameters,
      targets: ["POST /refunds", "POST /refunds/*/retry", "PUT /refunds"],
      effect_type: null,
    });
    expect(
      document.actions.find((entry) => entry.action === "order.acknowledge")?.source,
    ).toMatchObject({ kind: "api", profile: "walmart/api/v3" });
  });

  it("includes the derived actions only when the rest is governed", () => {
    const governed = gatewayManifest(new RouteTable([], "GOVERN"));
    expect(governed.actions.map((entry) => [entry.action, entry.targets])).toEqual([
      ["http.delete", ["DELETE /**"]],
      ["http.patch", ["PATCH /**"]],
      ["http.post", ["POST /**"]],
      ["http.put", ["PUT /**"]],
    ]);
    expect(() => gatewayManifest(new RouteTable([], "PASSTHROUGH"))).toThrow(
      "ACTION_MANIFEST_INVALID",
    );
  });
});
