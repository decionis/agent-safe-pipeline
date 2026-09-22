import { describe, expect, it } from "vitest";
import {
  IDENTITY_REPORT_VERSION,
  renderIdentityReport,
  runIdentity,
} from "../../src/cli/Identity.js";
import {
  BOUNDARY_ENVIRONMENT,
  DERIVED_BOUNDARY_PREFIX,
} from "../../src/boundary/BoundaryIdentity.js";
import { SURFACE_ENVIRONMENT } from "../../src/gateway/InstallSurface.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const UPSTREAM = ["--upstream", "https://payments.internal.example"];

describe("agentsafe identity", () => {
  it("reports the boundary an operator named, for the configuration it is running", () => {
    const io = fakeProcess({
      env: {
        [SURFACE_ENVIRONMENT]: "docker",
        [BOUNDARY_ENVIRONMENT.boundaryId]: "prod-payments-eu",
        AGENTSAFE_ENVIRONMENT: "production",
      },
    });
    const report = runIdentity(io, [...UPSTREAM, "--json"]);

    expect(io.exits).toEqual([0]);
    expect(report).toMatchObject({
      version: IDENTITY_REPORT_VERSION,
      boundary_id: "prod-payments-eu",
      boundary_source: "configured",
      deployment_type: "docker",
      environment: "production",
      protocol_version: "agent-safe.intent/1",
      conformance_version: "agent-safe-intent-v1",
      configured: true,
    });
    expect(JSON.parse(io.out.join(""))).toEqual(report);
  });

  it("describes the boundary it would resolve to before there is a configuration", () => {
    const io = fakeProcess({ env: { [SURFACE_ENVIRONMENT]: "docker" } });
    const report = runIdentity(io, []);

    expect(io.exits).toEqual([0]);
    expect(report?.configured).toBe(false);
    expect(report?.boundary_id).toMatch(new RegExp(`^${DERIVED_BOUNDARY_PREFIX}[0-9a-f]{16}$`));
    expect(io.out.join("")).toContain("No usable gateway configuration");
  });

  it("refuses an option it does not know", () => {
    const io = fakeProcess();
    expect(runIdentity(io, ["--nope"])).toBeNull();
    expect(io.exits).toEqual([2]);
    expect(io.out).toEqual([]);
  });

  it("prints placement in the report and the instance only beneath it", () => {
    const io = fakeProcess({
      env: {
        [SURFACE_ENVIRONMENT]: "kubernetes",
        [BOUNDARY_ENVIRONMENT.clusterId]: "eu-1",
        [BOUNDARY_ENVIRONMENT.namespace]: "payments",
        [BOUNDARY_ENVIRONMENT.region]: "eu-west-1",
        [BOUNDARY_ENVIRONMENT.workloadId]: "payments-agent",
        [BOUNDARY_ENVIRONMENT.podId]: "agentsafe-7c9f-xk2",
      },
    });
    const report = runIdentity(io, UPSTREAM);
    const text = io.out.join("");

    expect(report?.placement).toMatchObject({ clusterId: "eu-1", namespace: "payments" });
    expect(text).toContain("cluster              eu-1");
    expect(text).toContain("never bound into evidence");
    expect(text).toContain("agentsafe-7c9f-xk2");
    expect(text).toContain("Every intent this boundary captures names it");
  });

  it("renders without placement, instance or colour when there is none", () => {
    const plain = renderIdentityReport(
      {
        version: IDENTITY_REPORT_VERSION,
        boundary_id: "bd_0000000000000000",
        boundary_source: "derived",
        agentsafe_version: "0.0.0",
        protocol_version: "agent-safe.intent/1",
        conformance_version: "agent-safe-intent-v1",
        deployment_type: "unknown",
        environment: null,
        placement: null,
        instance: null,
        configured: false,
      },
      { color: false },
    );
    expect(plain).toContain("environment          none");
    expect(plain).not.toContain("cluster");
    expect(plain).not.toContain(String.fromCharCode(27));

    const painted = renderIdentityReport(
      {
        version: IDENTITY_REPORT_VERSION,
        boundary_id: "prod-payments-eu",
        boundary_source: "configured",
        agentsafe_version: "0.0.0",
        protocol_version: "agent-safe.intent/1",
        conformance_version: "agent-safe-intent-v1",
        deployment_type: "docker",
        environment: "production",
        placement: { clusterId: null, namespace: "payments", region: null, workloadId: null },
        instance: { containerId: "3f2a91c4bb01", podId: null, nodeId: null },
        configured: true,
      },
      { color: true },
    );
    expect(painted).toContain(String.fromCharCode(27));
    expect(painted).toContain("namespace            payments");
    expect(painted).toContain("container            3f2a91c4bb01");
    expect(painted).not.toContain("cluster ");
  });
});
