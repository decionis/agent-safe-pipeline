import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  BOUNDARY_CONFORMANCE,
  BOUNDARY_ENVIRONMENT,
  BOUNDARY_PROTOCOL,
  DERIVED_BOUNDARY_PREFIX,
  boundarySignal,
  resolveBoundary,
  type BoundaryFacts,
} from "../../src/boundary/BoundaryIdentity.js";
import { EnforcementBoundarySignalSchema } from "@decionis/agent-safe-pipeline";

const FACTS: BoundaryFacts = {
  env: {},
  version: "0.2.4",
  deploymentType: "docker",
  environment: "production",
  upstreamOrigin: "https://payments.internal.example",
};

describe("the enforcement boundary", () => {
  it("takes the id an operator named, from the environment or the file", () => {
    const fromEnv = resolveBoundary({
      ...FACTS,
      env: { [BOUNDARY_ENVIRONMENT.boundaryId]: "prod-payments-eu" },
    });
    expect(fromEnv).toMatchObject({
      boundaryId: "prod-payments-eu",
      boundarySource: "configured",
    });

    const fromFile = resolveBoundary({ ...FACTS, configuredId: "prod-payments-eu" });
    expect(fromFile).toMatchObject({
      boundaryId: "prod-payments-eu",
      boundarySource: "configured",
    });

    // The environment wins, the way every other setting resolves.
    const both = resolveBoundary({
      ...FACTS,
      env: { [BOUNDARY_ENVIRONMENT.boundaryId]: "from-env" },
      configuredId: "from-file",
    });
    expect(both.boundaryId).toBe("from-env");
  });

  it("derives a stable id when nobody named one", () => {
    const first = resolveBoundary(FACTS);
    const restarted = resolveBoundary(FACTS);

    expect(first.boundarySource).toBe("derived");
    expect(first.boundaryId).toMatch(new RegExp(`^${DERIVED_BOUNDARY_PREFIX}[0-9a-f]{16}$`));
    expect(restarted.boundaryId).toBe(first.boundaryId);
  });

  /**
   * The derivation is pinned, not merely exercised. An operator who never
   * named a boundary has one anyway, and every dossier their estate has
   * produced names it; a change to the material, its order, its separator or
   * its encoding would re-partition all of that evidence without a word. A
   * deliberate change breaks this vector first.
   */
  it("derives the same id this version has always derived", () => {
    const material = ["docker", "production", "https://payments.internal.example"].join("\n");
    const expected = `${DERIVED_BOUNDARY_PREFIX}${createHash("sha256")
      .update(material, "utf8")
      .digest("hex")
      .slice(0, 16)}`;

    expect(expected).toBe("bd_baff7f0d8ffced28");
    expect(resolveBoundary(FACTS).boundaryId).toBe(expected);
    // The parts a deployment did not set are empty, not absent: a boundary
    // with no environment is not the same boundary as one with no upstream.
    expect(resolveBoundary({ ...FACTS, environment: null }).boundaryId).toBe(
      `${DERIVED_BOUNDARY_PREFIX}${createHash("sha256")
        .update("docker\n\nhttps://payments.internal.example", "utf8")
        .digest("hex")
        .slice(0, 16)}`,
    );
    expect(
      resolveBoundary({ ...FACTS, deploymentType: null, environment: null, upstreamOrigin: null })
        .boundaryId,
    ).toBe(
      `${DERIVED_BOUNDARY_PREFIX}${createHash("sha256")
        .update("unknown\n\n", "utf8")
        .digest("hex")
        .slice(0, 16)}`,
    );
  });

  it("does not move when the instance does", () => {
    // Same configured boundary, rescheduled: a new container, a new pod, a
    // new node. A boundary id that changed here would be an instance id.
    const before = resolveBoundary({
      ...FACTS,
      env: {
        [BOUNDARY_ENVIRONMENT.containerId]: "3f2a91c4bb01",
        [BOUNDARY_ENVIRONMENT.podId]: "agentsafe-7c9f-xk2",
        [BOUNDARY_ENVIRONMENT.nodeId]: "ip-10-0-4-21",
      },
    });
    const after = resolveBoundary({
      ...FACTS,
      env: {
        [BOUNDARY_ENVIRONMENT.containerId]: "b71de0049aa7",
        [BOUNDARY_ENVIRONMENT.podId]: "agentsafe-7c9f-9qzt",
        [BOUNDARY_ENVIRONMENT.nodeId]: "ip-10-0-7-88",
      },
    });

    expect(after.boundaryId).toBe(before.boundaryId);
    expect(after.instance).not.toEqual(before.instance);
  });

  it("is a different boundary when it stands in front of something else", () => {
    const eu = resolveBoundary(FACTS);
    const us = resolveBoundary({ ...FACTS, upstreamOrigin: "https://payments.us.example" });
    const staging = resolveBoundary({ ...FACTS, environment: "staging" });
    const linux = resolveBoundary({ ...FACTS, deploymentType: "linux" });

    expect(new Set([eu, us, staging, linux].map((one) => one.boundaryId)).size).toBe(4);
  });

  it("trims a declared value and holds it to the token shape at the exact bound", () => {
    const padded = resolveBoundary({
      ...FACTS,
      env: { [BOUNDARY_ENVIRONMENT.clusterId]: "  eu-1  " },
    });
    expect(padded.placement?.clusterId).toBe("eu-1");

    const atBound = "c".repeat(200);
    expect(
      resolveBoundary({ ...FACTS, env: { [BOUNDARY_ENVIRONMENT.clusterId]: atBound } }).placement
        ?.clusterId,
    ).toBe(atBound);
    expect(
      resolveBoundary({ ...FACTS, env: { [BOUNDARY_ENVIRONMENT.clusterId]: `${atBound}c` } })
        .placement,
    ).toBeNull();
  });

  it("reads placement and instance only from declared variables, and only when they are well formed", () => {
    const boundary = resolveBoundary({
      ...FACTS,
      env: {
        [BOUNDARY_ENVIRONMENT.clusterId]: "eu-1",
        [BOUNDARY_ENVIRONMENT.namespace]: "payments",
        [BOUNDARY_ENVIRONMENT.region]: "eu-west-1",
        [BOUNDARY_ENVIRONMENT.workloadId]: "payments-agent",
        [BOUNDARY_ENVIRONMENT.containerId]: "3f2a91c4bb01",
        [BOUNDARY_ENVIRONMENT.podId]: "agentsafe-7c9f-xk2",
        [BOUNDARY_ENVIRONMENT.nodeId]: "ip-10-0-4-21",
      },
    });
    expect(boundary.placement).toEqual({
      clusterId: "eu-1",
      namespace: "payments",
      region: "eu-west-1",
      workloadId: "payments-agent",
    });
    expect(boundary.instance).toEqual({
      containerId: "3f2a91c4bb01",
      podId: "agentsafe-7c9f-xk2",
      nodeId: "ip-10-0-4-21",
    });

    // A value that is not a token is no value rather than a guess, the same
    // way an unrecognised surface is no surface.
    const malformed = resolveBoundary({
      ...FACTS,
      env: {
        [BOUNDARY_ENVIRONMENT.boundaryId]: "not a token",
        [BOUNDARY_ENVIRONMENT.namespace]: " ",
        [BOUNDARY_ENVIRONMENT.region]: "x".repeat(201),
        [BOUNDARY_ENVIRONMENT.clusterId]: "eu-1",
      },
    });
    expect(malformed.boundarySource).toBe("derived");
    expect(malformed.placement).toEqual({
      clusterId: "eu-1",
      namespace: null,
      region: null,
      workloadId: null,
    });
    expect(malformed.instance).toBeNull();
  });

  it("reports an unnamed runtime as unknown rather than guessing", () => {
    const boundary = resolveBoundary({
      ...FACTS,
      deploymentType: null,
      environment: null,
      upstreamOrigin: null,
    });
    expect(boundary).toMatchObject({
      deploymentType: "unknown",
      environment: null,
      placement: null,
      instance: null,
      protocolVersion: BOUNDARY_PROTOCOL,
      conformanceVersion: BOUNDARY_CONFORMANCE,
      agentsafeVersion: "0.2.4",
    });
  });
});

describe("the boundary as an intent binds it", () => {
  it("carries the stable identity and placement and nothing else", () => {
    const boundary = resolveBoundary({
      ...FACTS,
      env: {
        [BOUNDARY_ENVIRONMENT.boundaryId]: "prod-payments-eu",
        [BOUNDARY_ENVIRONMENT.clusterId]: "eu-1",
        [BOUNDARY_ENVIRONMENT.namespace]: "payments",
        [BOUNDARY_ENVIRONMENT.region]: "eu-west-1",
        [BOUNDARY_ENVIRONMENT.workloadId]: "payments-agent",
        [BOUNDARY_ENVIRONMENT.containerId]: "3f2a91c4bb01",
        [BOUNDARY_ENVIRONMENT.podId]: "agentsafe-7c9f-xk2",
        [BOUNDARY_ENVIRONMENT.nodeId]: "ip-10-0-4-21",
      },
    });
    const signal = boundarySignal(boundary);

    expect(EnforcementBoundarySignalSchema.parse(signal)).toEqual(signal);
    expect(signal).toEqual({
      boundary_id: "prod-payments-eu",
      agentsafe_version: "0.2.4",
      protocol_version: BOUNDARY_PROTOCOL,
      deployment_type: "docker",
      environment: "production",
      conformance_version: BOUNDARY_CONFORMANCE,
      placement: {
        cluster_id: "eu-1",
        namespace: "payments",
        region: "eu-west-1",
        workload_id: "payments-agent",
      },
    });
    // The container this happens to be is reported locally and signed nowhere.
    expect(JSON.stringify(signal)).not.toContain("3f2a91c4bb01");
    expect(JSON.stringify(signal)).not.toContain("agentsafe-7c9f-xk2");
    expect(JSON.stringify(signal)).not.toContain("ip-10-0-4-21");
  });

  it("omits what it does not have", () => {
    const signal = boundarySignal(
      resolveBoundary({ ...FACTS, environment: null, deploymentType: null }),
    );

    expect(EnforcementBoundarySignalSchema.parse(signal)).toEqual(signal);
    expect(Object.hasOwn(signal, "environment")).toBe(false);
    expect(Object.hasOwn(signal, "placement")).toBe(false);
    expect(signal.deployment_type).toBe("unknown");
  });

  it("omits a placement whose every field was unreadable", () => {
    const signal = boundarySignal(
      resolveBoundary({ ...FACTS, env: { [BOUNDARY_ENVIRONMENT.namespace]: "" } }),
    );
    expect(Object.hasOwn(signal, "placement")).toBe(false);
  });

  it("carries only the placement fields it was given", () => {
    expect(
      boundarySignal(
        resolveBoundary({ ...FACTS, env: { [BOUNDARY_ENVIRONMENT.namespace]: "payments" } }),
      ).placement,
    ).toEqual({ namespace: "payments" });
    expect(
      boundarySignal(
        resolveBoundary({ ...FACTS, env: { [BOUNDARY_ENVIRONMENT.region]: "eu-west-1" } }),
      ).placement,
    ).toEqual({ region: "eu-west-1" });
    expect(
      boundarySignal(
        resolveBoundary({ ...FACTS, env: { [BOUNDARY_ENVIRONMENT.clusterId]: "eu-1" } }),
      ).placement,
    ).toEqual({ cluster_id: "eu-1" });
    expect(
      boundarySignal(
        resolveBoundary({ ...FACTS, env: { [BOUNDARY_ENVIRONMENT.workloadId]: "payments-agent" } }),
      ).placement,
    ).toEqual({ workload_id: "payments-agent" });
  });
});
