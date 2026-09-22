import { describe, expect, it } from "vitest";
import { WorkloadSignalSchema } from "@decionis/agent-safe-pipeline";
import {
  TRUST_ORDER,
  WORKLOAD_ENVIRONMENT,
  MAX_REPORTED_TRUST,
  assertReportable,
  resolveWorkload,
  type ProvenanceProvider,
} from "../../src/provenance/ProvenanceProvider.js";
import { DockerProvenanceProvider } from "../../src/provenance/DockerProvenanceProvider.js";
import { KubernetesProvenanceProvider } from "../../src/provenance/KubernetesProvenanceProvider.js";
import { NoneProvenanceProvider } from "../../src/provenance/NoneProvenanceProvider.js";
import { StaticProvenanceProvider } from "../../src/provenance/StaticProvenanceProvider.js";

const DIGEST = `sha256:${"a".repeat(64)}`;
const DECLARED = {
  [WORKLOAD_ENVIRONMENT.image]: "ghcr.io/example/payments-agent:1.4.2",
  [WORKLOAD_ENVIRONMENT.digest]: DIGEST,
  [WORKLOAD_ENVIRONMENT.publisher]: "Example Ltd",
};

describe("the provenance providers", () => {
  it("reports what the runtime declared, as supplied and never more", () => {
    for (const [provider, runtime] of [
      [new DockerProvenanceProvider(), "docker"],
      [new KubernetesProvenanceProvider(), "kubernetes"],
    ] as const) {
      const workload = provider.describe({ env: DECLARED });
      expect(WorkloadSignalSchema.parse(workload)).toEqual(workload);
      expect(workload).toEqual({
        runtime,
        artifact_type: "oci",
        image: "ghcr.io/example/payments-agent:1.4.2",
        digest: DIGEST,
        publisher: "Example Ltd",
        provenance: { source: runtime, trust_level: "supplied" },
      });
    }
  });

  /**
   * The load-bearing claim of this whole abstraction. AgentSafe does not scan
   * images, verify publishers or check signatures, so it must never say it
   * did. `verified` is reserved for a provider that consumes a signal the
   * platform itself attests.
   */
  it("never reports verified, whatever it is told", () => {
    const shouting = {
      ...DECLARED,
      [WORKLOAD_ENVIRONMENT.publisher]: "verified",
    };
    for (const provider of [new DockerProvenanceProvider(), new KubernetesProvenanceProvider()]) {
      expect(provider.describe({ env: shouting })?.provenance.trust_level).toBe("supplied");
    }
    expect(
      new StaticProvenanceProvider({ runtime: "systemd", digest: DIGEST }).describe().provenance
        .trust_level,
    ).toBe("supplied");
  });

  it("refuses a level above the ceiling rather than quietly weakening it", () => {
    expect(TRUST_ORDER).toEqual(["unverified", "supplied", "observed", "verified"]);
    expect(MAX_REPORTED_TRUST).toBe("supplied");
    expect(assertReportable("supplied")).toBe("supplied");
    expect(assertReportable("unverified")).toBe("unverified");
    // A provider reaching for these has decided it checked something. If it
    // did not, that is a defect to fix, not a value to downgrade in silence.
    expect(() => assertReportable("observed")).toThrow("WORKLOAD_TRUST_NOT_REPORTABLE");
    expect(() => assertReportable("verified")).toThrow("WORKLOAD_TRUST_NOT_REPORTABLE");
  });

  it("says nothing rather than guessing when nothing was declared", () => {
    expect(new DockerProvenanceProvider().describe({ env: {} })).toBeNull();
    expect(new KubernetesProvenanceProvider().describe({ env: {} })).toBeNull();
    expect(new NoneProvenanceProvider().describe()).toBeNull();
  });

  it("carries each declared field on its own, and omits the ones nobody declared", () => {
    const docker = new DockerProvenanceProvider();
    const onlyImage = docker.describe({ env: { [WORKLOAD_ENVIRONMENT.image]: "payments:1" } });
    expect(onlyImage?.image).toBe("payments:1");
    expect(Object.hasOwn(onlyImage ?? {}, "digest")).toBe(false);
    expect(Object.hasOwn(onlyImage ?? {}, "publisher")).toBe(false);

    const onlyDigest = docker.describe({ env: { [WORKLOAD_ENVIRONMENT.digest]: DIGEST } });
    expect(onlyDigest?.digest).toBe(DIGEST);
    expect(Object.hasOwn(onlyDigest ?? {}, "image")).toBe(false);
    expect(Object.hasOwn(onlyDigest ?? {}, "publisher")).toBe(false);

    const onlyPublisher = docker.describe({
      env: { [WORKLOAD_ENVIRONMENT.publisher]: "Example Ltd" },
    });
    expect(onlyPublisher?.publisher).toBe("Example Ltd");
    expect(Object.hasOwn(onlyPublisher ?? {}, "image")).toBe(false);
    expect(Object.hasOwn(onlyPublisher ?? {}, "digest")).toBe(false);
  });

  it("matches a declared value whole, never a fragment of one", () => {
    const docker = new DockerProvenanceProvider();
    // An unanchored pattern would accept a value with anything in front of or
    // behind the part that looks right.
    for (const image of ["ghcr.io/x ; rm -rf /", "!!ghcr.io/x", "ghcr.io/x\nother"]) {
      expect(docker.describe({ env: { [WORKLOAD_ENVIRONMENT.image]: image } })).toBeNull();
    }
    for (const digest of [`x${DIGEST}`, `${DIGEST}x`, DIGEST.toUpperCase()]) {
      expect(docker.describe({ env: { [WORKLOAD_ENVIRONMENT.digest]: digest } })).toBeNull();
    }
    for (const publisher of ["Example Ltd\u0000", "\u0000Example Ltd"]) {
      expect(docker.describe({ env: { [WORKLOAD_ENVIRONMENT.publisher]: publisher } })).toBeNull();
    }
    expect(docker.describe({ env: { [WORKLOAD_ENVIRONMENT.image]: "x".repeat(501) } })).toBeNull();
  });

  it("drops a field that is not shaped like the thing it claims to be", () => {
    const workload = new DockerProvenanceProvider().describe({
      env: {
        ...DECLARED,
        [WORKLOAD_ENVIRONMENT.digest]: "sha256:not-a-digest",
        [WORKLOAD_ENVIRONMENT.publisher]: "  ",
      },
    });
    expect(workload?.digest).toBeUndefined();
    expect(workload?.publisher).toBeUndefined();
    expect(workload?.image).toBe("ghcr.io/example/payments-agent:1.4.2");
  });

  it("carries an operator's stated workload, held to the same ceiling", () => {
    const stated = new StaticProvenanceProvider({
      runtime: "systemd",
      artifact_type: "oci",
      image: "payments-agent",
      digest: DIGEST,
    }).describe();
    expect(stated).toMatchObject({
      runtime: "systemd",
      digest: DIGEST,
      provenance: { source: "operator", trust_level: "supplied" },
    });
    // A caller cannot state a workload the schema does not accept.
    expect(() => new StaticProvenanceProvider({ digest: "nope" } as never)).toThrow();
  });
});

describe("resolving one workload from several providers", () => {
  const silent: ProvenanceProvider = { id: "silent", describe: () => null };

  it("takes the first provider with something to say and merges nothing", () => {
    const docker = new DockerProvenanceProvider();
    const operator = new StaticProvenanceProvider({ runtime: "systemd", image: "other" });

    expect(resolveWorkload([silent, docker, operator], { env: DECLARED })?.runtime).toBe("docker");
    // A workload assembled from two sources would carry one `provenance`
    // describing neither, so the second provider contributes nothing.
    expect(resolveWorkload([silent, docker, operator], { env: DECLARED })?.image).toBe(
      "ghcr.io/example/payments-agent:1.4.2",
    );
    expect(resolveWorkload([operator, docker], { env: DECLARED })?.runtime).toBe("systemd");
  });

  it("returns nothing when no provider can speak, so the key is absent from the intent", () => {
    expect(resolveWorkload([silent, new NoneProvenanceProvider()], { env: {} })).toBeNull();
    expect(resolveWorkload([], { env: DECLARED })).toBeNull();
  });
});
