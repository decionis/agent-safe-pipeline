import {
  resolveBoundary,
  type BoundaryInstance,
  type BoundaryPlacement,
  type EnforcementBoundary,
} from "../boundary/BoundaryIdentity.js";
import { processSurface } from "../gateway/InstallSurface.js";
import { DockerProvenanceProvider } from "../provenance/DockerProvenanceProvider.js";
import { KubernetesProvenanceProvider } from "../provenance/KubernetesProvenanceProvider.js";
import { NoneProvenanceProvider } from "../provenance/NoneProvenanceProvider.js";
import { resolveWorkload, type ProvenanceProvider } from "../provenance/ProvenanceProvider.js";
import type { WorkloadSignal } from "@decionis/agent-safe-pipeline";
import { packageVersion } from "../Version.js";
import { parseArguments, ArgumentError } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { resolveGateway, PROXY_ARGUMENTS } from "./Proxy.js";

export const IDENTITY_ARGUMENTS = {
  valued: [...PROXY_ARGUMENTS.valued],
  flags: [...PROXY_ARGUMENTS.flags],
} as const;

export const IDENTITY_REPORT_VERSION = "agent-safe.boundary-identity/1";

export interface IdentityReport {
  readonly version: typeof IDENTITY_REPORT_VERSION;
  readonly boundary_id: string;
  readonly boundary_source: "configured" | "derived";
  readonly agentsafe_version: string;
  readonly protocol_version: string;
  readonly conformance_version: string;
  readonly deployment_type: string;
  readonly environment: string | null;
  readonly placement: BoundaryPlacement | null;
  readonly instance: BoundaryInstance | null;
  /**
   * What software this boundary stands in front of, as a runtime reported it,
   * with the trust source beside it. Null when nothing trustworthy described
   * it, which is an answer and not a gap.
   */
  readonly workload: WorkloadSignal | null;
  /**
   * Whether the boundary was resolved from a usable gateway configuration.
   * Without one there is no upstream to stand in front of, so the derived id
   * is the one this process would use if nothing else changed — worth saying
   * out loud rather than printing as if it were settled.
   */
  readonly configured: boolean;
}

export function identityReport(
  boundary: EnforcementBoundary,
  workload: WorkloadSignal | null,
  configured: boolean,
): IdentityReport {
  return {
    version: IDENTITY_REPORT_VERSION,
    boundary_id: boundary.boundaryId,
    boundary_source: boundary.boundarySource,
    agentsafe_version: boundary.agentsafeVersion,
    protocol_version: boundary.protocolVersion,
    conformance_version: boundary.conformanceVersion,
    deployment_type: boundary.deploymentType,
    environment: boundary.environment,
    placement: boundary.placement,
    instance: boundary.instance,
    workload,
    configured,
  };
}

const ESC = String.fromCharCode(27);
const RESET = `${ESC}[0m`;
const BOLD = `${ESC}[1m`;
const DIM = `${ESC}[2m`;

export function renderIdentityReport(
  report: IdentityReport,
  options: { readonly color: boolean },
): string {
  const dim = (text: string): string => (options.color ? `${DIM}${text}${RESET}` : text);
  const row = (label: string, value: string): string => `${label.padEnd(20)} ${value}`;
  const lines = [
    `${options.color ? BOLD : ""}AgentSafe Boundary${options.color ? RESET : ""}`,
    "",
    row("boundary_id", `${report.boundary_id} (${report.boundary_source})`),
    row("runtime", report.deployment_type),
    row("agentsafe_version", report.agentsafe_version),
    row("protocol_version", report.protocol_version),
    row("environment", report.environment ?? "none"),
    row("conformance", report.conformance_version),
  ];
  const workload = report.workload;
  if (workload !== null) {
    if (workload.image !== undefined) lines.push(row("workload_image", workload.image));
    if (workload.digest !== undefined) lines.push(row("workload_digest", workload.digest));
    if (workload.publisher !== undefined) lines.push(row("workload_publisher", workload.publisher));
    lines.push(
      row(
        "workload_trust",
        `${workload.provenance.trust_level} (reported by ${workload.provenance.source})`,
      ),
    );
  }
  const placement = report.placement;
  if (placement !== null) {
    for (const [label, value] of [
      ["cluster", placement.clusterId],
      ["namespace", placement.namespace],
      ["region", placement.region],
      ["workload", placement.workloadId],
    ] as const) {
      if (value !== null) lines.push(row(label, value));
    }
  }
  const instance = report.instance;
  if (instance !== null) {
    lines.push("", dim("This instance, reported here and never bound into evidence:"));
    for (const [label, value] of [
      ["container", instance.containerId],
      ["pod", instance.podId],
      ["node", instance.nodeId],
    ] as const) {
      if (value !== null) lines.push(dim(row(label, value)));
    }
  }
  lines.push(
    "",
    report.configured
      ? dim("Every intent this boundary captures names it, inside the hash.")
      : dim("No usable gateway configuration; this is the identity it would resolve to."),
    "",
  );
  return lines.join("\n");
}

/**
 * `agentsafe identity`: which enforcement boundary this process is.
 *
 * An estate running many gateways needs to know which of them admitted an
 * effect, and an operator needs to see that the answer is stable before
 * relying on it. The id printed here is the one bound into every intent this
 * process captures, so it is the one a Decision Dossier will name.
 */
export function runIdentity(io: CliProcess, argv: readonly string[]): IdentityReport | null {
  let parsed;
  try {
    parsed = parseArguments(argv, IDENTITY_ARGUMENTS);
  } catch (error) {
    if (!(error instanceof ArgumentError)) throw error;
    io.stderr(`${error.message}\n`);
    io.exit(2);
    return null;
  }
  const json = parsed.options.get("json") === true;
  const version = packageVersion();
  // A configuration is preferable but not required: the command exists partly
  // to be run before there is one.
  let environment: string | null = null;
  let upstreamOrigin: string | null = null;
  let configuredId: string | null = null;
  let configured = false;
  let env = io.env;
  try {
    const resolved = resolveGateway(io, parsed);
    environment = resolved.config.upstream.environment;
    upstreamOrigin = new URL(resolved.config.upstream.url).origin;
    configuredId = resolved.config.boundary.id;
    env = resolved.env;
    configured = true;
  } catch {
    // No upstream, no file, or a refusal: the boundary is still describable.
  }
  const boundary = resolveBoundary({
    env,
    version,
    deploymentType: processSurface(env),
    environment,
    upstreamOrigin,
    configuredId,
  });
  const providers: readonly ProvenanceProvider[] = [
    ...(boundary.deploymentType === "docker" ? [new DockerProvenanceProvider()] : []),
    ...(boundary.deploymentType === "kubernetes" ? [new KubernetesProvenanceProvider()] : []),
    new NoneProvenanceProvider(),
  ];
  const report = identityReport(boundary, resolveWorkload(providers, { env }), configured);
  io.stdout(json ? `${JSON.stringify(report)}\n` : renderIdentityReport(report, io));
  io.exit(0);
  return report;
}
