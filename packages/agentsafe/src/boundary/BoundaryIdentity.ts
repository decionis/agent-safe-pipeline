import { createHash } from "node:crypto";
import type { EnforcementBoundarySignal } from "@decionis/agent-safe-pipeline";
import type { InstallSurface } from "../gateway/InstallSurface.js";

/**
 * Which enforcement boundary this process is.
 *
 * An estate may run hundreds of gateways across Docker, Kubernetes, a Linux
 * host and the hosted runtime. A Decision Dossier that names the boundary can
 * answer which of them admitted an effect; one that cannot is evidence about
 * an action with no evidence about the door it came through.
 *
 * The identity is of the *configured logical boundary*, not of the process or
 * the container: restarting a container, rescheduling a pod or scaling a
 * deployment to thirty replicas leaves it unchanged, because nothing
 * ephemeral goes into it. That is also why the derivation below reads
 * configuration rather than the machine: a boundary id that moved when a pod
 * did would be an instance id wearing a boundary's name, and an operator
 * grouping policy by boundary would be grouping by nothing.
 */

/** The conformance profile this boundary answers for. */
export const BOUNDARY_CONFORMANCE = "agent-safe-intent-v1";

export const BOUNDARY_PROTOCOL = "agent-safe.intent/1";

/** A derived id wears a prefix so it is never mistaken for one an operator chose. */
export const DERIVED_BOUNDARY_PREFIX = "bd_";

export const BOUNDARY_ENVIRONMENT = {
  boundaryId: "AGENTSAFE_BOUNDARY_ID",
  clusterId: "AGENTSAFE_CLUSTER_ID",
  namespace: "AGENTSAFE_NAMESPACE",
  region: "AGENTSAFE_REGION",
  workloadId: "AGENTSAFE_WORKLOAD_ID",
  containerId: "AGENTSAFE_CONTAINER_ID",
  podId: "AGENTSAFE_POD_ID",
  nodeId: "AGENTSAFE_NODE_ID",
} as const;

/**
 * The shape a value must have to be one of these. A variable holding anything
 * else is no value rather than a guess, the same way an unrecognised
 * `AGENTSAFE_SURFACE` is no surface.
 */
const TOKEN = /^[a-z0-9][\w.:/-]*$/i;
const MAX_TOKEN = 200;

/**
 * Where the boundary sits, as the operator's own manifest declared it. These
 * survive a restart and are what a policy means by "production in eu", so
 * they are bound into the intent and reach signed evidence.
 */
export interface BoundaryPlacement {
  readonly clusterId: string | null;
  readonly namespace: string | null;
  readonly region: string | null;
  readonly workloadId: string | null;
}

/**
 * Which instance of the boundary this happens to be. Ephemeral by
 * definition, so it is reported locally, for an operator reading one
 * process's own output, and never bound into an intent or signed into
 * evidence: an effect's evidence should say which boundary admitted it, not
 * which container was alive that second.
 */
export interface BoundaryInstance {
  readonly containerId: string | null;
  readonly podId: string | null;
  readonly nodeId: string | null;
}

export interface EnforcementBoundary {
  readonly boundaryId: string;
  /** Whether an operator named this boundary or the configuration derived it. */
  readonly boundarySource: "configured" | "derived";
  readonly agentsafeVersion: string;
  readonly protocolVersion: typeof BOUNDARY_PROTOCOL;
  readonly conformanceVersion: string;
  readonly deploymentType: InstallSurface | "unknown";
  readonly environment: string | null;
  readonly placement: BoundaryPlacement | null;
  readonly instance: BoundaryInstance | null;
}

/** What the resolution reads: the environment and the configuration, never the host. */
export interface BoundaryFacts {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly version: string;
  readonly deploymentType: InstallSurface | null;
  /** The operator's own name for this deployment, from `gateway.environment`. */
  readonly environment: string | null;
  /** The origin of the system this boundary stands in front of. */
  readonly upstreamOrigin: string | null;
  /** A boundary id from the configuration file, which the environment overrides. */
  readonly configuredId?: string | null;
}

function token(value: string | undefined): string | null {
  const trimmed = value?.trim();
  // An empty string needs no test of its own: the pattern requires a first
  // character, so `""` fails it like any other malformed value.
  if (trimmed === undefined || trimmed.length > MAX_TOKEN) return null;
  return TOKEN.test(trimmed) ? trimmed : null;
}

function present<T extends object>(value: T): T | null {
  return Object.values(value).some((entry) => entry !== null) ? value : null;
}

/**
 * The separator between the derivation's parts. It is not decoration: two
 * different configurations must not be able to join into the same string.
 */
const DERIVATION_SEPARATOR = "\n";

/**
 * A boundary nobody named, from the settings that define what it is: what it
 * was installed as, which deployment it serves, and what it stands in front
 * of. Two gateways configured alike are the same boundary and share an id;
 * one pointed at a different upstream or a different environment is a
 * different boundary and does not. No hostname, address, user or container id
 * reaches the digest, so the id is stable across restarts and carries nothing
 * about the host into evidence.
 *
 * The derivation is a compatibility contract, pinned by a vector in the
 * tests: changing it would silently re-partition the evidence of every
 * deployment that never named its boundary.
 */
function derive(facts: BoundaryFacts): string {
  const material = [
    facts.deploymentType ?? "unknown",
    facts.environment ?? "",
    facts.upstreamOrigin ?? "",
  ].join(DERIVATION_SEPARATOR);
  const digest = createHash("sha256").update(material).digest("hex");
  return `${DERIVED_BOUNDARY_PREFIX}${digest.slice(0, 16)}`;
}

export function resolveBoundary(facts: BoundaryFacts): EnforcementBoundary {
  const named =
    token(facts.env[BOUNDARY_ENVIRONMENT.boundaryId]) ?? token(facts.configuredId ?? undefined);
  return {
    boundaryId: named ?? derive(facts),
    boundarySource: named === null ? "derived" : "configured",
    agentsafeVersion: facts.version,
    protocolVersion: BOUNDARY_PROTOCOL,
    conformanceVersion: BOUNDARY_CONFORMANCE,
    deploymentType: facts.deploymentType ?? "unknown",
    environment: token(facts.environment ?? undefined),
    placement: present({
      clusterId: token(facts.env[BOUNDARY_ENVIRONMENT.clusterId]),
      namespace: token(facts.env[BOUNDARY_ENVIRONMENT.namespace]),
      region: token(facts.env[BOUNDARY_ENVIRONMENT.region]),
      workloadId: token(facts.env[BOUNDARY_ENVIRONMENT.workloadId]),
    }),
    instance: present({
      containerId: token(facts.env[BOUNDARY_ENVIRONMENT.containerId]),
      podId: token(facts.env[BOUNDARY_ENVIRONMENT.podId]),
      nodeId: token(facts.env[BOUNDARY_ENVIRONMENT.nodeId]),
    }),
  };
}

/**
 * The boundary as an intent binds it. The instance is left out deliberately:
 * what reaches signed evidence is the boundary, and the boundary is not the
 * container it happens to be running in.
 */
export function boundarySignal(boundary: EnforcementBoundary): EnforcementBoundarySignal {
  const placement = boundary.placement;
  const stable =
    placement === null
      ? {}
      : {
          ...(placement.clusterId === null ? {} : { cluster_id: placement.clusterId }),
          ...(placement.namespace === null ? {} : { namespace: placement.namespace }),
          ...(placement.region === null ? {} : { region: placement.region }),
          ...(placement.workloadId === null ? {} : { workload_id: placement.workloadId }),
        };
  return {
    boundary_id: boundary.boundaryId,
    agentsafe_version: boundary.agentsafeVersion,
    protocol_version: BOUNDARY_PROTOCOL,
    deployment_type: boundary.deploymentType,
    ...(boundary.environment === null ? {} : { environment: boundary.environment }),
    conformance_version: boundary.conformanceVersion,
    ...(Object.keys(stable).length === 0 ? {} : { placement: stable }),
  };
}
