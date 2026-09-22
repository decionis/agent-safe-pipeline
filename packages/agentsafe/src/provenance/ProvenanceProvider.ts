import type { WorkloadSignal, WorkloadTrustLevel } from "@decionis/agent-safe-pipeline";

/**
 * What software proposed the action, as some runtime reported it.
 *
 * AgentSafe is not the authority for any of this. Docker, OCI tooling and the
 * platform establish what is running; this package carries what they say so
 * that a policy can reason about it and evidence can record it. It does not
 * scan an image, generate an SBOM, verify a publisher or check a signature,
 * and it must never appear to have done so.
 *
 * That is why every workload carries its own `provenance`: who said this, and
 * how far that goes. A field with no trust source beside it is a claim
 * wearing the costume of a fact.
 *
 * The contract is deliberately one method. A family is a file beside this
 * one, the way an effect adapter is a directory beside `banking/`.
 */

/**
 * How far the report can be trusted, strictly ordered, weakest first.
 *
 * - `unverified` — nothing trustworthy was available. Recorded, never hidden.
 * - `supplied` — something told us, and nothing checked it. An environment
 *   variable an operator's manifest set is this, however true it happens to
 *   be: the process cannot distinguish a digest its orchestrator injected
 *   from one a compromised entrypoint wrote.
 * - `observed` — the runtime reported it through an interface that is not the
 *   workload's to write.
 * - `verified` — a signature or attestation was checked.
 *
 * **AgentSafe emits nothing above `supplied` today, and that is deliberate.**
 * `verified` is reserved for a provider that consumes a signal the platform
 * itself attests. Claiming it without one would be exactly the fabrication
 * this design exists to prevent: a policy reading
 * `workload.provenance.trust_level == "verified"` must be reading a checked
 * signature, not an environment variable with ambitions.
 */
export const TRUST_ORDER: readonly WorkloadTrustLevel[] = [
  "unverified",
  "supplied",
  "observed",
  "verified",
];

/** What a provider reads. Never the network, never an undocumented API. */
export interface ProvenanceFacts {
  readonly env: Readonly<Record<string, string | undefined>>;
}

export interface ProvenanceProvider {
  /** Names the trust source this provider speaks for; it appears in `provenance.source`. */
  readonly id: string;
  /**
   * What this provider can say about the running workload, or null when it
   * can say nothing. Bounded, synchronous and side-effect free: a provider
   * that had to reach something to answer would be a provenance authority,
   * which is the thing this abstraction exists not to be.
   */
  describe(facts: ProvenanceFacts): WorkloadSignal | null;
}

/** The strongest level anything in this repository may report. See `TRUST_ORDER`. */
export const MAX_REPORTED_TRUST: WorkloadTrustLevel = "supplied";

/**
 * Holds a provider to the ceiling, by refusing rather than clamping.
 *
 * A silent downgrade would hide the bug: a provider reaching for `verified`
 * has decided it checked something, and if it did not, that is a defect to
 * fix and not a value to quietly weaken on its way to a policy.
 */
export function assertReportable(level: WorkloadTrustLevel): WorkloadTrustLevel {
  if (TRUST_ORDER.indexOf(level) > TRUST_ORDER.indexOf(MAX_REPORTED_TRUST)) {
    throw new Error("WORKLOAD_TRUST_NOT_REPORTABLE");
  }
  return level;
}

/**
 * The variables an operator's own manifest declares about the artifact this
 * process is. There is no interface that hands a container its own image
 * digest — not the Docker API without a socket the gateway must not have, and
 * not the Kubernetes downward API, which exposes pod fields and not the
 * resolved image. So the orchestrator puts it here, and because the workload
 * could in principle write the same variable, what is read here is `supplied`
 * and never more.
 */
export const WORKLOAD_ENVIRONMENT = {
  image: "AGENTSAFE_WORKLOAD_IMAGE",
  digest: "AGENTSAFE_WORKLOAD_DIGEST",
  publisher: "AGENTSAFE_WORKLOAD_PUBLISHER",
} as const;

const IMAGE = /^[\w.:/@-]{1,500}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const PUBLISHER = /^[\w .:/@-]{1,200}$/;

function match(value: string | undefined, pattern: RegExp): string | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return pattern.test(trimmed) ? trimmed : undefined;
}

/**
 * An OCI artifact as the declared variables describe it, or null when they
 * describe nothing. A malformed value is dropped rather than carried: a
 * digest that is not a digest would be a field a policy could match on by
 * accident.
 */
export function declaredWorkload(
  facts: ProvenanceFacts,
  runtime: string,
  source: string,
  trustLevel: WorkloadTrustLevel,
): WorkloadSignal | null {
  const image = match(facts.env[WORKLOAD_ENVIRONMENT.image], IMAGE);
  const digest = match(facts.env[WORKLOAD_ENVIRONMENT.digest], DIGEST);
  const publisher = match(facts.env[WORKLOAD_ENVIRONMENT.publisher], PUBLISHER);
  if (image === undefined && digest === undefined && publisher === undefined) return null;
  return {
    runtime,
    artifact_type: "oci",
    ...(image === undefined ? {} : { image }),
    ...(digest === undefined ? {} : { digest }),
    ...(publisher === undefined ? {} : { publisher }),
    provenance: { source, trust_level: assertReportable(trustLevel) },
  };
}

/**
 * The first provider with something to say, in the order given.
 *
 * Nothing is merged. A workload assembled from two sources would carry one
 * `provenance` describing neither, and the trust level would belong to the
 * wrong fields. Silence is the honest answer when no provider has one: the
 * key is then absent from the intent, so a policy that requires provenance
 * refuses on its absence rather than matching a placeholder.
 */
export function resolveWorkload(
  providers: readonly ProvenanceProvider[],
  facts: ProvenanceFacts,
): WorkloadSignal | null {
  for (const provider of providers) {
    const described = provider.describe(facts);
    if (described !== null) return described;
  }
  return null;
}
