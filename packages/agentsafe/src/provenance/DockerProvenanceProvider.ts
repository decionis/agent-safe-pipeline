import type { WorkloadSignal } from "@decionis/agent-safe-pipeline";
import {
  declaredWorkload,
  type ProvenanceFacts,
  type ProvenanceProvider,
} from "./ProvenanceProvider.js";

/**
 * What Docker's own tooling put in this container's environment.
 *
 * Docker establishes what is running: the image, its digest, its provenance,
 * its SBOM, its publisher. None of that is AgentSafe's to determine, and none
 * of it is fabricated here. The image reference and digest arrive because the
 * operator's compose file or `docker run` put them there; no Docker socket is
 * opened, no undocumented API is called, and an image label is never read as
 * cryptographic provenance, because a label is not one.
 *
 * The consequence is stated rather than hidden: what this provider reports is
 * `supplied`. When Docker offers an attested channel — a verified publisher,
 * a Scout status, a provenance attestation this process can check — it
 * belongs behind a provider that can honestly say `verified`, and that
 * provider is a file beside this one.
 */
export class DockerProvenanceProvider implements ProvenanceProvider {
  public readonly id = "docker";

  public describe(facts: ProvenanceFacts): WorkloadSignal | null {
    return declaredWorkload(facts, "docker", this.id, "supplied");
  }
}
