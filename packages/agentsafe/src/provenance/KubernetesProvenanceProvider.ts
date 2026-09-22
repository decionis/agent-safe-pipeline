import type { WorkloadSignal } from "@decionis/agent-safe-pipeline";
import {
  declaredWorkload,
  type ProvenanceFacts,
  type ProvenanceProvider,
} from "./ProvenanceProvider.js";

/**
 * What the pod spec declared about the image this container runs.
 *
 * The downward API exposes pod fields, not the image the kubelet resolved, so
 * the digest is one the manifest names and the chart injects. That is a real
 * distinction and it is why this reports `supplied`: the admission controller
 * that pinned the digest is the authority for it, and a cluster that wants
 * more should bind its own attestation and read it through a provider that
 * can check one.
 */
export class KubernetesProvenanceProvider implements ProvenanceProvider {
  public readonly id = "kubernetes";

  public describe(facts: ProvenanceFacts): WorkloadSignal | null {
    return declaredWorkload(facts, "kubernetes", this.id, "supplied");
  }
}
