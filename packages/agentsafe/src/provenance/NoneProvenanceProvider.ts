import type { ProvenanceProvider } from "./ProvenanceProvider.js";

/**
 * No provenance, said out loud.
 *
 * The default everywhere AgentSafe runs outside a described runtime, and the
 * reason nothing degrades into a guess: an intent it contributes to carries
 * no `workload` key at all, so a policy that requires trusted provenance
 * refuses on the signal's absence rather than matching a placeholder that
 * claims there is none.
 */
export class NoneProvenanceProvider implements ProvenanceProvider {
  public readonly id = "none";

  public describe(): null {
    return null;
  }
}
