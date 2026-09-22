import type { WorkloadSignal } from "@decionis/agent-safe-pipeline";
import { WorkloadSignalSchema } from "@decionis/agent-safe-pipeline";
import {
  MAX_REPORTED_TRUST,
  assertReportable,
  type ProvenanceProvider,
} from "./ProvenanceProvider.js";

/**
 * A workload an operator states in code, for a deployment no runtime
 * describes: a systemd unit, a process on a host, a test.
 *
 * It is held to the same ceiling as everything else. An operator writing a
 * digest into a configuration has supplied it, not verified it, and a
 * provider that let a caller declare its own trust level would be the
 * silent upgrade this design exists to prevent.
 */
export class StaticProvenanceProvider implements ProvenanceProvider {
  public readonly id = "operator";
  private readonly workload: WorkloadSignal;

  public constructor(workload: Omit<WorkloadSignal, "provenance">) {
    this.workload = WorkloadSignalSchema.parse({
      ...workload,
      provenance: { source: this.id, trust_level: assertReportable(MAX_REPORTED_TRUST) },
    });
  }

  public describe(): WorkloadSignal {
    return this.workload;
  }
}
