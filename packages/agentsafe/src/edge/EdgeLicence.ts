import type { SecurityEvents } from "../incident/SecurityEvents.js";
import { verifyEntitlement, type EntitlementSource } from "./Entitlement.js";
import { licenceWarnings, type LicenceWarning } from "./EntitlementEvaluation.js";
import type { UsageMeter } from "./UsageMeter.js";

/**
 * Reads the signed entitlement, evaluates it with this installation's count
 * and report state, and says what changed: a warning that begins is an
 * `EDGE_LICENCE_WARNING` line (and the metric goes to 1), one that ends is
 * `EDGE_LICENCE_CLEARED` (and it goes to 0). It holds no reference to any
 * decision path: nothing here can stop, delay or change a decision.
 */
export class EdgeLicence {
  private standing = new Set<LicenceWarning>();

  public constructor(
    private readonly options: {
      readonly source: EntitlementSource;
      readonly meter: UsageMeter;
      readonly orgId: string;
      readonly events: SecurityEvents;
      readonly clock: () => number;
    },
  ) {}

  public get warnings(): readonly LicenceWarning[] {
    return [...this.standing];
  }

  public async check(): Promise<readonly LicenceWarning[]> {
    const entitlement = await verifyEntitlement(await this.options.source.read());
    const meter = this.options.meter;
    const warnings = licenceWarnings({
      entitlement,
      orgId: this.options.orgId,
      now: this.options.clock(),
      governed: meter.governed(),
      reporting: meter.reporting,
      undelivered: meter.undelivered(),
    });
    for (const code of warnings) {
      if (!this.standing.has(code))
        this.options.events.emit({ event: "EDGE_LICENCE_WARNING", code });
    }
    for (const code of this.standing) {
      if (!warnings.includes(code))
        this.options.events.emit({ event: "EDGE_LICENCE_CLEARED", code });
    }
    this.standing = new Set(warnings);
    return warnings;
  }
}
