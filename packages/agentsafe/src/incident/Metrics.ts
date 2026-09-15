import type { SecurityEvent } from "./SecurityEvents.js";

export type LabelValues = Readonly<Record<string, string>>;

interface Family {
  readonly name: string;
  readonly help: string;
  readonly kind: "counter" | "gauge";
  readonly labels: readonly string[];
  readonly samples: Map<string, { readonly values: readonly string[]; value: number }>;
}

function escape(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/** One family's handle: label names fixed at creation, values bounded by what the code passes. */
export class Counter {
  public constructor(private readonly family: Family) {}

  public inc(labels: LabelValues = {}, by = 1): void {
    Metrics.sample(this.family, labels).value += by;
  }

  public get(labels: LabelValues = {}): number {
    return Metrics.sample(this.family, labels).value;
  }
}

export class Gauge {
  public constructor(private readonly family: Family) {}

  public set(value: number, labels: LabelValues = {}): void {
    Metrics.sample(this.family, labels).value = value;
  }

  public get(labels: LabelValues = {}): number {
    return Metrics.sample(this.family, labels).value;
  }
}

/**
 * A registry of counters and gauges with fixed label names, rendered as
 * OpenMetrics text. Label values are codes, verdicts, names, and checks the
 * code itself supplies, never anything a caller sent, so cardinality is
 * bounded by the vocabulary and no value can leak through a label.
 */
export class Metrics {
  private readonly families = new Map<string, Family>();

  public counter(name: string, help: string, labels: readonly string[] = []): Counter {
    return new Counter(this.family(name, help, "counter", labels));
  }

  public gauge(name: string, help: string, labels: readonly string[] = []): Gauge {
    return new Gauge(this.family(name, help, "gauge", labels));
  }

  /** The exposition, families in registration order, samples in first-seen order, `# EOF` last. */
  public render(): string {
    const lines: string[] = [];
    for (const family of this.families.values()) {
      lines.push(`# HELP ${family.name} ${family.help}`, `# TYPE ${family.name} ${family.kind}`);
      const suffix = family.kind === "counter" ? "_total" : "";
      for (const sample of family.samples.values()) {
        const labels = family.labels
          .map((label, index) => `${label}="${escape(sample.values[index] ?? "")}"`)
          .join(",");
        lines.push(`${family.name}${suffix}${labels === "" ? "" : `{${labels}}`} ${sample.value}`);
      }
    }
    lines.push("# EOF");
    return `${lines.join("\n")}\n`;
  }

  /** @internal */
  public static sample(
    family: Family,
    labels: LabelValues,
  ): { readonly values: readonly string[]; value: number } {
    const values = family.labels.map((label) => labels[label] ?? "");
    const key = JSON.stringify(values);
    let sample = family.samples.get(key);
    if (sample === undefined) {
      sample = { values, value: 0 };
      family.samples.set(key, sample);
    }
    return sample;
  }

  private family(
    name: string,
    help: string,
    kind: Family["kind"],
    labels: readonly string[],
  ): Family {
    const existing = this.families.get(name);
    if (existing !== undefined) return existing;
    const family: Family = { name, help, kind, labels: [...labels], samples: new Map() };
    this.families.set(name, family);
    return family;
  }
}

/** The executor's own families, and the observer that counts security events into them. */
export interface ExecutorMetrics {
  readonly registry: Metrics;
  readonly proposals: Counter;
  readonly executions: Counter;
  readonly authFailures: Counter;
  readonly egressRefused: Counter;
  readonly secretRotations: Counter;
  readonly postureDrift: Counter;
  readonly leaksSuspected: Counter;
  readonly tlsRotations: Counter;
  readonly auditLines: Counter;
  readonly principalsLocked: Counter;
  readonly operatorActions: Counter;
  observe(event: SecurityEvent): void;
}

export function executorMetrics(registry: Metrics = new Metrics()): ExecutorMetrics {
  const metrics = {
    registry,
    proposals: registry.counter("agentsafe_proposals", "Proposals answered, by verdict.", [
      "verdict",
    ]),
    executions: registry.counter(
      "agentsafe_executions",
      "Executions attempted in enforcement, by outcome.",
      ["outcome"],
    ),
    authFailures: registry.counter(
      "agentsafe_auth_failures",
      "Requests refused at the door, by authentication method.",
      ["method"],
    ),
    egressRefused: registry.counter(
      "agentsafe_egress_refused",
      "Outbound requests the egress policy refused, by code.",
      ["code"],
    ),
    secretRotations: registry.counter(
      "agentsafe_secret_rotations",
      "Secrets that became current from a changed file, by name.",
      ["name"],
    ),
    postureDrift: registry.counter(
      "agentsafe_posture_drift",
      "Posture checks that regressed while running, by check.",
      ["check"],
    ),
    leaksSuspected: registry.counter(
      "agentsafe_leaks_suspected",
      "Lines the redactor changed before they left the process.",
    ),
    tlsRotations: registry.counter(
      "agentsafe_tls_rotations",
      "Listener certificate contexts replaced without a restart.",
    ),
    auditLines: registry.counter("agentsafe_audit_lines", "Chained lines written, by stream.", [
      "chain",
    ]),
    principalsLocked: registry.counter(
      "agentsafe_principals_locked",
      "Principals locked out after repeated authentication failures.",
    ),
    operatorActions: registry.counter(
      "agentsafe_operator_actions",
      "Control routes an operator exercised, by action.",
      ["action"],
    ),
  };
  return {
    ...metrics,
    observe: (event) => {
      switch (event.event) {
        case "AUTH_FAILED":
          return metrics.authFailures.inc({ method: event.method });
        case "EGRESS_REFUSED":
          return metrics.egressRefused.inc({ code: event.code });
        case "SECRET_ROTATED":
          return metrics.secretRotations.inc({ name: event.name });
        case "POSTURE_DRIFT":
          return metrics.postureDrift.inc({ check: event.check });
        case "LEAK_SUSPECTED":
          return metrics.leaksSuspected.inc();
        case "TLS_CONTEXT_ROTATED":
          return metrics.tlsRotations.inc();
        case "PRINCIPAL_LOCKED":
          return metrics.principalsLocked.inc();
        case "OPERATOR_ACTION":
          return metrics.operatorActions.inc({ action: event.action });
        default:
          return undefined;
      }
    },
  };
}
