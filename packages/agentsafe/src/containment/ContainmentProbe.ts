import type { DialOutcome } from "../egress/TcpProbe.js";

/**
 * The containment probe answers one question from inside the agent zone: can
 * a caller reach a system of record without going through the executor?
 *
 * It exists because `deploy/kubernetes/AgentZone.yaml` is a request to the
 * cluster rather than a control this repository can enforce. A cluster with
 * no NetworkPolicy-enforcing CNI accepts every policy in the kit and ignores
 * it, and no process can see that from inside itself. This probe cannot fix
 * that. It can make the failure visible.
 *
 * Read its verdicts asymmetrically, because they are not equally strong:
 *
 * - `REACHABLE` is proof of a hole. Something off the zone answered, so the
 *   path is not being dropped, and an agent with a credential could use it.
 * - `CONTAINED` is **not** proof of containment. A drop looks exactly like a
 *   provider that is down, a route that is briefly black-holed, or an
 *   address that stopped being the provider's. It is consistent with
 *   enforcement and it never establishes it.
 * - `INCONCLUSIVE` is a name that did not resolve, which is both what a
 *   policy does and what an outage does.
 *
 * Two further limits belong in the open:
 *
 * - The probe never authenticates. Holding the downstream credential in the
 *   agent zone to find out whether it works would create the hole the probe
 *   is looking for, so it can only say that a path exists, never that the
 *   path is usable.
 * - It runs in the agent zone, so a compromised caller can report whatever
 *   it likes. It is an operator's instrument, not an input the executor
 *   trusts: nothing in the process reads a finding, and the executor grants
 *   the probe no standing it does not grant any other caller.
 */
export const CONTAINMENT_STREAM = "agent-safe.containment/1";

export type ContainmentVerdict = "REACHABLE" | "CONTAINED" | "INCONCLUSIVE";

export interface ContainmentTarget {
  /** A label for the system of record, for the finding to name. */
  readonly name: string;
  readonly host: string;
  readonly port: number;
}

export interface ContainmentFinding {
  readonly stream: typeof CONTAINMENT_STREAM;
  readonly event: "CONTAINMENT_PROBED";
  readonly target: string;
  /** Host and port only. A probe carries no path, no parameter and no body. */
  readonly address: string;
  readonly verdict: ContainmentVerdict;
  /** Why, as a code the kernel chose. Never a message off the network. */
  readonly detail: string;
  readonly at: string;
}

export interface ContainmentReport {
  readonly findings: readonly ContainmentFinding[];
  /** How many targets answered. Any at all is a hole. */
  readonly reachable: number;
  /** True only when nothing answered. Never a claim that a policy is enforced. */
  readonly noneReachable: boolean;
}

/**
 * The verdict for one dial. A refusal counts as reachable on purpose: an RST
 * came back, so a packet reached a host that answered, which is what an
 * unenforced policy looks like. A policy that is enforcing drops.
 */
export function verdictFor(outcome: DialOutcome): {
  readonly verdict: ContainmentVerdict;
  readonly detail: string;
} {
  switch (outcome.state) {
    case "CONNECTED":
      return { verdict: "REACHABLE", detail: "CONNECTED" };
    case "REFUSED":
      return { verdict: "REACHABLE", detail: "REFUSED_NOT_DROPPED" };
    case "TIMED_OUT":
      return { verdict: "CONTAINED", detail: "TIMED_OUT" };
    case "UNREACHABLE":
      return { verdict: "CONTAINED", detail: outcome.code };
    // A name that did not resolve and an error nobody named are the same
    // answer: nothing was learned. They stay distinct in `DialOutcome`
    // because the kernel distinguishes them; the verdict does not.
    case "UNRESOLVED":
    case "OTHER":
      return { verdict: "INCONCLUSIVE", detail: outcome.code };
  }
}

export interface ContainmentProbeOptions {
  readonly targets: readonly ContainmentTarget[];
  readonly dial: (host: string, port: number, timeoutMs: number) => Promise<DialOutcome>;
  readonly timeoutMs?: number;
  readonly clock?: () => Date;
}

const DEFAULT_TIMEOUT_MS = 5_000;

/**
 * Dial every target once and report. Targets are probed in order rather than
 * together: a probe is not a load generator, and a system of record reading
 * its own logs should see one attempt at a time.
 */
export async function probeContainment(
  options: ContainmentProbeOptions,
): Promise<ContainmentReport> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const clock = options.clock ?? ((): Date => new Date());
  const findings: ContainmentFinding[] = [];
  for (const target of options.targets) {
    const { verdict, detail } = verdictFor(await options.dial(target.host, target.port, timeoutMs));
    findings.push({
      stream: CONTAINMENT_STREAM,
      event: "CONTAINMENT_PROBED",
      target: target.name,
      address: `${target.host}:${String(target.port)}`,
      verdict,
      detail,
      at: clock().toISOString(),
    });
  }
  const reachable = findings.filter((finding) => finding.verdict === "REACHABLE").length;
  return { findings, reachable, noneReachable: reachable === 0 };
}

/**
 * Parse `name=host:port` or `host:port`. A target the operator cannot spell
 * is refused rather than probed, because a probe of the wrong address that
 * times out reads exactly like containment.
 */
export function parseTarget(argument: string): ContainmentTarget {
  const separator = argument.indexOf("=");
  const name = separator === -1 ? argument : argument.slice(0, separator);
  // `slice(separator + 1)` is the whole argument when there is no separator,
  // so this needs no branch of its own.
  const address = argument.slice(separator + 1);
  const colon = address.lastIndexOf(":");
  if (colon <= 0) throw new Error(`CONTAINMENT_TARGET_INVALID: ${argument}`);
  const host = address.slice(0, colon);
  const port = Number(address.slice(colon + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`CONTAINMENT_TARGET_INVALID: ${argument}`);
  }
  return { name, host, port };
}
