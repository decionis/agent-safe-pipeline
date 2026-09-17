import type { JsonValue } from "@decionis/agent-safe-pipeline";

/** A running demo authority: where it listens, the key it accepts, and how to stop it. */
export interface DemoAuthorityHandle {
  readonly baseUrl: string;
  readonly apiKey: string;
  stop(): Promise<void>;
}

/** The synthetic policy's two ceilings, in minor units. */
export const DEMO_AUTONOMOUS_LIMIT_MINOR = 10_000;
export const DEMO_HUMAN_LIMIT_MINOR = 100_000;

/** The request shape the policy reads; the double validates the whole contract before it is called. */
export interface DemoPolicyRequest {
  readonly action: {
    readonly type: string;
    readonly parameters: Readonly<Record<string, unknown>>;
  };
  readonly context: Readonly<Record<string, unknown>>;
}

/**
 * The amount an HTTP body names, in minor units, or null when it names none.
 * `amountMinor` and `amount_minor` are integers already; `amount` is in major
 * units and is read to two places without floating arithmetic.
 */
export function amountMinorOf(body: JsonValue | undefined): number | null {
  if (body === undefined || body === null || typeof body !== "object" || Array.isArray(body)) {
    return null;
  }
  const record = body as Readonly<Record<string, JsonValue | undefined>>;
  for (const key of ["amountMinor", "amount_minor"]) {
    const value = record[key];
    if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  }
  const amount = record["amount"];
  const text =
    typeof amount === "number" ? String(amount) : typeof amount === "string" ? amount.trim() : null;
  if (text === null || !/^\d{1,15}(?:\.\d{1,2})?$/.test(text)) return null;
  const [whole = "0", fraction = ""] = text.split(".");
  return Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
}

/**
 * The demo policy: what the local authority decides. It is synthetic and
 * says nothing about any real policy. A body the gateway could not read is
 * escalated, because a policy cannot allow what it cannot see; a `DELETE`
 * is escalated as destructive; an amount above the autonomous ceiling is
 * escalated and one above the human ceiling is blocked; anything else is
 * allowed.
 */
export function demoPolicy(request: DemoPolicyRequest): "ALLOW" | "ESCALATE" | "BLOCK" {
  const parameters = request.action.parameters;
  if (request.context["body_embedded"] === false && request.context["body_bytes"] !== 0) {
    return "ESCALATE";
  }
  if (parameters["method"] === "DELETE") return "ESCALATE";
  const amount = amountMinorOf(parameters["body"] as JsonValue | undefined);
  if (amount === null) return "ALLOW";
  if (amount > DEMO_HUMAN_LIMIT_MINOR) return "BLOCK";
  if (amount > DEMO_AUTONOMOUS_LIMIT_MINOR) return "ESCALATE";
  return "ALLOW";
}

/**
 * Starts the loopback double of the Decionis routes with the demo policy.
 * The double is the pipeline's testing entry and is loaded only here, only
 * when the demo authority was chosen, so a production process never loads
 * it; the configuration refuses the choice in production before this runs.
 */
export async function startDemoAuthority(): Promise<DemoAuthorityHandle> {
  const testing = await import("@decionis/agent-safe-pipeline/testing");
  const authority = new testing.LocalAuthority({ policy: demoPolicy });
  await authority.start();
  return {
    baseUrl: authority.baseUrl,
    apiKey: testing.LOCAL_AUTHORITY_API_KEY,
    stop: () => authority.stop(),
  };
}
