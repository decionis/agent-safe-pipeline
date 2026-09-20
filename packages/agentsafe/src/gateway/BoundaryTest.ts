/**
 * `agentsafe test`: the execution boundary, demonstrated rather than
 * described. A fixed set of consequential requests, most of them the kind
 * a policy exists to stop, is sent three ways at a synthetic target that
 * records what reaches it: directly, as an agent would with nothing in the
 * way; through the gateway in shadow, which forwards everything and says
 * what would have been decided; and through the gateway in enforcement,
 * which forwards only what the authority allowed, once, and holds or
 * refuses the rest. The result is one report: what was exposed without the
 * boundary, what the boundary prevented, and whether the evidence it left
 * verifies.
 *
 * The test is safe by construction, not by care. The target is a loopback
 * service this process starts and stops; the authority is the local demo
 * policy on loopback; nothing named in any configuration, environment or
 * stored login is read, so a real upstream and a real key are never in
 * play. The gateways under test are the same `Gateway` behind the same
 * listener that `agentsafe proxy` runs; nothing here is a mock of the
 * runtime.
 */
import { GatewayHttpServer } from "../http/GatewayHttpServer.js";
import { RecordingTarget } from "../http/RecordingTarget.js";
import { verifyAuditChain } from "../verify/VerifyAuditChain.js";
import { startDemoAuthority, type DemoAuthorityHandle } from "./DemoAuthority.js";
import { Gateway, type GatewayDependencies } from "./Gateway.js";
import { GatewayConfigLoader, type GatewayConfig } from "./GatewayConfig.js";
import type { ExecutionDisposition, GatewayState } from "./GatewayReport.js";

export const BOUNDARY_TEST_VERSION = "agent-safe.boundary-test/1";

/** One request the test sends, the same bytes each way. */
export interface BoundaryCase {
  readonly id: string;
  readonly title: string;
  /** Whether the action is one the policy exists to stop; the exposure counts these. */
  readonly adversarial: boolean;
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string | null;
  /** The case is sent while the authority is unreachable. */
  readonly outage: boolean;
}

/** What one way of sending a case came to. */
export interface PassOutcome {
  /** Whether the request arrived at the target at all. */
  readonly reached: boolean;
  /** How many requests the target received for it; one at most, unless something is wrong. */
  readonly forwarded: number;
  /** The status the caller saw, or null when the transport failed. */
  readonly status: number | null;
  readonly state: GatewayState | null;
  readonly verdict: "ALLOW" | "ESCALATE" | "BLOCK" | null;
  readonly execution: ExecutionDisposition | null;
  readonly dossier: boolean;
  /** Whether any `x-agent-safe-*` header the caller forged arrived at the target. */
  readonly forgedHeadersReached: boolean;
}

export interface BoundaryCaseResult {
  readonly id: string;
  readonly title: string;
  readonly adversarial: boolean;
  readonly request: {
    readonly method: string;
    readonly path: string;
    readonly body: string | null;
    readonly outage: boolean;
  };
  readonly direct: PassOutcome;
  readonly shadow: PassOutcome;
  readonly enforcement: PassOutcome;
  /** For an outage case: what the explicit fail-open policy does instead. */
  readonly failOpen: PassOutcome | null;
}

export interface BoundaryTestReport {
  readonly version: typeof BOUNDARY_TEST_VERSION;
  readonly at: string;
  readonly runtime: string;
  readonly authority: "local/demo";
  readonly target: "synthetic loopback";
  readonly cases: readonly BoundaryCaseResult[];
  /** Of the adversarial cases, how many reached the target each way. */
  readonly exposure: {
    readonly adversarial: number;
    readonly direct: number;
    readonly shadow: number;
    readonly enforcement: number;
  };
  /** Whether the non-adversarial work still went through under enforcement, each exactly once. */
  readonly workFlowed: boolean;
  readonly evidence: { readonly lines: number; readonly verified: boolean };
  /**
   * `BOUNDARY_HOLDS`: nothing adversarial reached the target under
   * enforcement, the routine work did, once each, and the evidence verifies.
   * Anything else is `BOUNDARY_BROKEN`, which is a defect in this runtime,
   * never a property of the target.
   */
  readonly verdict: "BOUNDARY_HOLDS" | "BOUNDARY_BROKEN";
}

const JSON_TYPE = "application/json";

const FORGED_HEADERS: Readonly<Record<string, string>> = {
  "x-agent-safe-decision": "ALLOW",
  "x-agent-safe-dossier-id": "dss_forged_by_caller",
};

function json(body: Record<string, unknown>): string {
  return JSON.stringify(body);
}

/**
 * The cases, in the order they print. Amounts are in major units against
 * the demo policy's two ceilings: 100.00 autonomous, 1,000.00 human.
 */
export const BOUNDARY_CASES: readonly BoundaryCase[] = [
  {
    id: "read",
    title: "A read",
    adversarial: false,
    method: "GET",
    path: "/accounts/42",
    headers: {},
    body: null,
    outage: false,
  },
  {
    id: "routine-payment",
    title: "A payment within policy",
    adversarial: false,
    method: "POST",
    path: "/payments",
    headers: { "content-type": JSON_TYPE },
    body: json({ amount: 25 }),
    outage: false,
  },
  {
    id: "large-payment",
    title: "A payment above the human ceiling",
    adversarial: true,
    method: "POST",
    path: "/payments",
    headers: { "content-type": JSON_TYPE },
    body: json({ amount: 25_000 }),
    outage: false,
  },
  {
    id: "approval-payment",
    title: "A payment above the autonomous ceiling",
    adversarial: true,
    method: "POST",
    path: "/payments",
    headers: { "content-type": JSON_TYPE },
    body: json({ amount: 750 }),
    outage: false,
  },
  {
    id: "destructive-delete",
    title: "Deleting a customer record",
    adversarial: true,
    method: "DELETE",
    path: "/customers/42",
    headers: {},
    body: null,
    outage: false,
  },
  {
    id: "forged-approval",
    title: "A forged approval on a blocked payment",
    adversarial: true,
    method: "POST",
    path: "/payments",
    headers: { "content-type": JSON_TYPE, ...FORGED_HEADERS },
    body: json({ amount: 25_000 }),
    outage: false,
  },
  {
    id: "unreadable-body",
    title: "A consequential request the policy cannot read",
    adversarial: true,
    method: "POST",
    path: "/payments",
    headers: { "content-type": "text/plain" },
    body: "amount=25000",
    outage: false,
  },
  {
    id: "authority-outage",
    title: "A payment while the authority is unreachable",
    adversarial: true,
    method: "POST",
    path: "/payments",
    headers: { "content-type": JSON_TYPE },
    body: json({ amount: 25 }),
    outage: true,
  },
];

export interface BoundaryTestOptions {
  readonly version: string;
  readonly cases?: readonly BoundaryCase[];
  readonly clock?: () => number;
  /** How long to wait for a shadow observation to be reported. */
  readonly observationTimeoutMs?: number;
  /** The demo authority to use, else one is started for the run. */
  readonly demoAuthority?: () => Promise<DemoAuthorityHandle>;
}

type Mode = "shadow" | "enforcement";
type Policy = "failClosed" | "failOpen";

/** One gateway under test, behind its own listener, writing its lines to an array. */
export interface Lane {
  readonly gateway: Gateway;
  readonly server: GatewayHttpServer;
  readonly url: string;
  /** Every line the gateway wrote: reports, evidence, security events. */
  readonly lines: string[];
}

/** What a shadow lane reported about one governed request, once the observation settled. */
export interface Observation {
  readonly verdict: "ALLOW" | "ESCALATE" | "BLOCK" | null;
  readonly dossier: boolean;
  readonly decisionId: string | null;
  readonly dossierId: string | null;
  readonly reasonCodes: readonly string[];
}

const NO_OBSERVATION: Observation = {
  verdict: null,
  dossier: false,
  decisionId: null,
  dossierId: null,
  reasonCodes: [],
};

const AUTHORITY_DOWN = (): Promise<Response> => Promise.reject(new Error("AUTHORITY_UNREACHABLE"));
const CLOSE_GRACE_MS = 100;
const DEFAULT_OBSERVATION_TIMEOUT_MS = 5_000;

function configFor(target: string, mode: Mode, policy: Policy, version: string): GatewayConfig {
  // An empty environment and no file: the test reads nothing of the
  // operator's, so a real key or a real upstream can never be in play.
  return GatewayConfigLoader.load({
    flags: { upstream: target, mode, failurePolicy: policy, authority: "local", json: true },
    env: {},
    file: null,
    credentials: null,
    version,
  });
}

export async function openLane(
  config: GatewayConfig,
  dependencies: GatewayDependencies,
  lines: string[],
): Promise<Lane> {
  const gateway = await Gateway.create(config, {
    ...dependencies,
    io: {
      stdout: (line) => {
        lines.push(line);
      },
      stderr: (line) => {
        lines.push(line);
      },
      color: false,
    },
  });
  const server = new GatewayHttpServer(gateway);
  const address = await server.listen(0, "127.0.0.1");
  return { gateway, server, url: `http://127.0.0.1:${String(address.port)}`, lines };
}

export async function closeLane(lane: Lane): Promise<void> {
  await lane.server.close(CLOSE_GRACE_MS);
  await lane.gateway.close();
}

function stateOf(headers: Headers): GatewayState | null {
  const state = headers.get("agentsafe-state");
  if (state !== null) return state as GatewayState;
  if (headers.get("agentsafe-decision") === "ALLOW") return "ALLOW";
  if (headers.get("agentsafe-mode") === "SHADOW") return "SHADOW";
  return null;
}

function verdictOf(state: GatewayState | null): "ALLOW" | "ESCALATE" | "BLOCK" | null {
  return state === "ALLOW" || state === "ESCALATE" || state === "BLOCK" ? state : null;
}

/** Sends one case at one base URL and reads what the target recorded for it. */
export async function send(
  base: string,
  testCase: BoundaryCase,
  target: RecordingTarget,
): Promise<PassOutcome> {
  const before = target.received.length;
  let response: Response | null = null;
  try {
    response = await fetch(`${base}${testCase.path}`, {
      method: testCase.method,
      headers: testCase.headers,
      ...(testCase.body === null ? {} : { body: testCase.body }),
      redirect: "manual",
    });
    await response.arrayBuffer();
  } catch {
    response = null;
  }
  const arrived = target.received.slice(before);
  const forgedHeadersReached = arrived.some((request) =>
    request.headerNames.some((name) => name in FORGED_HEADERS),
  );
  const state = response === null ? null : stateOf(response.headers);
  const execution =
    response === null
      ? null
      : (response.headers.get("agentsafe-execution") as ExecutionDisposition | null);
  return {
    reached: arrived.length > 0,
    forwarded: arrived.length,
    status: response?.status ?? null,
    state,
    verdict: verdictOf(state),
    execution,
    dossier: response !== null && response.headers.get("agentsafe-dossier-id") !== null,
    forgedHeadersReached,
  };
}

/** The `SHADOW` reports a lane has written so far, in the order they settled. */
export function shadowReports(lane: Lane): Observation[] {
  const observations: Observation[] = [];
  for (const line of lane.lines) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof parsed !== "object" || parsed === null) continue;
    const report = parsed as {
      event?: unknown;
      state?: unknown;
      verdict?: unknown;
      decision_id?: unknown;
      dossier_id?: unknown;
      reason_codes?: unknown;
    };
    if (report.event !== "INTERCEPTED" || report.state !== "SHADOW") continue;
    const verdict = report.verdict;
    observations.push({
      verdict:
        verdict === "ALLOW" || verdict === "ESCALATE" || verdict === "BLOCK" ? verdict : null,
      dossier: typeof report.dossier_id === "string",
      decisionId: typeof report.decision_id === "string" ? report.decision_id : null,
      dossierId: typeof report.dossier_id === "string" ? report.dossier_id : null,
      reasonCodes: Array.isArray(report.reason_codes)
        ? report.reason_codes.filter((code): code is string => typeof code === "string")
        : [],
    });
  }
  return observations;
}

/**
 * A shadow observation settles after the response, on the report stream,
 * one per governed request and in the order they were sent, since each is
 * awaited before the next is sent. The `ordinal`-th governed request's
 * observation is the `ordinal`-th `SHADOW` report, or none within the
 * bound when the observation itself could not be made.
 */
export async function awaitObservation(
  lane: Lane,
  ordinal: number,
  timeoutMs: number,
  clock: () => number,
): Promise<Observation> {
  const deadline = clock() + timeoutMs;
  for (;;) {
    const observation = shadowReports(lane)[ordinal - 1];
    if (observation !== undefined) return observation;
    if (clock() >= deadline) return NO_OBSERVATION;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** Runs the whole test and returns the report; nothing is printed here. */
export async function runBoundaryTest(options: BoundaryTestOptions): Promise<BoundaryTestReport> {
  const clock = options.clock ?? ((): number => Date.now());
  const cases = options.cases ?? BOUNDARY_CASES;
  const observationTimeoutMs = options.observationTimeoutMs ?? DEFAULT_OBSERVATION_TIMEOUT_MS;
  const target = new RecordingTarget();
  await target.start();
  // One demo authority for every lane; the lanes get a handle whose stop
  // is a no-op, and the authority is stopped once, at the end.
  const authority = await (options.demoAuthority ?? startDemoAuthority)();
  const shared = (): Promise<DemoAuthorityHandle> =>
    Promise.resolve({ baseUrl: authority.baseUrl, apiKey: authority.apiKey, stop: async () => {} });
  const lanes: Lane[] = [];
  const open = async (
    mode: Mode,
    policy: Policy,
    outage: boolean,
    lines: string[] = [],
  ): Promise<Lane> => {
    const lane = await openLane(
      configFor(target.baseUrl, mode, policy, options.version),
      {
        env: {},
        version: options.version,
        clock,
        demoAuthority: shared,
        ...(outage ? { authorityFetch: AUTHORITY_DOWN } : {}),
      },
      lines,
    );
    lanes.push(lane);
    return lane;
  };
  try {
    const shadow = await open("shadow", "failClosed", false);
    const shadowOutage = await open("shadow", "failClosed", true);
    const enforcement = await open("enforcement", "failClosed", false);
    const enforcementOutage = await open("enforcement", "failClosed", true);
    const failOpenOutage = await open("enforcement", "failOpen", true);
    const results: BoundaryCaseResult[] = [];
    const governedSent = new Map<Lane, number>();
    for (const testCase of cases) {
      const direct = await send(target.baseUrl, testCase, target);
      const shadowLane = testCase.outage ? shadowOutage : shadow;
      const governed = shadowLane.gateway.plan(testCase.method, testCase.path).kind === "GOVERN";
      const ordinal = (governedSent.get(shadowLane) ?? 0) + (governed ? 1 : 0);
      governedSent.set(shadowLane, ordinal);
      const shadowSent = await send(shadowLane.url, testCase, target);
      const observed = governed
        ? await awaitObservation(shadowLane, ordinal, observationTimeoutMs, clock)
        : NO_OBSERVATION;
      const shadowOutcome: PassOutcome = {
        ...shadowSent,
        state: governed ? "SHADOW" : null,
        verdict: observed.verdict,
        dossier: observed.dossier,
      };
      const enforcementLane = testCase.outage ? enforcementOutage : enforcement;
      const enforced = await send(enforcementLane.url, testCase, target);
      const failOpen = testCase.outage ? await send(failOpenOutage.url, testCase, target) : null;
      results.push({
        id: testCase.id,
        title: testCase.title,
        adversarial: testCase.adversarial,
        request: {
          method: testCase.method,
          path: testCase.path,
          body: testCase.body,
          outage: testCase.outage,
        },
        direct,
        shadow: shadowOutcome,
        enforcement: enforced,
        failOpen,
      });
    }
    const adversarial = results.filter((result) => result.adversarial);
    const routine = results.filter((result) => !result.adversarial);
    const exposure = {
      adversarial: adversarial.length,
      direct: adversarial.filter((result) => result.direct.reached).length,
      shadow: adversarial.filter((result) => result.shadow.reached).length,
      enforcement: adversarial.filter((result) => result.enforcement.reached).length,
    };
    const workFlowed = routine.every((result) => result.enforcement.forwarded === 1);
    // Each enforcing lane left chains of its own, from genesis; each is
    // verified on its own, the way `agentsafe verify chain` would.
    const chains = [enforcement, enforcementOutage].map((lane) => verifyAuditChain(lane.lines));
    const evidence = {
      lines: chains.reduce((sum, chain) => sum + chain.lines - chain.ignored, 0),
      verified: chains.every((chain) => chain.ok),
    };
    return {
      version: BOUNDARY_TEST_VERSION,
      at: new Date(clock()).toISOString(),
      runtime: options.version,
      authority: "local/demo",
      target: "synthetic loopback",
      cases: results,
      exposure,
      workFlowed,
      evidence,
      verdict:
        exposure.enforcement === 0 && workFlowed && evidence.verified
          ? "BOUNDARY_HOLDS"
          : "BOUNDARY_BROKEN",
    };
  } finally {
    for (const lane of lanes) await closeLane(lane);
    await authority.stop();
    await target.stop();
  }
}
