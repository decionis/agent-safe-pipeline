/**
 * Changed conditions demo: the Changed Conditions Test.
 *
 * The Compromised Principal Test holds the world still and lets the principal
 * misbehave. This one does the opposite: the principal is honest, every
 * proposal it makes is one the policy allowed when it was decided, and the
 * world changes between the decision and the commit. A configuration changes
 * at the path a rollout read, the target group grows, another rollout takes
 * the last of the allowance, the change approval is withdrawn, a new policy is
 * released, a security group becomes production. Each of those has to stop
 * the queued work at the commit, and each has a legitimate counterpart that
 * must still complete: a valid renewal proceeds, a safe retry keeps its
 * identity, a repaired dependency allows reauthorized work.
 *
 * Everything runs offline over real HTTP: the loopback Decionis double from
 * the pipeline's testing entry decides and re-derives authority at the claim,
 * the production `DecionisGate`, `DecionisGrantVerifier` and
 * `GovernedExecutionRunner` carry the work, and the recording target behind
 * `agentsafe test` is the deploy and network API. The target is the observer:
 * every count below is what reached it, not what any component said. The run
 * is a self-checking proof and exits 0 only when no attempt on changed
 * conditions reached the target and every counterpart reached it exactly once.
 *
 * Two rollouts racing for the last unit of an allowance are refused when the
 * allowance is a material signal re-versioned with each commit: the signal is
 * the claim's concurrency scope, and the next claim reads its new version.
 * One case is beyond what the boundary decides today and is reported as
 * such: when the allowance is published after the commit rather than with it,
 * a claim inside that window reads the old value, and both rollouts commit.
 * That window, like any limit nobody publishes, needs the authority to
 * reserve the allowance with the grant. The run asserts today's result for
 * it, so the day it changes the case has to be moved, not quietly passed.
 *
 * All identities, services, groups and organisations are synthetic.
 */
import process from "node:process";
import { z } from "zod";
import {
  ActionRegistry,
  DecionisGate,
  DecionisGrantVerifier,
  GovernedExecutionRunner,
  IntentCapture,
  RegistryExecutor,
  type AgentProposal,
  type CapturedIntent,
  type DecisionGate,
  type SafeExecutionResult,
} from "@decionis/agent-safe-pipeline";
import {
  LocalAuthority,
  type LocalAuthorityPolicy,
  type LocalAuthorityPolicyInput,
} from "@decionis/agent-safe-pipeline/testing";
import { RecordingTarget } from "@decionis/agentsafe";

const ORG = "00000000-0000-4000-8000-000000000003";
const OTHER_ORG = "00000000-0000-4000-8000-000000000004";
/** Every hosted key belongs to one organisation; these two do as well. */
const ORG_KEY = "synthetic-org-executor-key";
const OTHER_ORG_KEY = "synthetic-other-org-executor-key";
/** What the agent holds: a credential to propose to its executor, and nothing the authority accepts. */
const AGENT_CREDENTIAL = "synthetic-agent-caller-token";
/** A policy and a proposal as the hosted policy lifecycle addresses them; synthetic. */
const POLICY_ID = "11111111-1111-4111-8111-111111111111";
const PRINCIPAL = "synthetic-deploy-agent";
const RUNTIME = "changed-conditions-demo";

/** The material signals the systems of record publish, by id. */
const CONFIG = "config:checkout/prod/app.yaml";
const GROUP = "group:checkout-canary";
const ALLOWANCE = "allowance:checkout-canary";
const CHANGE = "change:CHG-1042";
const classificationOf = (group: string): string => `classification:${group}`;
const ADMIN_PORTS: ReadonlySet<number> = new Set([22, 3389]);
const EVERYWHERE = "0.0.0.0/0";
const BASTION = "10.20.0.0/24";

const out = (line: string): void => {
  process.stdout.write(`${line}\n`);
};

// ---------------------------------------------------------------------------
// The governance authority's controls. Only `release` changes them, and only
// from here, outside every credential the agent or its executor holds.

interface Controls {
  readonly canaryMaxHosts: number;
  readonly blockedVersions: ReadonlySet<string>;
}

let controls: Controls = { canaryMaxHosts: 4, blockedVersions: new Set() };

const RolloutParameters = z
  .object({
    service: z.string().min(1),
    version: z.string().min(1),
    group: z.string().min(1),
    hosts: z.number().int().positive(),
    config_digest: z.string().min(1),
    change: z.string().min(1),
  })
  .strict();
const RuleParameters = z
  .object({
    group: z.string().min(1),
    protocol: z.literal("tcp"),
    port: z.number().int().min(1).max(65_535),
    cidr: z.string().min(1),
  })
  .strict();

function field(signals: Readonly<Record<string, unknown>>, id: string, key: string): unknown {
  const value = signals[id];
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

/**
 * Synthetic policy over the exact action and the world as published. A canary
 * names the configuration it read and the group as it is, stays inside the
 * ceiling, needs an allowance left and an approved change, and never ships a
 * blocked build. A firewall rule never opens an administrative port of a
 * production security group to every address: the article's invariant.
 */
function policyFor(current: Controls): LocalAuthorityPolicy {
  return (request: LocalAuthorityPolicyInput) => {
    const signals = request.material_signals ?? {};
    if (request.action.type === "rollout.canary") {
      const rollout = RolloutParameters.safeParse(request.action.parameters);
      if (!rollout.success) return "BLOCK";
      const { version, hosts, config_digest: configDigest } = rollout.data;
      if (configDigest !== field(signals, CONFIG, "digest")) return "BLOCK";
      if (hosts !== field(signals, GROUP, "hosts")) return "BLOCK";
      if (hosts > current.canaryMaxHosts) return "BLOCK";
      if (Number(field(signals, ALLOWANCE, "remaining") ?? 0) < 1) return "BLOCK";
      if (field(signals, CHANGE, "status") !== "APPROVED") return "BLOCK";
      return current.blockedVersions.has(version) ? "BLOCK" : "ALLOW";
    }
    if (request.action.type === "firewall.rule.add") {
      const rule = RuleParameters.safeParse(request.action.parameters);
      if (!rule.success) return "BLOCK";
      const environment = field(signals, classificationOf(rule.data.group), "environment");
      if (environment === undefined) return "BLOCK";
      const exposesAdministration =
        environment === "production" &&
        ADMIN_PORTS.has(rule.data.port) &&
        rule.data.cidr === EVERYWHERE;
      return exposesAdministration ? "BLOCK" : "ALLOW";
    }
    return "BLOCK";
  };
}

const authority = new LocalAuthority({
  policy: policyFor(controls),
  tenantKeys: { [ORG_KEY]: ORG, [OTHER_ORG_KEY]: OTHER_ORG },
  // The reconciliations resource is reachable only on an addressable grant.
  addressableGrants: true,
  materialSignals: (request) =>
    request.action.type === "rollout.canary"
      ? [CONFIG, GROUP, ALLOWANCE, CHANGE]
      : [classificationOf(String(request.action.parameters.group))],
});

function release(next: Controls): string {
  controls = next;
  return authority.releasePolicy(policyFor(next));
}

// ---------------------------------------------------------------------------
// The world: what the systems of record hold and publish. The agent reads it
// before it proposes, as an honest agent does.

const world = {
  configDigest: "c41",
  groupHosts: 4,
  allowance: 10,
  change: "APPROVED",
  classification: new Map<string, string>([
    ["sg-admin", "production"],
    ["sg-build", "staging"],
  ]),
};

function publishWorld(): void {
  authority.publishSignal(CONFIG, { digest: world.configDigest });
  authority.publishSignal(GROUP, { hosts: world.groupHosts });
  authority.publishSignal(ALLOWANCE, { remaining: world.allowance });
  authority.publishSignal(CHANGE, { status: world.change });
  for (const [group, environment] of world.classification) {
    authority.publishSignal(classificationOf(group), { environment });
  }
}

const setConfig = (digest: string): void => {
  world.configDigest = digest;
  authority.publishSignal(CONFIG, { digest });
};
const setGroup = (hosts: number): void => {
  world.groupHosts = hosts;
  authority.publishSignal(GROUP, { hosts });
};
const setAllowance = (remaining: number): void => {
  world.allowance = remaining;
  authority.publishSignal(ALLOWANCE, { remaining });
};
const setChange = (status: string): void => {
  world.change = status;
  authority.publishSignal(CHANGE, { status });
};
const classify = (group: string, environment: string): void => {
  world.classification.set(group, environment);
  authority.publishSignal(classificationOf(group), { environment });
};
/**
 * The deploy system's allowance, published as a material signal. It counts a
 * rollout it applied and re-versions the allowance as part of that commit, so
 * the next claim against the old version is stale. `lag()` makes it publish
 * later instead, on a schedule of its own, until `catchUp()`: the window the
 * open case measures.
 */
class AllowanceProducer {
  private lagging = false;
  private owed = 0;

  public applied(): void {
    if (this.lagging) this.owed += 1;
    else setAllowance(world.allowance - 1);
  }

  public lag(): void {
    this.lagging = true;
  }

  public catchUp(): void {
    this.lagging = false;
    setAllowance(world.allowance - this.owed);
    this.owed = 0;
  }
}

const producer = new AllowanceProducer();

// ---------------------------------------------------------------------------
// The target and the wire to it. The recording target is the deploy and
// network API, and the observer: it records every request that reaches it.

const target = new RecordingTarget();

/** The executor's connection to the target, with the transport faults a case can ask for. */
class Wire {
  private readonly faults: ("DROP_REQUEST" | "DROP_ACKNOWLEDGEMENT")[] = [];
  private readonly latches: Promise<void>[] = [];

  public dropNextRequest(): void {
    this.faults.push("DROP_REQUEST");
  }

  public dropNextAcknowledgement(): void {
    this.faults.push("DROP_ACKNOWLEDGEMENT");
  }

  /** Holds the next send until the returned function is called: a write in flight. */
  public holdNext(): () => void {
    let open = (): void => {};
    this.latches.push(
      new Promise<void>((resolve) => {
        open = resolve;
      }),
    );
    return open;
  }

  public async post(path: string, body: unknown): Promise<number> {
    const fault = this.faults.shift();
    await this.latches.shift();
    // The connection dropped before the request was written.
    if (fault === "DROP_REQUEST") throw new Error("CONNECTION_RESET");
    const response = await fetch(`${target.baseUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    await response.arrayBuffer();
    // The deploy API applied the rollout; its allowance moves with the commit,
    // whether or not the answer makes it back.
    if (response.ok && path.startsWith("/deployments/")) producer.applied();
    // The request landed and the answer never came back.
    if (fault === "DROP_ACKNOWLEDGEMENT") throw new Error("ACKNOWLEDGEMENT_LOST");
    if (!response.ok) throw new Error("TARGET_ERROR");
    return response.status;
  }
}

const wire = new Wire();
const rolloutPath = (service: string, identity: string): string =>
  `/deployments/${service}/rollouts/${identity}`;
const rulePath = (group: string, identity: string): string =>
  `/security-groups/${group}/rules/${identity}`;
const arrivalsAt = (path: string): number =>
  target.received.filter((request) => request.method === "POST" && request.path === path).length;

const registry = new ActionRegistry()
  .register("rollout.canary", {
    parametersSchema: RolloutParameters,
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async (identity) => ({
        status: await wire.post(rolloutPath(parameters.service, identity), parameters),
      })),
    // Read-only: the deploy API's own record of the rollout, by its identity.
    reconcile: ({ parameters, idempotencyKey }) =>
      arrivalsAt(rolloutPath(parameters.service, idempotencyKey)) > 0
        ? { status: "COMPLETED", result: { status: 201 } }
        : { status: "NOT_EXECUTED" },
  })
  .register("firewall.rule.add", {
    parametersSchema: RuleParameters,
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async (identity) => ({
        status: await wire.post(rulePath(parameters.group, identity), parameters),
      })),
  })
  .seal();
const executor = new RegistryExecutor(registry, "synthetic-deploy-api");

function laneFor(apiKey: string) {
  const options = { baseUrl: authority.baseUrl, apiKey, allowInsecureLoopback: true };
  return {
    gate: new DecionisGate(options),
    runner: new GovernedExecutionRunner({ verifier: new DecionisGrantVerifier(options) }),
  };
}

// ---------------------------------------------------------------------------
// The agent's proposals, read from the world as it is when it proposes.

let sequence = 0;
const identity = (label: string): string => {
  sequence += 1;
  return `synthetic-${label}-${sequence}`;
};

function rollout(version: string, hosts = world.groupHosts): AgentProposal {
  return {
    action: "rollout.canary",
    target: "deploy:checkout/canary",
    parameters: {
      service: "checkout",
      version,
      group: "checkout-canary",
      hosts,
      config_digest: world.configDigest,
      change: "CHG-1042",
    },
  };
}

function rule(group: string, port: number, cidr: string): AgentProposal {
  return {
    action: "firewall.rule.add",
    target: `network:security-groups/${group}`,
    parameters: { group, protocol: "tcp", port, cidr },
  };
}

function capture(proposal: AgentProposal, key: string, tenantId = ORG): CapturedIntent {
  return new IntentCapture({ ttlSeconds: 120 }).capture(proposal, {
    tenantId,
    // The principal is trusted context, valid every time: nothing here is about identity.
    actor: { id: PRINCIPAL, type: "AI_AGENT", runtime: RUNTIME },
    downstreamTarget:
      proposal.action === "rollout.canary"
        ? { system: "deploy", operation: "rollouts/canary", environment: "production" }
        : { system: "network", operation: "security-groups/rules" },
    idempotencyKey: key,
    context: { source: RUNTIME },
  });
}

/** The authority's own answer to the last claim it was asked for. */
function lastClaim(): { readonly status: number | null; readonly reason: string } {
  const claim = [...authority.requests]
    .reverse()
    .find((request) => request.path.endsWith("/claims") || request.path.endsWith("/claim-token"));
  const body = claim?.response?.body as { readonly reason_codes?: readonly string[] } | undefined;
  return { status: claim?.response?.status ?? null, reason: body?.reason_codes?.[0] ?? "none" };
}

const grantOf = (decision: DecisionGate) =>
  authority.grants.get(decision.authorization?.token ?? "");
const outcomeOf = (result: SafeExecutionResult): string =>
  result.outcome === "BLOCKED" ? `BLOCKED ${result.reason}` : result.outcome;

// ---------------------------------------------------------------------------
// Steps and the observer's counts.

/**
 * `attempt`: work on changed conditions, which must not reach the target.
 * `counterpart`: legitimate work, which must reach it exactly once, at the
 * path its identity names. `recovery`: an attempt whose outcome was lost, on
 * its way to reconciliation. `open`: a case the boundary does not close today.
 */
type Kind = "attempt" | "counterpart" | "recovery" | "open";
interface Step {
  readonly testCase: string;
  readonly kind: Kind;
  readonly title: string;
  readonly expected: string;
  readonly observed: string;
  readonly arrivals: number;
  readonly path: string | null;
  readonly ok: boolean;
}
const steps: Step[] = [];
let currentCase = "";

function begin(index: number, title: string, story: string): void {
  currentCase = title;
  out(`\n[case ${index}] ${title}`);
  out(`    ${story}`);
}

async function step(
  kind: Kind,
  title: string,
  expected: string,
  run: () => Promise<{ readonly observed: string; readonly ok: boolean; readonly path?: string }>,
  expectedArrivals = 0,
): Promise<void> {
  const before = target.received.length;
  let observed: string;
  let ok: boolean;
  let path: string | null = null;
  try {
    const answer = await run();
    ({ observed, ok } = answer);
    path = answer.path ?? null;
  } catch (error) {
    observed = `threw ${error instanceof Error ? error.message : "unknown"}`;
    ok = false;
  }
  const arrivals = target.received.length - before;
  // A counterpart is judged by the identity it was proposed with: one
  // request at its path, however and whenever it got there. Everything else
  // is judged by what arrived while it ran.
  const reached =
    kind === "counterpart"
      ? path !== null && arrivalsAt(path) === 1
      : arrivals === (kind === "attempt" ? 0 : expectedArrivals);
  const passed = ok && reached;
  steps.push({
    testCase: currentCase,
    kind,
    title,
    expected,
    observed,
    arrivals,
    path,
    ok: passed,
  });
  out(`    ${passed ? (kind === "open" ? "OPEN" : "PASS") : "FAIL"} ${kind}: ${title}`);
  out(
    `         ${observed}; ${kind === "counterpart" && path !== null ? `requests at its path ${arrivalsAt(path)}` : `reached the target ${arrivals}`}`,
  );
}

/** Decides and runs one proposal on a lane, and says what happened. */
async function propose(
  lane: ReturnType<typeof laneFor>,
  proposal: AgentProposal,
  key: string,
): Promise<{ captured: CapturedIntent; decision: DecisionGate; result: SafeExecutionResult }> {
  const captured = capture(proposal, key);
  const decision = await lane.gate.evaluate(captured);
  const result = await lane.runner.dispatch(executor, { captured, decision, action: captured });
  return { captured, decision, result };
}

async function decide(
  lane: ReturnType<typeof laneFor>,
  proposal: AgentProposal,
  key: string,
): Promise<{ captured: CapturedIntent; decision: DecisionGate }> {
  const captured = capture(proposal, key);
  return { captured, decision: await lane.gate.evaluate(captured) };
}

const run = async (
  lane: ReturnType<typeof laneFor>,
  queued: { captured: CapturedIntent; decision: DecisionGate },
): Promise<SafeExecutionResult> =>
  await lane.runner.dispatch(executor, {
    captured: queued.captured,
    decision: queued.decision,
    action: queued.captured,
  });

/** A queued grant presented after the world changed: refused at the claim, and not consumed. */
async function stale(
  lane: ReturnType<typeof laneFor>,
  queued: { captured: CapturedIntent; decision: DecisionGate },
  reason: string,
): Promise<{ observed: string; ok: boolean }> {
  const result = await run(lane, queued);
  const claim = lastClaim();
  const unspent = grantOf(queued.decision)?.claimed === false;
  return {
    observed: `authority ${claim.status} ${claim.reason} at the claim; executor ${outcomeOf(result)}; grant unspent ${unspent}`,
    ok: result.outcome === "BLOCKED" && claim.reason === reason && unspent,
  };
}

/** A proposal the authority refuses at decision under the world as it now is. */
async function refused(
  lane: ReturnType<typeof laneFor>,
  proposal: AgentProposal,
  label: string,
): Promise<{ observed: string; ok: boolean }> {
  const { decision, result } = await propose(lane, proposal, identity(label));
  return {
    observed: `authority ${decision.verdict}; executor ${outcomeOf(result)}`,
    ok: decision.verdict === "BLOCK" && result.outcome === "BLOCKED",
  };
}

/** A legitimate proposal that has to complete, once, at the path its identity names. */
async function completes(
  lane: ReturnType<typeof laneFor>,
  proposal: AgentProposal,
  label: string,
): Promise<{ observed: string; ok: boolean; path: string }> {
  const key = identity(label);
  const { decision, result } = await propose(lane, proposal, key);
  const committed = grantOf(decision)?.finalized === "COMMITTED";
  return {
    observed: `authority ${decision.verdict} under ${authority.policyVersion}; executor ${outcomeOf(result)}; recorded COMMITTED ${committed}`,
    ok: decision.verdict === "ALLOW" && result.outcome === "COMPLETED" && committed,
    path: pathOf(proposal, key),
  };
}

function pathOf(proposal: AgentProposal, key: string): string {
  const parameters = proposal.parameters as { service?: string; group?: string };
  return proposal.action === "rollout.canary"
    ? rolloutPath(String(parameters.service), key)
    : rulePath(String(parameters.group), key);
}

// ---------------------------------------------------------------------------

await target.start();
await authority.start();
publishWorld();
const lane = laneFor(ORG_KEY);

out("Changed conditions demo: the Changed Conditions Test");
out(
  `Principal ${PRINCIPAL} is honest throughout: it proposes from the world as it reads it, and never alters what was decided.`,
);
out(
  "What changes is the world, between the decision and the commit. The target counts what reached it.",
);

// ---------------------------------------------------------------------------
begin(
  1,
  "The configuration changes at the same path",
  "A canary is decided against checkout/prod/app.yaml at c41; while it is queued, the file at that path becomes c42.",
);
{
  const queued = await decide(lane, rollout("2.4.1"), identity("config"));
  setConfig("c42");
  await step("attempt", "the queued rollout, decided against c41", "SIGNAL_VERSION_STALE", () =>
    stale(lane, queued, "SIGNAL_VERSION_STALE"),
  );
  await step(
    "counterpart",
    "reauthorized work: the agent reads c42 and proposes again",
    "ALLOW, one rollout",
    () => completes(lane, rollout("2.4.1"), "config-reread"),
  );
}

// ---------------------------------------------------------------------------
begin(
  2,
  "The target group grows",
  "A four-host canary is decided; while it is queued, autoscaling grows the canary group to six, past the four-host ceiling.",
);
{
  const queued = await decide(lane, rollout("2.4.1"), identity("group"));
  setGroup(6);
  await step("attempt", "the queued four-host rollout", "SIGNAL_VERSION_STALE", () =>
    stale(lane, queued, "SIGNAL_VERSION_STALE"),
  );
  await step("attempt", "the same rollout proposed for the group as it now is", "BLOCK", () =>
    refused(lane, rollout("2.4.1"), "group-six"),
  );
  setGroup(4);
  await step(
    "counterpart",
    "a repaired dependency: the group is pinned back to four, and the work is reauthorized",
    "ALLOW, one rollout",
    () => completes(lane, rollout("2.4.1"), "group-repaired"),
  );
}

// ---------------------------------------------------------------------------
begin(
  3,
  "Two rollouts race for the last unit of the allowance",
  "One canary is left in today's allowance, a material signal the deploy API re-versions with every commit. Two rollouts are decided against it; the first is in flight when the second is presented.",
);
{
  setAllowance(1);
  const first = await decide(lane, rollout("2.4.1"), identity("allowance-first"));
  const second = await decide(lane, rollout("2.4.2"), identity("allowance-second"));
  const open = wire.holdNext();
  const firstRun = run(lane, first);
  // The first rollout is claimed and its write is in flight, held on the wire.
  for (let waited = 0; grantOf(first.decision)?.claimed !== true && waited < 2_000; waited += 2) {
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  await step(
    "attempt",
    "the second rollout, while the first holds the allowance",
    "AUTHORIZATION_SCOPE_BUSY",
    async () => {
      const result = await run(lane, second);
      const claim = lastClaim();
      return {
        observed: `authority ${claim.status} ${claim.reason} at the claim; executor ${outcomeOf(result)}`,
        ok: result.outcome === "BLOCKED" && claim.reason === "AUTHORIZATION_SCOPE_BUSY",
      };
    },
  );
  await step(
    "counterpart",
    "the first rollout, which held the allowance, completes",
    "COMPLETED, one rollout",
    async () => {
      open();
      const result = await firstRun;
      const committed = grantOf(first.decision)?.finalized === "COMMITTED";
      return {
        observed: `executor ${outcomeOf(result)}; recorded COMMITTED ${committed}; the deploy API re-versioned the allowance to ${world.allowance} with the commit`,
        ok: result.outcome === "COMPLETED" && committed,
        path: rolloutPath("checkout", first.captured.intent.idempotencyKey),
      };
    },
  );
  await step(
    "attempt",
    "the second rollout, presented again after the commit re-versioned the allowance to zero",
    "SIGNAL_VERSION_STALE",
    () => stale(lane, second, "SIGNAL_VERSION_STALE"),
  );
  await step("attempt", "the second rollout, proposed again", "BLOCK", () =>
    refused(lane, rollout("2.4.2"), "allowance-again"),
  );
  setAllowance(10);
  await step(
    "counterpart",
    "a valid renewal after a top-up: tomorrow's allowance is published, and the second rollout proceeds",
    "ALLOW, one rollout",
    () => completes(lane, rollout("2.4.2"), "allowance-renewed"),
  );
}

// ---------------------------------------------------------------------------
begin(
  4,
  "The approval is withdrawn while the rollout is queued",
  "CHG-1042 is approved and a canary is decided under it; the change board withdraws the approval before it runs.",
);
{
  const queued = await decide(lane, rollout("2.4.3"), identity("approval"));
  setChange("WITHDRAWN");
  await step("attempt", "the queued rollout", "SIGNAL_VERSION_STALE", () =>
    stale(lane, queued, "SIGNAL_VERSION_STALE"),
  );
  await step("attempt", "the rollout proposed again while the change is withdrawn", "BLOCK", () =>
    refused(lane, rollout("2.4.3"), "approval-withdrawn"),
  );
  setChange("APPROVED");
  await step(
    "counterpart",
    "a valid renewal: the change is approved again, and the rollout proceeds",
    "ALLOW, one rollout",
    () => completes(lane, rollout("2.4.3"), "approval-renewed"),
  );
}

// ---------------------------------------------------------------------------
begin(
  5,
  "A policy release lands between the grant and the claim",
  "A canary of 2.4.4 is decided; the policy owner then releases a policy that blocks build 2.4.0.",
);
{
  const queued = await decide(lane, rollout("2.4.4"), identity("release"));
  const released = release({ ...controls, blockedVersions: new Set(["2.4.0"]) });
  await step(
    "attempt",
    `the queued rollout, decided before ${released}`,
    "POLICY_VERSION_STALE",
    () => stale(lane, queued, "POLICY_VERSION_STALE"),
  );
  await step(
    "counterpart",
    `a valid renewal: the same rollout decided under ${released}`,
    "ALLOW, one rollout",
    () => completes(lane, rollout("2.4.4"), "release-renewed"),
  );
}

// ---------------------------------------------------------------------------
begin(
  6,
  "The agent tries to change the controls with its own credential",
  "The canary group grows to six and the agent wants a six-host canary, past the ceiling it is held to.",
);
{
  setGroup(6);
  await step("attempt", "a six-host canary under the four-host ceiling", "BLOCK", () =>
    refused(lane, rollout("2.4.5", 6), "controls-six"),
  );
  await step(
    "attempt",
    "the agent raises the ceiling itself, at the policy lifecycle and through a signal",
    "401 at both",
    async () => {
      const before = authority.policyVersion;
      const call = async (path: string, credential: string): Promise<string> => {
        const response = await fetch(`${authority.baseUrl}${path}`, {
          method: "POST",
          headers: { authorization: `Bearer ${credential}`, "content-type": "application/json" },
          body: JSON.stringify({ canary_max_hosts: 6 }),
        });
        const body = (await response.json()) as { readonly error?: string };
        return `${response.status} ${body.error ?? "none"}`;
      };
      const decisions = `/v1/policies/${POLICY_ID}/proposals/${POLICY_ID}/decisions`;
      const policy = await call(decisions, AGENT_CREDENTIAL);
      const signal = await call("/v1/protocol/signals/envelopes", AGENT_CREDENTIAL);
      // Not even the executor's own key reaches the policy lifecycle.
      const executorKey = await call(decisions, ORG_KEY);
      const unchanged = authority.policyVersion === before;
      return {
        observed: `policy lifecycle ${policy}; signal ingestion ${signal}; with the executor's key ${executorKey}; policy unchanged ${unchanged}`,
        ok:
          policy === "401 ACCOUNT_SESSION_REQUIRED" &&
          signal === "401 UNAUTHORIZED" &&
          executorKey === "401 ACCOUNT_SESSION_REQUIRED" &&
          unchanged,
      };
    },
  );
  const released = release({ ...controls, canaryMaxHosts: 6 });
  await step(
    "counterpart",
    `the change made where it belongs: the policy owner releases ${released} with a six-host ceiling`,
    "ALLOW, one rollout",
    () => completes(lane, rollout("2.4.5", 6), "controls-released"),
  );
  setGroup(4);
}

// ---------------------------------------------------------------------------
begin(
  7,
  "The proposal content is substituted after the decision",
  "A canary of 2.4.6 is decided; the executor is then handed the same decision with 2.4.7 in its place.",
);
{
  const decided = await decide(lane, rollout("2.4.6"), identity("substitution"));
  await step(
    "attempt",
    "2.4.7 presented with the 2.4.6 decision",
    "INTENT_BINDING_MISMATCH",
    async () => {
      const substituted = capture(rollout("2.4.7"), decided.captured.intent.idempotencyKey);
      const result = await run(lane, { captured: substituted, decision: decided.decision });
      return {
        observed: `executor ${outcomeOf(result)}; the authority was not asked: ${grantOf(decided.decision)?.claimed === false}`,
        ok: result.outcome === "BLOCKED" && result.reason === "INTENT_BINDING_MISMATCH",
      };
    },
  );
  await step(
    "counterpart",
    "reauthorized work: 2.4.7 proposed in its own right",
    "ALLOW, one rollout",
    () => completes(lane, rollout("2.4.7"), "substitution-own"),
  );
}

// ---------------------------------------------------------------------------
begin(
  8,
  "A lost request, a replayed grant, and a safe retry",
  "The connection drops before a canary's request is written. Reconciliation proves nothing landed.",
);
{
  const key = identity("retry");
  const lost = await decide(lane, rollout("2.4.8"), key);
  wire.dropNextRequest();
  await step(
    "recovery",
    "the attempt whose request never left: INDETERMINATE, then reconciled as not executed",
    "UNKNOWN_AFTER_DISPATCH, then DEFINITELY_NOT_EXECUTED",
    async () => {
      const result = await run(lane, lost);
      if (result.outcome !== "UNKNOWN_AFTER_DISPATCH") {
        return { observed: `executor ${outcomeOf(result)}`, ok: false };
      }
      const indeterminate = grantOf(lost.decision)?.finalized === "INDETERMINATE";
      const reconciled = await lane.runner.reconcile(executor, {
        captured: lost.captured,
        recovery: result.recovery,
        action: lost.captured,
      });
      const failed = grantOf(lost.decision)?.finalized === "FAILED";
      return {
        observed: `executor ${result.outcome}; recorded INDETERMINATE ${indeterminate}; reconciliation ${reconciled.outcome}; recorded FAILED ${failed}`,
        ok: indeterminate && reconciled.outcome === "DEFINITELY_NOT_EXECUTED" && failed,
      };
    },
    0,
  );
  await step("attempt", "the consumed grant replayed", "NONCE_REPLAY_DETECTED", async () => {
    const result = await run(lane, lost);
    const claim = lastClaim();
    return {
      observed: `authority ${claim.status} ${claim.reason} at the claim; executor ${outcomeOf(result)}`,
      ok: result.outcome === "BLOCKED" && claim.reason === "NONCE_REPLAY_DETECTED",
    };
  });
  await step(
    "counterpart",
    "a safe retry that keeps its identity: a new decision for the same rollout key",
    "ALLOW, one rollout under the original identity",
    async () => {
      const retried = await propose(lane, rollout("2.4.8"), key);
      const committed = grantOf(retried.decision)?.finalized === "COMMITTED";
      return {
        observed: `authority ${retried.decision.verdict}; executor ${outcomeOf(retried.result)}; identity ${key}; recorded COMMITTED ${committed}`,
        ok: retried.result.outcome === "COMPLETED" && committed,
        path: rolloutPath("checkout", key),
      };
    },
  );
}

// ---------------------------------------------------------------------------
begin(
  9,
  "A lost acknowledgement",
  "A canary lands at the deploy API and the answer never comes back. The agent, hearing nothing, asks again.",
);
{
  const key = identity("acknowledgement");
  const landed = await decide(lane, rollout("2.4.9"), key);
  wire.dropNextAcknowledgement();
  let result: SafeExecutionResult | null = null;
  await step(
    "recovery",
    "the rollout lands and its acknowledgement is lost",
    "UNKNOWN_AFTER_DISPATCH, recorded INDETERMINATE",
    async () => {
      result = await run(lane, landed);
      const indeterminate = grantOf(landed.decision)?.finalized === "INDETERMINATE";
      return {
        observed: `executor ${result.outcome}; recorded INDETERMINATE ${indeterminate}`,
        ok: result.outcome === "UNKNOWN_AFTER_DISPATCH" && indeterminate,
      };
    },
    1,
  );
  await step(
    "attempt",
    "an eager retry of the same rollout while the first is unresolved",
    "CURRENT_STATE_UNRESOLVED",
    async () => {
      const retry = await decide(lane, rollout("2.4.9"), key);
      const retried = await run(lane, retry);
      const claim = lastClaim();
      return {
        observed: `authority ${retry.decision.verdict}, then ${claim.status} ${claim.reason} at the claim; executor ${outcomeOf(retried)}`,
        ok: retried.outcome === "BLOCKED" && claim.reason === "CURRENT_STATE_UNRESOLVED",
      };
    },
  );
  await step(
    "counterpart",
    "the rollout itself, reconciled from the deploy API's record: no duplicate",
    "COMPLETED on reconciliation, one rollout",
    async () => {
      const lost = result as SafeExecutionResult | null;
      if (lost?.outcome !== "UNKNOWN_AFTER_DISPATCH") {
        return { observed: "nothing to reconcile", ok: false };
      }
      const reconciled = await lane.runner.reconcile(executor, {
        captured: landed.captured,
        recovery: lost.recovery,
        action: landed.captured,
      });
      const committed = grantOf(landed.decision)?.finalized === "COMMITTED";
      return {
        observed: `reconciliation ${reconciled.outcome}; recorded COMMITTED ${committed}; nothing sent again`,
        ok: reconciled.outcome === "COMPLETED" && committed,
        path: rolloutPath("checkout", key),
      };
    },
  );
}

// ---------------------------------------------------------------------------
begin(
  10,
  "A grant is carried into another organisation",
  "Another organisation's executor, with its own valid key, is handed this organisation's grant.",
);
{
  const other = laneFor(OTHER_ORG_KEY);
  const decided = await decide(lane, rollout("2.5.0"), identity("organisation"));
  await step("attempt", "the grant presented with its own intent", "TENANT_MISMATCH", async () => {
    const result = await run(other, decided);
    const claim = lastClaim();
    return {
      observed: `authority ${claim.status} ${claim.reason} at the claim; executor ${outcomeOf(result)}`,
      ok:
        result.outcome === "BLOCKED" && claim.status === 403 && claim.reason === "TENANT_MISMATCH",
    };
  });
  await step(
    "attempt",
    "the grant presented with the intent rewritten into the other organisation",
    "INTENT_BINDING_MISMATCH",
    async () => {
      const rewritten = capture(
        rollout("2.5.0"),
        decided.captured.intent.idempotencyKey,
        OTHER_ORG,
      );
      const result = await run(other, { captured: rewritten, decision: decided.decision });
      return {
        observed: `executor ${outcomeOf(result)}`,
        ok: result.outcome === "BLOCKED" && result.reason === "INTENT_BINDING_MISMATCH",
      };
    },
  );
  await step(
    "counterpart",
    "the grant used where it was issued",
    "COMPLETED, one rollout",
    async () => {
      const result = await run(lane, decided);
      const committed = grantOf(decided.decision)?.finalized === "COMMITTED";
      return {
        observed: `executor ${outcomeOf(result)}; recorded COMMITTED ${committed}`,
        ok: result.outcome === "COMPLETED" && committed,
        path: rolloutPath("checkout", decided.captured.intent.idempotencyKey),
      };
    },
  );
}

// ---------------------------------------------------------------------------
begin(
  11,
  "No administrative port of a production group open to every address",
  "The invariant at decision, and again at the commit when the group is reclassified while a rule is queued.",
);
{
  await step("attempt", `SSH to ${EVERYWHERE} on sg-admin, a production group`, "BLOCK", () =>
    refused(lane, rule("sg-admin", 22, EVERYWHERE), "rule-admin"),
  );
  await step(
    "counterpart",
    `SSH to sg-admin from the bastion range ${BASTION}`,
    "ALLOW, one rule",
    () => completes(lane, rule("sg-admin", 22, BASTION), "rule-bastion"),
  );
  const queued = await decide(lane, rule("sg-build", 22, EVERYWHERE), identity("rule-build"));
  classify("sg-build", "production");
  await step(
    "attempt",
    `SSH to ${EVERYWHERE} on sg-build, decided while it was staging and presented after it became production`,
    "SIGNAL_VERSION_STALE",
    () => stale(lane, queued, "SIGNAL_VERSION_STALE"),
  );
  await step("attempt", "the same rule proposed for sg-build as it now is", "BLOCK", () =>
    refused(lane, rule("sg-build", 22, EVERYWHERE), "rule-build-again"),
  );
  await step(
    "counterpart",
    `a repaired rule: SSH to sg-build from ${BASTION}`,
    "ALLOW, one rule",
    () => completes(lane, rule("sg-build", 22, BASTION), "rule-build-bastion"),
  );
}

// ---------------------------------------------------------------------------
begin(
  12,
  "The allowance is published after the commit, not with it",
  "The same race as case 3, with a producer that publishes on its own schedule: the second rollout is claimed after the first committed and before the consumed allowance is published.",
);
{
  setAllowance(1);
  const first = await decide(lane, rollout("2.5.1"), identity("late-first"));
  const second = await decide(lane, rollout("2.5.2"), identity("late-second"));
  producer.lag();
  await step(
    "open",
    "both rollouts, inside the window between a commit and its publication",
    "today: both commit; a reservation taken with the grant closes it",
    async () => {
      const a = await run(lane, first);
      const b = await run(lane, second);
      producer.catchUp();
      return {
        observed: `first ${outcomeOf(a)}, second ${outcomeOf(b)}; the allowance, published late, reads ${world.allowance}`,
        ok: a.outcome === "COMPLETED" && b.outcome === "COMPLETED",
      };
    },
    2,
  );
}

// ---------------------------------------------------------------------------
out("\nSummary");
const cases = [...new Set(steps.map((entry) => entry.testCase))];
const width = Math.max(...cases.map((title) => title.length));
for (const title of cases) {
  const own = steps.filter((entry) => entry.testCase === title);
  const of = (kind: Kind): Step[] => own.filter((entry) => entry.kind === kind);
  const held = (kind: Kind): string =>
    `${of(kind).filter((entry) => entry.ok).length} of ${of(kind).length}`;
  const label = own.every((entry) => entry.ok) ? (of("open").length > 0 ? "OPEN" : "PASS") : "FAIL";
  const tally =
    of("open").length > 0
      ? `${own.reduce((sum, entry) => sum + entry.arrivals, 0)} committed against an allowance of 1`
      : `${held("attempt")} refused, ${held("counterpart")} completed`;
  out(`    ${label}  ${title.padEnd(width)}  ${tally}`);
}
const attempts = steps.filter((entry) => entry.kind === "attempt");
const counterparts = steps.filter((entry) => entry.kind === "counterpart");
const openCases = steps.filter((entry) => entry.kind === "open");
const staleCommits = attempts.reduce((sum, entry) => sum + entry.arrivals, 0);
const openCommits = openCases.reduce((sum, entry) => sum + entry.arrivals, 0);
// Read again at the end: no later step sent a counterpart a second time.
const owned = new Set(counterparts.flatMap((entry) => (entry.path === null ? [] : [entry.path])));
const exactlyOnce = [...owned].filter((path) => arrivalsAt(path) === 1).length;
// Every request the target ever received belongs to a counterpart's identity
// or to the open case; anything else reached it without a step that owns it.
const unowned =
  target.received.length -
  [...owned].reduce((sum, path) => sum + arrivalsAt(path), 0) -
  openCommits;
const allOk =
  steps.every((entry) => entry.ok) &&
  staleCommits === 0 &&
  exactlyOnce === counterparts.length &&
  owned.size === counterparts.length &&
  unowned === 0;

out(`\nObserver: the target received ${target.received.length} requests.`);
out(
  `    attempts on changed conditions: ${attempts.length}, requests that reached the target: ${staleCommits}`,
);
out(
  `    legitimate counterparts: ${counterparts.length}, reached it exactly once under their own identity: ${exactlyOnce}`,
);
out(`    the open case: ${openCommits} requests; requests no step accounts for: ${unowned}`);
out(
  `\n${allOk ? "PROVEN" : "NOT PROVEN"}: ${attempts.length} changed-condition attempts, ${staleCommits} stale commits; ${exactlyOnce} legitimate counterparts completed, each exactly once.`,
);
out(
  `OPEN: ${openCases.length} case the boundary does not close today: with the allowance published after the commit instead of with it, ${openCommits} rollouts committed against an allowance of 1. That window, and any limit nobody publishes as a signal, need a reservation the authority takes with the grant.`,
);
process.exitCode = allOk ? 0 : 1;

await authority.stop();
await target.stop();
