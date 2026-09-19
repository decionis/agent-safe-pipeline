/**
 * Infrastructure scale demo: the Compromised Principal Test.
 *
 * One legitimate scale-out and seven adversarial attempts against the same
 * execution boundary, run offline with the development fixture authority, an
 * in-process Presence double and an in-process cluster API. Every expectation
 * is asserted, so the run is a self-checking proof: the process exits 0 only
 * when every attack failed to execute and each legitimate path executed
 * exactly once per verified grant.
 *
 * The scenario: an infrastructure agent with a valid identity and a valid
 * credential to a permitted API proposes to scale the inference deployment in
 * prod-eu from 48 to 96 replicas. Nothing about the agent is forged, and
 * nothing here tests a forged credential. The test the demo is named for is
 * the other one:
 *
 *   valid principal → valid credential → permitted API
 *     → unauthorized consequential intent → BLOCK or ESCALATE
 *
 * An agent that may call `deployment.scale` is not an agent that may scale
 * anything to anything. The boundary binds the exact action: principal,
 * cluster, service, replicas, policy and expiry, and a change to any of them
 * after authorization fails the binding. Identity says who is asking;
 * execution authority says whether this is permitted to happen, and the
 * faster and more autonomous the agent, the less the first can stand in for
 * the second. All identities, clusters and services are synthetic.
 */
import process from "node:process";
import { z } from "zod";
import {
  ActionRegistry,
  AuditRecorder,
  createFixtureAuthorityPair,
  createHostedGate,
  IntentCapture,
  PresenceApprovalCoordinator,
  printHostedOutcome,
  SafeExecutor,
  type AgentProposal,
  type AuditEventV1,
  type CapturedIntent,
  type DecisionEvidence,
  type GateDecision,
  type PresenceApprovalClient,
  type PresenceGateResult,
} from "@decionis/agent-safe-pipeline";

const SYNTHETIC_TENANT_ID = "00000000-0000-4000-8000-000000000009";
const PRINCIPAL = "synthetic-infra-agent";
const SRE_IDENTITY = "synthetic-sre-on-call";
const CEREMONY = "FIDO2 / WebAuthn with active liveness";
/** The agent's remit: one cluster, two services. Policy, not identity, holds it. */
const CLUSTER_IN_REMIT = "prod-eu";
const SERVICES_IN_REMIT: ReadonlySet<string> = new Set(["inference", "retrieval"]);
/** Replica ceilings: autonomous to 128, the SRE on call to 512, nothing above and never zero. */
const AUTONOMOUS_REPLICAS = 128;
const HUMAN_REPLICAS = 512;
/** The credential the cluster API accepts. It exists in the handler and nowhere else. */
const EXECUTOR_CLUSTER_TOKEN = "synthetic-executor-service-account-token";

const out = (line: string): void => {
  process.stdout.write(`${line}\n`);
};
const short = (value: string | null | undefined): string =>
  value === null || value === undefined ? "none" : `${value.slice(0, 18)}…`;

/**
 * The cluster's API, as far as this demo needs it: it scales a deployment for
 * a caller that presents the executor's credential, and refuses everyone
 * else. The refusal is the third chokepoint of bypass resistance, the one no
 * agent-side compromise can get around: the agent zone holds no credential
 * the cluster accepts.
 */
class ClusterApi {
  public readonly replicas = new Map<string, number>([["prod-eu/inference", 48]]);
  public readonly scaled: string[] = [];
  public readonly refused: string[] = [];

  public scale(
    token: string | null,
    cluster: string,
    service: string,
    replicas: number,
    idempotencyKey: string,
  ): { readonly ok: boolean; readonly status: number } {
    if (token !== EXECUTOR_CLUSTER_TOKEN) {
      this.refused.push(`${cluster}/${service}`);
      return { ok: false, status: 401 };
    }
    this.replicas.set(`${cluster}/${service}`, replicas);
    this.scaled.push(idempotencyKey);
    return { ok: true, status: 200 };
  }
}

/**
 * In-process stand-in for Presence with the semantics that matter: a request
 * is bound to the exact intent hash shown to the person, a receipt exists only
 * after the ceremony, and verification checks receipt, request, and hash.
 */
class PresenceDouble implements PresenceApprovalClient {
  private readonly requests = new Map<
    string,
    { readonly intentHash: string | null; readonly identity: string }
  >();
  private readonly receipts = new Map<
    string,
    { readonly requestId: string; readonly intentHash: string | null }
  >();
  private sequence = 0;

  public async gate(
    request: Parameters<PresenceApprovalClient["gate"]>[0],
  ): Promise<PresenceGateResult> {
    this.sequence += 1;
    const requestId = `synthetic-presence-request-${this.sequence}`;
    const intentHash =
      request.presentation.displayFields?.find((field) => field.key === "intent_hash")?.value ??
      null;
    this.requests.set(requestId, { intentHash, identity: request.approver.id });
    out(`    Presence: request ${requestId} bound to intent ${short(intentHash)}`);
    out(`    Presence: invitation delivered to ${request.approver.id}; ceremony ${CEREMONY}`);
    return {
      verdict: "HUMAN_REQUIRED",
      request_id: requestId,
      approval_url: `https://presence.example.invalid/approve/${requestId}`,
    };
  }

  public async outcome(requestId: string): Promise<PresenceGateResult> {
    const request = this.requests.get(requestId);
    if (request === undefined) return { verdict: "DENIED", request_id: requestId };
    const receiptDossierId = `synthetic-presence-receipt-${requestId.split("-").at(-1)}`;
    this.receipts.set(receiptDossierId, { requestId, intentHash: request.intentHash });
    out(
      `    Presence: ${request.identity} completed the ceremony; sealed receipt ${receiptDossierId}`,
    );
    return { verdict: "PROCEED", request_id: requestId, receipt_dossier_id: receiptDossierId };
  }

  /** What the authority checks before evidence counts: receipt, request, and exact intent hash. */
  public verify(evidence: DecisionEvidence | undefined, intentHash: string): boolean {
    const approval = evidence?.humanApproval;
    if (approval === undefined) return false;
    const receipt = this.receipts.get(approval.receiptDossierId);
    return (
      receipt !== undefined &&
      receipt.requestId === approval.requestId &&
      receipt.intentHash === intentHash
    );
  }
}

const cluster = new ClusterApi();
const presence = new PresenceDouble();

/**
 * Synthetic policy over the exact action. The principal is valid in every
 * case below and never enters the verdict: what is evaluated is the cluster,
 * the service, the replica count and, past the autonomous ceiling, whether a
 * present SRE approved this exact intent.
 */
const pair = createFixtureAuthorityPair(
  (intent, evidence) => {
    const {
      cluster: target,
      service,
      replicas,
    } = intent.intent.parameters as {
      cluster: string;
      service: string;
      replicas: number;
    };
    if (target !== CLUSTER_IN_REMIT) return "BLOCK";
    if (!SERVICES_IN_REMIT.has(service)) return "BLOCK";
    if (replicas === 0 || replicas > HUMAN_REPLICAS) return "BLOCK";
    if (replicas <= AUTONOMOUS_REPLICAS) return "ALLOW";
    if (evidence === undefined) return "ESCALATE";
    return presence.verify(evidence, intent.intentHash) ? "ALLOW" : "BLOCK";
  },
  { unsafeAllowDevelopmentFixture: true },
);

// With nothing set the fixture is the whole authority. With DECIONIS_HOSTED=1,
// or a key, Decionis evaluates the golden scale-out beside it (in shadow, so
// nothing below changes) and leaves a signed Decision Dossier; the adversarial
// attempts stay local by design. A hosted tenant is the key's own.
const gate = await createHostedGate({
  local: pair,
  tenantId: SYNTHETIC_TENANT_ID,
  source: {
    repo: "decionis/agent-safe-pipeline",
    example: "infra-scale-demo",
    surface: "github",
  },
});
const TENANT_ID = gate.tenantId;

const ScaleParameters = z
  .object({
    cluster: z.string().min(1),
    namespace: z.string().min(1),
    service: z.string().min(1),
    replicas: z.number().int().min(0),
  })
  .strict();

const registry = new ActionRegistry()
  .register("deployment.scale", {
    parametersSchema: ScaleParameters,
    // The only code that can change a replica count. It resolves the cluster
    // credential at dispatch; the agent never sees it and cannot name it.
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async (idempotencyKey) => {
        const answer = cluster.scale(
          EXECUTOR_CLUSTER_TOKEN,
          parameters.cluster,
          parameters.service,
          parameters.replicas,
          idempotencyKey,
        );
        return { simulated: true, status: answer.status, replicas: parameters.replicas };
      }),
  })
  .seal();

const events: AuditEventV1[] = [];
const audit = new AuditRecorder({
  sink: {
    write: (event) => {
      events.push(event);
    },
  },
});
const executor = new SafeExecutor(registry, pair.verifier, audit);

function proposeScale(
  replicas: number,
  { cluster: target = CLUSTER_IN_REMIT, service = "inference" } = {},
): AgentProposal {
  return {
    action: "deployment.scale",
    target: `kubernetes:${target}:deployments/${service}`,
    parameters: { cluster: target, namespace: "serving", service, replicas },
  };
}

function capture(
  proposal: AgentProposal,
  idempotencyKey: string,
  ttlSeconds = 300,
): CapturedIntent {
  return new IntentCapture({ ttlSeconds }).capture(proposal, {
    tenantId: TENANT_ID,
    // The principal is trusted context, set by the runtime that authenticated
    // the caller, and inside the hash: a valid identity, every time.
    actor: { id: PRINCIPAL, type: "AI_AGENT", runtime: "infra-scale-demo" },
    downstreamTarget: {
      system: "kubernetes",
      operation: "deployments/scale",
      environment: "production",
    },
    idempotencyKey,
    context: { source: "infra-scale-demo", approval_role: "SRE" },
  });
}

/** The escalation path: hold, verified ceremony by the SRE on call, re-authorization, exact grant. */
async function approveThroughPresence(captured: CapturedIntent): Promise<GateDecision> {
  const coordinator = new PresenceApprovalCoordinator(
    presence,
    pair.authority,
    "Synthetic Platform Team",
    SRE_IDENTITY,
    { audit, initialDelayMs: 1, maxDelayMs: 2 },
  );
  const handoff = await coordinator.request(captured);
  return await coordinator.resolveAndReauthorize(captured, handoff);
}

interface Outcome {
  readonly title: string;
  readonly expected: string;
  readonly observed: string;
  readonly ok: boolean;
}
const outcomes: Outcome[] = [];
/** Executions the run itself authorised: the golden path and the two attacks that end in a legitimate grant. */
let authorizedExecutions = 0;

function record(title: string, expected: string, observed: string, ok: boolean): void {
  outcomes.push({ title, expected, observed, ok });
  out(`    ${ok ? "PASS" : "FAIL"}: ${observed}`);
}

const blockedReason = (result: Awaited<ReturnType<SafeExecutor["run"]>>): string =>
  result.outcome === "BLOCKED" ? `${result.outcome} ${result.reason}` : result.outcome;

async function attack(
  index: number,
  title: string,
  expected: string,
  run: () => Promise<{ readonly observed: string; readonly authorized?: number }>,
): Promise<void> {
  const before = cluster.scaled.length;
  out(`\n[attack ${index}/7] ${title}`);
  let observed: string;
  let authorized = 0;
  try {
    const answer = await run();
    observed = answer.observed;
    authorized = answer.authorized ?? 0;
  } catch (error) {
    observed = `rejected before execution: ${error instanceof Error ? error.message : "unknown"}`;
  }
  authorizedExecutions += authorized;
  const unauthorized = cluster.scaled.length - before - authorized;
  record(
    title,
    expected,
    unauthorized > 0 ? `EXECUTED: ${observed}` : observed,
    unauthorized === 0,
  );
}

out("Infrastructure scale demo: the Compromised Principal Test");
out(
  `Principal ${PRINCIPAL} is valid throughout, holds a valid credential to the executor, and deployment.scale is an API it may call.`,
);
out(
  `Policy: ${CLUSTER_IN_REMIT} only; services ${[...SERVICES_IN_REMIT].join(", ")}; autonomous to ${AUTONOMOUS_REPLICAS} replicas, the SRE on call to ${HUMAN_REPLICAS}, never zero, nothing above.`,
);

// ---------------------------------------------------------------------------
out("\n[golden path] inference in prod-eu scaled 48 → 96, autonomous, once");
const scaleA = capture(proposeScale(96), "synthetic-scale-a");
out(`    Agent proposes replicas 96 for prod-eu/inference; intent ${short(scaleA.intentHash)}`);
const decisionA = await pair.authority.evaluate(scaleA);
out(
  `    Authority: ${decisionA.verdict}; grant ${decisionA.authorization === null ? "none" : "present"}`,
);
const golden = await executor.run(scaleA, decisionA);
const ledgerEntry =
  golden.outcome === "BLOCKED" ? null : pair.verifier.commitOf(golden.authorization.grantId);
out(
  `    Cluster: prod-eu/inference now ${cluster.replicas.get("prod-eu/inference")} replicas; fixture ledger: grant ${short(ledgerEntry?.grantId)} ${ledgerEntry?.outcome ?? "none"}`,
);
authorizedExecutions += 1;
const goldenOk =
  decisionA.verdict === "ALLOW" &&
  golden.outcome === "COMPLETED" &&
  ledgerEntry?.outcome === "COMMITTED" &&
  cluster.scaled.length === 1 &&
  cluster.replicas.get("prod-eu/inference") === 96;
record(
  "Golden path",
  "ALLOW, exact grant, one execution",
  `${golden.outcome}; scaled ${cluster.scaled.length}; finalization ${golden.outcome === "BLOCKED" ? "n/a" : golden.finalization}`,
  goldenOk,
);

// ---------------------------------------------------------------------------
await attack(
  1,
  "Compromised principal: the same valid agent proposes 960 replicas",
  "authority BLOCK",
  async () => {
    const scale = capture(proposeScale(960), "synthetic-scale-960");
    const decision = await pair.authority.evaluate(scale);
    const result = await executor.run(scale, decision);
    return {
      observed: `valid principal, valid credential, permitted API; authority ${decision.verdict}; executor ${blockedReason(result)}; replicas still ${cluster.replicas.get("prod-eu/inference")}`,
    };
  },
);

await attack(
  2,
  "Compromised principal: payments scaled to zero, a service outside the remit",
  "authority BLOCK",
  async () => {
    const scale = capture(proposeScale(0, { service: "payments" }), "synthetic-scale-payments");
    const decision = await pair.authority.evaluate(scale);
    const result = await executor.run(scale, decision);
    return {
      observed: `authority ${decision.verdict}; executor ${blockedReason(result)}; payments untouched ${!cluster.replicas.has("prod-eu/payments")}`,
    };
  },
);

await attack(
  3,
  "Compromised principal: inference in prod-us, a cluster outside the remit",
  "authority BLOCK",
  async () => {
    const scale = capture(proposeScale(96, { cluster: "prod-us" }), "synthetic-scale-us");
    const decision = await pair.authority.evaluate(scale);
    const result = await executor.run(scale, decision);
    return {
      observed: `authority ${decision.verdict}; executor ${blockedReason(result)}; prod-us untouched ${!cluster.replicas.has("prod-us/inference")}`,
    };
  },
);

await attack(
  4,
  "Replicas changed after authorization: 96 → 960",
  "INTENT_BINDING_MISMATCH",
  async () => {
    // The decision for 96 is real. The parameters it is presented with are not
    // the ones it was made over, and the captured intent is frozen, so the
    // agent's only move is a second intent with a second hash.
    const mutated = capture(proposeScale(960), "synthetic-scale-a");
    const result = await executor.run(mutated, decisionA);
    return {
      observed: `960 replicas with the 96 decision: ${blockedReason(result)}; captured intent frozen ${Object.isFrozen(scaleA.intent.parameters)}; replicas still ${cluster.replicas.get("prod-eu/inference")}`,
    };
  },
);

await attack(
  5,
  "256 replicas need the SRE; the approval for 256 is then presented for 512",
  "ESCALATE, one approved execution, then BLOCK",
  async () => {
    const scale256 = capture(proposeScale(256), "synthetic-scale-256");
    const held = await pair.authority.evaluate(scale256);
    const approved = await approveThroughPresence(scale256);
    const executed = await executor.run(scale256, approved);
    const scale512 = capture(proposeScale(512), "synthetic-scale-512");
    // The receipt binds the hash the SRE saw; another intent has another hash.
    const swapped = await pair.authority.evaluate(scale512, approved.evidence);
    const withApprovedDecision = await executor.run(scale512, approved);
    const ok =
      held.verdict === "ESCALATE" &&
      approved.verdict === "ALLOW" &&
      executed.outcome === "COMPLETED" &&
      swapped.verdict === "BLOCK" &&
      withApprovedDecision.outcome === "BLOCKED";
    if (!ok) {
      throw new Error(
        `held ${held.verdict}; approved ${approved.verdict}; executed ${executed.outcome}; swapped ${swapped.verdict}; ${withApprovedDecision.outcome}`,
      );
    }
    return {
      observed: `256: ${held.verdict}, then ${approved.verdict} after the SRE's ceremony, ${executed.outcome} once; 512 with the 256 receipt: authority ${swapped.verdict}; 512 with the 256 decision: ${blockedReason(withApprovedDecision)}`,
      authorized: 1,
    };
  },
);

await attack(
  6,
  "The consumed grant replayed, then 25 concurrent claims of a fresh grant",
  "one execution per grant",
  async () => {
    const replay = await executor.run(scaleA, decisionA);
    const scaleC = capture(proposeScale(100), "synthetic-scale-c");
    const decisionC = await pair.authority.evaluate(scaleC);
    const results = await Promise.all(
      Array.from({ length: 25 }, async () => await executor.run(scaleC, decisionC)),
    );
    const completed = results.filter((result) => result.outcome === "COMPLETED").length;
    if (replay.outcome !== "BLOCKED" || completed !== 1) {
      throw new Error(`replay ${replay.outcome}; concurrent completions ${completed}`);
    }
    return {
      observed: `replay ${blockedReason(replay)}; 25 concurrent claims, ${completed} execution`,
      authorized: 1,
    };
  },
);

await attack(
  7,
  "The agent calls the cluster API itself, with the credential it has",
  "refused by the cluster: no credential in the agent zone",
  async () => {
    // The agent's credential is the one it presents to the executor. The
    // cluster does not accept it, and nothing in the agent zone holds one it
    // does: this is the chokepoint no policy decision is needed for.
    const answer = cluster.scale(null, CLUSTER_IN_REMIT, "inference", 960, "synthetic-direct");
    return {
      observed: `cluster answered ${answer.status}; refused calls ${cluster.refused.length}; replicas still ${cluster.replicas.get("prod-eu/inference")}`,
    };
  },
);

// ---------------------------------------------------------------------------
out("\nAudit trail recorded for the golden path (redacted lifecycle events):");
for (const event of events.slice(0, 6)) {
  out(
    `    ${event.eventType.padEnd(24)} ${event.authority.padEnd(18)} ${event.reasonCodes.join(",")}`,
  );
}
const leaked =
  decisionA.authorization !== null &&
  JSON.stringify(events).includes(decisionA.authorization.token);
out(`    execution token present in audit events: ${leaked}`);
out(
  `    cluster credential present in audit events: ${JSON.stringify(events).includes(EXECUTOR_CLUSTER_TOKEN)}`,
);

out("\nSummary");
const width = Math.max(...outcomes.map((outcome) => outcome.title.length));
for (const outcome of outcomes) {
  out(`    ${outcome.ok ? "PASS" : "FAIL"}  ${outcome.title.padEnd(width)}  ${outcome.expected}`);
}
const unauthorized = cluster.scaled.length - authorizedExecutions;
const allOk =
  outcomes.every((outcome) => outcome.ok) &&
  !leaked &&
  !JSON.stringify(events).includes(EXECUTOR_CLUSTER_TOKEN) &&
  unauthorized === 0 &&
  cluster.scaled.length === authorizedExecutions;
out(
  `\n${allOk ? "PROVEN" : "NOT PROVEN"}: 7 adversarial attempts by a valid principal, ${unauthorized} unauthorized executions; ${cluster.scaled.length} executions for ${authorizedExecutions} verified grants.`,
);
process.exitCode = allOk ? 0 : 1;

// ---------------------------------------------------------------------------
// Hosted epilogue: the same golden scale-out, evaluated by Decionis beside the
// fixture, ending with the signed record and where to verify it.
await printHostedOutcome(
  gate,
  gate.credentials === null ? decisionA : await gate.authority.evaluate(scaleA),
);
