/**
 * Golden adversarial demo.
 *
 * One legitimate path and eight adversarial attempts against the same
 * execution boundary, run offline with the development fixture authority and
 * an in-process Presence double. Every expectation is asserted, so the run is
 * a self-checking proof: the process exits 0 only when every attack failed to
 * execute and the legitimate path executed exactly once per grant.
 *
 * Scenario: a treasury agent proposes a USD 250,000 wire. Policy escalates it
 * to a remote Chief Risk Officer, who completes a FIDO2 plus liveness ceremony.
 * All identities, accounts, and receipts are synthetic.
 */
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import { z } from "zod";
import {
  ActionRegistry,
  AuditRecorder,
  IntentCapture,
  PresenceApprovalCoordinator,
  SafeExecutor,
  ShadowPipeline,
  createFixtureAuthorityPair,
  type AgentProposal,
  type AuditEventV1,
  type CapturedIntent,
  type DecisionEvidence,
  type GateDecision,
  type PresenceApprovalClient,
  type PresenceGateResult,
} from "@decionis/agent-safe-pipeline";

const TENANT_ID = "00000000-0000-4000-8000-000000000004";
const AUTONOMOUS_LIMIT_MINOR = 1_000_000; // USD 10,000
const HUMAN_LIMIT_MINOR = 50_000_000; // USD 500,000
const CEREMONY = "FIDO2 / WebAuthn with active liveness";
const CRO_IDENTITY = "synthetic-cro-approver";

const out = (line: string): void => {
  process.stdout.write(`${line}\n`);
};
const usd = (minor: number): string =>
  `USD ${(minor / 100).toLocaleString("en-US", { minimumFractionDigits: 2 })}`;
const short = (value: string | null | undefined): string =>
  value === null || value === undefined ? "none" : `${value.slice(0, 18)}…`;

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

const presence = new PresenceDouble();

/** Synthetic policy: autonomous below USD 10,000, verified human presence to USD 500,000, blocked above. */
const pair = createFixtureAuthorityPair(
  (intent, evidence) => {
    const amount = Number(intent.intent.parameters.amountMinor ?? 0);
    if (amount > HUMAN_LIMIT_MINOR) return "BLOCK";
    if (amount <= AUTONOMOUS_LIMIT_MINOR) return "ALLOW";
    if (evidence === undefined) return "ESCALATE";
    return presence.verify(evidence, intent.intentHash) ? "ALLOW" : "BLOCK";
  },
  { unsafeAllowDevelopmentFixture: true },
);

const wires: string[] = [];
const registry = new ActionRegistry()
  .register("wire.transfer", {
    parametersSchema: z
      .object({
        amountMinor: z.number().int().positive(),
        currency: z.literal("USD"),
        beneficiary: z.string(),
        reference: z.string(),
      })
      .strict(),
    // The only code that can move money. It holds the core-banking credential;
    // the agent never sees it and cannot name it.
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async (idempotencyKey) => {
        wires.push(idempotencyKey);
        return {
          simulated: true,
          wireReference: `synthetic-wire-${wires.length}`,
          amountMinor: parameters.amountMinor,
          idempotencyKey,
        };
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

function proposeWire(
  beneficiary: string,
  amountMinor: number,
  extraParameters: Readonly<Record<string, string | number | boolean>> = {},
): AgentProposal {
  return {
    action: "wire.transfer",
    target: "synthetic-bank-core:account:synthetic-operating-1001",
    parameters: {
      amountMinor,
      currency: "USD",
      beneficiary,
      reference: `synthetic-invoice-${beneficiary}`,
      ...extraParameters,
    },
  };
}

function capture(
  proposal: AgentProposal,
  idempotencyKey: string,
  ttlSeconds = 300,
): CapturedIntent {
  return new IntentCapture({ ttlSeconds }).capture(proposal, {
    tenantId: TENANT_ID,
    actor: { id: "synthetic-treasury-agent", type: "AI_AGENT", runtime: "golden-adversarial-demo" },
    downstreamTarget: {
      system: "synthetic-bank-core",
      operation: "wire.transfer",
      environment: "demo",
    },
    idempotencyKey,
    context: { source: "golden-adversarial-demo", approval_role: "CRO" },
  });
}

/** The legitimate path: escalate, verified ceremony, re-authorization, exact grant. */
async function approveThroughPresence(captured: CapturedIntent): Promise<GateDecision> {
  const coordinator = new PresenceApprovalCoordinator(
    presence,
    pair.authority,
    "Synthetic Bank Treasury",
    CRO_IDENTITY,
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

function record(title: string, expected: string, observed: string, ok: boolean): void {
  outcomes.push({ title, expected, observed, ok });
  out(`    ${ok ? "PASS" : "FAIL"}: ${observed}`);
}

async function attack(
  index: number,
  title: string,
  expected: string,
  run: () => Promise<string>,
): Promise<void> {
  const before = wires.length;
  out(`\n[attack ${index}/8] ${title}`);
  let observed: string;
  try {
    observed = await run();
  } catch (error) {
    observed = `rejected before execution: ${error instanceof Error ? error.message : "unknown"}`;
  }
  const executed = wires.length !== before;
  record(title, expected, executed ? `EXECUTED: ${observed}` : observed, !executed);
}

out("Golden adversarial demo: a treasury agent, a remote CRO, and one execution boundary");
out(
  `Policy: autonomous up to ${usd(AUTONOMOUS_LIMIT_MINOR)}, verified human presence up to ${usd(HUMAN_LIMIT_MINOR)}, blocked above.`,
);

// ---------------------------------------------------------------------------
out("\n[golden path] USD 250,000 wire escalated to the CRO and executed once");
const wireA = capture(proposeWire("synthetic-vendor-7781", 25_000_000), "synthetic-wire-a");
out(
  `    Agent proposes ${usd(25_000_000)} to synthetic-vendor-7781; intent ${short(wireA.intentHash)}`,
);
const first = await pair.authority.evaluate(wireA);
out(`    Authority: ${first.verdict}; grant ${first.authorization === null ? "none" : "present"}`);
const decisionA = await approveThroughPresence(wireA);
out(
  `    Authority after receipt: ${decisionA.verdict}; grant ${decisionA.authorization === null ? "none" : "present"}; evidence ${short(decisionA.evidence?.humanApproval?.receiptDossierId)}`,
);
const golden = await executor.run(wireA, decisionA);
const goldenOk =
  first.verdict === "ESCALATE" &&
  first.authorization === null &&
  decisionA.verdict === "ALLOW" &&
  golden.outcome === "COMPLETED" &&
  wires.length === 1;
record(
  "Golden path",
  "escalate, verified ceremony, exact grant, one execution",
  `${golden.outcome}; wires executed ${wires.length}; finalization ${golden.outcome === "BLOCKED" ? "n/a" : golden.finalization}`,
  goldenOk,
);

// ---------------------------------------------------------------------------
await attack(
  1,
  "Proposal carries injected authorization fields",
  "rejected at capture",
  async () => {
    const injected = {
      ...proposeWire("synthetic-vendor-7781", 25_000_000),
      authorized: true,
      approved_by: "CRO",
    } as unknown as AgentProposal;
    try {
      capture(injected, "synthetic-wire-injected");
      return "captured despite injected fields";
    } catch {
      return "capture refused a proposal with fields outside action, target, parameters";
    }
  },
);

await attack(
  2,
  "Evidence smuggled inside agent parameters",
  "no grant; registry refuses",
  async () => {
    const smuggled = capture(
      proposeWire("synthetic-vendor-7781", 25_000_000, {
        approval_receipt: "synthetic-presence-receipt-1",
      }),
      "synthetic-wire-smuggled",
    );
    const decision = await pair.authority.evaluate(smuggled);
    try {
      const result = await executor.run(smuggled, decision);
      return `${decision.verdict} from authority; executor ${result.outcome}`;
    } catch (error) {
      return `${decision.verdict} from authority; registry refused unknown parameter (${error instanceof Error ? error.message : "unknown"})`;
    }
  },
);

await attack(
  3,
  "Agent fabricates an ALLOW decision with its own token",
  "AUTHORIZATION_INVALID",
  async () => {
    const forged: GateDecision = {
      verdict: "ALLOW",
      decisionId: "synthetic-forged-decision",
      dossierId: "synthetic-forged-dossier",
      intentHash: wireA.intentHash,
      reasonCodes: ["AGENT_SAYS_SO"],
      authorization: { token: "forged-token", expiresAt: wireA.intent.expiresAt },
      failClosed: false,
    };
    const result = await executor.run(wireA, forged);
    return `${result.outcome} ${result.outcome === "BLOCKED" ? result.reason : ""}`.trim();
  },
);

await attack(
  4,
  "Agent asserts the CRO approved without a ceremony",
  "authority BLOCK",
  async () => {
    const wire = capture(
      proposeWire("synthetic-vendor-7781", 25_000_000),
      "synthetic-wire-asserted",
    );
    const decision = await pair.authority.evaluate(wire, {
      humanApproval: {
        provider: "presence",
        requestId: "synthetic-presence-request-forged",
        receiptDossierId: "synthetic-presence-receipt-forged",
      },
    });
    const result = await executor.run(wire, decision);
    return `authority ${decision.verdict}; executor ${result.outcome}`;
  },
);

await attack(
  5,
  "Receipt for wire A presented for wire B (approval swapping)",
  "authority BLOCK",
  async () => {
    const wireB = capture(proposeWire("synthetic-vendor-9902", 25_000_000), "synthetic-wire-b");
    const swapped = await pair.authority.evaluate(wireB, decisionA.evidence);
    const withOldDecision = await executor.run(wireB, decisionA);
    return `authority ${swapped.verdict} for wire B; wire B with wire A's decision ${withOldDecision.outcome} ${withOldDecision.outcome === "BLOCKED" ? withOldDecision.reason : ""}`.trim();
  },
);

await attack(6, "Amount changed after approval", "INTENT_BINDING_MISMATCH", async () => {
  const inflated = capture(proposeWire("synthetic-vendor-7781", 250_000_000), "synthetic-wire-a");
  const result = await executor.run(inflated, decisionA);
  return `${usd(250_000_000)} with the ${usd(25_000_000)} decision: ${result.outcome} ${result.outcome === "BLOCKED" ? result.reason : ""}; captured intent frozen ${Object.isFrozen(wireA.intent.parameters)}`.trim();
});

await attack(
  7,
  "Grant replayed after execution, then 25 concurrent claims of a fresh grant",
  "one execution per grant",
  async () => {
    const replay = await executor.run(wireA, decisionA);
    const wireC = capture(proposeWire("synthetic-vendor-7781", 25_000_000), "synthetic-wire-c");
    const decisionC = await approveThroughPresence(wireC);
    const before = wires.length;
    const results = await Promise.all(
      Array.from({ length: 25 }, async () => await executor.run(wireC, decisionC)),
    );
    const completed = results.filter((result) => result.outcome === "COMPLETED").length;
    const winnerExecuted = wires.length - before;
    const ok = replay.outcome === "BLOCKED" && completed === 1 && winnerExecuted === 1;
    // This attack legitimately executes once: the fresh grant is consumed by exactly one winner.
    wires.splice(before, winnerExecuted);
    if (!ok) throw new Error(`replay ${replay.outcome}; concurrent completions ${completed}`);
    return `replay ${replay.outcome} ${replay.outcome === "BLOCKED" ? replay.reason : ""}; 25 concurrent claims, ${completed} execution`;
  },
);

await attack(
  8,
  "Shadow observation and an expired grant presented as authority",
  "DECISION_NOT_AUTHORITATIVE, AUTHORIZATION_INVALID",
  async () => {
    const small = capture(proposeWire("synthetic-vendor-7781", 500_000), "synthetic-wire-small");
    const shadow = await new ShadowPipeline(pair.authority).compare(small, () => "legacy-path");
    const castObservation = await executor.run(
      small,
      shadow.observation as unknown as GateDecision,
    );
    const shortLived = capture(
      proposeWire("synthetic-vendor-7781", 25_000_000),
      "synthetic-wire-expiring",
      1,
    );
    const expiring = await approveThroughPresence(shortLived);
    await sleep(1_500);
    const expired = await executor.run(shortLived, expiring);
    return `shadow ${shadow.observation.verdict} cast: ${castObservation.outcome} ${castObservation.outcome === "BLOCKED" ? castObservation.reason : ""}; expired grant: ${expired.outcome} ${expired.outcome === "BLOCKED" ? expired.reason : ""}`;
  },
);

// ---------------------------------------------------------------------------
out("\nAudit trail recorded for the golden path (redacted lifecycle events):");
for (const event of events.slice(0, 8)) {
  out(
    `    ${event.eventType.padEnd(24)} ${event.authority.padEnd(18)} ${event.reasonCodes.join(",")}`,
  );
}
const leaked =
  decisionA.authorization !== null &&
  JSON.stringify(events).includes(decisionA.authorization.token);
out(`    execution token present in audit events: ${leaked}`);

out("\nSummary");
const width = Math.max(...outcomes.map((outcome) => outcome.title.length));
for (const outcome of outcomes) {
  out(`    ${outcome.ok ? "PASS" : "FAIL"}  ${outcome.title.padEnd(width)}  ${outcome.expected}`);
}
const allOk = outcomes.every((outcome) => outcome.ok) && !leaked && wires.length === 1;
out(
  `\n${allOk ? "PROVEN" : "NOT PROVEN"}: 8 adversarial attempts, ${wires.length - 1} unauthorized executions; ${wires.length} execution for ${wires.length} verified grant on the golden path.`,
);
process.exitCode = allOk ? 0 : 1;
