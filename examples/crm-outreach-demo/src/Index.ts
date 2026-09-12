/**
 * CRM outreach demo: who can approve an AI agent's customer-acquisition action?
 *
 * One legitimate CRM update, one approved outbound message, and six
 * adversarial attempts against the same execution boundary, run offline with
 * the development fixture authority and an in-process Presence double. Every
 * expectation is asserted, so the run is a self-checking proof: the process
 * exits 0 only when every attack failed to execute and each legitimate path
 * executed exactly once per grant.
 *
 * This is the sales reading of "customer acquisition": a sales-development
 * agent working a prospect list, updating contact records and sending
 * outreach. Opening a bank customer relationship is a different action with
 * different evidence and is not shown here. All contacts, accounts, owners,
 * and receipts are synthetic.
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
  createFixtureAuthorityPair,
  type AgentProposal,
  type AuditEventV1,
  type CapturedIntent,
  type DecisionEvidence,
  type GateDecision,
  type PresenceApprovalClient,
  type PresenceGateResult,
} from "@decionis/agent-safe-pipeline";

const TENANT_ID = "00000000-0000-4000-8000-000000000006";
const CEREMONY = "FIDO2 / WebAuthn with active liveness";

const out = (line: string): void => {
  process.stdout.write(`${line}\n`);
};
const short = (value: string | null | undefined): string =>
  value === null || value === undefined ? "none" : `${value.slice(0, 18)}…`;

/**
 * What the CRM of record says about a contact at capture time. The host
 * attaches it as trusted context; the agent never writes any of it.
 */
interface ContactSnapshot {
  readonly territory: string;
  readonly consentStatus: "OPTED_IN" | "OPTED_OUT";
  readonly lifecycleStage: "LEAD" | "MQL" | "SQL";
  readonly contactTier: "standard" | "executive";
  readonly accountOwner: string;
}

const CONTACTS: Readonly<Record<string, ContactSnapshot>> = {
  "synthetic-contact-2201": {
    territory: "EMEA-North",
    consentStatus: "OPTED_IN",
    lifecycleStage: "MQL",
    contactTier: "standard",
    accountOwner: "synthetic-account-owner-emea",
  },
  "synthetic-contact-2202": {
    territory: "EMEA-North",
    consentStatus: "OPTED_OUT",
    lifecycleStage: "LEAD",
    contactTier: "standard",
    accountOwner: "synthetic-account-owner-emea",
  },
  "synthetic-contact-2203": {
    territory: "EMEA-North",
    consentStatus: "OPTED_IN",
    lifecycleStage: "SQL",
    contactTier: "executive",
    accountOwner: "synthetic-account-owner-emea",
  },
};

const APPROVED_TEMPLATES = new Set(["synthetic-template-intro-v3"]);

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

/**
 * Synthetic policy, read only from trusted context and the exact intent:
 * - a contact update inside the owner's territory is allowed on its own;
 * - an outbound message needs the named account owner's verified approval,
 *   and only on an approved template, and only to a contact who opted in;
 * - an executive-tier contact is never messaged by an agent at all.
 */
const pair = createFixtureAuthorityPair(
  (intent, evidence) => {
    const contact = CONTACTS[String(intent.intent.parameters.contactId ?? "")];
    if (contact === undefined) return "BLOCK";
    if (intent.intent.action === "crm.contact.update") {
      return contact.territory === intent.intent.context?.territory ? "ALLOW" : "ESCALATE";
    }
    if (contact.consentStatus !== "OPTED_IN") return "BLOCK";
    if (contact.contactTier === "executive") return "BLOCK";
    if (!APPROVED_TEMPLATES.has(String(intent.intent.parameters.templateId ?? ""))) return "BLOCK";
    if (evidence === undefined) return "ESCALATE";
    return presence.verify(evidence, intent.intentHash) ? "ALLOW" : "BLOCK";
  },
  { unsafeAllowDevelopmentFixture: true },
);

/** The provider side: what the CRM and the messaging provider actually did. */
const crmWrites: string[] = [];
const messagesSent: string[] = [];
let loseNextResponse = false;
const registry = new ActionRegistry()
  .register("crm.contact.update", {
    parametersSchema: z
      .object({
        contactId: z.string(),
        lifecycleStage: z.enum(["LEAD", "MQL", "SQL"]),
        note: z.string().max(200),
      })
      .strict(),
    // The only code that can write to the CRM. It holds the CRM credential;
    // the agent never sees it and cannot name it.
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async (idempotencyKey) => {
        crmWrites.push(idempotencyKey);
        return { simulated: true, contactId: parameters.contactId, idempotencyKey };
      }),
  })
  .register("outreach.message.send", {
    parametersSchema: z
      .object({
        contactId: z.string(),
        templateId: z.string(),
        recipient: z.string().email(),
      })
      .strict(),
    // The only code that can send a message. It holds the provider credential.
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async (idempotencyKey) => {
        if (loseNextResponse) {
          loseNextResponse = false;
          // The provider accepted the send and the response was lost in transit.
          messagesSent.push(idempotencyKey);
          throw new Error("response lost after dispatch");
        }
        messagesSent.push(idempotencyKey);
        return {
          simulated: true,
          messageId: `synthetic-message-${messagesSent.length}`,
          to: parameters.recipient,
          idempotencyKey,
        };
      }),
    // Read-only lookup by idempotency key: what the provider says happened.
    reconcile: async ({ idempotencyKey }) =>
      messagesSent.includes(idempotencyKey)
        ? {
            status: "COMPLETED",
            result: { simulated: true, messageId: "synthetic-message-recovered" },
          }
        : { status: "NOT_EXECUTED" },
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

function proposeUpdate(contactId: string, lifecycleStage: "LEAD" | "MQL" | "SQL"): AgentProposal {
  return {
    action: "crm.contact.update",
    target: `synthetic-crm:contact:${contactId}`,
    parameters: { contactId, lifecycleStage, note: "Qualified on the discovery call" },
  };
}

function proposeSend(
  contactId: string,
  recipient: string,
  templateId = "synthetic-template-intro-v3",
): AgentProposal {
  return {
    action: "outreach.message.send",
    target: `synthetic-messaging:contact:${contactId}`,
    parameters: { contactId, templateId, recipient },
  };
}

function capture(
  proposal: AgentProposal,
  idempotencyKey: string,
  ttlSeconds = 300,
): CapturedIntent {
  const contactId = String(proposal.parameters.contactId ?? "");
  const snapshot = CONTACTS[contactId];
  return new IntentCapture({ ttlSeconds }).capture(proposal, {
    tenantId: TENANT_ID,
    actor: { id: "synthetic-sdr-agent", type: "AI_AGENT", runtime: "crm-outreach-demo" },
    downstreamTarget: {
      system: proposal.action === "crm.contact.update" ? "synthetic-crm" : "synthetic-messaging",
      operation: proposal.action,
      environment: "demo",
    },
    idempotencyKey,
    // Trusted context: what the CRM of record says, attached by the host.
    context: {
      source: "crm-outreach-demo",
      territory: snapshot?.territory ?? "unknown",
      consent_status: snapshot?.consentStatus ?? "unknown",
      lifecycle_stage: snapshot?.lifecycleStage ?? "unknown",
      contact_tier: snapshot?.contactTier ?? "unknown",
      account_owner: snapshot?.accountOwner ?? "unknown",
    },
  });
}

/** The legitimate path: escalate, verified ceremony by the account owner, re-authorization, exact grant. */
async function approveThroughPresence(captured: CapturedIntent): Promise<GateDecision> {
  const coordinator = new PresenceApprovalCoordinator(
    presence,
    pair.authority,
    "Synthetic Sales Org",
    String(captured.intent.context?.account_owner ?? "unknown"),
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
  const before = crmWrites.length + messagesSent.length;
  out(`\n[attack ${index}/6] ${title}`);
  let observed: string;
  try {
    observed = await run();
  } catch (error) {
    observed = `rejected before execution: ${error instanceof Error ? error.message : "unknown"}`;
  }
  const executed = crmWrites.length + messagesSent.length !== before;
  record(title, expected, executed ? `EXECUTED: ${observed}` : observed, !executed);
}

out(
  "CRM outreach demo: a sales-development agent, a named account owner, and one execution boundary",
);
out(
  "Policy: a contact update inside the owner's territory is allowed on its own; an outbound message needs the account owner's verified approval, an approved template, and a contact who opted in; executive contacts are never messaged by an agent.",
);

// ---------------------------------------------------------------------------
out("\n[golden path 1] Contact record updated inside the territory, no approval needed");
const update = capture(proposeUpdate("synthetic-contact-2201", "SQL"), "synthetic-update-a");
const updateDecision = await pair.authority.evaluate(update);
const updateResult = await executor.run(update, updateDecision);
const updateLedger =
  updateResult.outcome === "BLOCKED"
    ? null
    : pair.verifier.commitOf(updateResult.authorization.grantId);
record(
  "Golden path 1: CRM update",
  "ALLOW, one write, COMMITTED",
  `${updateDecision.verdict}; executor ${updateResult.outcome}; CRM writes ${crmWrites.length}; ledger ${updateLedger?.outcome ?? "none"}`,
  updateDecision.verdict === "ALLOW" &&
    updateResult.outcome === "COMPLETED" &&
    updateLedger?.outcome === "COMMITTED" &&
    crmWrites.length === 1,
);

// ---------------------------------------------------------------------------
out("\n[golden path 2] Outbound message escalated to the account owner and sent once");
const sendA = capture(
  proposeSend("synthetic-contact-2201", "synthetic-contact-2201@example.com"),
  "synthetic-send-a",
);
const first = await pair.authority.evaluate(sendA);
out(`    Authority: ${first.verdict}; grant ${first.authorization === null ? "none" : "present"}`);
const decisionA = await approveThroughPresence(sendA);
out(
  `    Authority after receipt: ${decisionA.verdict}; grant ${decisionA.authorization === null ? "none" : "present"}; evidence ${short(decisionA.evidence?.humanApproval?.receiptDossierId)}`,
);
const golden = await executor.run(sendA, decisionA);
const goldenLedger =
  golden.outcome === "BLOCKED" ? null : pair.verifier.commitOf(golden.authorization.grantId);
record(
  "Golden path 2: outbound message",
  "escalate, verified owner, exact grant, one send",
  `${golden.outcome}; messages sent ${messagesSent.length}; ledger ${goldenLedger?.outcome ?? "none"}`,
  first.verdict === "ESCALATE" &&
    first.authorization === null &&
    decisionA.verdict === "ALLOW" &&
    golden.outcome === "COMPLETED" &&
    goldenLedger?.outcome === "COMMITTED" &&
    messagesSent.length === 1,
);

// ---------------------------------------------------------------------------
await attack(
  1,
  "Recipient changed after the owner approved",
  "INTENT_BINDING_MISMATCH",
  async () => {
    const redirected = capture(
      proposeSend("synthetic-contact-2201", "synthetic-attacker@example.com"),
      "synthetic-send-a",
    );
    const result = await executor.run(redirected, decisionA);
    return `${result.outcome} ${result.outcome === "BLOCKED" ? result.reason : ""}`.trim();
  },
);

await attack(2, "Template swapped for one the owner never saw", "authority BLOCK", async () => {
  const offTemplate = capture(
    proposeSend(
      "synthetic-contact-2201",
      "synthetic-contact-2201@example.com",
      "synthetic-template-unreviewed",
    ),
    "synthetic-send-off-template",
  );
  const decision = await pair.authority.evaluate(offTemplate, decisionA.evidence);
  const result = await executor.run(offTemplate, decision);
  return `authority ${decision.verdict}; executor ${result.outcome}`;
});

await attack(3, "Message to a contact who opted out", "authority BLOCK", async () => {
  const optedOut = capture(
    proposeSend("synthetic-contact-2202", "synthetic-contact-2202@example.com"),
    "synthetic-send-opted-out",
  );
  const decision = await pair.authority.evaluate(optedOut);
  const result = await executor.run(optedOut, decision);
  return `authority ${decision.verdict}; executor ${result.outcome}`;
});

await attack(
  4,
  "Message to an executive contact, with the owner's receipt from another send",
  "authority BLOCK",
  async () => {
    const executive = capture(
      proposeSend("synthetic-contact-2203", "synthetic-contact-2203@example.com"),
      "synthetic-send-executive",
    );
    const decision = await pair.authority.evaluate(executive, decisionA.evidence);
    const result = await executor.run(executive, decision);
    return `authority ${decision.verdict}; executor ${result.outcome}`;
  },
);

await attack(
  5,
  "Owner's approval used again after it expired",
  "AUTHORIZATION_INVALID",
  async () => {
    const shortLived = capture(
      proposeSend("synthetic-contact-2201", "synthetic-contact-2201@example.com"),
      "synthetic-send-expiring",
      1,
    );
    const expiring = await approveThroughPresence(shortLived);
    await sleep(1_500);
    const expired = await executor.run(shortLived, expiring);
    const replay = await executor.run(sendA, decisionA);
    return `expired grant: ${expired.outcome} ${expired.outcome === "BLOCKED" ? expired.reason : ""}; replay of the consumed grant: ${replay.outcome} ${replay.outcome === "BLOCKED" ? replay.reason : ""}`;
  },
);

await attack(
  6,
  "Provider response lost after dispatch, then a retry",
  "UNKNOWN_AFTER_DISPATCH, reconciled once, never re-sent",
  async () => {
    const sendB = capture(
      proposeSend("synthetic-contact-2201", "synthetic-contact-2201@example.com"),
      "synthetic-send-b",
    );
    const decisionB = await approveThroughPresence(sendB);
    loseNextResponse = true;
    const before = messagesSent.length;
    const lost = await executor.run(sendB, decisionB);
    if (lost.outcome !== "UNKNOWN_AFTER_DISPATCH")
      throw new Error(`expected UNKNOWN_AFTER_DISPATCH, got ${lost.outcome}`);
    const ledger = pair.verifier.commitOf(lost.recovery.grantId);
    const retry = await executor.run(sendB, decisionB);
    const reconciled = await executor.reconcile(sendB, lost.recovery);
    const sentDuring = messagesSent.length - before;
    // The provider did send once; the demo counts that single send as the legitimate effect.
    messagesSent.splice(before, sentDuring);
    const ok =
      lost.executed === null &&
      ledger?.outcome === "INDETERMINATE" &&
      retry.outcome === "BLOCKED" &&
      reconciled.outcome === "COMPLETED" &&
      sentDuring === 1;
    if (!ok)
      throw new Error(
        `lost ${lost.outcome}; ledger ${ledger?.outcome}; retry ${retry.outcome}; reconciled ${reconciled.outcome}; sends ${sentDuring}`,
      );
    return `lost: ${lost.outcome} (executed ${String(lost.executed)}, finalized ${ledger?.outcome}); retry with the same grant: ${retry.outcome}; reconcile: ${reconciled.outcome} from the provider's record; sends during the leg ${sentDuring}`;
  },
);

// ---------------------------------------------------------------------------
const leaked =
  decisionA.authorization !== null &&
  JSON.stringify(events).includes(decisionA.authorization.token);
out(`\n    execution token present in audit events: ${leaked}`);

out("\nSummary");
const width = Math.max(...outcomes.map((outcome) => outcome.title.length));
for (const outcome of outcomes) {
  out(`    ${outcome.ok ? "PASS" : "FAIL"}  ${outcome.title.padEnd(width)}  ${outcome.expected}`);
}
const allOk =
  outcomes.every((outcome) => outcome.ok) &&
  !leaked &&
  crmWrites.length === 1 &&
  messagesSent.length === 1;
out(
  `\n${allOk ? "PROVEN" : "NOT PROVEN"}: 6 adversarial attempts, ${crmWrites.length + messagesSent.length - 2} unauthorized executions; 1 CRM write and 1 message for 2 verified grants on the golden paths.`,
);
process.exitCode = allOk ? 0 : 1;
