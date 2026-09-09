/**
 * Local escalation to Presence, both integration modes, no credentials.
 *
 * Two loopback doubles from `@decionis/agent-safe-pipeline/testing` stand in
 * for Decionis and Presence. The production clients are used unchanged:
 * `DecionisGate` and `DecionisGrantVerifier` talk to the local authority, and
 * the real `@decionis/presence-node` gate talks to the local Presence. The
 * person's ceremony is simulated through the local control route.
 *
 * All identities are synthetic. The process exits 0 only when both modes end
 * with a claimed grant, one execution, and a recorded commit outcome.
 */
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import { HumanApprovalGate, PresenceClient } from "@decionis/presence-node";
import {
  ActionRegistry,
  DecionisGate,
  DecionisGrantVerifier,
  IntentCapture,
  PresenceApprovalCoordinator,
  SafeExecutor,
} from "@decionis/agent-safe-pipeline";
import {
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_PRESENCE_API_KEY,
  LocalAuthority,
  LocalPresence,
} from "@decionis/agent-safe-pipeline/testing";
import { z } from "zod";

const TENANT_ID = "00000000-0000-4000-8000-000000000005";
const CRO_IDENTITY = "synthetic-cro";
// Trusted executor configuration: who must approve, and in which role.
const MANAGED_APPROVER = { principal_id: CRO_IDENTITY, role_id: "CRO" } as const;

function log(stage: string, detail: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify({ at: new Date().toISOString(), stage, ...detail })}\n`);
}

// The person completes the ceremony by hand: nothing auto-approves.
const presence = new LocalPresence({ autoComplete: "MANUAL", roles: { [CRO_IDENTITY]: "CRO" } });
const authority = new LocalAuthority({ presence });
await presence.start();
await authority.start();

const gate = new DecionisGate({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});
const verifier = new DecionisGrantVerifier({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});
const wires: string[] = [];
const registry = new ActionRegistry()
  .register("refund_order", {
    parametersSchema: z
      .object({ amountMinor: z.number().int().positive(), currency: z.literal("USD") })
      .strict(),
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async (idempotencyKey) => {
        wires.push(idempotencyKey);
        return { simulated: true, refundedMinor: parameters.amountMinor, idempotencyKey };
      }),
  })
  .seal();
const executor = new SafeExecutor(registry, verifier);

function capture(label: string) {
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "refund_order",
      target: `shopify:order:synthetic-${label}`,
      parameters: { amountMinor: 50_000, currency: "USD" },
    },
    {
      tenantId: TENANT_ID,
      actor: { id: "synthetic-local-agent", type: "AI_AGENT", runtime: "local-escalation" },
      downstreamTarget: { system: "shopify", operation: "refund", environment: "local" },
      idempotencyKey: `local-${label}-${Date.now()}`,
      context: { source: "local-escalation" },
    },
  );
}

/** What a person would do on their device, expressed against the local control route. */
async function completeCeremony(requestId: string, response: "APPROVE" | "DENY"): Promise<void> {
  await sleep(50);
  const reply = await fetch(
    `${presence.baseUrl}/local/verification-requests/${encodeURIComponent(requestId)}/complete`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${LOCAL_PRESENCE_API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ response }),
    },
  );
  log("ceremony", { requestId, response, status: reply.status });
}

let failures = 0;

// ---------------------------------------------------------------------------
// DIRECT: the executor coordinates Presence itself and returns the receipt to the authority.
{
  const captured = capture("direct");
  const first = await gate.evaluate(captured);
  log("direct_decision", { verdict: first.verdict, executable: first.authorization !== null });
  const coordinator = new PresenceApprovalCoordinator(
    new HumanApprovalGate(
      new PresenceClient({ baseUrl: presence.baseUrl, apiKey: LOCAL_PRESENCE_API_KEY }),
    ),
    gate,
    "Local bank",
    CRO_IDENTITY,
    {
      initialDelayMs: 20,
      maxDelayMs: 100,
      requirements: {
        level: "HIGH_CONFIDENCE",
        methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
        hardware_pki_required: false,
        disallow_virtual_cameras: true,
      },
    },
  );
  const handoff = await coordinator.request(captured);
  const requestId = handoff.request_id ?? "";
  const view = presence.verification(requestId);
  log("direct_handoff", {
    verdict: handoff.verdict,
    requestId,
    approvalUrl: handoff.approval_url ?? null,
    boundIntentHash: view?.intentHash ?? null,
    bindingSource: view?.bindingSource ?? null,
    subject: view?.subjectActorId ?? null,
  });
  const [decision] = await Promise.all([
    coordinator.resolveAndReauthorize(captured, handoff),
    completeCeremony(requestId, "APPROVE"),
  ]);
  const result = await executor.run(captured, decision);
  const grant =
    decision.authorization === null ? null : authority.grants.get(decision.authorization.token);
  log("direct_execution", {
    verdict: decision.verdict,
    reasonCodes: decision.reasonCodes,
    evidence: decision.evidence ?? null,
    outcome: result.outcome,
    finalization: result.outcome === "BLOCKED" ? null : result.finalization,
    authorityRecordedCommit: grant?.finalized ?? null,
  });
  if (result.outcome !== "COMPLETED" || grant?.finalized !== "COMMITTED") failures += 1;

  // A receipt for one intent must not authorize another.
  const other = capture("direct-other");
  const swapped = await gate.evaluate(other, decision.evidence);
  log("direct_swapped_receipt", { verdict: swapped.verdict, reasonCodes: swapped.reasonCodes });
  if (swapped.verdict !== "BLOCK") failures += 1;

  // A denial is terminal and never authorizes.
  const denied = capture("direct-denied");
  const deniedHandoff = await coordinator.request(denied);
  const [deniedDecision] = await Promise.all([
    coordinator.resolveAndReauthorize(denied, deniedHandoff),
    completeCeremony(deniedHandoff.request_id ?? "", "DENY"),
  ]);
  log("direct_denied", {
    verdict: deniedDecision.verdict,
    reasonCodes: deniedDecision.reasonCodes,
  });
  if (deniedDecision.verdict !== "BLOCK") failures += 1;
}

// ---------------------------------------------------------------------------
// MANAGED: the authority orchestrates Presence; the executor polls the authority only.
{
  const captured = capture("managed");
  const pending = await gate.evaluate(captured, undefined, {
    escalation: {
      mode: "MANAGED",
      approver: MANAGED_APPROVER,
      verification_requirements: {
        level: "HIGH_CONFIDENCE",
        methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
      },
    },
  });
  const escalation = pending.managedEscalation;
  const presenceRequestId =
    escalation === undefined
      ? null
      : (authority.escalations.get(escalation.escalationId)?.presenceRequestId ?? null);
  const view = presenceRequestId === null ? null : presence.verification(presenceRequestId);
  log("managed_pending", {
    verdict: pending.verdict,
    executable: pending.authorization !== null,
    escalation: escalation ?? null,
    presenceRequestId,
    boundIntentHash: view?.intentHash ?? null,
    bindingSource: view?.bindingSource ?? null,
    requirements: view?.requirements ?? null,
  });
  if (escalation === undefined || presenceRequestId === null) {
    failures += 1;
  } else {
    const [authorized] = await Promise.all([
      gate.waitForAuthorization(captured, pending, { initialDelayMs: 20, maxDelayMs: 100 }),
      completeCeremony(presenceRequestId, "APPROVE"),
    ]);
    const result = await executor.run(captured, authorized);
    const grant =
      authorized.authorization === null
        ? null
        : authority.grants.get(authorized.authorization.token);
    log("managed_execution", {
      verdict: authorized.verdict,
      reasonCodes: authorized.reasonCodes,
      status: authorized.managedEscalation?.status ?? null,
      outcome: result.outcome,
      finalization: result.outcome === "BLOCKED" ? null : result.finalization,
      authorityRecordedCommit: grant?.finalized ?? null,
    });
    if (result.outcome !== "COMPLETED" || grant?.finalized !== "COMMITTED") failures += 1;
  }

  // A denied managed ceremony is a typed terminal state with no grant.
  const denied = capture("managed-denied");
  const deniedPending = await gate.evaluate(denied, undefined, {
    escalation: { mode: "MANAGED", approver: MANAGED_APPROVER },
  });
  const deniedRequestId =
    deniedPending.managedEscalation === undefined
      ? null
      : (authority.escalations.get(deniedPending.managedEscalation.escalationId)
          ?.presenceRequestId ?? null);
  const [deniedDecision] = await Promise.all([
    gate.waitForAuthorization(denied, deniedPending, { initialDelayMs: 20, maxDelayMs: 100 }),
    completeCeremony(deniedRequestId ?? "", "DENY"),
  ]);
  log("managed_denied", {
    verdict: deniedDecision.verdict,
    reasonCodes: deniedDecision.reasonCodes,
    status: deniedDecision.managedEscalation?.status ?? null,
    executable: deniedDecision.authorization !== null,
  });
  if (deniedDecision.verdict !== "BLOCK" || deniedDecision.authorization !== null) failures += 1;
}

await authority.stop();
await presence.stop();
log("summary", { executions: wires.length, expectedExecutions: 2, failures });
process.exitCode = failures === 0 && wires.length === 2 ? 0 : 1;
