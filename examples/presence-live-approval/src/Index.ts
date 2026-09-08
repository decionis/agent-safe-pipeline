/**
 * Live Presence-bound enforcement against the real Decionis and Presence
 * services. It captures one refund intent, asks Decionis, hands the escalation
 * to Presence with an explicit ceremony requirement, waits for the human to
 * complete it, re-authorizes with the receipt, claims the grant, runs a
 * simulated handler, and finalizes. No downstream provider is called.
 *
 * Credentials come from the environment only; see README.md.
 */
import process from "node:process";
import { parseArgs } from "node:util";
import { HumanApprovalGate, PresenceClient } from "@decionis/presence-node";
import {
  ActionRegistry,
  AuditRecorder,
  DecionisGate,
  DecionisGrantVerifier,
  IntentCapture,
  PresenceApprovalCoordinator,
  SafeExecutor,
  type PresenceVerificationRequirements,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

interface Ceremony {
  readonly label: string;
  readonly requirements: PresenceVerificationRequirements;
}

const CEREMONIES: Readonly<Record<string, Ceremony>> = {
  fido: {
    label: "FIDO2 / WebAuthn",
    requirements: {
      level: "STANDARD",
      methods: ["WEBAUTHN"],
      hardware_pki_required: false,
      disallow_virtual_cameras: true,
    },
  },
  "fido-liveness": {
    label: "FIDO2 / WebAuthn with active liveness",
    requirements: {
      level: "HIGH_CONFIDENCE",
      methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
      hardware_pki_required: false,
      disallow_virtual_cameras: true,
    },
  },
};
/** The intent, the Presence request, and the polling budget share one five-minute window. */
const WINDOW_SECONDS = 300;
const SERVICE_TIMEOUT_MS = 15_000;

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required; see examples/presence-live-approval/README.md`);
  }
  return value;
}

function log(stage: string, detail: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify({ at: new Date().toISOString(), stage, ...detail })}\n`);
}

const { values } = parseArgs({
  options: {
    ceremony: { type: "string", default: "fido" },
    "amount-minor": { type: "string", default: "50000" },
  },
});
const ceremonyKey = values.ceremony ?? "fido";
const ceremony = CEREMONIES[ceremonyKey];
if (ceremony === undefined) {
  throw new Error(`Unknown ceremony "${ceremonyKey}"; use fido or fido-liveness`);
}
const amountMinor = Number.parseInt(values["amount-minor"] ?? "50000", 10);
if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) {
  throw new Error("--amount-minor must be a positive integer");
}

const decionisUrl = requireEnv("DECIONIS_API_URL");
const decionisKey = requireEnv("DECIONIS_API_KEY");
const tenantId = requireEnv("DECIONIS_TENANT_ID");
const presenceUrl = requireEnv("PRESENCE_API_URL");
const presenceKey = requireEnv("PRESENCE_API_KEY");
const approverEmail = requireEnv("APPROVER_EMAIL");
const organization =
  process.env.APPROVER_ORGANIZATION?.trim() || "Agent-Safe Pipeline live approval";

const audit = new AuditRecorder({
  sink: {
    write: (event) => {
      log("audit", {
        eventType: event.eventType,
        authority: event.authority,
        verdict: event.verdict,
        reasonCodes: event.reasonCodes,
        decisionId: event.correlation.decisionId ?? null,
        dossierId: event.correlation.dossierId ?? null,
      });
    },
  },
});

const stamp = Date.now();
const captured = new IntentCapture({ ttlSeconds: WINDOW_SECONDS }).capture(
  {
    action: "refund_order",
    target: `shopify:order:synthetic-live-${stamp}`,
    parameters: { amountMinor, currency: "USD", orderId: `synthetic-live-${stamp}` },
  },
  {
    tenantId,
    actor: {
      id: "synthetic-live-approval-agent",
      type: "AI_AGENT",
      runtime: "presence-live-approval",
    },
    downstreamTarget: { system: "shopify", operation: "refund", environment: "live-test" },
    idempotencyKey: `live-approval-${ceremonyKey}-${stamp}`,
    // The person who must approve is part of the trusted context, so the
    // routing identity is hash-bound and lands in the Decision Dossier.
    context: {
      source: "presence-live-approval",
      approver_email: approverEmail,
      ceremony: ceremonyKey,
    },
  },
);
log("captured", {
  intentId: captured.intent.intentId,
  intentHash: captured.intentHash,
  action: captured.intent.action,
  target: captured.intent.target,
  amountMinor,
  expiresAt: captured.intent.expiresAt,
  ceremony: ceremony.label,
});

const gate = new DecionisGate({
  baseUrl: decionisUrl,
  apiKey: decionisKey,
  timeoutMs: SERVICE_TIMEOUT_MS,
});
const verifier = new DecionisGrantVerifier({
  baseUrl: decionisUrl,
  apiKey: decionisKey,
  timeoutMs: SERVICE_TIMEOUT_MS,
});

function describe(
  decision: Awaited<ReturnType<DecionisGate["evaluate"]>>,
): Record<string, unknown> {
  return {
    verdict: decision.verdict,
    decisionId: decision.decisionId,
    dossierId: decision.dossierId,
    reasonCodes: decision.reasonCodes,
    failClosed: decision.failClosed,
    executable: decision.authorization !== null,
    evidence: decision.evidence ?? null,
  };
}

let decision = await gate.evaluate(captured);
log("decision", describe(decision));

if (decision.verdict === "ESCALATE") {
  const presence = new PresenceClient({
    baseUrl: presenceUrl,
    apiKey: presenceKey,
    timeoutMs: SERVICE_TIMEOUT_MS,
  });
  const coordinator = new PresenceApprovalCoordinator(
    new HumanApprovalGate(presence),
    gate,
    organization,
    approverEmail,
    {
      audit,
      requirements: ceremony.requirements,
      ttlSeconds: WINDOW_SECONDS,
      maxAttempts: 100,
      initialDelayMs: 1_000,
      maxDelayMs: 5_000,
      deadlineMs: WINDOW_SECONDS * 1_000,
    },
  );
  const handoff = await coordinator.request(captured);
  log("presence_handoff", {
    verdict: handoff.verdict,
    requestId: handoff.request_id ?? null,
    approvalUrl: handoff.approval_url ?? null,
    expiresAt: handoff.expires_at ?? null,
    ceremony: ceremony.label,
    next: "Complete the ceremony on the trusted device of the person approving. Presence pushes to enrolled devices bound to that identity; otherwise open approvalUrl there. Polling continues for up to five minutes.",
  });
  decision = await coordinator.resolveAndReauthorize(captured, handoff);
  log("reauthorization", describe(decision));
} else if (decision.verdict === "ALLOW") {
  log("notice", {
    message:
      "Policy allowed the action without escalation, so Presence was not exercised. Raise --amount-minor or configure the tenant policy to require human approval for this action.",
  });
}

const registry = new ActionRegistry()
  .register("refund_order", {
    parametersSchema: z
      .object({
        amountMinor: z.number().int().positive(),
        currency: z.literal("USD"),
        orderId: z.string(),
      })
      .strict(),
    // Simulated provider: proves the grant was claimed and finalized without a side effect.
    execute: async ({ parameters, dispatch }) =>
      await dispatch.run(async (idempotencyKey) => ({
        simulated: true,
        refundedMinor: parameters.amountMinor,
        idempotencyKey,
      })),
  })
  .seal();

const result = await new SafeExecutor(registry, verifier, audit).run(captured, decision);
log("execution", {
  outcome: result.outcome,
  executed: result.executed,
  ...(result.outcome === "BLOCKED"
    ? { reason: result.reason }
    : { finalization: result.finalization, authorization: result.authorization }),
  result: result.result,
});
process.exitCode = result.outcome === "COMPLETED" ? 0 : 1;
