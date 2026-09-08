/**
 * Decionis-managed Presence enforcement against the real Decionis service.
 * The trusted executor calls only Decionis: Decionis creates the Presence
 * request, verifies the signed receipt, re-evaluates policy, and exposes a
 * normal execution grant through escalation status.
 */
import process from "node:process";
import { parseArgs } from "node:util";
import {
  ActionRegistry,
  AuditRecorder,
  DecionisGate,
  DecionisGrantVerifier,
  IntentCapture,
  SafeExecutor,
  type ManagedEscalationRequest,
} from "@decionis/agent-safe-pipeline";
import { z } from "zod";

interface Ceremony {
  readonly label: string;
  readonly requirements: NonNullable<ManagedEscalationRequest["verification_requirements"]>;
}

const CEREMONIES: Readonly<Record<string, Ceremony>> = {
  fido: {
    label: "FIDO2 / WebAuthn",
    requirements: { level: "STANDARD", methods: ["WEBAUTHN"] },
  },
  "fido-liveness": {
    label: "FIDO2 / WebAuthn with active liveness",
    requirements: {
      level: "HIGH_CONFIDENCE",
      methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
    },
  },
};
const WINDOW_SECONDS = 300;
const SERVICE_TIMEOUT_MS = 15_000;

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required; see examples/presence-managed-approval/README.md`);
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
const approverPrincipalId = requireEnv("APPROVER_PRINCIPAL_ID");
const approverRoleId = process.env.APPROVER_ROLE_ID?.trim() || "APPROVER";

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
    target: `shopify:order:synthetic-managed-${stamp}`,
    parameters: { amountMinor, currency: "USD", orderId: `synthetic-managed-${stamp}` },
  },
  {
    tenantId,
    actor: {
      id: "synthetic-managed-approval-agent",
      type: "AI_AGENT",
      runtime: "presence-managed-approval",
    },
    downstreamTarget: { system: "shopify", operation: "refund", environment: "live-test" },
    idempotencyKey: `managed-approval-${ceremonyKey}-${stamp}`,
    // These values come from trusted executor configuration, not agent output.
    context: {
      source: "presence-managed-approval",
      approver_principal_id: approverPrincipalId,
      approver_role_id: approverRoleId,
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
    managedEscalation: decision.managedEscalation ?? null,
  };
}

let decision = await gate.evaluate(captured, undefined, {
  escalation: {
    mode: "MANAGED",
    approver: { principal_id: approverPrincipalId, role_id: approverRoleId },
    verification_requirements: ceremony.requirements,
  },
});
log("decision", describe(decision));

if (decision.managedEscalation !== undefined) {
  log("managed_escalation_pending", {
    escalationId: decision.managedEscalation.escalationId,
    status: decision.managedEscalation.status,
    outcome: decision.managedEscalation.outcome,
    expiresAt: decision.managedEscalation.expiresAt,
    grant: null,
    next: "Complete the Presence ceremony from the opaque invitation delivered by Decionis. The executor is polling Decionis only.",
  });
  decision = await gate.waitForAuthorization(captured, decision);
  log("authorization", describe(decision));
} else if (decision.verdict === "ALLOW") {
  log("notice", {
    message:
      "Policy allowed the action without escalation, so Decionis did not create a Presence request.",
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
