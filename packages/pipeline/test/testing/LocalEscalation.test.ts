import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { HumanApprovalGate, PresenceClient } from "@decionis/presence-node";
import { PresenceApprovalCoordinator } from "../../src/approval/PresenceApprovalCoordinator.js";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import {
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_PRESENCE_API_KEY,
  LocalAuthority,
  LocalPresence,
} from "../../src/testing/Index.js";

const CRO = "synthetic-cro";
const presence = new LocalPresence({ autoComplete: "MANUAL", roles: { [CRO]: "CRO" } });
const authority = new LocalAuthority({ presence });
let sequence = 0;

beforeAll(async () => {
  await presence.start();
  await authority.start();
});

afterAll(async () => {
  await authority.stop();
  await presence.stop();
});

function capture(amountMinor = 50_000) {
  sequence += 1;
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "refund_order",
      target: `shopify:order:synthetic-${sequence}`,
      parameters: { amountMinor, currency: "USD" },
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000005",
      actor: { id: "synthetic-local-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: `local-${sequence}`,
      context: {},
    },
  );
}

function gate() {
  return new DecionisGate({
    baseUrl: authority.baseUrl,
    apiKey: LOCAL_AUTHORITY_API_KEY,
    allowInsecureLoopback: true,
  });
}

function executor() {
  const calls: string[] = [];
  const registry = new ActionRegistry()
    .register("refund_order", {
      parametersSchema: z.object({ amountMinor: z.number(), currency: z.string() }).strict(),
      execute: async ({ dispatch }) =>
        await dispatch.run(async (key) => {
          calls.push(key);
          return "done";
        }),
    })
    .seal();
  const verifier = new DecionisGrantVerifier({
    baseUrl: authority.baseUrl,
    apiKey: LOCAL_AUTHORITY_API_KEY,
    allowInsecureLoopback: true,
  });
  return { calls, executor: new SafeExecutor(registry, verifier) };
}

function coordinator(authorityGate: DecionisGate) {
  return new PresenceApprovalCoordinator(
    new HumanApprovalGate(
      new PresenceClient({ baseUrl: presence.baseUrl, apiKey: LOCAL_PRESENCE_API_KEY }),
    ),
    authorityGate,
    "Local bank",
    CRO,
    {
      initialDelayMs: 5,
      maxDelayMs: 10,
      requirements: {
        level: "HIGH_CONFIDENCE",
        methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
        hardware_pki_required: false,
        disallow_virtual_cameras: true,
      },
    },
  );
}

function grantOf(decision: GateDecision) {
  return decision.authorization === null
    ? null
    : authority.grants.get(decision.authorization.token);
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 25));
const waitOptions = { initialDelayMs: 5, maxDelayMs: 10 };

function verificationBody(intentHash?: string, displayed?: string) {
  return {
    action_context: {
      intent: "refund_order",
      surface: "test",
      actor_id: CRO,
      target_resource_id: "shopify:order:synthetic-binding",
      ...(intentHash === undefined ? {} : { intent_hash: intentHash }),
    },
    originator: { organization_name: "Local bank" },
    presentation: {
      locale: "en",
      title: "Approve refund",
      description: "Approve the exact refund shown.",
      display_fields:
        displayed === undefined
          ? []
          : [{ key: "intent_hash", label: "Intent hash", value: displayed }],
    },
    verification_requirements: {
      level: "STANDARD",
      methods: ["WEBAUTHN"],
      hardware_pki_required: false,
      disallow_virtual_cameras: true,
    },
    ttl_seconds: 60,
  };
}

describe("local escalation doubles", () => {
  it("DIRECT: a receipt bound to the exact intent authorizes it and the commit is recorded", async () => {
    const captured = capture();
    const authorityGate = gate();
    expect((await authorityGate.evaluate(captured)).verdict).toBe("ESCALATE");

    const approval = coordinator(authorityGate);
    const handoff = await approval.request(captured);
    const requestId = handoff.request_id ?? "";
    const view = presence.verification(requestId);
    expect(view?.intentHash).toBe(captured.intentHash);
    expect(["structural", "display_field"]).toContain(view?.bindingSource);
    expect(view?.requirements).toMatchObject({
      level: "HIGH_CONFIDENCE",
      methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
    });

    const resolving = approval.resolveAndReauthorize(captured, handoff);
    await settle();
    expect(presence.verification(requestId)?.status).toBe("PENDING");
    expect(presence.approve(requestId)).not.toBeNull();
    const decision = await resolving;

    expect(decision.verdict).toBe("ALLOW");
    expect(decision.reasonCodes).toEqual(["PRESENCE_RECEIPT_VERIFIED"]);
    expect(decision.evidence?.humanApproval?.requestId).toBe(requestId);
    const { calls, executor: run } = executor();
    const result = await run.run(captured, decision);
    expect(result.outcome).toBe("COMPLETED");
    if (result.outcome === "BLOCKED") throw new Error("TEST_EXPECTED_EXECUTION");
    expect(result.finalization).toBe("RECORDED");
    expect(calls).toHaveLength(1);
    expect(grantOf(decision)?.finalized).toBe("COMMITTED");
  });

  it("DIRECT: swapped receipts, denials, expiry, and malformed bindings are refused with reason codes", async () => {
    const approved = capture();
    const authorityGate = gate();
    const approval = coordinator(authorityGate);
    const handoff = await approval.request(approved);
    presence.approve(handoff.request_id ?? "");
    const decision = await approval.resolveAndReauthorize(approved, handoff);
    expect(decision.verdict).toBe("ALLOW");
    const evidence = decision.evidence?.humanApproval;
    if (evidence === undefined) throw new Error("TEST_EXPECTED_EVIDENCE");

    const other = capture();
    expect(await authorityGate.evaluate(other, decision.evidence)).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      authorization: null,
    });
    expect(presence.verifyReceiptDetailed(evidence, { intentHash: other.intentHash })).toEqual({
      ok: false,
      reasonCode: "PRESENCE_INTENT_HASH_MISMATCH",
    });
    expect(
      presence.verifyReceiptDetailed(evidence, {
        intentHash: approved.intentHash,
        actionType: "delete_customer",
      }),
    ).toEqual({ ok: false, reasonCode: "PRESENCE_ACTION_MISMATCH" });
    expect(
      presence.verifyReceiptDetailed(evidence, {
        intentHash: approved.intentHash,
        requiredRole: "TREASURY_APPROVER",
      }),
    ).toEqual({ ok: false, reasonCode: "PRESENCE_APPROVER_ROLE_MISMATCH" });
    expect(
      presence.verifyReceiptDetailed(
        {
          requestId: "synthetic-presence-request-unknown",
          receiptDossierId: evidence.receiptDossierId,
        },
        { intentHash: approved.intentHash },
      ),
    ).toEqual({ ok: false, reasonCode: "PRESENCE_REQUEST_UNKNOWN" });
    expect(
      presence.verifyReceiptDetailed(
        { requestId: evidence.requestId, receiptDossierId: "synthetic-presence-receipt-forged" },
        { intentHash: approved.intentHash },
      ),
    ).toEqual({ ok: false, reasonCode: "PRESENCE_DOSSIER_INVALID" });
    expect(
      presence.verifyReceiptDetailed(evidence, { intentHash: approved.intentHash }),
    ).toMatchObject({
      ok: true,
      approverIdentity: CRO,
      approverRole: "CRO",
      authenticator: { method: "WEBAUTHN", user_verified: true },
    });

    const denied = capture();
    const deniedHandoff = await approval.request(denied);
    presence.deny(deniedHandoff.request_id ?? "");
    expect(await approval.resolveAndReauthorize(denied, deniedHandoff)).toMatchObject({
      verdict: "BLOCK",
      reasonCodes: ["PRESENCE_DENIED"],
    });

    const expiring = capture();
    const expiringHandoff = await approval.request(expiring);
    presence.expire(expiringHandoff.request_id ?? "");
    expect(await approval.resolveAndReauthorize(expiring, expiringHandoff)).toMatchObject({
      verdict: "BLOCK",
      reasonCodes: ["PRESENCE_DENIED"],
    });

    const a = approved.intentHash;
    const b = other.intentHash;
    expect(presence.createRequest(verificationBody(a, b), "binding-conflict-000001").status).toBe(
      400,
    );
    const structural = presence.createRequest(verificationBody(a), "binding-structural-0001");
    expect(structural.status).toBe(200);
    const structuralId = (structural.body as { request_id: string }).request_id;
    expect(presence.verification(structuralId)?.bindingSource).toBe("structural");
    expect(
      presence.createRequest(verificationBody(a), "binding-structural-0001").body,
    ).toMatchObject({ request_id: structuralId });
    const unbound = presence.createRequest(verificationBody(), "binding-none-00000001");
    const unboundId = (unbound.body as { request_id: string }).request_id;
    expect(presence.verification(unboundId)?.bindingSource).toBe("none");
    presence.approve(unboundId);
    const unboundReceipt = presence.verification(unboundId)?.receiptDossierId ?? "";
    expect(
      presence.verifyReceiptDetailed(
        { requestId: unboundId, receiptDossierId: unboundReceipt },
        { intentHash: a },
      ),
    ).toEqual({ ok: false, reasonCode: "PRESENCE_INTENT_HASH_MISMATCH" });
    expect(presence.createRequest(verificationBody(a), "short").status).toBe(400);
  });

  it("MANAGED: the authority orchestrates the local Presence and exposes a normal grant", async () => {
    const captured = capture();
    const authorityGate = gate();
    const pending = await authorityGate.evaluate(captured, undefined, {
      escalation: {
        mode: "MANAGED",
        approver: { principal_id: CRO, role_id: "CRO" },
        verification_requirements: {
          level: "HIGH_CONFIDENCE",
          methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
        },
      },
    });
    expect(pending.verdict).toBe("ESCALATE");
    expect(pending.authorization).toBeNull();
    expect(pending.managedEscalation?.status).toBe("PENDING_PRESENCE");
    const record = authority.escalations.get(pending.managedEscalation?.escalationId ?? "");
    if (record === undefined || record.presenceRequestId === null) {
      throw new Error("TEST_EXPECTED_ORCHESTRATED_ESCALATION");
    }
    expect(record.status).toBe("AWAITING_APPROVER");
    const view = presence.verification(record.presenceRequestId);
    expect(view).toMatchObject({
      bindingSource: "structural",
      intentHash: captured.intentHash,
      subjectActorId: CRO,
      action: { intent: "refund_order", target: captured.intent.target },
    });
    expect(view?.requirements).toMatchObject({
      level: "HIGH_CONFIDENCE",
      methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
    });

    const waiting = authorityGate.waitForAuthorization(captured, pending, waitOptions);
    await settle();
    expect(presence.verification(record.presenceRequestId)?.status).toBe("PENDING");
    presence.approve(record.presenceRequestId);
    const authorized = await waiting;

    expect(authorized.verdict).toBe("ALLOW");
    expect(authorized.reasonCodes).toEqual(["PRESENCE_RECEIPT_VERIFIED"]);
    expect(authorized.authorization).not.toBeNull();
    expect(record.status).toBe("GRANT_READY");
    const { calls, executor: run } = executor();
    const result = await run.run(captured, authorized);
    expect(result.outcome).toBe("COMPLETED");
    if (result.outcome === "BLOCKED") throw new Error("TEST_EXPECTED_EXECUTION");
    expect(result.finalization).toBe("RECORDED");
    expect(calls).toHaveLength(1);
    expect(grantOf(authorized)?.finalized).toBe("COMMITTED");
    const claim = authority.requests.filter((r) => r.path === "/v1/execution/claim-token").at(-1);
    expect((claim?.body as { evidence?: unknown }).evidence).toBeUndefined();
  });

  it("MANAGED: denial, role mismatch, cancellation, and expiry are terminal without a grant", async () => {
    const open = async (approver: { principal_id: string; role_id: string }) => {
      const captured = capture();
      const authorityGate = gate();
      const pending = await authorityGate.evaluate(captured, undefined, {
        escalation: { mode: "MANAGED", approver },
      });
      const record = authority.escalations.get(pending.managedEscalation?.escalationId ?? "");
      if (record === undefined || record.presenceRequestId === null) {
        throw new Error("TEST_EXPECTED_ORCHESTRATED_ESCALATION");
      }
      return {
        captured,
        authorityGate,
        pending,
        record,
        presenceRequestId: record.presenceRequestId,
      };
    };

    const denied = await open({ principal_id: CRO, role_id: "CRO" });
    presence.deny(denied.presenceRequestId);
    expect(
      await denied.authorityGate.waitForAuthorization(denied.captured, denied.pending, waitOptions),
    ).toMatchObject({ verdict: "BLOCK", authorization: null, reasonCodes: ["PRESENCE_REJECTED"] });
    expect(denied.record.status).toBe("REJECTED");

    const wrongRole = await open({ principal_id: CRO, role_id: "TREASURY_APPROVER" });
    presence.approve(wrongRole.presenceRequestId);
    const roleDecision = await wrongRole.authorityGate.waitForAuthorization(
      wrongRole.captured,
      wrongRole.pending,
      waitOptions,
    );
    expect(roleDecision.verdict).toBe("BLOCK");
    expect(roleDecision.authorization).toBeNull();
    expect(roleDecision.reasonCodes).toContain("PRESENCE_APPROVER_ROLE_MISMATCH");
    expect(wrongRole.record.status).toBe("FAILED");

    const cancelled = await open({ principal_id: CRO, role_id: "CRO" });
    const reply = await fetch(
      `${authority.baseUrl}/v1/authority/escalations/${cancelled.record.escalationId}`,
      { method: "DELETE", headers: { authorization: `Bearer ${LOCAL_AUTHORITY_API_KEY}` } },
    );
    expect(reply.status).toBe(200);
    expect(presence.verification(cancelled.presenceRequestId)?.status).toBe("CANCELLED");
    const cancelledDecision = await cancelled.authorityGate.waitForAuthorization(
      cancelled.captured,
      cancelled.pending,
      waitOptions,
    );
    expect(cancelledDecision).toMatchObject({ verdict: "BLOCK", authorization: null });
    expect(cancelledDecision.reasonCodes).toContain("MANAGED_ESCALATION_CANCELLED");

    const expired = await open({ principal_id: CRO, role_id: "CRO" });
    presence.expire(expired.presenceRequestId);
    const expiredDecision = await expired.authorityGate.waitForAuthorization(
      expired.captured,
      expired.pending,
      waitOptions,
    );
    expect(expiredDecision.verdict).toBe("BLOCK");
    expect(expiredDecision.reasonCodes).toContain("PRESENCE_EXPIRED");
    expect(expired.record.status).toBe("EXPIRED");
  });

  it("refuses to construct under NODE_ENV=production", () => {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      expect(() => new LocalPresence()).toThrow("LOCAL_DOUBLE_FORBIDDEN");
      expect(() => new LocalAuthority()).toThrow("LOCAL_DOUBLE_FORBIDDEN");
    } finally {
      if (previous === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previous;
    }
  });
});
