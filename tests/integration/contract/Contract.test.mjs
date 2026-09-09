/**
 * End-to-end wire-contract harness for @decionis/agent-safe-pipeline.
 *
 * Every scenario drives the package through its public entry point against a
 * loopback Decionis authority stub and a loopback Presence stub over a real
 * HTTP stack. Assertions cover methods, paths, headers, the exact binding
 * fields, evidence forwarding, response limits, grant claim and finalization
 * payloads, and fail-closed behavior under transport faults.
 *
 * All tenants, actors, orders, grants, and receipts are synthetic.
 */
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { after, before, test } from "node:test";
import { z } from "zod";
import { HumanApprovalGate, PresenceClient } from "@decionis/presence-node";
import {
  ActionRegistry,
  AuditRecorder,
  DecionisGate,
  DecionisGrantVerifier,
  IntentCapture,
  PresenceApprovalCoordinator,
  SafeExecutor,
  ShadowPipeline,
} from "@decionis/agent-safe-pipeline";
import {
  LOCAL_AUTHORITY_API_KEY as STUB_API_KEY,
  LOCAL_PRESENCE_API_KEY as PRESENCE_API_KEY,
  LocalAuthority as AuthorityStub,
  LocalPresence as PresenceStub,
  hashBinding,
} from "@decionis/agent-safe-pipeline/testing";

const TENANT_ID = "00000000-0000-4000-8000-000000000003";
const ACTOR_ID = "synthetic-contract-agent";
const TEST_OPTIONS = { timeout: 15_000 };
const ENFORCE_PATH = "/v1/authority/enforce-and-bind";
const CLAIM_PATH = "/v1/execution/claim-token";
const FINALIZE_PATH = "/v1/execution/finalize-token";
const REQUEST_KEYS = [
  "action",
  "actor",
  "captured_at",
  "context",
  "downstream_target",
  "expires_at",
  "intent_hash",
  "intent_id",
  "mode",
  "protocol_version",
  "tenant_id",
];
const BINDING_KEYS = REQUEST_KEYS.filter((key) => key !== "intent_hash" && key !== "mode");
const OTHER_HASH = `sha256:${"0".repeat(64)}`;

const presence = new PresenceStub();
const authority = new AuthorityStub({
  verifyReceipt: (approval, intentHash) => presence.verifyReceipt(approval, intentHash),
});

before(async () => {
  await presence.start();
  await authority.start();
});

after(async () => {
  await writeDiagnostics();
  await authority.stop();
  await presence.stop();
});

function capture(amountMinor, target = "shopify:order:synthetic-2001", action = "refund_order") {
  const orderId = target.split(":").at(-1);
  return new IntentCapture().capture(
    {
      action,
      target,
      parameters: { amountMinor, currency: "USD", orderId },
    },
    {
      tenantId: TENANT_ID,
      actor: { id: ACTOR_ID, type: "AI_AGENT", runtime: "contract-harness" },
      downstreamTarget: { system: "shopify", operation: "refund", environment: "synthetic" },
      idempotencyKey: `${action}-${orderId}-${amountMinor}`,
      context: { source: "contract-harness" },
    },
  );
}

function gate(options = {}) {
  return new DecionisGate({
    baseUrl: authority.baseUrl,
    apiKey: STUB_API_KEY,
    allowInsecureLoopback: true,
    ...options,
  });
}

function verifier(options = {}) {
  return new DecionisGrantVerifier({
    baseUrl: authority.baseUrl,
    apiKey: STUB_API_KEY,
    allowInsecureLoopback: true,
    ...options,
  });
}

function registry() {
  const calls = [];
  const sealed = new ActionRegistry()
    .register("refund_order", {
      parametersSchema: z
        .object({
          amountMinor: z.number().int().positive(),
          currency: z.literal("USD"),
          orderId: z.string(),
        })
        .strict(),
      execute: async ({ parameters, dispatch }) =>
        await dispatch.run(async (idempotencyKey) => {
          calls.push(idempotencyKey);
          return { refunded: parameters.amountMinor, idempotencyKey };
        }),
    })
    .seal();
  return { calls, sealed };
}

function requestsSince(from, path) {
  return authority.requests.slice(from).filter((request) => request.path === path);
}

function lastRequest(path) {
  const matching = authority.requests.filter((request) => request.path === path);
  return matching[matching.length - 1];
}

async function approveThroughPresence(captured, authorityGate = gate()) {
  const coordinator = new PresenceApprovalCoordinator(
    new HumanApprovalGate(
      new PresenceClient({ baseUrl: presence.baseUrl, apiKey: PRESENCE_API_KEY }),
    ),
    authorityGate,
    "Synthetic Shop",
    "synthetic-approver",
    { initialDelayMs: 20, maxDelayMs: 50 },
  );
  const gateResult = await coordinator.request(captured);
  const decision = await coordinator.resolveAndReauthorize(captured, gateResult);
  return { gateResult, decision };
}

test(
  "ALLOW: the full wire round trip claims, executes once, and finalizes",
  TEST_OPTIONS,
  async () => {
    const from = authority.requests.length;
    const captured = capture(5_000);
    const { calls, sealed } = registry();
    const events = [];
    const audit = new AuditRecorder({
      sink: {
        write: (event) => {
          events.push(event);
        },
      },
    });

    const decision = await gate().evaluate(captured);
    assert.equal(decision.verdict, "ALLOW");
    assert.deepEqual(decision.reasonCodes, ["POLICY_AUTONOMOUS_LIMIT"]);
    assert.ok(decision.authorization);
    assert.equal(decision.evidence, undefined);

    const result = await new SafeExecutor(sealed, verifier(), audit).run(captured, decision);
    assert.equal(result.outcome, "COMPLETED");
    assert.equal(result.executed, true);
    assert.equal(result.finalization, "RECORDED");
    assert.deepEqual(result.result, {
      refunded: 5_000,
      idempotencyKey: captured.intent.idempotencyKey,
    });
    assert.deepEqual(calls, [captured.intent.idempotencyKey]);

    const seen = authority.requests.slice(from);
    assert.deepEqual(
      seen.map((request) => `${request.method} ${request.path}`),
      [`POST ${ENFORCE_PATH}`, `POST ${CLAIM_PATH}`, `POST ${FINALIZE_PATH}`],
    );
    const [enforce, claim, finalize] = seen;

    assert.equal(enforce.headers.authorization, `Bearer ${STUB_API_KEY}`);
    assert.equal(enforce.headers["content-type"], "application/json");
    assert.equal(enforce.headers["idempotency-key"], captured.intent.intentId);
    assert.deepEqual(Object.keys(enforce.body).sort(), REQUEST_KEYS);
    assert.equal(enforce.body.intent_hash, captured.intentHash);
    assert.equal(enforce.recomputedHash, captured.intentHash);
    assert.equal(enforce.body.mode, "ENFORCEMENT");
    assert.equal(enforce.body.evidence, undefined);
    assert.deepEqual(enforce.body.context, {
      source: "contract-harness",
      idempotency_key: captured.intent.idempotencyKey,
    });
    assert.deepEqual(enforce.body.downstream_target, {
      system: "shopify",
      operation: "refund",
      environment: "synthetic",
    });
    assert.equal(enforce.response.status, 200);

    const grant = authority.grants.get(decision.authorization.token);
    assert.ok(grant, "the stub issued a grant for the returned token");
    assert.deepEqual(Object.keys(claim.body).sort(), [
      "commit_correlation_id",
      "consumed_by",
      "execution_token",
      "intent",
      "intent_hash",
    ]);
    assert.equal(claim.body.execution_token, decision.authorization.token);
    assert.equal(claim.body.intent_hash, captured.intentHash);
    assert.deepEqual(Object.keys(claim.body.intent).sort(), BINDING_KEYS);
    assert.equal(claim.recomputedHash, captured.intentHash);
    assert.equal(claim.body.consumed_by, ACTOR_ID);
    assert.equal(claim.body.commit_correlation_id, captured.intent.intentId);
    assert.equal(claim.response.status, 200);
    assert.deepEqual(result.authorization, {
      decisionId: decision.decisionId,
      dossierId: decision.dossierId,
      grantId: grant.jti,
      intentHash: captured.intentHash,
      expiresAt: decision.authorization.expiresAt,
    });

    assert.deepEqual(finalize.body, {
      execution_token: decision.authorization.token,
      claim_token: grant.claimToken,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
    });
    assert.equal(grant.finalized, "COMMITTED");

    assert.deepEqual(
      events.map((event) => event.eventType),
      [
        "INTENT_CAPTURED",
        "AUTHORITY_DECISION",
        "GRANT_CONSUMED",
        "EXECUTION_STARTED",
        "EXECUTION_COMPLETED",
      ],
    );
    assert.deepEqual(events.at(-1).reasonCodes, ["COMMIT_FINALIZATION_RECORDED"]);
    const serialized = JSON.stringify(events);
    assert.ok(!serialized.includes(decision.authorization.token));
    assert.ok(!serialized.includes(grant.claimToken));
  },
);

test(
  "BLOCK: a policy refusal never reaches the claim route or the handler",
  TEST_OPTIONS,
  async () => {
    const from = authority.requests.length;
    const captured = capture(250_000);
    const { calls, sealed } = registry();

    const decision = await gate().evaluate(captured);
    assert.equal(decision.verdict, "BLOCK");
    assert.equal(decision.failClosed, false);
    assert.equal(decision.authorization, null);
    assert.deepEqual(decision.reasonCodes, ["POLICY_HARD_LIMIT_EXCEEDED"]);
    assert.ok(decision.dossierId);

    const result = await new SafeExecutor(sealed, verifier()).run(captured, decision);
    assert.deepEqual(result, {
      outcome: "BLOCKED",
      executed: false,
      reason: "DECISION_NOT_ALLOW",
      result: null,
      authorization: null,
    });
    assert.deepEqual(calls, []);
    assert.equal(requestsSince(from, CLAIM_PATH).length, 0);
    assert.equal(requestsSince(from, FINALIZE_PATH).length, 0);
  },
);

test(
  "ESCALATE: Presence evidence flows through re-authorization and the claim",
  TEST_OPTIONS,
  async () => {
    const captured = capture(50_000);
    const authorityGate = gate();

    const first = await authorityGate.evaluate(captured);
    assert.equal(first.verdict, "ESCALATE");
    assert.equal(first.authorization, null);
    assert.deepEqual(first.reasonCodes, ["HUMAN_APPROVAL_REQUIRED"]);
    assert.equal(
      lastRequest(ENFORCE_PATH).response.body.approval_request_id,
      "synthetic-approval-3",
    );

    const presenceFrom = presence.requests.length;
    const { gateResult, decision } = await approveThroughPresence(captured, authorityGate);
    assert.equal(gateResult.verdict, "HUMAN_REQUIRED");

    const presenceSeen = presence.requests.slice(presenceFrom);
    const created = presenceSeen[0];
    assert.equal(`${created.method} ${created.path}`, "POST /v1/verification-requests");
    assert.equal(created.headers.authorization, `Bearer ${PRESENCE_API_KEY}`);
    assert.match(created.headers["idempotency-key"], /^presence-[0-9a-f]{64}$/);
    assert.equal(created.body.originator.actor_id, ACTOR_ID);
    assert.equal(created.body.action_context.intent, "refund_order");
    assert.deepEqual(
      created.body.presentation.display_fields.map((field) => field.key),
      ["action", "target", "intent_hash"],
    );
    assert.equal(created.body.presentation.display_fields[2].value, captured.intentHash);
    const lookups = presenceSeen.filter((request) => request.method === "GET");
    assert.ok(lookups.length >= 2, "the coordinator polled through a pending outcome");
    assert.equal(lookups.at(-1).response.body.status, "ALLOWED");
    const receiptDossierId = lookups.at(-1).response.body.receipt_dossier_id;

    assert.equal(decision.verdict, "ALLOW");
    assert.deepEqual(decision.reasonCodes, ["PRESENCE_RECEIPT_VERIFIED"]);
    assert.ok(decision.authorization);
    assert.deepEqual(decision.evidence, {
      humanApproval: {
        provider: "presence",
        requestId: gateResult.request_id,
        receiptDossierId,
      },
    });
    const reauthorization = lastRequest(ENFORCE_PATH);
    assert.equal(reauthorization.body.intent_hash, captured.intentHash);
    assert.deepEqual(reauthorization.body.evidence, decision.evidence);
    assert.equal(reauthorization.headers["idempotency-key"], captured.intent.intentId);

    // A claim that omits the evidence is refused by the authority, so the handler never runs.
    const { calls, sealed } = registry();
    const stripped = { ...decision, evidence: undefined };
    const blocked = await new SafeExecutor(sealed, verifier()).run(captured, stripped);
    assert.equal(blocked.outcome, "BLOCKED");
    assert.equal(blocked.reason, "AUTHORIZATION_INVALID");
    const refusedClaim = lastRequest(CLAIM_PATH);
    assert.equal(refusedClaim.body.evidence, undefined);
    assert.equal(refusedClaim.response.status, 409);
    assert.deepEqual(refusedClaim.response.body.reason_codes, ["PRESENCE_APPROVAL_STALE"]);
    assert.deepEqual(calls, []);

    const result = await new SafeExecutor(sealed, verifier()).run(captured, decision);
    assert.equal(result.outcome, "COMPLETED");
    assert.equal(result.finalization, "RECORDED");
    assert.deepEqual(lastRequest(CLAIM_PATH).body.evidence, decision.evidence);
    assert.deepEqual(calls, [captured.intent.idempotencyKey]);
  },
);

test(
  "Approval swapping: a receipt for one intent cannot authorize another",
  TEST_OPTIONS,
  async () => {
    const approved = capture(50_000);
    const { decision: approvedDecision } = await approveThroughPresence(approved);
    assert.equal(approvedDecision.verdict, "ALLOW");

    const other = capture(60_000);
    const swapped = await gate().evaluate(other, approvedDecision.evidence);

    assert.equal(swapped.verdict, "BLOCK");
    assert.equal(swapped.failClosed, true);
    assert.equal(swapped.authorization, null);
    assert.deepEqual(swapped.reasonCodes, ["AUTHORITY_REQUEST_FAILED"]);
    const refused = lastRequest(ENFORCE_PATH);
    assert.equal(refused.response.status, 409);
    assert.deepEqual(refused.response.body, { error: "PRESENCE_RECEIPT_INVALID" });

    presence.scriptNextStatus("BLOCKED");
    const denied = capture(70_000);
    const { decision: deniedDecision } = await approveThroughPresence(denied);
    assert.equal(deniedDecision.verdict, "BLOCK");
    assert.equal(deniedDecision.failClosed, true);
    assert.deepEqual(deniedDecision.reasonCodes, ["PRESENCE_DENIED"]);
  },
);

test(
  "MANAGED: Decionis-only polling yields a normal single-use grant and finalization",
  TEST_OPTIONS,
  async () => {
    const from = authority.requests.length;
    const presenceFrom = presence.requests.length;
    const escalationsBefore = authority.escalations.size;
    const captured = capture(50_000, "shopify:order:synthetic-managed-4001");
    const authorityGate = gate();
    const escalation = {
      escalation: {
        mode: "MANAGED",
        approver: { principal_id: "synthetic-approver", role_id: "APPROVER" },
        verification_requirements: { methods: ["WEBAUTHN"], level: "STANDARD" },
      },
    };
    authority.scriptNextManagedLifecycle([
      "AWAITING_APPROVER",
      "PRESENCE_VERIFIED",
      "REAUTHORIZING",
      "GRANT_READY",
    ]);

    const pending = await authorityGate.evaluate(captured, undefined, escalation);
    assert.equal(pending.verdict, "ESCALATE");
    assert.equal(pending.authorization, null);
    assert.equal(pending.evidence, undefined);
    assert.equal(pending.managedEscalation?.outcome, "ESCALATE_PENDING");
    assert.equal(pending.managedEscalation?.status, "PENDING_PRESENCE");
    assert.equal(pending.managedEscalation?.intentId, captured.intent.intentId);

    const repeated = await authorityGate.evaluate(captured, undefined, escalation);
    assert.equal(repeated.managedEscalation?.escalationId, pending.managedEscalation?.escalationId);
    assert.equal(authority.escalations.size, escalationsBefore + 1);

    const enforceRequests = requestsSince(from, ENFORCE_PATH);
    assert.equal(enforceRequests.length, 2);
    assert.deepEqual(enforceRequests[0].body.escalation, escalation.escalation);
    assert.equal(enforceRequests[0].headers["idempotency-key"], captured.intent.intentId);
    assert.equal(enforceRequests[1].headers["idempotency-key"], captured.intent.intentId);
    assert.equal(enforceRequests[0].body.intent_hash, captured.intentHash);
    assert.equal(enforceRequests[0].response.body.execution_token, null);
    assert.equal(enforceRequests[0].response.body.execution_token_expires_at, null);

    const firstStatus = await authorityGate.getManagedEscalationStatus(
      captured,
      pending.managedEscalation,
    );
    assert.equal(firstStatus.status, "AWAITING_APPROVER");
    assert.equal(firstStatus.outcome, "ESCALATE_PENDING");
    assert.equal(firstStatus.decision, null);

    const authorized = await authorityGate.waitForAuthorization(captured, pending, {
      initialDelayMs: 1,
      maxDelayMs: 2,
      random: () => 1,
    });
    assert.equal(authorized.verdict, "ALLOW");
    assert.equal(authorized.failClosed, false);
    assert.ok(authorized.authorization);
    assert.equal(authorized.evidence, undefined);
    assert.equal(authorized.managedEscalation?.status, "GRANT_READY");
    assert.equal(authorized.managedEscalation?.outcome, "ALLOW");

    const { calls, sealed } = registry();
    const executor = new SafeExecutor(sealed, verifier());
    const completed = await executor.run(captured, authorized);
    const replayed = await executor.run(captured, authorized);

    assert.equal(completed.outcome, "COMPLETED");
    assert.equal(completed.finalization, "RECORDED");
    assert.equal(replayed.outcome, "BLOCKED");
    assert.equal(replayed.reason, "AUTHORIZATION_INVALID");
    assert.deepEqual(calls, [captured.intent.idempotencyKey]);
    const managedClaims = requestsSince(from, CLAIM_PATH);
    assert.equal(managedClaims.length, 2);
    assert.equal(managedClaims[0].body.evidence, undefined);
    assert.equal(managedClaims[0].response.status, 200);
    assert.equal(managedClaims[1].response.status, 409);
    assert.equal(requestsSince(from, FINALIZE_PATH).length, 1);
    assert.equal(
      presence.requests.length,
      presenceFrom,
      "managed executor never contacted Presence",
    );
  },
);

test(
  "MANAGED: liveness is forwarded and reauthorization BLOCK, ESCALATE, expiry, and failure stay grant-free",
  TEST_OPTIONS,
  async () => {
    const presenceFrom = presence.requests.length;
    const scenarios = [
      {
        lifecycle: { status: "BLOCKED", reasonCodes: ["REAUTHORIZATION_BLOCKED"] },
        reason: "REAUTHORIZATION_BLOCKED",
        failClosed: false,
      },
      {
        lifecycle: { status: "BLOCKED", reasonCodes: ["REAUTHORIZATION_ESCALATED"] },
        reason: "REAUTHORIZATION_ESCALATED",
        failClosed: false,
      },
      {
        lifecycle: { status: "EXPIRED", reasonCodes: ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"] },
        reason: "INTENT_EXPIRED",
        failClosed: false,
      },
      {
        lifecycle: { status: "FAILED", reasonCodes: ["PRESENCE_VERIFICATION_FAILED"] },
        reason: "PRESENCE_VERIFICATION_FAILED",
        failClosed: true,
      },
    ];

    for (const [index, scenario] of scenarios.entries()) {
      const from = authority.requests.length;
      const captured = capture(51_000 + index, `shopify:order:synthetic-managed-${4100 + index}`);
      authority.scriptNextManagedLifecycle([scenario.lifecycle]);
      const authorityGate = gate();
      const pending = await authorityGate.evaluate(captured, undefined, {
        escalation: {
          mode: "MANAGED",
          approver: { role_id: "TREASURY_APPROVER" },
          verification_requirements: {
            methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
            level: "HIGH_CONFIDENCE",
          },
        },
      });
      const request = requestsSince(from, ENFORCE_PATH)[0];
      assert.deepEqual(request.body.escalation.verification_requirements, {
        methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
        level: "HIGH_CONFIDENCE",
      });

      const terminal = await authorityGate.waitForAuthorization(captured, pending, {
        maxAttempts: 1,
      });
      assert.equal(terminal.verdict, "BLOCK", scenario.reason);
      assert.equal(terminal.authorization, null, scenario.reason);
      assert.equal(terminal.failClosed, scenario.failClosed, scenario.reason);
      assert.equal(terminal.reasonCodes[0], scenario.reason);

      const { calls, sealed } = registry();
      const result = await new SafeExecutor(sealed, verifier()).run(captured, terminal);
      assert.equal(result.outcome, "BLOCKED");
      assert.deepEqual(calls, []);
      assert.equal(requestsSince(from, CLAIM_PATH).length, 0);
      assert.equal(requestsSince(from, FINALIZE_PATH).length, 0);
    }
    assert.equal(presence.requests.length, presenceFrom);
  },
);

test(
  "MANAGED: changed action target cannot use another escalation or its ready grant",
  TEST_OPTIONS,
  async () => {
    const approved = capture(50_000, "shopify:order:synthetic-managed-4201");
    const changedTarget = capture(50_000, "shopify:order:synthetic-managed-4202");
    const changedAction = capture(
      50_000,
      "shopify:order:synthetic-managed-4201",
      "capture_payment",
    );
    authority.scriptNextManagedLifecycle(["GRANT_READY"]);
    const authorityGate = gate();
    const pending = await authorityGate.evaluate(approved, undefined, {
      escalation: { mode: "MANAGED" },
    });

    const statusFrom = authority.requests.length;
    for (const changed of [changedTarget, changedAction]) {
      const swappedStatus = await authorityGate.getManagedEscalationStatus(
        changed,
        pending.managedEscalation,
      );
      assert.equal(swappedStatus.status, "FAILED");
      assert.deepEqual(swappedStatus.reasonCodes, ["MANAGED_ESCALATION_INTENT_MISMATCH"]);
    }
    assert.equal(
      authority.requests.length,
      statusFrom,
      "binding mismatch was rejected before polling",
    );

    const authorized = await authorityGate.waitForAuthorization(approved, pending, {
      maxAttempts: 1,
    });
    assert.equal(authorized.verdict, "ALLOW");
    const from = authority.requests.length;
    const { calls, sealed } = registry();
    const executor = new SafeExecutor(sealed, verifier());
    for (const changed of [changedTarget, changedAction]) {
      const swappedExecution = await executor.run(changed, authorized);
      assert.equal(swappedExecution.outcome, "BLOCKED");
      assert.equal(swappedExecution.reason, "INTENT_BINDING_MISMATCH");
    }
    assert.deepEqual(calls, []);
    assert.equal(requestsSince(from, CLAIM_PATH).length, 0);
  },
);

test("MANAGED: concurrent waits share one bounded status lookup", TEST_OPTIONS, async () => {
  const captured = capture(50_000, "shopify:order:synthetic-managed-4301");
  authority.scriptNextManagedLifecycle(["GRANT_READY"]);
  const authorityGate = gate();
  const pending = await authorityGate.evaluate(captured, undefined, {
    escalation: { mode: "MANAGED" },
  });
  const from = authority.requests.length;

  const decisions = await Promise.all(
    Array.from(
      { length: 20 },
      async () => await authorityGate.waitForAuthorization(captured, pending),
    ),
  );

  assert.ok(decisions.every((decision) => decision.verdict === "ALLOW"));
  assert.equal(
    authority.requests.slice(from).filter((request) => request.method === "GET").length,
    1,
  );
});

test("Shadow mode records the decision on the wire without a grant", TEST_OPTIONS, async () => {
  const captured = capture(5_000);
  const grantsBefore = authority.grants.size;
  const shadow = new ShadowPipeline(gate({ mode: "SHADOW" }));

  const comparison = await shadow.compare(captured, () => "legacy-executed");

  assert.deepEqual(comparison.production, { status: "COMPLETED", result: "legacy-executed" });
  assert.equal(comparison.observation.status, "OBSERVED");
  assert.equal(comparison.observation.verdict, "ALLOW");
  assert.equal(comparison.observation.grantDiscarded, false);
  assert.equal("authorization" in comparison.observation, false);
  const request = lastRequest(ENFORCE_PATH);
  assert.equal(request.body.mode, "SHADOW");
  assert.equal(request.body.intent_hash, captured.intentHash);
  assert.equal(request.response.body.mode, "SHADOW");
  assert.equal(request.response.body.execution_token, null);
  assert.equal(request.response.body.should_execute, false);
  assert.equal(request.response.body.decision_id, comparison.observation.decisionId);
  assert.equal(authority.grants.size, grantsBefore);
});

test("A grant is claimed exactly once across repeated executions", TEST_OPTIONS, async () => {
  const captured = capture(5_000);
  const { calls, sealed } = registry();
  const decision = await gate().evaluate(captured);
  const executor = new SafeExecutor(sealed, verifier());

  const first = await executor.run(captured, decision);
  const second = await executor.run(captured, decision);

  assert.equal(first.outcome, "COMPLETED");
  assert.equal(second.outcome, "BLOCKED");
  assert.equal(second.reason, "AUTHORIZATION_INVALID");
  const replay = lastRequest(CLAIM_PATH);
  assert.equal(replay.response.status, 409);
  assert.deepEqual(replay.response.body.reason_codes, ["NONCE_REPLAY_DETECTED"]);
  assert.deepEqual(calls, [captured.intent.idempotencyKey]);
});

test(
  "Authority faults on enforce-and-bind fail closed before any claim",
  TEST_OPTIONS,
  async () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const errorDecision = (reasonCode) => (decision) => ({
      ...decision,
      status: "ERROR",
      should_execute: false,
      reason_codes: [reasonCode],
      mode: null,
      execution_token: null,
      execution_token_expires_at: null,
    });
    const scenarios = [
      {
        name: "401 unauthorized",
        gateOptions: { apiKey: "wrong-key" },
        expect: "AUTHORITY_REQUEST_FAILED",
      },
      {
        name: "503 ERROR decision body",
        override: { status: 503, transform: errorDecision("EXECUTION_GRANTS_UNAVAILABLE") },
        expect: "EXECUTION_GRANTS_UNAVAILABLE",
      },
      {
        name: "409 idempotency conflict",
        override: { status: 409, transform: errorDecision("AUTHORITY_IDEMPOTENCY_CONFLICT") },
        expect: "AUTHORITY_IDEMPOTENCY_CONFLICT",
      },
      { name: "malformed JSON", override: { body: "{not-json" }, expect: "AUTHORITY_UNAVAILABLE" },
      {
        name: "oversized body",
        override: { body: JSON.stringify({ padding: "x".repeat(150 * 1024) }) },
        expect: "AUTHORITY_RESPONSE_TOO_LARGE",
      },
      { name: "truncated body", override: { truncateTo: 64 }, expect: "AUTHORITY_UNAVAILABLE" },
      {
        name: "binding mismatch",
        override: { transform: (decision) => ({ ...decision, action_hash: OTHER_HASH }) },
        expect: "AUTHORITY_BINDING_MISMATCH",
      },
      {
        name: "expired grant",
        override: {
          transform: (decision) => ({ ...decision, execution_token_expires_at: past }),
        },
        expect: "AUTHORITY_GRANT_MISSING",
      },
      {
        name: "mode mismatch",
        override: { transform: (decision) => ({ ...decision, mode: "SHADOW" }) },
        expect: "AUTHORITY_MODE_MISMATCH",
      },
      {
        name: "undocumented field",
        override: { transform: (decision) => ({ ...decision, bypass_execution: true }) },
        expect: "AUTHORITY_UNAVAILABLE",
      },
      {
        name: "delayed beyond the gate timeout",
        gateOptions: { timeoutMs: 300 },
        override: { delayMs: 1_500 },
        expect: "AUTHORITY_UNAVAILABLE",
        maxElapsedMs: 1_200,
      },
      {
        name: "connection terminated",
        override: { destroy: true },
        expect: "AUTHORITY_UNAVAILABLE",
      },
    ];

    for (const scenario of scenarios) {
      const from = authority.requests.length;
      const captured = capture(5_000);
      const { calls, sealed } = registry();
      if (scenario.override !== undefined) authority.scriptOnce("enforce", scenario.override);

      const startedAt = Date.now();
      const decision = await gate(scenario.gateOptions).evaluate(captured);
      const elapsed = Date.now() - startedAt;

      assert.equal(decision.verdict, "BLOCK", scenario.name);
      assert.equal(decision.failClosed, true, scenario.name);
      assert.equal(decision.authorization, null, scenario.name);
      assert.deepEqual(decision.reasonCodes, [scenario.expect], scenario.name);
      if (scenario.maxElapsedMs !== undefined) {
        assert.ok(elapsed < scenario.maxElapsedMs, `${scenario.name}: took ${elapsed}ms`);
      }

      const result = await new SafeExecutor(sealed, verifier()).run(captured, decision);
      assert.equal(result.outcome, "BLOCKED", scenario.name);
      assert.equal(result.reason, "DECISION_NOT_ALLOW", scenario.name);
      assert.deepEqual(calls, [], scenario.name);
      assert.equal(requestsSince(from, CLAIM_PATH).length, 0, scenario.name);
    }
  },
);

test("Claim faults block execution without invoking the handler", TEST_OPTIONS, async () => {
  const pastSeconds = Math.floor(Date.now() / 1_000) - 60;
  const scenarios = [
    {
      name: "503 unresolved state",
      override: {
        status: 503,
        body: { valid: false, reason_codes: ["CURRENT_STATE_UNRESOLVED"], claims: null },
      },
    },
    { name: "malformed JSON", override: { body: "{not-json" } },
    {
      name: "oversized body",
      override: { body: JSON.stringify({ padding: "x".repeat(150 * 1024) }) },
    },
    { name: "truncated body", override: { truncateTo: 64 } },
    {
      name: "claims binding mismatch",
      override: {
        transform: (response) => ({
          ...response,
          claims: {
            ...response.claims,
            binding: { ...response.claims.binding, intent_hash: OTHER_HASH },
          },
        }),
      },
    },
    {
      name: "expired claims",
      override: {
        transform: (response) => ({
          ...response,
          claims: { ...response.claims, exp: pastSeconds },
        }),
      },
    },
    {
      name: "missing claim token",
      override: { transform: (response) => ({ ...response, claim_token: null }) },
    },
    {
      name: "delayed beyond the verifier timeout",
      verifierOptions: { timeoutMs: 300 },
      override: { delayMs: 1_500 },
      maxElapsedMs: 1_200,
    },
    { name: "connection terminated", override: { destroy: true } },
  ];

  for (const scenario of scenarios) {
    const from = authority.requests.length;
    const captured = capture(5_000);
    const { calls, sealed } = registry();
    const decision = await gate().evaluate(captured);
    assert.equal(decision.verdict, "ALLOW", scenario.name);
    authority.scriptOnce("claim", scenario.override);

    const startedAt = Date.now();
    const result = await new SafeExecutor(sealed, verifier(scenario.verifierOptions)).run(
      captured,
      decision,
    );
    const elapsed = Date.now() - startedAt;

    assert.equal(result.outcome, "BLOCKED", scenario.name);
    assert.equal(result.reason, "AUTHORIZATION_INVALID", scenario.name);
    if (scenario.maxElapsedMs !== undefined) {
      assert.ok(elapsed < scenario.maxElapsedMs, `${scenario.name}: took ${elapsed}ms`);
    }
    assert.deepEqual(calls, [], scenario.name);
    assert.equal(requestsSince(from, CLAIM_PATH).length, 1, scenario.name);
    assert.equal(requestsSince(from, FINALIZE_PATH).length, 0, scenario.name);
  }
});

test(
  "Finalization faults are reported as PENDING and never change the outcome",
  TEST_OPTIONS,
  async () => {
    const scenarios = [
      {
        name: "409 replay",
        override: {
          status: 409,
          body: { finalized: false, reason_codes: ["NONCE_REPLAY_DETECTED"] },
        },
      },
      { name: "malformed JSON", override: { body: "{not-json" } },
      {
        name: "delayed beyond the verifier timeout",
        verifierOptions: { timeoutMs: 300 },
        override: { delayMs: 1_500 },
      },
      { name: "connection terminated", override: { destroy: true } },
    ];

    for (const scenario of scenarios) {
      const captured = capture(5_000);
      const { calls, sealed } = registry();
      const decision = await gate().evaluate(captured);
      authority.scriptOnce("finalize", scenario.override);

      const result = await new SafeExecutor(sealed, verifier(scenario.verifierOptions)).run(
        captured,
        decision,
      );

      assert.equal(result.outcome, "COMPLETED", scenario.name);
      assert.equal(result.executed, true, scenario.name);
      assert.equal(result.finalization, "PENDING", scenario.name);
      assert.deepEqual(result.result, {
        refunded: 5_000,
        idempotencyKey: captured.intent.idempotencyKey,
      });
      assert.deepEqual(calls, [captured.intent.idempotencyKey], scenario.name);
      assert.equal(lastRequest(FINALIZE_PATH).body.outcome, "COMMITTED", scenario.name);
    }
  },
);

test(
  "The package's canonical hash matches an independent canonicalizer",
  TEST_OPTIONS,
  async () => {
    const captured = capture(5_000);
    const wire = lastRequest(ENFORCE_PATH);
    assert.ok(wire, "an enforce-and-bind request was recorded");
    const decision = await gate().evaluate(captured);
    const request = lastRequest(ENFORCE_PATH);
    const binding = Object.fromEntries(BINDING_KEYS.map((key) => [key, request.body[key]]));

    assert.equal(hashBinding(binding), captured.intentHash);
    assert.equal(decision.intentHash, captured.intentHash);
    assert.equal(
      JSON.parse(captured.canonicalIntent).context.idempotency_key,
      captured.intent.idempotencyKey,
    );
  },
);

test("The stub bounds request bodies", TEST_OPTIONS, async () => {
  const oversized = JSON.stringify({ padding: "x".repeat(300 * 1024) });
  const outcome = await fetch(`${authority.baseUrl}${ENFORCE_PATH}`, {
    method: "POST",
    headers: { authorization: `Bearer ${STUB_API_KEY}`, "content-type": "application/json" },
    body: oversized,
  }).then(
    (response) => ({ status: response.status }),
    (error) => ({ error: error instanceof Error ? error.name : "unknown" }),
  );

  assert.ok(outcome.status === 413 || outcome.error !== undefined, JSON.stringify(outcome));
});

async function writeDiagnostics() {
  const directory = process.env.CONTRACT_DIAGNOSTICS_DIR ?? join(tmpdir(), "agent-safe-contract");
  const bounded = (records) =>
    records.slice(-200).map((record) => ({
      ...record,
      body: JSON.stringify(record.body)?.slice(0, 2_048) ?? null,
      response:
        record.response === null
          ? null
          : {
              status: record.response.status,
              body: JSON.stringify(record.response.body)?.slice(0, 2_048),
            },
    }));
  try {
    await mkdir(directory, { recursive: true });
    await writeFile(
      join(directory, "contract-diagnostics.json"),
      `${JSON.stringify(
        {
          writtenAt: new Date().toISOString(),
          authority: bounded(authority.requests),
          presence: bounded(presence.requests),
        },
        null,
        2,
      )}\n`,
    );
  } catch {
    // Diagnostics are best effort; a write failure must not mask a test result.
  }
}
