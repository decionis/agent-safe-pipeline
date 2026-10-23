/**
 * Loopback proof that `LocalAuthority` re-derives authority at claim the way
 * the hosted revalidator does: a policy released since the grant, a material
 * signal published since the grant, and a concurrency scope another open
 * claim holds each refuse the claim without consuming the grant; a key bound
 * to one organisation cannot carry a grant into another; and no key at all
 * reaches the policy lifecycle. Every call goes over real HTTP through the
 * production clients.
 *
 * All tenants, actors, rollouts and grants are synthetic.
 */
import { afterEach, describe, expect, it } from "vitest";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import type { DecisionGate } from "../../src/decision/DecisionAuthority.js";
import {
  DecionisGrantVerifier,
  type VerifiedAuthorization,
} from "../../src/execution/AuthorizationVerifier.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import {
  LOCAL_AUTHORITY_API_KEY,
  LocalAuthority,
  type LocalAuthorityOptions,
} from "../../src/testing/Index.js";

const TENANT = "00000000-0000-4000-8000-000000000006";
const OTHER_TENANT = "00000000-0000-4000-8000-000000000007";
const TENANT_KEY = "synthetic-tenant-key";
const OTHER_TENANT_KEY = "synthetic-other-tenant-key";
const ALLOWANCE = "synthetic-rollout-allowance";
const CONFIG = "synthetic-config-digest";

let authority: LocalAuthority | null = null;

afterEach(async () => {
  await authority?.stop();
  authority = null;
});

async function start(options: LocalAuthorityOptions = {}): Promise<LocalAuthority> {
  authority = new LocalAuthority(options);
  await authority.start();
  return authority;
}

function clients(local: LocalAuthority, apiKey = LOCAL_AUTHORITY_API_KEY) {
  const options = { baseUrl: local.baseUrl, apiKey, allowInsecureLoopback: true };
  return { gate: new DecionisGate(options), verifier: new DecionisGrantVerifier(options) };
}

let sequence = 0;

function rollout(
  version: string,
  { tenantId = TENANT, resource = "synthetic-checkout" } = {},
): CapturedIntent {
  sequence += 1;
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "rollout.canary",
      target: `deploy:${resource}`,
      parameters: { service: resource, version },
    },
    {
      tenantId,
      actor: { id: "synthetic-deploy-agent", type: "AI_AGENT", runtime: "revalidation-test" },
      downstreamTarget: { system: "deploy", operation: "rollouts/canary", environment: "prod" },
      idempotencyKey: `synthetic-rollout-${sequence}`,
      context: { source: "revalidation-test" },
    },
  );
}

/** The last claim the authority answered, on the grant resource or its legacy alias. */
function lastClaim(local: LocalAuthority) {
  return [...local.requests]
    .reverse()
    .find((request) => request.path.endsWith("/claims") || request.path.endsWith("/claim-token"));
}

function lastClaimReason(local: LocalAuthority): string | undefined {
  const body = lastClaim(local)?.response?.body as { reason_codes?: string[] } | undefined;
  return body?.reason_codes?.[0];
}

function lastClaimStatus(local: LocalAuthority): number | null | undefined {
  return lastClaim(local)?.response?.status;
}

async function granted(gate: DecionisGate, captured: CapturedIntent): Promise<DecisionGate> {
  const decision = await gate.evaluate(captured);
  expect(decision.verdict).toBe("ALLOW");
  expect(decision.authorization).not.toBeNull();
  return decision;
}

function grantOf(local: LocalAuthority, decision: DecisionGate) {
  const grant = local.grants.get(decision.authorization?.token ?? "");
  if (grant === undefined) throw new Error("grant missing");
  return grant;
}

describe("commit-time revalidation in LocalAuthority", () => {
  it("refuses a grant decided under an earlier policy release, and burns nothing", async () => {
    const local = await start();
    const { gate, verifier } = clients(local);
    const before = rollout("2.4.1");
    const stale = await granted(gate, before);
    expect(local.policyVersion).toBe("synthetic-policy-v1");
    expect(local.releasePolicy()).toBe("synthetic-policy-v2");

    expect(await verifier.verifyAndConsume(before, stale)).toBeNull();
    expect([lastClaimStatus(local), lastClaimReason(local)]).toEqual([409, "POLICY_VERSION_STALE"]);
    expect(grantOf(local, stale).claimed).toBe(false);

    const renewed = rollout("2.4.1");
    const decision = await granted(gate, renewed);
    expect(grantOf(local, decision).policyVersion).toBe("synthetic-policy-v2");
    expect(await verifier.verifyAndConsume(renewed, decision)).not.toBeNull();
  });

  it("decides a new release with the policy it was released with", async () => {
    const local = await start({ policy: () => "ALLOW" });
    const { gate } = clients(local);
    local.releasePolicy(() => "BLOCK");
    expect((await gate.evaluate(rollout("2.4.1"))).verdict).toBe("BLOCK");
  });

  it("shows the policy the current material signals and binds the versions it read", async () => {
    const seen: unknown[] = [];
    const local = await start({
      materialSignals: () => [CONFIG, "synthetic-never-published"],
      policy: (request) => {
        seen.push(request.material_signals);
        return "ALLOW";
      },
    });
    const { gate } = clients(local);
    expect(local.publishSignal(CONFIG, { digest: "a" })).toMatchObject({
      signal_id: CONFIG,
      version: "1",
    });
    const decision = await granted(gate, rollout("2.4.1"));
    expect(seen).toEqual([{ [CONFIG]: { digest: "a" } }]);
    expect(grantOf(local, decision).materialSignals.map((signal) => signal.version)).toEqual(["1"]);
    expect(grantOf(local, decision).scopes).toEqual([`signal:${CONFIG}`]);
    expect(local.publishSignal(CONFIG, { digest: "b" }).version).toBe("2");
  });

  it("gives a policy with no material signals none, and holds no scope", async () => {
    const seen: unknown[] = [];
    const local = await start({
      policy: (request) => {
        seen.push("material_signals" in request);
        return "ALLOW";
      },
    });
    const decision = await granted(clients(local).gate, rollout("2.4.1"));
    expect(seen).toEqual([false]);
    expect(grantOf(local, decision).scopes).toEqual([]);
  });

  it("refuses a grant whose material signal was published again, then grants on the new value", async () => {
    const local = await start({ materialSignals: () => [CONFIG] });
    const { gate, verifier } = clients(local);
    local.publishSignal(CONFIG, { digest: "a" });
    const queued = rollout("2.4.1");
    const stale = await granted(gate, queued);
    local.publishSignal(CONFIG, { digest: "b" });

    expect(await verifier.verifyAndConsume(queued, stale)).toBeNull();
    expect(lastClaimReason(local)).toBe("SIGNAL_VERSION_STALE");
    expect(grantOf(local, stale).claimed).toBe(false);

    const reread = rollout("2.4.1");
    expect(await verifier.verifyAndConsume(reread, await granted(gate, reread))).not.toBeNull();
  });

  it("checks the policy release before the signals, and both before a replay", async () => {
    const local = await start({ materialSignals: () => [CONFIG] });
    const { gate, verifier } = clients(local);
    local.publishSignal(CONFIG, 1);
    const captured = rollout("2.4.1");
    const decision = await granted(gate, captured);
    expect(await verifier.verifyAndConsume(captured, decision)).not.toBeNull();
    expect(await verifier.verifyAndConsume(captured, decision)).toBeNull();
    expect(lastClaimReason(local)).toBe("NONCE_REPLAY_DETECTED");
    local.publishSignal(CONFIG, 2);
    expect(await verifier.verifyAndConsume(captured, decision)).toBeNull();
    expect(lastClaimReason(local)).toBe("SIGNAL_VERSION_STALE");
    local.releasePolicy();
    expect(await verifier.verifyAndConsume(captured, decision)).toBeNull();
    expect(lastClaimReason(local)).toBe("POLICY_VERSION_STALE");
  });

  it("holds a signal's scope from the claim until a commit or a failure releases it", async () => {
    const local = await start({ materialSignals: () => [ALLOWANCE] });
    const { gate, verifier } = clients(local);
    local.publishSignal(ALLOWANCE, { remaining: 2 });
    const first = rollout("2.4.1");
    const second = rollout("2.4.2");
    const third = rollout("2.4.3");
    const firstDecision = await granted(gate, first);
    const secondDecision = await granted(gate, second);
    const thirdDecision = await granted(gate, third);

    const claimed = await verifier.verifyAndConsume(first, firstDecision);
    expect(claimed).not.toBeNull();
    expect(await verifier.verifyAndConsume(second, secondDecision)).toBeNull();
    expect([lastClaimStatus(local), lastClaimReason(local)]).toEqual([
      409,
      "AUTHORIZATION_SCOPE_BUSY",
    ]);
    expect(grantOf(local, secondDecision).claimed).toBe(false);

    const authorization = claimed as VerifiedAuthorization;
    await verifier.finalize({
      captured: first,
      decision: firstDecision,
      authorization,
      outcome: "COMMITTED",
    });
    const secondClaim = await verifier.verifyAndConsume(second, secondDecision);
    expect(secondClaim).not.toBeNull();
    await verifier.finalize({
      captured: second,
      decision: secondDecision,
      authorization: secondClaim as VerifiedAuthorization,
      outcome: "FAILED",
    });
    expect(await verifier.verifyAndConsume(third, thirdDecision)).not.toBeNull();
  });

  it("keeps a scope unresolved behind an INDETERMINATE attempt until it is reconciled", async () => {
    // Reconciliation is a grant resource with no legacy alias, so the grant
    // has to be addressable for the client to reach it.
    const local = await start({ materialSignals: () => [ALLOWANCE], addressableGrants: true });
    const { gate, verifier } = clients(local);
    local.publishSignal(ALLOWANCE, { remaining: 2 });
    const first = rollout("2.4.1");
    const retry = rollout("2.4.1");
    const firstDecision = await granted(gate, first);
    const retryDecision = await granted(gate, retry);
    const authorization = (await verifier.verifyAndConsume(
      first,
      firstDecision,
    )) as VerifiedAuthorization;
    await verifier.finalize({
      captured: first,
      decision: firstDecision,
      authorization,
      outcome: "INDETERMINATE",
    });

    expect(await verifier.verifyAndConsume(retry, retryDecision)).toBeNull();
    expect(lastClaimReason(local)).toBe("CURRENT_STATE_UNRESOLVED");
    expect(await verifier.reconcile({ captured: first, authorization, outcome: "COMMITTED" })).toBe(
      "RECORDED",
    );
    expect(await verifier.verifyAndConsume(retry, retryDecision)).not.toBeNull();
    expect(lastClaim(local)?.path).toBe(
      `/v1/authority/grants/${grantOf(local, retryDecision).jti}/claims`,
    );
  });

  it("mints opaque tokens unless grants are addressable", async () => {
    const local = await start();
    const decision = await granted(clients(local).gate, rollout("2.4.1"));
    expect(decision.authorization?.token).toMatch(/^synthetic-grant\.synthetic-jti-/);
  });

  it("scopes per organisation and per signal", async () => {
    const local = await start({
      materialSignals: (request) => [`${ALLOWANCE}:${String(request.action.parameters.service)}`],
    });
    const { gate, verifier } = clients(local);
    for (const service of ["synthetic-checkout", "synthetic-search"]) {
      local.publishSignal(`${ALLOWANCE}:${service}`, { remaining: 1 });
    }
    const checkout = rollout("2.4.1");
    const search = rollout("7.0.0", { resource: "synthetic-search" });
    const elsewhere = rollout("2.4.1", { tenantId: OTHER_TENANT });
    const checkoutDecision = await granted(gate, checkout);
    const searchDecision = await granted(gate, search);
    const elsewhereDecision = await granted(gate, elsewhere);
    expect(await verifier.verifyAndConsume(checkout, checkoutDecision)).not.toBeNull();
    expect(await verifier.verifyAndConsume(search, searchDecision)).not.toBeNull();
    expect(await verifier.verifyAndConsume(elsewhere, elsewhereDecision)).not.toBeNull();
  });

  it("keeps a bound key inside its organisation at enforce-and-bind and at claim", async () => {
    const local = await start({
      tenantKeys: { [TENANT_KEY]: TENANT, [OTHER_TENANT_KEY]: OTHER_TENANT },
    });
    const own = clients(local, TENANT_KEY);
    const other = clients(local, OTHER_TENANT_KEY);
    const captured = rollout("2.4.1");

    const refused = await other.gate.evaluate(captured);
    expect(refused.verdict).toBe("BLOCK");
    expect(local.requests.at(-1)?.response).toEqual({
      status: 403,
      body: { error: "AUTHORITY_TENANT_MISMATCH" },
    });

    const decision = await granted(own.gate, captured);
    expect(await other.verifier.verifyAndConsume(captured, decision)).toBeNull();
    expect([lastClaimStatus(local), lastClaimReason(local)]).toEqual([403, "TENANT_MISMATCH"]);
    expect(grantOf(local, decision).claimed).toBe(false);

    // The same grant presented with the intent rewritten into the other
    // organisation is another intent, and not the one the grant binds.
    const rewritten = rollout("2.4.1", { tenantId: OTHER_TENANT });
    expect(await other.verifier.verifyAndConsume(rewritten, decision)).toBeNull();
    expect(await own.verifier.verifyAndConsume(captured, decision)).not.toBeNull();
  });

  it("accepts only its own and its bound keys", async () => {
    const local = await start({ tenantKeys: { [TENANT_KEY]: TENANT } });
    for (const key of ["synthetic-unknown-key", "constructor", "__proto__"]) {
      const refused = await clients(local, key).gate.evaluate(rollout("2.4.1"));
      expect(refused.verdict).toBe("BLOCK");
      expect(local.requests.at(-1)?.response?.status).toBe(401);
    }
    expect((await clients(local).gate.evaluate(rollout("2.4.1"))).verdict).toBe("ALLOW");
  });

  it("answers the policy lifecycle with an account-session refusal, whatever key is presented", async () => {
    const local = await start();
    for (const path of [
      "/v1/policies",
      "/v1/policies/00000000-0000-4000-8000-000000000006/proposals/00000000-0000-4000-8000-000000000007/decisions",
    ]) {
      const response = await fetch(`${local.baseUrl}${path}`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${LOCAL_AUTHORITY_API_KEY}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ decision: "ACCEPT" }),
      });
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: "ACCOUNT_SESSION_REQUIRED" });
    }
    expect(local.policyVersion).toBe("synthetic-policy-v1");
  });
});
