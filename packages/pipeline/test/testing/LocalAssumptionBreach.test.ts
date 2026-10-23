/**
 * The hosted assumption breach, through the fixture and the grant verifier:
 * a receipt that contradicts a `deployment.scale` grant holds that action at
 * that target. The next proposal there escalates, a grant issued before the
 * contradiction fails at claim with `POLICY_STATE_CHANGED`, and only a
 * governed release that cites the breach and every piece of its evidence
 * restores ALLOW. Decionis proves the same on its side
 * (`AssumptionBreachAdmissibility.test.ts`, `AssumptionBreach.pg.test.ts`).
 */
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import {
  EFFECT_RECEIPT_TYPE,
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_AUTHORITY_ISSUER,
  LocalAuthority,
} from "../../src/testing/Index.js";

const EXPECTED = `sha256:${"1".repeat(64)}`;
const ELSEWHERE = `sha256:${"2".repeat(64)}`;
const PROVIDER_ISSUER = "https://cluster.example";
const authority = new LocalAuthority();
const provider = generateKeyPairSync("ed25519");
let sequence = 0;

beforeAll(async () => {
  await authority.start();
  authority.registerProviderKey({
    kid: "cluster-receipts-1",
    issuer: PROVIDER_ISSUER,
    publicJwk: provider.publicKey.export({ format: "jwk" }),
  });
});

afterAll(async () => {
  await authority.stop();
});

const options = () => ({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});

/** Scale one deployment, the way the infrastructure example proposes it. */
function scale(deployment = "deployment:payments-api"): CapturedIntent {
  sequence += 1;
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    { action: "deployment.scale", target: deployment, parameters: { replicas: 6 } },
    {
      tenantId: "00000000-0000-4000-8000-000000000005",
      actor: { id: "synthetic-sre-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "kubernetes", operation: "scale", environment: "production" },
      idempotencyKey: `scale-${sequence}`,
      context: {},
      expectedEffectDigest: EXPECTED,
    },
  );
}

async function decide(captured: CapturedIntent) {
  return await new DecionisGate(options()).evaluate(captured);
}

/** What the cluster signs after scaling: the effect it says it made, under the claim it answered. */
function receipt(
  grant: { jti: string; decisionId: string; dossierId: string; claimToken: string | null },
  digest: string,
): string {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const header = encode({ alg: "EdDSA", typ: EFFECT_RECEIPT_TYPE, kid: "cluster-receipts-1" });
  const payload = encode({
    iss: PROVIDER_ISSUER,
    aud: LOCAL_AUTHORITY_ISSUER,
    sub: grant.jti,
    decision_id: grant.decisionId,
    dossier_id: grant.dossierId,
    claim_token_digest: `sha256:${createHash("sha256")
      .update(grant.claimToken ?? "", "utf8")
      .digest("hex")}`,
    effect: { status: "EFFECTED", digest, effected_at: new Date().toISOString() },
    iat: Math.floor(Date.now() / 1_000),
    jti: `receipt-${sequence}`,
  });
  const signature = sign(null, Buffer.from(`${header}.${payload}`, "ascii"), provider.privateKey);
  return `${header}.${payload}.${signature.toString("base64url")}`;
}

function last(path: string) {
  return [...authority.requests].reverse().find((request) => request.path === path);
}

describe("an assumption breach in the fixture", () => {
  it("holds deployment.scale at its target until a governed release cites it", async () => {
    // Two grants issued while nothing is held; the first one executes.
    const first = scale();
    const firstDecision = await decide(first);
    const queued = scale();
    const queuedDecision = await decide(queued);
    expect([firstDecision.verdict, queuedDecision.verdict]).toEqual(["ALLOW", "ALLOW"]);
    const verifier = new DecionisGrantVerifier(options());
    const authorization = await verifier.verifyAndConsume(first, firstDecision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    const grant = authority.grants.get(String(firstDecision.authorization?.token));
    if (grant === undefined) throw new Error("TEST_EXPECTED_GRANT");

    // The cluster's signed receipt says it scaled to something else.
    const token = receipt(grant, ELSEWHERE);
    expect(
      await verifier.finalize({
        captured: first,
        decision: firstDecision,
        authorization,
        outcome: "COMMITTED",
        effectReceipt: token,
      }),
    ).toBe("RECORDED");
    const reported = last("/v1/execution/finalize-token")?.response?.body as Record<
      string,
      unknown
    >;
    expect(reported).toMatchObject({
      finalized: true,
      effect_receipt: { verified: true },
      assumption_breach: { trigger: "EFFECT_RECEIPT_CONTRADICTION", created: true },
    });
    const [breach] = authority.assumptionBreaches.all;
    expect(breach).toMatchObject({
      status: "OPEN",
      grantJti: grant.jti,
      scope: {
        actionType: "deployment.scale",
        system: "kubernetes",
        environment: "production",
        resource: "deployment:payments-api",
      },
    });
    expect(breach?.evidenceIds).toEqual(
      [
        `dossier:${grant.dossierId}`,
        `grant:${grant.jti}`,
        `receipt:sha256:${createHash("sha256").update(token, "utf8").digest("hex")}`,
        `effect:sha256:${createHash("sha256").update(token, "utf8").digest("hex")}`,
      ].sort(),
    );

    // The next proposal in that scope waits for a person; another target does not.
    expect(await decide(scale())).toMatchObject({
      verdict: "ESCALATE",
      reasonCodes: ["ASSUMPTION_BREACH_OPEN"],
    });
    expect((await decide(scale("deployment:ledger"))).verdict).toBe("ALLOW");

    // The grant issued before the contradiction no longer claims.
    expect(await verifier.verifyAndConsume(queued, queuedDecision)).toBeNull();
    expect(last("/v1/execution/claim-token")?.response).toMatchObject({
      status: 409,
      body: { reason_codes: ["POLICY_STATE_CHANGED"] },
    });

    // A release that cites the breach without all of its evidence clears nothing.
    expect(() =>
      authority.assumptionBreaches.clear([
        { breachId: breach!.breachId, evidenceIds: breach!.evidenceIds.slice(1) },
      ]),
    ).toThrow("POLICY_BREACH_EVIDENCE_MISMATCH");
    expect((await decide(scale())).verdict).toBe("ESCALATE");

    // The governed release that cites it, and all of it, restores ALLOW.
    authority.assumptionBreaches.clear([
      { breachId: breach!.breachId, evidenceIds: breach!.evidenceIds },
    ]);
    expect(breach?.status).toBe("CLEARED");
    expect((await decide(scale())).verdict).toBe("ALLOW");
    expect(() =>
      authority.assumptionBreaches.clear([
        { breachId: breach!.breachId, evidenceIds: breach!.evidenceIds },
      ]),
    ).toThrow("POLICY_BREACH_NOT_OPEN");
  });

  it("opens nothing for an outcome that matches its grant", async () => {
    const captured = scale("deployment:checkout");
    const decision = await decide(captured);
    const verifier = new DecionisGrantVerifier(options());
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    const grant = authority.grants.get(String(decision.authorization?.token))!;
    await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectReceipt: receipt(grant, EXPECTED),
    });
    expect(last("/v1/execution/finalize-token")?.response?.body).not.toHaveProperty(
      "assumption_breach",
    );
    expect((await decide(scale("deployment:checkout"))).verdict).toBe("ALLOW");
  });
});
