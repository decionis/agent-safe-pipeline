/**
 * A signed standing signal at the claim, through the fixture and the grant
 * verifier: the claim looks again at who signed it and until when, as the
 * hosted claim does. A signal that has run out, or whose key the organisation
 * has revoked since, admits nothing more: the claim fails
 * `CURRENT_STATE_UNRESOLVED` and the grant is not consumed. Decionis proves
 * the same on its side (the claim's signed-signal revalidation in
 * `ExecutionAuthorityRoutes.ts`).
 */
import { generateKeyPairSync } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "../../src/testing/Index.js";
import { mintSignedSignal } from "../../src/testing/SignedSignals.js";

const ORG = "00000000-0000-4000-8000-000000000007";
const AGENT = "synthetic-deploy-agent";
const PRODUCER = "synthetic-partner-bank";
const KID = "partner-bank-mandates-1";
const institution = generateKeyPairSync("ed25519");
let now = Date.now();
let sequence = 0;

const authority = new LocalAuthority({
  clock: () => now,
  // The rollout is allowed only under a mandate the partner bank signed for this agent.
  policy: (request) =>
    request.signed_signals?.["mandate"]?.covers_intent === true ? "ALLOW" : "BLOCK",
});

const register = (issuer = PRODUCER): void => {
  authority.registerProviderKey({
    kid: KID,
    issuer,
    purpose: "signed_signal",
    publicJwk: institution.publicKey.export({ format: "jwk" }),
  });
};

beforeAll(async () => {
  await authority.start();
});

beforeEach(() => {
  now = Date.now();
  register();
});

afterAll(async () => {
  await authority.stop();
});

const options = () => ({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});

function rollout(): CapturedIntent {
  sequence += 1;
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "rollout.canary",
      target: "deploy:checkout/canary",
      parameters: { version: "4.2.0" },
    },
    {
      tenantId: ORG,
      actor: { id: AGENT, type: "AI_AGENT" },
      downstreamTarget: {
        system: "deploy",
        operation: "rollouts/canary",
        environment: "production",
      },
      idempotencyKey: `rollout-${sequence}`,
      context: {},
    },
  );
}

/** The partner bank's standing mandate for this agent to roll out canaries. */
function mandate(lifetimeSeconds = 3_600): string {
  return mintSignedSignal({
    privateKey: institution.privateKey,
    kid: KID,
    issuer: PRODUCER,
    audience: ORG,
    subject: "change-board-synthetic",
    signal: {
      name: "mandate",
      method: "change_board",
      result: "VERIFIED",
      agent: AGENT,
      scope: { actions: ["rollout.canary"] },
    },
    issuedAtMs: now,
    lifetimeSeconds,
  });
}

async function decided(lifetimeSeconds?: number) {
  const captured = rollout();
  const decision = await new DecionisGate(options()).evaluate(captured, {
    signals: [{ token: mandate(lifetimeSeconds) }],
  });
  expect(decision.verdict).toBe("ALLOW");
  return { captured, decision };
}

/** The claim's answer, the grant's state after it, and whether a grant came back. */
async function claimed(queued: Awaited<ReturnType<typeof decided>>) {
  const authorization = await new DecionisGrantVerifier(options()).verifyAndConsume(
    queued.captured,
    queued.decision,
  );
  const claim = [...authority.requests]
    .reverse()
    .find((request) => request.path.endsWith("/claims") || request.path.endsWith("/claim-token"));
  const body = claim?.response?.body as { readonly reason_codes?: readonly string[] } | undefined;
  return {
    granted: authorization !== null,
    reason: body?.reason_codes?.[0] ?? null,
    consumed: authority.grants.get(String(queued.decision.authorization?.token))?.claimed,
  };
}

describe("a signed signal at the claim", () => {
  it("keeps who signed it and until when, and is claimed while both still hold", async () => {
    const queued = await decided(30);
    expect(
      authority.grants.get(String(queued.decision.authorization?.token))?.signedSignals,
    ).toEqual([
      {
        name: "mandate",
        producer: PRODUCER,
        key_id: KID,
        expires_at: new Date((Math.floor(now / 1_000) + 30) * 1_000).toISOString(),
      },
    ]);
    // A grant lives a minute; the mandate, half of that, is still current here.
    now += 29_000;
    expect(await claimed(queued)).toEqual({ granted: true, reason: null, consumed: true });
  });

  it("admits nothing once the mandate has run out, and leaves the grant unspent", async () => {
    const queued = await decided(30);
    // Within the grant's minute, after the mandate's thirty seconds.
    now += 31_000;
    expect(await claimed(queued)).toEqual({
      granted: false,
      reason: "CURRENT_STATE_UNRESOLVED",
      consumed: false,
    });
  });

  it("admits nothing once the organisation revokes the producer's key", async () => {
    const queued = await decided();
    const revoked = await fetch(`${authority.baseUrl}/v1/execution/provider-keys/${KID}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${LOCAL_AUTHORITY_API_KEY}` },
    });
    expect([revoked.status, await revoked.json()]).toEqual([
      200,
      { service: "decionis", kid: KID, revoked: true },
    ]);
    expect(await claimed(queued)).toEqual({
      granted: false,
      reason: "CURRENT_STATE_UNRESOLVED",
      consumed: false,
    });
  });

  it("admits nothing when the key id is registered again for another issuer", async () => {
    const queued = await decided();
    expect(authority.revokeProviderKey(KID)).toBe(true);
    register("synthetic-someone-else");
    expect(await claimed(queued)).toEqual({
      granted: false,
      reason: "CURRENT_STATE_UNRESOLVED",
      consumed: false,
    });
  });

  it("revokes only a key it holds", async () => {
    expect(authority.revokeProviderKey("no-such-key")).toBe(false);
    const missing = await fetch(`${authority.baseUrl}/v1/execution/provider-keys/no-such-key`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${LOCAL_AUTHORITY_API_KEY}` },
    });
    expect([missing.status, await missing.json()]).toEqual([
      404,
      { error: "NOT_FOUND", message: "No such provider key." },
    ]);
  });

  it("binds no signed signal for a decision that carried none", async () => {
    const quiet = new LocalAuthority({ clock: () => now });
    await quiet.start();
    try {
      const decision = await new DecionisGate({ ...options(), baseUrl: quiet.baseUrl }).evaluate(
        rollout(),
      );
      expect(quiet.grants.get(String(decision.authorization?.token))?.signedSignals).toEqual([]);
    } finally {
      await quiet.stop();
    }
  });
});
