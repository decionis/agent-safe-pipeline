/**
 * The fixture's side of the effect receipt (VP-3), checked from the
 * provider's side: a receipt signed with a registered key, describing this
 * grant and this claim, is verified and recorded, and read as SIGNED_RECEIPT
 * evidence when the grant named the effect it expected; everything else is
 * recorded with its code, and the finalization is never refused for it.
 */
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
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

const EFFECT_DIGEST = `sha256:${"1".repeat(64)}`;
const OTHER_DIGEST = `sha256:${"2".repeat(64)}`;
const PROVIDER_ISSUER = "https://core.example";
const authority = new LocalAuthority();
const provider = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
let sequence = 0;

beforeAll(async () => {
  await authority.start();
  const response = await fetch(`${authority.baseUrl}/v1/execution/provider-keys`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${LOCAL_AUTHORITY_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      kid: "core-receipts-1",
      issuer: PROVIDER_ISSUER,
      algorithm: "EdDSA",
      public_jwk: provider.publicKey.export({ format: "jwk" }),
      label: "core banking",
    }),
  });
  expect(response.status).toBe(201);
  expect(await response.json()).toMatchObject({
    service: "decionis",
    kid: "core-receipts-1",
    issuer: PROVIDER_ISSUER,
    algorithm: "EdDSA",
    revoked_at: null,
  });
});

afterAll(async () => {
  await authority.stop();
});

function capture(expectedEffectDigest?: string) {
  sequence += 1;
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "refund_order",
      target: `core:account:synthetic-${sequence}`,
      parameters: { amountMinor: 5_000, currency: "USD" },
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000005",
      actor: { id: "synthetic-receipt-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "core", operation: "refund" },
      idempotencyKey: `receipt-${sequence}`,
      context: {},
      ...(expectedEffectDigest === undefined ? {} : { expectedEffectDigest }),
    },
  );
}

const options = () => ({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});

async function claim(captured: CapturedIntent) {
  const decision = await new DecionisGate(options()).evaluate(captured);
  expect(decision.verdict).toBe("ALLOW");
  const token = decision.authorization?.token;
  if (token === undefined) throw new Error("TEST_EXPECTED_GRANT");
  const verifier = new DecionisGrantVerifier(options());
  const authorization = await verifier.verifyAndConsume(captured, decision);
  if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
  const grant = authority.grants.get(token);
  if (grant?.claimToken === null || grant === undefined) throw new Error("TEST_EXPECTED_CLAIM");
  return { captured, decision, authorization, grant, verifier };
}

/** What a verifying provider does after effecting: sign what it did, under the claim it answered. */
function receipt(
  grant: { jti: string; decisionId: string; dossierId: string; claimToken: string | null },
  effect: Record<string, unknown>,
  overrides: {
    key?: KeyObject;
    header?: Record<string, unknown>;
    claims?: Record<string, unknown>;
  } = {},
): string {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const header = encode({
    alg: "EdDSA",
    typ: EFFECT_RECEIPT_TYPE,
    kid: "core-receipts-1",
    ...overrides.header,
  });
  const payload = encode({
    iss: PROVIDER_ISSUER,
    aud: LOCAL_AUTHORITY_ISSUER,
    sub: grant.jti,
    decision_id: grant.decisionId,
    dossier_id: grant.dossierId,
    claim_token_digest: `sha256:${createHash("sha256")
      .update(grant.claimToken ?? "", "utf8")
      .digest("hex")}`,
    effect,
    iat: Math.floor(Date.now() / 1_000),
    jti: `receipt-${sequence}`,
    ...overrides.claims,
  });
  const signature = sign(
    null,
    Buffer.from(`${header}.${payload}`, "ascii"),
    overrides.key ?? provider.privateKey,
  );
  return `${header}.${payload}.${signature.toString("base64url")}`;
}

/** The authority's record of the latest finalization: what it was sent and what it answered. */
function lastFinalize() {
  return [...authority.requests]
    .reverse()
    .find((request) => request.path === "/v1/execution/finalize-token");
}

describe("LocalAuthority effect receipts", () => {
  it("verifies a registered provider's receipt and reads it as SIGNED_RECEIPT evidence for the effect the grant expected", async () => {
    const { captured, decision, authorization, grant, verifier } = await claim(
      capture(EFFECT_DIGEST),
    );
    const token = receipt(grant, {
      status: "EFFECTED",
      reference: "ledger:entry:9081",
      digest: EFFECT_DIGEST,
      effected_at: new Date().toISOString(),
    });
    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectReceipt: token,
    });
    expect(status).toBe("RECORDED");
    expect(verifier.effectReport(authorization)).toEqual({
      effectEvidenceSent: false,
      effectEvidenceRefused: false,
      effectEvidenceRecorded: false,
      effectConfirmation: "UNCONFIRMED",
      effectReceiptSent: true,
      effectReceiptVerified: true,
      effectReceiptVerification: "EFFECT_RECEIPT_VERIFIED",
    });
    // The authority's own record: the receipt, verified, and the evidence it
    // stood in for, confirmed by the provider's key.
    expect(grant.receipt).toMatchObject({
      token,
      verified: true,
      verification_code: "EFFECT_RECEIPT_VERIFIED",
      provider_key_id: "core-receipts-1",
      issuer: PROVIDER_ISSUER,
      effect_status: "EFFECTED",
      effect_digest: EFFECT_DIGEST,
      effect_reference: "ledger:entry:9081",
    });
    const finalize = lastFinalize();
    expect(finalize?.response?.body).toMatchObject({
      finalized: true,
      effect_evidence_recorded: true,
      effect_confirmation: "CONFIRMED",
      effect_receipt: {
        verified: true,
        verification_code: "EFFECT_RECEIPT_VERIFIED",
        provider_key_id: "core-receipts-1",
        recorded: true,
      },
    });
  });

  it("confirms nothing from a receipt whose effect is not the one expected, or that reports a refusal", async () => {
    for (const effect of [
      { status: "EFFECTED", digest: OTHER_DIGEST, effected_at: new Date().toISOString() },
      { status: "REFUSED", reference: "core:refused:limit", effected_at: new Date().toISOString() },
    ]) {
      const { captured, decision, authorization, grant, verifier } = await claim(
        capture(EFFECT_DIGEST),
      );
      const status = await verifier.finalize({
        captured,
        decision,
        authorization,
        outcome: effect.status === "EFFECTED" ? "COMMITTED" : "FAILED",
        effectReceipt: receipt(grant, effect),
      });
      expect(status).toBe("RECORDED");
      expect(grant.receipt?.verified).toBe(true);
      const body = lastFinalize()?.response?.body as Record<string, unknown>;
      expect(body.effect_confirmation).toBe("UNCONFIRMED");
      // A digest that differs is still an observation; a refusal without a digest is not one.
      expect(body.effect_evidence_recorded).toBe(effect.status === "EFFECTED");
    }
  });

  it("records a receipt it cannot verify with its code, and never refuses the finalization for it", async () => {
    const cases: Array<[string, (grant: Awaited<ReturnType<typeof claim>>["grant"]) => string]> = [
      [
        "EFFECT_RECEIPT_MALFORMED",
        (grant) => receipt(grant, { status: "EFFECTED" }, { header: { typ: "JWT" } }),
      ],
      [
        "EFFECT_RECEIPT_KEY_UNKNOWN",
        (grant) => receipt(grant, { status: "EFFECTED" }, { header: { kid: "nobody" } }),
      ],
      [
        "EFFECT_RECEIPT_SIGNATURE_INVALID",
        (grant) =>
          receipt(
            grant,
            { status: "EFFECTED", effected_at: new Date().toISOString() },
            { key: stranger.privateKey },
          ),
      ],
      [
        "EFFECT_RECEIPT_SIGNATURE_INVALID",
        (grant) =>
          receipt(
            grant,
            { status: "EFFECTED", effected_at: new Date().toISOString() },
            { claims: { aud: "https://elsewhere.example" } },
          ),
      ],
      [
        "EFFECT_RECEIPT_MALFORMED",
        (grant) => receipt(grant, { status: "DONE", effected_at: new Date().toISOString() }),
      ],
      [
        "EFFECT_RECEIPT_BINDING_MISMATCH",
        (grant) =>
          receipt(
            grant,
            { status: "EFFECTED", effected_at: new Date().toISOString() },
            { claims: { sub: "another-grant" } },
          ),
      ],
      [
        "EFFECT_RECEIPT_BINDING_MISMATCH",
        (grant) =>
          receipt(
            grant,
            { status: "EFFECTED", effected_at: new Date().toISOString() },
            { claims: { claim_token_digest: OTHER_DIGEST } },
          ),
      ],
    ];
    for (const [code, build] of cases) {
      const { captured, decision, authorization, grant, verifier } = await claim(capture());
      const status = await verifier.finalize({
        captured,
        decision,
        authorization,
        outcome: "COMMITTED",
        effectReceipt: build(grant),
      });
      expect(status, code).toBe("RECORDED");
      expect(grant.finalized).toBe("COMMITTED");
      expect(grant.receipt, code).toMatchObject({ verified: false, verification_code: code });
      expect(verifier.effectReport(authorization), code).toMatchObject({
        effectReceiptSent: true,
        effectReceiptVerified: false,
        effectReceiptVerification: code,
      });
    }
  });

  it("refuses to register anything but the public half of an Ed25519 key", async () => {
    const privateJwk = provider.privateKey.export({ format: "jwk" });
    for (const body of [
      { kid: "k", issuer: PROVIDER_ISSUER, algorithm: "EdDSA", public_jwk: privateJwk },
      {
        kid: "k",
        issuer: PROVIDER_ISSUER,
        algorithm: "ES256",
        public_jwk: { kty: "EC", crv: "P-256", x: "a".repeat(43), y: "b".repeat(43) },
      },
    ]) {
      const response = await fetch(`${authority.baseUrl}/v1/execution/provider-keys`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${LOCAL_AUTHORITY_API_KEY}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(400);
    }
    expect(authority.providerKeys.has("k")).toBe(false);
  });
});
