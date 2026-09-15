/**
 * The fixture's claim attestation and payload digest, checked from both
 * sides: the pipeline must accept what the fixture binds (two independent
 * canonicalizers agreeing on the parameters), and a provider double must be
 * able to verify the attestation with nothing but the fixture's public JWKS.
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import {
  CLAIM_ATTESTATION_TYPE,
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_AUTHORITY_ISSUER,
  LOCAL_AUTHORITY_JWKS_PATH,
  LocalAuthority,
  hashBinding,
  type LocalClaimAttestationClaims,
} from "../../src/testing/Index.js";

const authority = new LocalAuthority();
let sequence = 0;

beforeAll(async () => {
  await authority.start();
});

afterAll(async () => {
  await authority.stop();
});

function capture(parameters: Record<string, unknown> = { amountMinor: 5_000, currency: "USD" }) {
  sequence += 1;
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "refund_order",
      target: `shopify:order:synthetic-${sequence}`,
      parameters: parameters as never,
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000005",
      actor: { id: "synthetic-attestation-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: `attest-${sequence}`,
      context: {},
    },
  );
}

/** Built per call: the fixture's base URL exists only once it has started. */
const options = () => ({
  baseUrl: authority.baseUrl,
  apiKey: LOCAL_AUTHORITY_API_KEY,
  allowInsecureLoopback: true,
});

async function claim(captured: CapturedIntent) {
  const decision = await new DecionisGate(options()).evaluate(captured);
  expect(decision.verdict).toBe("ALLOW");
  return new DecionisGrantVerifier(options()).verifyAndConsume(captured, decision);
}

/** What a provider does: decode, look the key up in the JWKS, verify, read. */
async function verifyAttestation(token: string): Promise<LocalClaimAttestationClaims> {
  const [header, payload, signature] = token.split(".");
  if (header === undefined || payload === undefined || signature === undefined) {
    throw new Error("not a compact JWS");
  }
  const protectedHeader = JSON.parse(Buffer.from(header, "base64url").toString("utf8"));
  expect(protectedHeader).toEqual({
    alg: "EdDSA",
    kid: authority.attestationKeyId,
    typ: CLAIM_ATTESTATION_TYPE,
  });
  const response = await fetch(`${authority.baseUrl}${LOCAL_AUTHORITY_JWKS_PATH}`);
  expect(response.status).toBe(200);
  const jwks = (await response.json()) as { keys: Array<Record<string, unknown>> };
  const jwk = jwks.keys.find((key) => key.kid === protectedHeader.kid);
  expect(jwk).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig" });
  const publicKey = createPublicKey({ key: jwk as never, format: "jwk" });
  expect(
    verify(
      null,
      Buffer.from(`${header}.${payload}`, "ascii"),
      publicKey,
      Buffer.from(signature, "base64url"),
    ),
  ).toBe(true);
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

describe("the fixture's claim attestation", () => {
  it("binds a payload digest the pipeline reproduces, so two canonicalizers agree on the parameters", async () => {
    const captured = capture({
      currency: "USD",
      amountMinor: 5_000,
      note: { b: [1, "x"], a: null },
    });
    const authorization = await claim(captured);
    expect(authorization).not.toBeNull();
    expect(authorization?.payloadDigest).toBe(
      DecionisGrantVerifier.parametersDigest(captured.intent.parameters),
    );
    expect(authorization?.payloadDigest).toBe(hashBinding(captured.intent.parameters));
  });

  it("returns an attestation a provider verifies with the public JWKS alone, describing exactly this claim", async () => {
    const captured = capture();
    const authorization = await claim(captured);
    expect(authorization?.claimAttestation).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    const claims = await verifyAttestation(authorization!.claimAttestation!);
    const grant = [...authority.grants.values()].find((g) => g.jti === authorization?.grantId);
    expect(grant?.claimToken).toBeTruthy();
    expect(claims).toMatchObject({
      iss: LOCAL_AUTHORITY_ISSUER,
      sub: authorization?.grantId,
      org_id: captured.intent.tenantId,
      decision_id: authorization?.decisionId,
      dossier_id: authorization?.dossierId,
      binding: {
        intent_hash: captured.intentHash,
        execution_payload_digest: authorization?.payloadDigest,
        execution_payload_canonicalization_profile: "RFC8785/JCS",
        execution_correlation_id: captured.intent.intentId,
      },
      claim_token_digest: `sha256:${createHash("sha256")
        .update(grant!.claimToken!, "utf8")
        .digest("hex")}`,
    });
    expect(authorization!.claimAttestation).not.toContain(grant!.claimToken);
    expect(claims.exp).toBe(Math.floor(Date.parse(authorization!.leaseExpiresAt!) / 1_000));
    expect(claims.exp).toBeGreaterThan(claims.iat);
    expect(claims.nbf).toBe(claims.iat);
    // The JWKS needs no credential: a provider is not a client of the authority.
    const anonymous = await fetch(`${authority.baseUrl}${LOCAL_AUTHORITY_JWKS_PATH}`);
    expect(anonymous.status).toBe(200);
    expect(authority.jwks.keys).toHaveLength(1);
  });

  it("is refused by the pipeline when the authority bound a digest over other parameters", async () => {
    const captured = capture();
    authority.misbindNextPayloadDigest = true;
    expect(await claim(captured)).toBeNull();
    // The knob is consumed: the very next claim is honest again.
    expect(authority.misbindNextPayloadDigest).toBe(false);
    expect(await claim(capture())).not.toBeNull();
  });
});
