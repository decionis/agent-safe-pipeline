import { describe, expect, it, vi } from "vitest";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import {
  DecionisGrantVerifier,
  type AuthorityEffectEvidence,
} from "../../src/execution/AuthorizationVerifier.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

const CLAIM_TOKEN = "c".repeat(43);
const EFFECT_DIGEST = `sha256:${"e".repeat(64)}`;
const OTHER_DIGEST = `sha256:${"f".repeat(64)}`;

/**
 * `expectedEffectDigest` binds the commitment into the intent and echoes it in
 * the grant's claims, which is the only combination the authority issues.
 * Omitting it reproduces the pre-commitment fixture byte for byte.
 */
function setup(expectedEffectDigest?: string) {
  const captured = new IntentCapture().capture(
    { action: "deploy", target: "github:repo", parameters: { environment: "production" } },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-deploy-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "github", operation: "deploy" },
      idempotencyKey: "deploy-1",
      context: {},
      ...(expectedEffectDigest === undefined ? {} : { expectedEffectDigest }),
    },
  );
  const expiresAtSeconds = Math.floor(Date.parse(captured.intent.expiresAt) / 1_000);
  const decision: GateDecision = {
    verdict: "ALLOW",
    decisionId: "decision-1",
    dossierId: "dossier-1",
    intentHash: captured.intentHash,
    reasonCodes: [],
    authorization: {
      token: "token-1",
      expiresAt: new Date(expiresAtSeconds * 1_000).toISOString(),
    },
    failClosed: false,
  };
  /** Full `ExecutionTokenClaims` as the Decionis contract documents them. */
  const claims = {
    iss: "decionis",
    sub: "synthetic-deploy-agent",
    aud: "github:deploy",
    org_id: "00000000-0000-4000-8000-000000000002",
    dossier_id: "dossier-1",
    decision_id: "decision-1",
    chain_id: "chain-1",
    action: "deploy",
    decision: "allow",
    scope: "execute",
    binding: {
      intent_hash: captured.intentHash,
      execution_binding_digest: `sha256:${"b".repeat(64)}`,
      execution_nonce: "n".repeat(43),
      execution_correlation_id: captured.intent.intentId,
      ...(expectedEffectDigest === undefined
        ? {}
        : { expected_effect_digest: expectedEffectDigest }),
    },
    jti: "grant-1",
    iat: expiresAtSeconds - 60,
    nbf: expiresAtSeconds - 60,
    exp: expiresAtSeconds,
  };
  /** The live claim response carries revalidation fields beyond the documented envelope. */
  const claimResponse = {
    valid: true,
    should_execute: true,
    would_block: false,
    verdict: "ALLOW",
    reason_codes: [],
    claims,
    claim_token: CLAIM_TOKEN,
    claim_lease_expires_at: captured.intent.expiresAt,
    evidence: { nonce_claim_state: "CLAIMED" },
  };
  return { captured, decision, expiresAtSeconds, claims, claimResponse };
}

function verifierWith(fetchMock: typeof fetch) {
  return new DecionisGrantVerifier({
    baseUrl: "http://127.0.0.1:3001",
    apiKey: "key",
    allowInsecureLoopback: true,
    fetch: fetchMock,
  });
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

/** A Protocol 1.1 observation as a trusted runtime would hand it to `finalize`. */
function effectEvidence(overrides: Partial<AuthorityEffectEvidence> = {}): AuthorityEffectEvidence {
  return {
    version: "1.0",
    status: "UNCONFIRMED",
    observation_method: "DOWNSTREAM_ACK",
    observer: null,
    expected_effect_digest: EFFECT_DIGEST,
    observed_effect_digest: null,
    observed_at: null,
    evidence_digest: null,
    evidence_reference: null,
    execution_correlation_id: "",
    ...overrides,
  };
}

function finalizeResponseBody(extra: Record<string, unknown> = {}) {
  return {
    finalized: true,
    outcome: "COMMITTED",
    evidence_recorded: true,
    reason_codes: [],
    ...extra,
  };
}

/** Answers the claim route once, then walks the scripted finalize responses in order. */
function fetchScript(claimResponse: unknown, finalizeResponses: Array<() => Response>) {
  let index = 0;
  return vi.fn<typeof fetch>(async (input) => {
    if (String(input).endsWith("/v1/execution/claim-token")) return json(claimResponse);
    const next = finalizeResponses[Math.min(index, finalizeResponses.length - 1)];
    index += 1;
    if (next === undefined) throw new Error("TEST_NO_FINALIZE_RESPONSE");
    return next();
  });
}

function finalizeBodies(fetchMock: ReturnType<typeof fetchScript>) {
  return fetchMock.mock.calls
    .filter(([input]) => String(input).endsWith("/v1/execution/finalize-token"))
    .map(
      ([, request]) =>
        JSON.parse((request as RequestInit).body as string) as Record<string, unknown>,
    );
}

/** The shape of a receipt: three base64url segments. The verifier reads nothing in it. */
const RECEIPT = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJnMSJ9.c2ln";

describe("DecionisGrantVerifier", () => {
  it("claims a grant through the contract route with the exact binding and evidence", async () => {
    const { captured, decision, claimResponse } = setup();
    const evidence = {
      humanApproval: {
        provider: "presence" as const,
        requestId: "synthetic-presence-request",
        receiptDossierId: "synthetic-presence-receipt",
      },
    };
    const fetchMock = vi.fn<typeof fetch>(async () => json(claimResponse));
    const verifier = verifierWith(fetchMock);

    const authorization = await verifier.verifyAndConsume(captured, { ...decision, evidence });

    expect(authorization).toEqual({
      decisionId: "decision-1",
      dossierId: "dossier-1",
      grantId: "grant-1",
      intentHash: captured.intentHash,
      expiresAt: decision.authorization?.expiresAt,
      // The window the authority named for committing this claim, reported
      // rather than discarded: it is the real bound a side effect has to
      // finish inside, and it is shorter than the grant's own expiry.
      leaseExpiresAt: captured.intent.expiresAt,
    });
    expect(Object.isFrozen(authorization)).toBe(true);
    expect(JSON.stringify(authorization)).not.toContain(CLAIM_TOKEN);

    const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:3001/v1/execution/claim-token");
    const body = JSON.parse(request.body as string) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "commit_correlation_id",
      "consumed_by",
      "evidence",
      "execution_token",
      "intent",
      "intent_hash",
    ]);
    expect(body).toMatchObject({
      execution_token: "token-1",
      intent_hash: captured.intentHash,
      consumed_by: "synthetic-deploy-agent",
      commit_correlation_id: captured.intent.intentId,
      evidence,
    });
    const intent = body.intent as Record<string, unknown>;
    expect(Object.keys(intent).sort()).toEqual([
      "action",
      "actor",
      "captured_at",
      "context",
      "downstream_target",
      "expires_at",
      "intent_id",
      "protocol_version",
      "tenant_id",
    ]);
    expect(intent.context).toEqual({ idempotency_key: "deploy-1" });

    const withoutEvidence = vi.fn<typeof fetch>(async () => json(claimResponse));
    await verifierWith(withoutEvidence).verifyAndConsume(captured, decision);
    const plainBody = JSON.parse(
      (withoutEvidence.mock.calls[0]?.[1] as RequestInit).body as string,
    ) as Record<string, unknown>;
    expect("evidence" in plainBody).toBe(false);
  });

  it("omits the lease when the authority named none, and takes it verbatim when it did", async () => {
    const { captured, decision, claimResponse } = setup();
    // A deployment whose issuer predates the field returns no lease, and a
    // consumer that never reads one is as correct as before it existed.
    const without = { ...claimResponse };
    delete (without as { claim_lease_expires_at?: unknown }).claim_lease_expires_at;
    const silent = await verifierWith(
      vi.fn<typeof fetch>(async () => json(without)),
    ).verifyAndConsume(captured, decision);
    expect(silent).not.toBeNull();
    expect("leaseExpiresAt" in (silent ?? {})).toBe(false);
    // Explicitly null is the same statement as absent.
    const nulled = await verifierWith(
      vi.fn<typeof fetch>(async () => json({ ...claimResponse, claim_lease_expires_at: null })),
    ).verifyAndConsume(captured, decision);
    expect("leaseExpiresAt" in (nulled ?? {})).toBe(false);
    // A lease already in the past is reported as it was given: this verifier
    // does not decide what a caller should do with a window.
    const past = new Date(Date.now() - 60_000).toISOString();
    const stale = await verifierWith(
      vi.fn<typeof fetch>(async () => json({ ...claimResponse, claim_lease_expires_at: past })),
    ).verifyAndConsume(captured, decision);
    expect(stale?.leaseExpiresAt).toBe(past);
    // Something that is not a timestamp is not a lease, and is not a reason
    // to refuse the claim either.
    const nonsense = await verifierWith(
      vi.fn<typeof fetch>(async () =>
        json({ ...claimResponse, claim_lease_expires_at: "whenever" }),
      ),
    ).verifyAndConsume(captured, decision);
    expect(nonsense).toBeNull();
  });

  it("refuses a claim whose bound payload digest is not the digest of the captured parameters", async () => {
    const { captured, decision, claimResponse, claims } = setup();
    const bound = (binding: Record<string, unknown>) =>
      verifierWith(
        vi.fn<typeof fetch>(async () =>
          json({
            ...claimResponse,
            claims: { ...claims, binding: { ...claims.binding, ...binding } },
          }),
        ),
      ).verifyAndConsume(captured, decision);
    const own = DecionisGrantVerifier.parametersDigest(captured.intent.parameters);
    // The authority bound exactly what this process captured: authorized, and
    // the digest rides on the authorization for a handler to show downstream.
    const agreed = await bound({
      execution_payload_digest: own,
      execution_payload_canonicalization_profile: "RFC8785/JCS",
    });
    expect(agreed?.payloadDigest).toBe(own);
    // A different digest is a different payload, whatever the authority calls it.
    expect(
      await bound({
        execution_payload_digest: `sha256:${"e".repeat(64)}`,
        execution_payload_canonicalization_profile: "RFC8785/JCS",
      }),
    ).toBeNull();
    // The right digest under a profile this package cannot reproduce is a
    // claim it cannot check, and an unchecked claim about the payload is refused.
    expect(
      await bound({
        execution_payload_digest: own,
        execution_payload_canonicalization_profile: "DECIONIS_SORTED_JSON_V1",
      }),
    ).toBeNull();
    expect(await bound({ execution_payload_digest: own })).toBeNull();
    // No digest, a null one, or one this package cannot read: no comparison,
    // exactly as before the field was read at all.
    for (const absent of [
      {},
      { execution_payload_digest: null },
      { execution_payload_digest: 7 },
    ]) {
      const authorization = await bound(absent);
      expect(authorization).not.toBeNull();
      expect("payloadDigest" in (authorization ?? {})).toBe(false);
    }
  });

  it("digests the parameters in their canonical form, so key order cannot change the answer", () => {
    const forward = DecionisGrantVerifier.parametersDigest({ a: 1, b: { c: [1, "x"], d: null } });
    const shuffled = DecionisGrantVerifier.parametersDigest({ b: { d: null, c: [1, "x"] }, a: 1 });
    expect(forward).toBe(shuffled);
    expect(forward).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(DecionisGrantVerifier.parametersDigest({ a: 2 })).not.toBe(forward);
  });

  it("carries the claim attestation for the downstream, and never verifies it itself", async () => {
    const { captured, decision, claimResponse } = setup();
    const attestation = ["header", "payload", "signature"]
      .map((part) => Buffer.from(part).toString("base64url"))
      .join(".");
    const carried = await verifierWith(
      vi.fn<typeof fetch>(async () => json({ ...claimResponse, claim_attestation: attestation })),
    ).verifyAndConsume(captured, decision);
    expect(carried?.claimAttestation).toBe(attestation);
    // Absent, null, or not a compact JWS: nothing is carried, and the grant
    // still authorizes, because the attestation is the downstream's to
    // require and this verifier is not its audience.
    for (const value of [undefined, null, "not a jws", "two.parts"]) {
      const body = { ...claimResponse, claim_attestation: value };
      if (value === undefined) delete (body as { claim_attestation?: unknown }).claim_attestation;
      const authorization = await verifierWith(
        vi.fn<typeof fetch>(async () => json(body)),
      ).verifyAndConsume(captured, decision);
      expect(authorization).not.toBeNull();
      expect("claimAttestation" in (authorization ?? {})).toBe(false);
    }
  });

  it("reads the credential at each request, so a rotation needs no new client", async () => {
    const { captured, decision, claimResponse } = setup();
    const seen: string[] = [];
    let current = "first-key";
    const fetchMock = vi.fn<typeof fetch>(async (_url, request) => {
      seen.push(String((request?.headers as Record<string, string>)["authorization"]));
      return json(claimResponse);
    });
    const verifier = new DecionisGrantVerifier({
      baseUrl: "http://127.0.0.1:3001",
      apiKey: () => current,
      allowInsecureLoopback: true,
      fetch: fetchMock,
    });
    await verifier.verifyAndConsume(captured, decision);
    current = "second-key";
    await verifier.verifyAndConsume(captured, decision);
    expect(seen).toEqual(["Bearer first-key", "Bearer second-key"]);
    // A value is still a value: a credential that does not rotate needs no
    // function, and the client holds the one it was given.
    const constant: string[] = [];
    await new DecionisGrantVerifier({
      baseUrl: "http://127.0.0.1:3001",
      apiKey: "only-key",
      allowInsecureLoopback: true,
      fetch: vi.fn<typeof fetch>(async (_url, request) => {
        constant.push(String((request?.headers as Record<string, string>)["authorization"]));
        return json(claimResponse);
      }),
    }).verifyAndConsume(captured, decision);
    expect(constant).toEqual(["Bearer only-key"]);
  });

  it("rejects missing tokens, failed claims, and every grant-binding mismatch", async () => {
    const { captured, decision, expiresAtSeconds, claims, claimResponse } = setup();
    const noToken = { ...decision, authorization: null };
    const rejected = verifierWith(async () =>
      json({ valid: false, reason_codes: ["NONCE_REPLAY_DETECTED"], claims: null }, 409),
    );
    expect(await rejected.verifyAndConsume(captured, noToken)).toBeNull();
    expect(await rejected.verifyAndConsume(captured, decision)).toBeNull();

    const mismatches: Array<Record<string, unknown>> = [
      { ...claims, decision_id: "other" },
      { ...claims, dossier_id: "other" },
      { ...claims, binding: { ...claims.binding, intent_hash: `sha256:${"0".repeat(64)}` } },
      { ...claims, exp: expiresAtSeconds - 1 },
      { ...claims, jti: "" },
      { ...claims, org_id: "00000000-0000-4000-8000-000000000009" },
      { ...claims, sub: "another-agent" },
      { ...claims, sub: undefined },
      { ...claims, action: "delete_repo" },
      { ...claims, aud: "github:delete" },
      { ...claims, decision: "deny" },
      { ...claims, scope: "verify" },
      { ...claims, iss: undefined },
    ];
    for (const mismatchedClaims of mismatches) {
      const mismatch = verifierWith(async () =>
        json({ ...claimResponse, claims: mismatchedClaims }),
      );
      expect(
        await mismatch.verifyAndConsume(captured, decision),
        JSON.stringify(mismatchedClaims),
      ).toBeNull();
    }

    const envelopes: Array<Record<string, unknown>> = [
      { ...claimResponse, valid: false },
      { ...claimResponse, should_execute: false },
      { ...claimResponse, claim_token: null },
      { ...claimResponse, claim_token: "too-short" },
      { ...claimResponse, claims: null },
    ];
    for (const envelope of envelopes) {
      const verifier = verifierWith(async () => json(envelope));
      expect(
        await verifier.verifyAndConsume(captured, decision),
        JSON.stringify(envelope),
      ).toBeNull();
    }

    const malformed = verifierWith(async () => new Response("{not-json", { status: 200 }));
    expect(await malformed.verifyAndConsume(captured, decision)).toBeNull();
  });

  it("finalizes a claimed grant with the downstream outcome and never throws", async () => {
    const { captured, decision, claimResponse } = setup();
    const fetchMock = vi.fn<typeof fetch>(async (input) =>
      String(input).endsWith("/v1/execution/claim-token")
        ? json(claimResponse)
        : json({
            finalized: true,
            outcome: "COMMITTED",
            evidence_recorded: true,
            reason_codes: [],
          }),
    );
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
    });

    expect(status).toBe("RECORDED");
    const [url, request] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:3001/v1/execution/finalize-token");
    expect(JSON.parse(request.body as string)).toEqual({
      execution_token: "token-1",
      claim_token: CLAIM_TOKEN,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
    });

    // A finalized claim is consumed; a second report has nothing to finalize.
    expect(
      await verifier.finalize({ captured, decision, authorization, outcome: "COMMITTED" }),
    ).toBe("PENDING");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("reports PENDING for an unknown authorization or a rejected, malformed, or failed finalization", async () => {
    const { captured, decision, claimResponse } = setup();
    const foreign = Object.freeze({
      decisionId: "decision-1",
      dossierId: "dossier-1",
      grantId: "grant-1",
      intentHash: captured.intentHash,
      expiresAt: decision.authorization?.expiresAt ?? "",
    });
    const idle = vi.fn<typeof fetch>();
    expect(
      await verifierWith(idle).finalize({
        captured,
        decision,
        authorization: foreign,
        outcome: "FAILED",
      }),
    ).toBe("PENDING");
    expect(idle).not.toHaveBeenCalled();

    const finalizeResponses: Array<() => Response | never> = [
      () => json({ finalized: false, reason_codes: ["NONCE_REPLAY_DETECTED"] }, 409),
      () => json({ finalized: false, reason_codes: ["NONCE_REPLAY_DETECTED"] }),
      () => new Response("{not-json", { status: 200 }),
      () => {
        throw new Error("offline");
      },
    ];
    for (const finalizeResponse of finalizeResponses) {
      const verifier = verifierWith(async (input) =>
        String(input).endsWith("/v1/execution/claim-token")
          ? json(claimResponse)
          : finalizeResponse(),
      );
      const authorization = await verifier.verifyAndConsume(captured, decision);
      if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
      expect(
        await verifier.finalize({ captured, decision, authorization, outcome: "INDETERMINATE" }),
      ).toBe("PENDING");
    }
  });

  it("stops reading an oversized claim response", async () => {
    const { captured, decision } = setup();
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(60 * 1024));
      },
      cancel() {
        cancelled = true;
      },
    });
    const verifier = verifierWith(async () => new Response(body, { status: 200 }));

    expect(await verifier.verifyAndConsume(captured, decision)).toBeNull();
    expect(cancelled).toBe(true);
  });

  it("carries the expected-effect digest on the claim's intent binding", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = vi.fn<typeof fetch>(async () => json(claimResponse));

    const authorization = await verifierWith(fetchMock).verifyAndConsume(captured, decision);

    expect(authorization).not.toBeNull();
    const body = JSON.parse((fetchMock.mock.calls[0]?.[1] as RequestInit).body as string) as {
      intent: Record<string, unknown>;
    };
    expect(Object.keys(body.intent).sort()).toEqual([
      "action",
      "actor",
      "captured_at",
      "context",
      "downstream_target",
      "expected_effect_digest",
      "expires_at",
      "intent_id",
      "protocol_version",
      "tenant_id",
    ]);
    expect(body.intent.expected_effect_digest).toBe(EFFECT_DIGEST);
  });

  it("refuses the authorization when the grant does not echo the bound expected-effect digest", async () => {
    const { captured, decision, claims, claimResponse } = setup(EFFECT_DIGEST);
    const binding: Record<string, unknown> = { ...claims.binding };
    delete binding.expected_effect_digest;
    const verifier = verifierWith(async () =>
      json({ ...claimResponse, claims: { ...claims, binding } }),
    );

    expect(await verifier.verifyAndConsume(captured, decision)).toBeNull();
  });

  it("refuses the authorization when the grant echoes a different expected-effect digest", async () => {
    const { captured, decision, claims, claimResponse } = setup(EFFECT_DIGEST);
    const verifier = verifierWith(async () =>
      json({
        ...claimResponse,
        claims: { ...claims, binding: { ...claims.binding, expected_effect_digest: OTHER_DIGEST } },
      }),
    );

    expect(await verifier.verifyAndConsume(captured, decision)).toBeNull();
  });

  it("accepts a grant that echoes no digest for an intent that bound none", async () => {
    const { captured, decision, claimResponse } = setup();

    const authorization = await verifierWith(async () => json(claimResponse)).verifyAndConsume(
      captured,
      decision,
    );

    expect(authorization).not.toBeNull();
    expect(captured.intent.expectedEffectDigest).toBeUndefined();
  });

  it("forwards bindable effect evidence verbatim on finalize", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [
      () =>
        json(
          finalizeResponseBody({
            effect_evidence_recorded: true,
            effect_confirmation: "UNCONFIRMED",
          }),
        ),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    const evidence = effectEvidence({ execution_correlation_id: captured.intent.intentId });

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: evidence,
    });

    expect(status).toBe("RECORDED");
    expect(finalizeBodies(fetchMock)).toEqual([
      {
        execution_token: "token-1",
        claim_token: CLAIM_TOKEN,
        outcome: "COMMITTED",
        commit_correlation_id: captured.intent.intentId,
        effect_evidence: evidence,
      },
    ]);
    expect(verifier.effectReport(authorization)).toEqual({
      effectEvidenceSent: true,
      effectEvidenceRefused: false,
      effectEvidenceRecorded: true,
      effectConfirmation: "UNCONFIRMED",
      effectReceiptSent: false,
      effectReceiptVerified: false,
      effectReceiptVerification: null,
    });
  });

  it("drops effect evidence the grant committed no expected effect for", async () => {
    const { captured, decision, claimResponse } = setup();
    const fetchMock = fetchScript(claimResponse, [() => json(finalizeResponseBody())]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({ execution_correlation_id: captured.intent.intentId }),
    });

    expect(status).toBe("RECORDED");
    expect(finalizeBodies(fetchMock)).toEqual([
      {
        execution_token: "token-1",
        claim_token: CLAIM_TOKEN,
        outcome: "COMMITTED",
        commit_correlation_id: captured.intent.intentId,
      },
    ]);
    expect(verifier.effectReport(authorization)?.effectEvidenceSent).toBe(false);
  });

  it("drops effect evidence naming a different expected-effect digest", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [() => json(finalizeResponseBody())]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({
        expected_effect_digest: OTHER_DIGEST,
        execution_correlation_id: captured.intent.intentId,
      }),
    });

    expect(status).toBe("RECORDED");
    expect(finalizeBodies(fetchMock)[0]).not.toHaveProperty("effect_evidence");
  });

  it("drops effect evidence naming a different execution correlation id", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [() => json(finalizeResponseBody())]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({ execution_correlation_id: "another-correlation" }),
    });

    expect(status).toBe("RECORDED");
    expect(finalizeBodies(fetchMock)[0]).not.toHaveProperty("effect_evidence");
  });

  it("retries the finalization once without evidence when the authority refuses it", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [
      () =>
        json({ finalized: false, reason_codes: ["EFFECT_OBSERVER_PROVENANCE_UNAVAILABLE"] }, 409),
      () => json(finalizeResponseBody()),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({ execution_correlation_id: captured.intent.intentId }),
    });

    // The commit record survives a refused observation.
    expect(status).toBe("RECORDED");
    const bodies = finalizeBodies(fetchMock);
    expect(bodies).toHaveLength(2);
    expect(bodies[0]).toHaveProperty("effect_evidence");
    // The retry body is exactly what this package sent before evidence existed.
    expect(bodies[1]).toEqual({
      execution_token: "token-1",
      claim_token: CLAIM_TOKEN,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
    });
    expect(verifier.effectReport(authorization)).toEqual({
      effectEvidenceSent: false,
      effectEvidenceRefused: true,
      effectEvidenceRecorded: false,
      effectConfirmation: "UNCONFIRMED",
      effectReceiptSent: false,
      effectReceiptVerified: false,
      effectReceiptVerification: null,
    });
  });

  it("reports PENDING when the evidence-free retry is refused too", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [
      () => json({ finalized: false, reason_codes: ["NONCE_REPLAY_DETECTED"] }, 409),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({ execution_correlation_id: captured.intent.intentId }),
    });

    expect(status).toBe("PENDING");
    expect(finalizeBodies(fetchMock)).toHaveLength(2);
    expect(verifier.effectReport(authorization)).toBeNull();
  });

  it("does not retry a refused finalization that carried no evidence", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [
      () => json({ finalized: false, reason_codes: ["NONCE_REPLAY_DETECTED"] }, 409),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
    });

    expect(status).toBe("PENDING");
    expect(finalizeBodies(fetchMock)).toHaveLength(1);
  });

  it("does not retry when the authority is unreachable", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [
      () => {
        throw new Error("offline");
      },
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({ execution_correlation_id: captured.intent.intentId }),
    });

    // A transport failure is not an answer, so there is nothing to fall back from.
    expect(status).toBe("PENDING");
    expect(finalizeBodies(fetchMock)).toHaveLength(1);
  });

  it("accepts a grant that reports its uncommitted expected effect as null", async () => {
    const { captured, decision, claims, claimResponse } = setup();
    // A nullable column serialised as `null` is no commitment, exactly as an
    // absent property is, and must behave as it did before this field existed.
    const verifier = verifierWith(async () =>
      json({
        ...claimResponse,
        claims: { ...claims, binding: { ...claims.binding, expected_effect_digest: null } },
      }),
    );

    expect(await verifier.verifyAndConsume(captured, decision)).not.toBeNull();
  });

  it("grants when a bound-nothing intent meets a grant whose expected effect it cannot read", async () => {
    // Before this property existed the loose envelope carried any value here
    // untouched and nothing read it. A consumer using none of this must not
    // start being refused because its authority, or a gateway in front of it,
    // emits a shape this package does not recognise.
    for (const unreadable of ["NOT-A-DIGEST", "SHA256:" + "A".repeat(64), "", 12_345, {}]) {
      const { captured, decision, claims, claimResponse } = setup();
      const verifier = verifierWith(async () =>
        json({
          ...claimResponse,
          claims: { ...claims, binding: { ...claims.binding, expected_effect_digest: unreadable } },
        }),
      );

      expect(
        await verifier.verifyAndConsume(captured, decision),
        `${JSON.stringify(unreadable)} must read as no commitment`,
      ).not.toBeNull();
    }
  });

  it("refuses an intent that bound a digest when the grant's is unreadable", async () => {
    // The same tolerance must not soften the guarantee. An unreadable value is
    // no commitment, and an intent that committed one finds no match.
    const { captured, decision, claims, claimResponse } = setup(EFFECT_DIGEST);
    const verifier = verifierWith(async () =>
      json({
        ...claimResponse,
        claims: {
          ...claims,
          binding: { ...claims.binding, expected_effect_digest: "NOT-A-DIGEST" },
        },
      }),
    );

    expect(await verifier.verifyAndConsume(captured, decision)).toBeNull();
  });

  it("refuses a grant that reports null for an expected effect the intent bound", async () => {
    const { captured, decision, claims, claimResponse } = setup(EFFECT_DIGEST);
    const verifier = verifierWith(async () =>
      json({
        ...claimResponse,
        claims: { ...claims, binding: { ...claims.binding, expected_effect_digest: null } },
      }),
    );

    expect(await verifier.verifyAndConsume(captured, decision)).toBeNull();
  });

  it("records a finalization whose effect fields carry values outside their contract", async () => {
    const { captured, decision, claimResponse } = setup();
    const fetchMock = fetchScript(claimResponse, [
      () =>
        json(
          finalizeResponseBody({
            effect_evidence_recorded: "true",
            effect_confirmation: "NOT_OBSERVED",
          }),
        ),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
    });

    // Reporting-only fields never cost a consumer its commit record.
    expect(status).toBe("RECORDED");
    expect(verifier.effectReport(authorization)).toEqual({
      effectEvidenceSent: false,
      effectEvidenceRefused: false,
      effectEvidenceRecorded: false,
      effectConfirmation: "UNCONFIRMED",
      effectReceiptSent: false,
      effectReceiptVerified: false,
      effectReceiptVerification: null,
    });
  });

  it("never reports an observation the authority was not sent", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [
      () => json({ finalized: false, reason_codes: ["EFFECT_EVIDENCE_INVALID"] }, 409),
      () =>
        json(
          finalizeResponseBody({
            effect_evidence_recorded: true,
            effect_confirmation: "CONFIRMED",
          }),
        ),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({ execution_correlation_id: captured.intent.intentId }),
    });

    // The retry carried nothing, so an authority claiming a confirmed record
    // for it is describing something this executor did not send.
    expect(status).toBe("RECORDED");
    expect(finalizeBodies(fetchMock)[1]).not.toHaveProperty("effect_evidence");
    expect(verifier.effectReport(authorization)).toEqual({
      effectEvidenceSent: false,
      effectEvidenceRefused: true,
      effectEvidenceRecorded: false,
      effectConfirmation: "UNCONFIRMED",
      effectReceiptSent: false,
      effectReceiptVerified: false,
      effectReceiptVerification: null,
    });
  });

  it("does not re-post to an authority that answered with anything but a refusal", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [() => json({ error: "RATE_LIMITED" }, 429)]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({ execution_correlation_id: captured.intent.intentId }),
    });

    // Only a 409 is an effect refusal. Re-posting to a shedding or rejecting
    // authority would double the load it is already refusing.
    expect(status).toBe("PENDING");
    expect(finalizeBodies(fetchMock)).toHaveLength(1);
  });

  it("drops effect evidence that does not conform to the contract's bounded shape", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [() => json(finalizeResponseBody())]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    const oversized = {
      ...effectEvidence({ execution_correlation_id: captured.intent.intentId }),
      evidence_reference: "r".repeat(5_000),
      attacker_supplied_key: "x",
    } as unknown as AuthorityEffectEvidence;

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: oversized,
    });

    // Nothing a caller controls reaches an authenticated request unbounded.
    expect(status).toBe("RECORDED");
    expect(finalizeBodies(fetchMock)[0]).not.toHaveProperty("effect_evidence");
    expect(verifier.effectReport(authorization)?.effectEvidenceSent).toBe(false);
  });

  it("sends exactly the observation the drop rule checked", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [() => json(finalizeResponseBody())]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    let reads = 0;
    const shifting = {
      ...effectEvidence({ execution_correlation_id: captured.intent.intentId }),
      get expected_effect_digest() {
        reads += 1;
        return reads === 1 ? EFFECT_DIGEST : OTHER_DIGEST;
      },
    } as AuthorityEffectEvidence;

    await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: shifting,
    });

    // The checks run against the snapshot that is serialised, so a value that
    // changes between reads cannot present one digest and send another.
    const sent = finalizeBodies(fetchMock)[0]?.effect_evidence as Record<string, unknown>;
    expect(sent.expected_effect_digest).toBe(EFFECT_DIGEST);
  });

  it("reports the authority's own effect record through effectReport", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [
      () =>
        json(
          finalizeResponseBody({
            effect_evidence_recorded: true,
            effect_confirmation: "CONFIRMED",
          }),
        ),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    expect(verifier.effectReport(authorization)).toBeNull();

    await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({
        status: "CONFIRMED",
        observation_method: "READ_AFTER_WRITE",
        observer: { id: "synthetic-observer", version: "1" },
        observed_effect_digest: EFFECT_DIGEST,
        observed_at: captured.intent.capturedAt,
        evidence_digest: `sha256:${"9".repeat(64)}`,
        execution_correlation_id: captured.intent.intentId,
      }),
    });

    // The confirmation is the authority's statement, never this package's inference.
    expect(verifier.effectReport(authorization)).toEqual({
      effectEvidenceSent: true,
      effectEvidenceRefused: false,
      effectEvidenceRecorded: true,
      effectConfirmation: "CONFIRMED",
      effectReceiptSent: false,
      effectReceiptVerified: false,
      effectReceiptVerification: null,
    });
  });

  it("forwards the provider's effect receipt verbatim on finalize, and reports the authority's verdict", async () => {
    const { captured, decision, claimResponse } = setup();
    const fetchMock = fetchScript(claimResponse, [
      () =>
        json(
          finalizeResponseBody({
            effect_receipt: {
              verified: true,
              verification_code: "EFFECT_RECEIPT_VERIFIED",
              provider_key_id: "core-receipts-1",
              recorded: true,
            },
          }),
        ),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectReceipt: RECEIPT,
    });

    expect(status).toBe("RECORDED");
    // No expected effect was bound, so no evidence travels; the receipt does.
    expect(finalizeBodies(fetchMock)).toEqual([
      {
        execution_token: "token-1",
        claim_token: CLAIM_TOKEN,
        outcome: "COMMITTED",
        commit_correlation_id: captured.intent.intentId,
        effect_receipt: RECEIPT,
      },
    ]);
    expect(verifier.effectReport(authorization)).toEqual({
      effectEvidenceSent: false,
      effectEvidenceRefused: false,
      effectEvidenceRecorded: false,
      effectConfirmation: "UNCONFIRMED",
      effectReceiptSent: true,
      effectReceiptVerified: true,
      effectReceiptVerification: "EFFECT_RECEIPT_VERIFIED",
    });
  });

  it("reports a receipt the authority could not verify as sent and unverified, with its code", async () => {
    const { captured, decision, claimResponse } = setup();
    const fetchMock = fetchScript(claimResponse, [
      () =>
        json(
          finalizeResponseBody({
            effect_receipt: { verified: false, verification_code: "EFFECT_RECEIPT_KEY_UNKNOWN" },
          }),
        ),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectReceipt: RECEIPT,
    });
    expect(verifier.effectReport(authorization)).toMatchObject({
      effectReceiptSent: true,
      effectReceiptVerified: false,
      effectReceiptVerification: "EFFECT_RECEIPT_KEY_UNKNOWN",
    });
  });

  it("drops a receipt that is not a compact JWS within the contract's bound, sending nothing else differently", async () => {
    for (const malformed of [
      "",
      "not.a.jws!",
      "two.parts",
      "a.b.c.d",
      `${"a".repeat(19_990)}.b.${"c".repeat(20)}`,
      "eyJ.eyJ.c2ln ",
    ]) {
      const { captured, decision, claimResponse } = setup();
      const fetchMock = fetchScript(claimResponse, [() => json(finalizeResponseBody())]);
      const verifier = verifierWith(fetchMock);
      const authorization = await verifier.verifyAndConsume(captured, decision);
      if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
      const status = await verifier.finalize({
        captured,
        decision,
        authorization,
        outcome: "COMMITTED",
        effectReceipt: malformed,
      });
      expect(status, JSON.stringify(malformed.slice(0, 20))).toBe("RECORDED");
      expect(finalizeBodies(fetchMock)[0]).not.toHaveProperty("effect_receipt");
      expect(verifier.effectReport(authorization)).toMatchObject({
        effectReceiptSent: false,
        effectReceiptVerified: false,
        effectReceiptVerification: null,
      });
    }
    // The longest receipt the contract accepts is forwarded.
    const longest = `${"a".repeat(19_990)}.b.${"c".repeat(7)}`;
    expect(longest).toHaveLength(20_000);
    const { captured, decision, claimResponse } = setup();
    const fetchMock = fetchScript(claimResponse, [() => json(finalizeResponseBody())]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectReceipt: longest,
    });
    expect(finalizeBodies(fetchMock)[0]).toHaveProperty("effect_receipt", longest);
  });

  it("keeps the receipt on the evidence-free retry, because a receipt is never what the authority refused", async () => {
    const { captured, decision, claimResponse } = setup(EFFECT_DIGEST);
    const fetchMock = fetchScript(claimResponse, [
      () =>
        json({ finalized: false, reason_codes: ["EFFECT_OBSERVER_PROVENANCE_UNAVAILABLE"] }, 409),
      () => json(finalizeResponseBody({ effect_receipt: { verified: true } })),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectEvidence: effectEvidence({ execution_correlation_id: captured.intent.intentId }),
      effectReceipt: RECEIPT,
    });
    expect(status).toBe("RECORDED");
    const bodies = finalizeBodies(fetchMock);
    expect(bodies).toHaveLength(2);
    expect(bodies[0]).toMatchObject({ effect_receipt: RECEIPT });
    expect(bodies[0]).toHaveProperty("effect_evidence");
    expect(bodies[1]).toEqual({
      execution_token: "token-1",
      claim_token: CLAIM_TOKEN,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
      effect_receipt: RECEIPT,
    });
    expect(verifier.effectReport(authorization)).toMatchObject({
      effectEvidenceRefused: true,
      effectReceiptSent: true,
      effectReceiptVerified: true,
      effectReceiptVerification: null,
    });
  });

  it("reads a receipt verdict outside its contract as absent, never as PENDING", async () => {
    const { captured, decision, claimResponse } = setup();
    const fetchMock = fetchScript(claimResponse, [
      () => json(finalizeResponseBody({ effect_receipt: "verified" })),
    ]);
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
      effectReceipt: RECEIPT,
    });
    expect(status).toBe("RECORDED");
    expect(verifier.effectReport(authorization)).toMatchObject({
      effectReceiptSent: true,
      effectReceiptVerified: false,
      effectReceiptVerification: null,
    });
  });

  it("rejects unsafe authority URLs", () => {
    expect(
      () => new DecionisGrantVerifier({ baseUrl: "http://example.com", apiKey: "key" }),
    ).toThrow("DECIONIS_URL_MUST_USE_HTTPS");
    expect(
      () =>
        new DecionisGrantVerifier({
          baseUrl: "https://user:secret@example.com",
          apiKey: "key",
        }),
    ).toThrow("DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS");
    expect(
      () =>
        new DecionisGrantVerifier({
          baseUrl: "https://example.com#credential",
          apiKey: "key",
        }),
    ).toThrow("DECIONIS_URL_MUST_NOT_CONTAIN_QUERY_OR_FRAGMENT");
  });
});
