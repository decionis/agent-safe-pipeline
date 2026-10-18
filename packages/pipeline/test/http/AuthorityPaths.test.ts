import { describe, expect, it, vi } from "vitest";
import type { DecisionGate } from "../../src/decision/DecisionAuthority.js";
import {
  DecionisGrantVerifier,
  type VerifiedAuthorization,
} from "../../src/execution/AuthorizationVerifier.js";
import { AuthorityPaths } from "../../src/http/AuthorityPaths.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

const CLAIM_TOKEN = "c".repeat(43);
const GRANT = "9b2f6a1e-4c3d-4e5f-8a7b-1c2d3e4f5a6b";
/** The nth UUID grant id, for tests that need many. */
const grantNumber = (index: number): string =>
  `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
const BASE = "http://127.0.0.1:3001";

/** A token shaped as a Decionis execution token: a JWT whose payload names its grant. */
function tokenFor(jti: unknown): string {
  const payload = Buffer.from(JSON.stringify({ jti }), "utf8").toString("base64url");
  return `eyJhbGciOiJFZERTQSJ9.${payload}.c2lnbmF0dXJl`;
}

describe("AuthorityPaths", () => {
  it("names every execution-authority resource as REST, one place", () => {
    expect(AuthorityPaths.GRANTS).toBe("/v1/authority/grants");
    expect(AuthorityPaths.grant("g 1")).toBe("/v1/authority/grants/g%201");
    expect(AuthorityPaths.claims("grant-1")).toBe("/v1/authority/grants/grant-1/claims");
    expect(AuthorityPaths.receipts("grant-1")).toBe("/v1/authority/grants/grant-1/receipts");
    expect(AuthorityPaths.reconciliations("grant-1")).toBe(
      "/v1/authority/grants/grant-1/reconciliations",
    );
    expect(AuthorityPaths.escalation("esc/1")).toBe("/v1/authority/escalations/esc%2F1");
    expect(AuthorityPaths.LEGACY).toEqual({
      enforceAndBind: "/v1/authority/enforce-and-bind",
      verifyToken: "/v1/execution/verify-token",
      claimToken: "/v1/execution/claim-token",
      finalizeToken: "/v1/execution/finalize-token",
    });
  });

  it("reads a grant id from a token's jti, and nothing from a token that has none", () => {
    expect(AuthorityPaths.grantIdOf(tokenFor(GRANT))).toBe(GRANT);
    expect(AuthorityPaths.grantIdOf(tokenFor("grant-1"))).toBeNull();
    expect(AuthorityPaths.grantIdOf("token-1")).toBeNull();
    expect(AuthorityPaths.grantIdOf("a..c")).toBeNull();
    expect(AuthorityPaths.grantIdOf("a.!!!.c")).toBeNull();
    expect(AuthorityPaths.grantIdOf(tokenFor(42))).toBeNull();
    expect(AuthorityPaths.grantIdOf(tokenFor("has/slash"))).toBeNull();
    expect(AuthorityPaths.grantIdOf(tokenFor("x".repeat(201)))).toBeNull();
    expect(AuthorityPaths.grantIdOf(`h.${Buffer.from("null").toString("base64url")}.s`)).toBeNull();
  });

  it("claims and records receipts on the grant's resources, and on the aliases only without an id", () => {
    expect(AuthorityPaths.claimFor(tokenFor(GRANT))).toBe(`/v1/authority/grants/${GRANT}/claims`);
    expect(AuthorityPaths.receiptFor(tokenFor(GRANT))).toBe(
      `/v1/authority/grants/${GRANT}/receipts`,
    );
    expect(AuthorityPaths.claimFor("token-1")).toBe("/v1/execution/claim-token");
    expect(AuthorityPaths.receiptFor("token-1")).toBe("/v1/execution/finalize-token");
  });
});

function setup() {
  const captured = new IntentCapture().capture(
    { action: "deploy", target: "github:repo", parameters: { environment: "production" } },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-deploy-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "github", operation: "deploy" },
      idempotencyKey: "deploy-1",
      context: {},
    },
  );
  const expiresAtSeconds = Math.floor(Date.parse(captured.intent.expiresAt) / 1_000);
  const token = tokenFor(GRANT);
  const decision: DecisionGate = {
    verdict: "ALLOW",
    decisionId: "decision-1",
    dossierId: "dossier-1",
    intentHash: captured.intentHash,
    reasonCodes: [],
    authorization: { token, expiresAt: new Date(expiresAtSeconds * 1_000).toISOString() },
    failClosed: false,
  };
  const claims = {
    iss: "decionis",
    sub: "synthetic-deploy-agent",
    aud: "github:deploy",
    org_id: "00000000-0000-4000-8000-000000000002",
    dossier_id: "dossier-1",
    decision_id: "decision-1",
    action: "deploy",
    decision: "allow",
    scope: "execute",
    binding: { intent_hash: captured.intentHash },
    jti: GRANT,
    iat: expiresAtSeconds - 60,
    nbf: expiresAtSeconds - 60,
    exp: expiresAtSeconds,
  };
  return { captured, decision, token, claims };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

const verifierWith = (fetchMock: typeof fetch) =>
  new DecionisGrantVerifier({
    baseUrl: BASE,
    apiKey: "key",
    allowInsecureLoopback: true,
    fetch: fetchMock,
  });

describe("DecionisGrantVerifier on the grant's resources", () => {
  it("claims, records an indeterminate receipt, and reports the reconciliation that resolves it", async () => {
    const { captured, decision, token, claims } = setup();
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.endsWith("/claims")) {
        return json({ valid: true, should_execute: true, claims, claim_token: CLAIM_TOKEN });
      }
      if (url.endsWith("/receipts")) return json({ finalized: true, outcome: "INDETERMINATE" });
      return json({ reconciled: true, resolution: "FINALIZED" });
    });
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("not claimed");
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(
      `${BASE}/v1/authority/grants/${GRANT}/claims`,
    );
    expect(
      await verifier.finalize({ captured, decision, authorization, outcome: "INDETERMINATE" }),
    ).toBe("RECORDED");
    expect(String(fetchMock.mock.calls[1]?.[0])).toBe(
      `${BASE}/v1/authority/grants/${GRANT}/receipts`,
    );

    // A recovery reference rebuilds the authorization: the claim is found by grant, not by object.
    const rebuilt: VerifiedAuthorization = Object.freeze({ ...authorization });
    expect(
      await verifier.reconcile({ captured, authorization: rebuilt, outcome: "COMMITTED" }),
    ).toBe("RECORDED");
    const [url, init] = fetchMock.mock.calls[2] as [string, RequestInit];
    expect(url).toBe(`${BASE}/v1/authority/grants/${GRANT}/reconciliations`);
    expect(JSON.parse(String(init.body))).toEqual({
      execution_token: token,
      claim_token: CLAIM_TOKEN,
      commit_correlation_id: captured.intent.intentId,
      outcome: "COMMITTED",
    });
    // Reported once: the claim is forgotten after the authority recorded it.
    expect(
      await verifier.reconcile({ captured, authorization: rebuilt, outcome: "COMMITTED" }),
    ).toBe("PENDING");
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("keeps a claim it could not report, and reports nothing for a grant it never held", async () => {
    const { captured, decision, claims } = setup();
    let reconciliation: () => Promise<Response> = async () => json({ error: "UNAVAILABLE" }, 503);
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.endsWith("/claims")) {
        return json({ valid: true, should_execute: true, claims, claim_token: CLAIM_TOKEN });
      }
      if (url.endsWith("/receipts")) return json({ finalized: true });
      return await reconciliation();
    });
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("not claimed");
    await verifier.finalize({ captured, decision, authorization, outcome: "INDETERMINATE" });
    expect(await verifier.reconcile({ captured, authorization, outcome: "FAILED" })).toBe(
      "PENDING",
    );
    reconciliation = async () => {
      throw new Error("socket hang up");
    };
    expect(await verifier.reconcile({ captured, authorization, outcome: "FAILED" })).toBe(
      "PENDING",
    );
    reconciliation = async () => json({ reconciled: true });
    expect(await verifier.reconcile({ captured, authorization, outcome: "FAILED" })).toBe(
      "RECORDED",
    );
    const calls = fetchMock.mock.calls.length;
    expect(
      await verifier.reconcile({
        captured,
        authorization: { ...authorization, grantId: "grant-never" },
        outcome: "FAILED",
      }),
    ).toBe("PENDING");
    expect(fetchMock).toHaveBeenCalledTimes(calls);
  });

  it("holds a bounded number of indeterminate claims, forgetting the oldest first", async () => {
    const { captured, decision } = setup();
    const fetchMock = vi.fn<typeof fetch>(async (input) =>
      String(input).endsWith("/receipts") ? json({ finalized: true }) : json({ reconciled: true }),
    );
    const verifier = verifierWith(fetchMock);
    const adopt = (index: number): VerifiedAuthorization => {
      const authorization = Object.freeze({
        decisionId: "decision-1",
        dossierId: "dossier-1",
        grantId: grantNumber(index),
        intentHash: captured.intentHash,
        expiresAt: decision.authorization?.expiresAt ?? "",
      });
      verifier.adoptClaim(authorization, {
        kind: "decionis",
        execution_token: tokenFor(grantNumber(index)),
        claim_token: CLAIM_TOKEN,
        commit_correlation_id: captured.intent.intentId,
      });
      return authorization;
    };
    for (let index = 0; index <= 1_000; index += 1) {
      await verifier.finalize({
        captured,
        decision,
        authorization: adopt(index),
        outcome: "INDETERMINATE",
      });
    }
    const forgotten = { ...adopt(0), grantId: grantNumber(0) };
    expect(
      await verifier.reconcile({ captured, authorization: forgotten, outcome: "COMMITTED" }),
    ).toBe("PENDING");
    const kept = { ...adopt(1_000), grantId: grantNumber(1_000) };
    expect(await verifier.reconcile({ captured, authorization: kept, outcome: "COMMITTED" })).toBe(
      "RECORDED",
    );
  });
});
