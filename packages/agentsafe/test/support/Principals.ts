import { createHash } from "node:crypto";
import { Authenticator, type AuthenticatorOptions } from "../../src/identity/Authenticator.js";
import { PrincipalRegistry } from "../../src/identity/PrincipalRegistry.js";
import { parsePrincipalsFile } from "../../src/identity/PrincipalsFile.js";
import { RateLimiter } from "../../src/identity/RateLimiter.js";
import type { SecurityEvents } from "../../src/incident/SecurityEvents.js";
import type { SecretHandle } from "../../src/secrets/SecretHandle.js";
import { CALLER_TOKEN, TENANT_ID, collectedEvents } from "./Environment.js";

export const sha256Hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

/** The legacy caller as the executor synthesises it: one proposer holding the caller token. */
export function legacyRegistry(
  callerToken: () => SecretHandle,
  actions: readonly string[] = ["forward_request"],
): PrincipalRegistry {
  return PrincipalRegistry.legacy({
    tenantId: TENANT_ID,
    actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
    registeredActions: actions,
    callerToken: () => callerToken().digestBytes(),
  });
}

/** A door for tests: the legacy registry, no lockout, a generous window, and whatever else is given. */
export function legacyAuthenticator(
  callerToken: () => SecretHandle,
  options: Partial<AuthenticatorOptions> & { readonly events?: SecurityEvents } = {},
): Authenticator {
  return new Authenticator({
    registry: legacyRegistry(callerToken),
    jwt: null,
    audience: null,
    limits: new RateLimiter(),
    unauthenticated: { count: 1_000, windowSeconds: 60 },
    lockout: null,
    requireCertificate: false,
    events: collectedEvents(),
    ...options,
  });
}

/** The token the operator in `mixedAuthenticator` presents. */
export const OPERATOR_TOKEN = "synthetic-operator-token-0123456789abcdef";

/**
 * A door with both roles behind bearer tokens: the caller token is a
 * proposer, `OPERATOR_TOKEN` an operator holding every scope. For the tests
 * that drive the control routes over HTTP.
 */
export function mixedAuthenticator(
  options: Partial<AuthenticatorOptions> & { readonly events?: SecurityEvents } = {},
): Authenticator {
  const file = JSON.stringify({
    version: "agent-safe.principals/1",
    principals: [
      {
        id: "synthetic-treasury-workflow",
        role: "PROPOSER",
        tenant_id: TENANT_ID,
        actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
        allowed_actions: ["forward_request"],
        credential: { kind: "BEARER", token_sha256: sha256Hex(CALLER_TOKEN) },
      },
      {
        id: "synthetic-ops-oncall",
        role: "OPERATOR",
        scopes: ["status", "metrics", "secrets.reload", "halt", "resume", "evidence"],
        credential: { kind: "BEARER", token_sha256: sha256Hex(OPERATOR_TOKEN) },
      },
    ],
  });
  return new Authenticator({
    registry: PrincipalRegistry.fromEntries(parsePrincipalsFile(file), {
      registeredActions: ["forward_request"],
      jwtConfigured: false,
      mutualTls: false,
    }),
    jwt: null,
    audience: null,
    limits: new RateLimiter(),
    unauthenticated: { count: 1_000, windowSeconds: 60 },
    lockout: null,
    requireCertificate: false,
    events: collectedEvents(),
    ...options,
  });
}

/** A principals file with one of each kind, ready to be tailored. */
export function principalsFile(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: "agent-safe.principals/1",
    principals: [
      {
        id: "treasury-workflow",
        role: "PROPOSER",
        tenant_id: TENANT_ID,
        actor: { id: "synthetic-payout-agent", type: "AI_AGENT", runtime: "workflow-runner" },
        allowed_actions: ["forward_request"],
        credential: { kind: "BEARER", token_sha256: sha256Hex(CALLER_TOKEN) },
        rate_limit: "100/60",
      },
      {
        id: "ops-oncall",
        role: "OPERATOR",
        scopes: ["status", "metrics", "secrets.reload"],
        credential: { kind: "MTLS", san_uri: "spiffe://synthetic.example/ns/ops/sa/oncall" },
      },
      {
        id: "batch-runner",
        role: "PROPOSER",
        tenant_id: TENANT_ID,
        actor: { id: "synthetic-batch-agent", type: "AI_AGENT" },
        allowed_actions: ["forward_request"],
        credential: {
          kind: "WORKLOAD_JWT",
          issuer: "https://issuer.synthetic.example",
          subject: "system:serviceaccount:agents:batch-runner",
          required_claims: { "kubernetes.io/namespace": "agents" },
        },
      },
    ],
    ...overrides,
  });
}
