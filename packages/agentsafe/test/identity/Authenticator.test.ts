import { SignJWT, exportJWK, generateKeyPair, type JSONWebKeySet } from "jose";

type KeyLike = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  AuthError,
  Authenticator,
  UNAUTHENTICATED_KEY,
  type AuthenticationInput,
  type AuthenticatorOptions,
} from "../../src/identity/Authenticator.js";
import { PrincipalRegistry } from "../../src/identity/PrincipalRegistry.js";
import { parsePrincipalsFile } from "../../src/identity/PrincipalsFile.js";
import { RateLimiter } from "../../src/identity/RateLimiter.js";
import { WorkloadJwtVerifier } from "../../src/identity/WorkloadJwtVerifier.js";
import { ROUTES, type RouteDefinition } from "../../src/http/Routes.js";
import { CALLER_TOKEN, TENANT_ID, collectedEvents } from "../support/Environment.js";
import { legacyRegistry, sha256Hex } from "../support/Principals.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";

const ISSUER = "https://issuer.synthetic.example";
const SUBJECT = "system:serviceaccount:agents:batch-runner";
const OTHER_SUBJECT = "system:serviceaccount:agents:other";
const SAN = "spiffe://synthetic.example/ns/ops/sa/oncall";
const PINNED_SAN = "spiffe://synthetic.example/ns/agents/sa/pinned";
const SECOND_TOKEN = "synthetic-second-bearer-token-0123456789";

const route = (path: string): RouteDefinition =>
  ROUTES.find((candidate) => candidate.path === path) as RouteDefinition;
const actions = route("/v1/actions");
const status = route("/v1/control/status");
const reload = route("/v1/control/secrets/reload");

let privateKey: KeyLike;
let keys: JSONWebKeySet;

beforeAll(async () => {
  const pair = await generateKeyPair("ES256");
  privateKey = pair.privateKey;
  keys = {
    keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "ES256" }],
  } as JSONWebKeySet;
});

async function jwt(
  claims: {
    sub?: string;
    iss?: string;
    aud?: string | string[];
    extra?: Record<string, unknown>;
  } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1_000);
  return await new SignJWT({ "kubernetes.io/namespace": "agents", ...(claims.extra ?? {}) })
    .setProtectedHeader({ alg: "ES256", kid: "k1" })
    .setIssuer(claims.iss ?? ISSUER)
    .setSubject(claims.sub ?? SUBJECT)
    .setAudience(claims.aud ?? "agentsafe")
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(privateKey);
}

function registry(): PrincipalRegistry {
  const proposer = {
    role: "PROPOSER",
    tenant_id: TENANT_ID,
    actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
    allowed_actions: ["forward_request"],
  };
  const text = JSON.stringify({
    version: "agent-safe.principals/1",
    principals: [
      {
        ...proposer,
        id: "bearer-agent",
        credential: { kind: "BEARER", token_sha256: sha256Hex(CALLER_TOKEN) },
        rate_limit: "2/60",
      },
      {
        ...proposer,
        id: "second-bearer",
        credential: { kind: "BEARER", token_sha256: sha256Hex(SECOND_TOKEN) },
      },
      {
        id: "ops-oncall",
        role: "OPERATOR",
        scopes: ["status", "metrics"],
        credential: { kind: "MTLS", san_uri: SAN },
      },
      {
        ...proposer,
        id: "pinned-agent",
        credential: { kind: "MTLS", san_uri: PINNED_SAN, cert_fingerprint_sha256: "ab".repeat(32) },
      },
      {
        ...proposer,
        id: "batch-runner",
        credential: {
          kind: "WORKLOAD_JWT",
          issuer: ISSUER,
          subject: SUBJECT,
          required_claims: { "kubernetes.io/namespace": "agents" },
        },
      },
      {
        ...proposer,
        id: "audited-runner",
        credential: {
          kind: "WORKLOAD_JWT",
          issuer: ISSUER,
          subject: "system:serviceaccount:agents:audited",
          audience: "agentsafe-batch",
        },
      },
    ],
  });
  return PrincipalRegistry.fromEntries(parsePrincipalsFile(text), {
    registeredActions: ["forward_request"],
    jwtConfigured: true,
    mutualTls: true,
  });
}

interface Door {
  readonly door: Authenticator;
  readonly lines: string[];
  readonly limits: RateLimiter;
  tick(ms: number): void;
}

function door(overrides: Partial<AuthenticatorOptions> = {}): Door {
  let now = 1_000_000;
  const limits = new RateLimiter(() => now);
  const lines: string[] = [];
  const authenticator = new Authenticator({
    registry: registry(),
    jwt: new WorkloadJwtVerifier({
      audiences: ["agentsafe", "agentsafe-batch"],
      keys,
      clockToleranceSeconds: 5,
    }),
    audience: "agentsafe",
    limits,
    unauthenticated: { count: 100, windowSeconds: 60 },
    lockout: { failures: 2, windowSeconds: 60, lockSeconds: 300 },
    requireCertificate: false,
    events: collectedEvents(lines),
    ...overrides,
  });
  return {
    door: authenticator,
    lines,
    limits,
    tick: (ms) => {
      now += ms;
    },
  };
}

const bearer = (token: string, path = "/v1/actions"): AuthenticationInput => ({
  authorization: `Bearer ${token}`,
  peer: null,
  route: route(path),
});
const cert = (
  sanUris: string[],
  options: {
    authorized?: boolean;
    fingerprint?: string;
    authorization?: string;
    path?: string;
  } = {},
): AuthenticationInput => ({
  authorization: options.authorization,
  peer: {
    authorized: options.authorized ?? true,
    sanUris,
    fingerprint: options.fingerprint ?? "00".repeat(32),
  },
  route: route(options.path ?? "/v1/control/status"),
});

async function refused(work: Promise<unknown>): Promise<[number, string]> {
  try {
    await work;
  } catch (error) {
    if (error instanceof AuthError) return [error.status, error.code];
    throw error;
  }
  throw new Error("expected a refusal");
}

const failures = (lines: string[]): [string, string][] =>
  lines
    .map((line) => JSON.parse(line) as { event: string; method?: string; code?: string })
    .filter((event) => event.event === "AUTH_FAILED")
    .map((event) => [event.method ?? "", event.code ?? ""]);

describe("Authenticator", () => {
  it("admits a bearer by digest, a workload by token, and a certificate by SAN, each as its own method", async () => {
    const { door: d, lines } = door();
    expect(await d.authenticate(bearer(CALLER_TOKEN))).toMatchObject({
      principal: { id: "bearer-agent" },
      method: "bearer",
    });
    expect(await d.authenticate(bearer(await jwt()))).toMatchObject({
      principal: { id: "batch-runner" },
      method: "jwt",
    });
    expect(await d.authenticate(cert([SAN]))).toMatchObject({
      principal: { id: "ops-oncall" },
      method: "mtls",
    });
    expect(
      await d.authenticate(
        cert(["dns:x", PINNED_SAN], { fingerprint: "AB:".repeat(31) + "AB", path: "/v1/actions" }),
      ),
    ).toMatchObject({
      principal: { id: "pinned-agent" },
      method: "mtls",
    });
    expect(
      await d.authenticate(
        bearer(
          await jwt({ sub: "system:serviceaccount:agents:audited", aud: ["agentsafe-batch"] }),
        ),
      ),
    ).toMatchObject({
      principal: { id: "audited-runner" },
    });
    expect(lines).toEqual([]);
  });

  it("refuses at the door in order, each refusal one event with the method and the code", async () => {
    const { door: d, lines } = door();
    expect(
      await refused(d.authenticate({ authorization: undefined, peer: null, route: actions })),
    ).toEqual([401, "CALLER_NOT_AUTHENTICATED"]);
    expect(
      await refused(d.authenticate({ authorization: "Basic abc", peer: null, route: actions })),
    ).toEqual([401, "CALLER_NOT_AUTHENTICATED"]);
    expect(await refused(d.authenticate(bearer("synthetic-unknown-token-0123456789")))).toEqual([
      401,
      "CALLER_NOT_AUTHENTICATED",
    ]);
    expect(
      await refused(d.authenticate(cert([SAN], { authorization: `Bearer ${CALLER_TOKEN}` }))),
    ).toEqual([401, "AUTH_AMBIGUOUS"]);
    expect(await refused(d.authenticate(cert([SAN], { authorized: false })))).toEqual([
      401,
      "CALLER_NOT_AUTHENTICATED",
    ]);
    expect(
      await refused(d.authenticate(cert(["spiffe://synthetic.example/ns/ops/sa/stranger"]))),
    ).toEqual([401, "CALLER_NOT_AUTHENTICATED"]);
    expect(
      await refused(
        d.authenticate(cert([PINNED_SAN], { fingerprint: "cd".repeat(32), path: "/v1/actions" })),
      ),
    ).toEqual([401, "CALLER_NOT_AUTHENTICATED"]);
    expect(await refused(d.authenticate(cert([SAN], { path: "/v1/actions" })))).toEqual([
      403,
      "ROLE_FORBIDDEN",
    ]);
    expect(await refused(d.authenticate(bearer(SECOND_TOKEN, "/v1/control/status")))).toEqual([
      403,
      "ROLE_FORBIDDEN",
    ]);
    expect(await refused(d.authenticate(cert([SAN], { path: reload.path })))).toEqual([
      403,
      "SCOPE_FORBIDDEN",
    ]);
    expect(failures(lines)).toEqual([
      ["bearer", "CALLER_NOT_AUTHENTICATED"],
      ["bearer", "CALLER_NOT_AUTHENTICATED"],
      ["bearer", "CALLER_NOT_AUTHENTICATED"],
      ["none", "AUTH_AMBIGUOUS"],
      ["mtls", "CALLER_NOT_AUTHENTICATED"],
      ["mtls", "CALLER_NOT_AUTHENTICATED"],
      ["mtls", "CALLER_NOT_AUTHENTICATED"],
      ["mtls", "ROLE_FORBIDDEN"],
      ["bearer", "ROLE_FORBIDDEN"],
      ["mtls", "SCOPE_FORBIDDEN"],
    ]);
    expect(status.scope).toBe("status");
  });

  it("closes the window on failed attempts after the configured count, and reopens it later", async () => {
    const { door: d, lines, tick } = door({ unauthenticated: { count: 3, windowSeconds: 60 } });
    for (let attempt = 0; attempt < 3; attempt += 1) {
      expect(
        await refused(d.authenticate(bearer("synthetic-wrong-token-0123456789abcdef"))),
      ).toEqual([401, "CALLER_NOT_AUTHENTICATED"]);
    }
    expect(await refused(d.authenticate(bearer(CALLER_TOKEN)))).toEqual([429, "RATE_LIMITED"]);
    expect(failures(lines).at(-1)).toEqual(["none", "RATE_LIMITED"]);
    tick(61_000);
    expect(await d.authenticate(bearer(CALLER_TOKEN))).toMatchObject({
      principal: { id: "bearer-agent" },
    });
    expect(await refused(d.authenticate(cert([SAN], { path: "/v1/actions" })))).toEqual([
      403,
      "ROLE_FORBIDDEN",
    ]);
    expect(await refused(d.authenticate(cert([SAN], { path: "/v1/actions" })))).toEqual([
      403,
      "ROLE_FORBIDDEN",
    ]);
    expect(await refused(d.authenticate(cert([SAN], { path: "/v1/actions" })))).toEqual([
      403,
      "ROLE_FORBIDDEN",
    ]);
    expect(await d.authenticate(cert([SAN]))).toMatchObject({ principal: { id: "ops-oncall" } });
  });

  it("holds each principal to its own window, without counting a full window as a failure", async () => {
    const { door: d, limits, tick } = door();
    expect(await d.authenticate(bearer(CALLER_TOKEN))).toMatchObject({ method: "bearer" });
    expect(await d.authenticate(bearer(CALLER_TOKEN))).toMatchObject({ method: "bearer" });
    expect(await refused(d.authenticate(bearer(CALLER_TOKEN)))).toEqual([429, "RATE_LIMITED"]);
    expect(limits.exhausted(UNAUTHENTICATED_KEY, { count: 1, windowSeconds: 60 })).toBe(false);
    expect(limits.locked("bearer-agent")).toBe(false);
    tick(61_000);
    expect(await d.authenticate(bearer(CALLER_TOKEN))).toMatchObject({ method: "bearer" });
    expect(await d.authenticate(bearer(SECOND_TOKEN))).toMatchObject({
      principal: { id: "second-bearer" },
    });
    expect(await d.authenticate(bearer(SECOND_TOKEN))).toMatchObject({
      principal: { id: "second-bearer" },
    });
    expect(await d.authenticate(bearer(SECOND_TOKEN))).toMatchObject({
      principal: { id: "second-bearer" },
    });
  });

  it("refuses a workload token by its own code, locks the principal after repeated proven failures, and unlocks later", async () => {
    const { door: d, lines, limits, tick } = door();
    expect(
      await refused(d.authenticate(bearer(await jwt({ iss: "https://other.synthetic.example" })))),
    ).toEqual([401, "JWT_ISSUER_UNKNOWN"]);
    expect(await refused(d.authenticate(bearer(await jwt({ sub: OTHER_SUBJECT }))))).toEqual([
      401,
      "JWT_SUBJECT_UNKNOWN",
    ]);
    expect(await refused(d.authenticate(bearer(await jwt({ aud: "elsewhere" }))))).toEqual([
      401,
      "JWT_AUDIENCE_MISMATCH",
    ]);
    expect(await refused(d.authenticate(bearer("a.b.c")))).toEqual([401, "JWT_SIGNATURE_INVALID"]);
    tick(61_000);
    expect(limits.locked("batch-runner")).toBe(false);
    expect(await refused(d.authenticate(bearer(await jwt({ aud: "agentsafe-batch" }))))).toEqual([
      401,
      "JWT_AUDIENCE_MISMATCH",
    ]);
    expect(
      await refused(
        d.authenticate(bearer(await jwt({ extra: { "kubernetes.io/namespace": "elsewhere" } }))),
      ),
    ).toEqual([401, "JWT_CLAIM_MISMATCH"]);
    expect(limits.locked("batch-runner")).toBe(true);
    expect(await refused(d.authenticate(bearer(await jwt())))).toEqual([423, "PRINCIPAL_LOCKED"]);
    expect(
      await refused(
        d.authenticate(
          bearer(await jwt({ sub: "system:serviceaccount:agents:audited", aud: "agentsafe" })),
        ),
      ),
    ).toEqual([401, "JWT_AUDIENCE_MISMATCH"]);
    tick(301_000);
    expect(await d.authenticate(bearer(await jwt()))).toMatchObject({
      principal: { id: "batch-runner" },
    });
    const events = lines.map(
      (line) => JSON.parse(line) as { event: string; principal?: string; code?: string },
    );
    expect(events.filter((event) => event.event === "PRINCIPAL_LOCKED")).toEqual([
      expect.objectContaining({ principal: "batch-runner" }),
    ]);
    expect(failures(lines).map(([, code]) => code)).toEqual([
      "JWT_ISSUER_UNKNOWN",
      "JWT_SUBJECT_UNKNOWN",
      "JWT_AUDIENCE_MISMATCH",
      "JWT_SIGNATURE_INVALID",
      "JWT_AUDIENCE_MISMATCH",
      "JWT_CLAIM_MISMATCH",
      "PRINCIPAL_LOCKED",
      "JWT_AUDIENCE_MISMATCH",
    ]);
    expect(failures(lines).every(([method]) => method === "jwt")).toBe(true);
  });

  it("treats a token-shaped bearer as a bearer when no verifier is configured, and never locks without a rule", async () => {
    const { door: d, limits } = door({ jwt: null, lockout: null });
    expect(await refused(d.authenticate(bearer(await jwt())))).toEqual([
      401,
      "CALLER_NOT_AUTHENTICATED",
    ]);
    const { door: unlocked, limits: none } = door({ lockout: null });
    for (let attempt = 0; attempt < 3; attempt += 1) {
      expect(await refused(unlocked.authenticate(bearer(await jwt({ aud: "elsewhere" }))))).toEqual(
        [401, "JWT_AUDIENCE_MISMATCH"],
      );
    }
    expect(none.locked("batch-runner")).toBe(false);
    expect(limits.locked("batch-runner")).toBe(false);
    const { door: unaudienced } = door({ audience: null });
    expect(await refused(unaudienced.authenticate(bearer(await jwt())))).toEqual([
      401,
      "JWT_AUDIENCE_MISMATCH",
    ]);
  });

  it("requires the certificate and the token together in legacy mode with a client CA", async () => {
    const token = SecretHandle.fromString("EXECUTOR_CALLER_TOKEN", CALLER_TOKEN);
    const { door: d, lines } = door({
      registry: legacyRegistry(() => token),
      jwt: null,
      requireCertificate: true,
    });
    expect(await refused(d.authenticate(bearer(CALLER_TOKEN)))).toEqual([
      401,
      "CALLER_NOT_AUTHENTICATED",
    ]);
    expect(
      await refused(
        d.authenticate(
          cert([], {
            authorized: false,
            authorization: `Bearer ${CALLER_TOKEN}`,
            path: "/v1/actions",
          }),
        ),
      ),
    ).toEqual([401, "CALLER_NOT_AUTHENTICATED"]);
    expect(
      await refused(
        d.authenticate(cert([], { authorization: "Bearer wrong", path: "/v1/actions" })),
      ),
    ).toEqual([401, "CALLER_NOT_AUTHENTICATED"]);
    expect(await refused(d.authenticate(cert([], { path: "/v1/actions" })))).toEqual([
      401,
      "CALLER_NOT_AUTHENTICATED",
    ]);
    expect(
      await d.authenticate(
        cert([], { authorization: `Bearer ${CALLER_TOKEN}`, path: "/v1/actions" }),
      ),
    ).toMatchObject({
      principal: { id: "legacy-caller" },
      method: "bearer",
    });
    expect(failures(lines).map(([method]) => method)).toEqual(["mtls", "mtls", "bearer", "bearer"]);
  });

  it("lets a failure that is not a refusal escape untouched", async () => {
    const broken = {
      byBearerDigest: () => {
        throw new Error("registry exploded");
      },
    } as unknown as PrincipalRegistry;
    const { door: d, lines } = door({ registry: broken });
    await expect(d.authenticate(bearer(CALLER_TOKEN))).rejects.toThrow("registry exploded");
    expect(lines).toEqual([]);
    expect(vi.isMockFunction(broken.byBearerDigest)).toBe(false);
  });
});
