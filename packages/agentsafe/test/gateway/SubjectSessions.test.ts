import { createServer, type Server } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Gateway } from "../../src/gateway/Gateway.js";
import {
  IssuerSubjectVerifier,
  SubjectSessions,
  TOKEN_EXCHANGE_GRANT,
  type SubjectTokenVerifier,
} from "../../src/gateway/SubjectSessions.js";
import { JwtError, WorkloadJwtVerifier } from "../../src/identity/WorkloadJwtVerifier.js";
import { collectedIo, LOOPBACK_ORIGIN, testConfig } from "../support/GatewayHarness.js";

const JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";

/** A verifier that names the token itself as the subject, and refuses "bad". */
const echo = (expiresAt: number): SubjectTokenVerifier => ({
  verify: async (token) => {
    if (token === "bad") throw new JwtError("JWT_EXPIRED");
    if (token === "odd") throw new Error("not a JwtError");
    return { subject: token, expiresAt };
  },
});

const form = (token: string, extra: Record<string, string> = {}): URLSearchParams =>
  new URLSearchParams({
    grant_type: TOKEN_EXCHANGE_GRANT,
    subject_token: token,
    subject_token_type: JWT_TYPE,
    ...extra,
  });

describe("SubjectSessions", () => {
  it("holds a session no longer than the token, and no longer than its own lifetime", async () => {
    let now = 1_000_000;
    const sessions = new SubjectSessions(echo(now + 120_000), {
      ttlSeconds: 900,
      clock: () => now,
    });
    const answer = await sessions.exchange(form("C-1"));
    if (answer.status !== 200) throw new Error("expected a session");
    expect(answer.body.expires_in).toBe(120);
    expect(answer.session).toMatchObject({ subject: "C-1", expiresAt: now + 120_000 });
    expect(answer.session.id).toMatch(/^sha256:[0-9a-f]{12}$/);
    expect(await sessions.resolve({ "agentsafe-session": answer.body.access_token })).toMatchObject(
      {
        subject: "C-1",
      },
    );
    expect(sessions.size).toBe(1);
    now += 120_000;
    expect(await sessions.resolve({ "agentsafe-session": answer.body.access_token })).toBe(
      "SUBJECT_SESSION_INVALID",
    );
    expect(sessions.size).toBe(0);
  });

  it("replaces a token's session when the token is exchanged again, so one token cannot fill it", async () => {
    const sessions = new SubjectSessions(echo(Date.now() + 600_000), {
      ttlSeconds: 900,
      clock: () => Date.now(),
      maxSessions: 2,
    });
    const first = await sessions.exchange(form("C-1"));
    const again = await sessions.exchange(form("C-1"));
    if (first.status !== 200 || again.status !== 200) throw new Error("expected sessions");
    expect(sessions.size).toBe(1);
    expect(await sessions.resolve({ "agentsafe-session": first.body.access_token })).toBe(
      "SUBJECT_SESSION_INVALID",
    );
    expect(await sessions.resolve({ "agentsafe-session": again.body.access_token })).toMatchObject({
      subject: "C-1",
    });
    for (let index = 0; index < 5; index += 1) await sessions.exchange(form("C-1"));
    expect(sessions.size).toBe(1);
    // Another token still gets a session of its own.
    expect((await sessions.exchange(form("C-2"))).status).toBe(200);
    expect(sessions.size).toBe(2);
  });

  it("refuses past its capacity rather than drop a session, and names a refusal by code", async () => {
    const sessions = new SubjectSessions(echo(Date.now() + 600_000), {
      ttlSeconds: 900,
      clock: () => Date.now(),
      maxSessions: 1,
    });
    expect((await sessions.exchange(form("C-1"))).status).toBe(200);
    expect(await sessions.exchange(form("C-2"))).toMatchObject({
      status: 503,
      body: { error: "temporarily_unavailable", error_description: "SESSION_CAPACITY_EXCEEDED" },
    });
    expect(await sessions.exchange(form("bad"))).toMatchObject({
      body: { error: "invalid_request", error_description: "JWT_EXPIRED" },
    });
    expect(await sessions.exchange(form("odd"))).toMatchObject({
      body: { error_description: "JWT_INVALID" },
    });
    expect(
      await sessions.exchange(form("C-3", { requested_token_type: "urn:x:other" })),
    ).toMatchObject({ body: { error_description: "REQUESTED_TOKEN_TYPE_UNSUPPORTED" } });
    const twice = form("C-3");
    twice.append("subject_token", "C-4");
    expect(await sessions.exchange(twice)).toMatchObject({
      body: { error_description: "SUBJECT_TOKEN_MISSING" },
    });
  });

  it("takes the provider's token per request, refusing one that does not verify or has expired", async () => {
    const live = new SubjectSessions(echo(Date.now() + 60_000), {
      ttlSeconds: 900,
      clock: () => Date.now(),
    });
    expect(await live.resolve({})).toBeNull();
    expect(await live.resolve({ "agentsafe-subject-token": "C-9" })).toMatchObject({
      subject: "C-9",
    });
    expect(await live.resolve({ "agentsafe-subject-token": "bad" })).toBe("SUBJECT_TOKEN_INVALID");
    expect(await live.resolve({ "agentsafe-subject-token": " " })).toBe("SUBJECT_TOKEN_INVALID");
    const stale = new SubjectSessions(echo(Date.now() - 1), {
      ttlSeconds: 900,
      clock: () => Date.now(),
    });
    expect(await stale.resolve({ "agentsafe-subject-token": "C-9" })).toBe("SUBJECT_TOKEN_INVALID");
  });
});

describe("IssuerSubjectVerifier", () => {
  it("reads the subject from the configured claim, a number as its decimal string", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256" };
    const jwt = new WorkloadJwtVerifier({
      audiences: ["agentsafe-gateway"],
      keys: { keys: [jwk] },
      clockToleranceSeconds: 0,
    });
    const sign = (claims: Record<string, unknown>): Promise<string> =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "ES256", kid: "k1" })
        .setIssuer("https://login.example/synthetic")
        .setAudience("agentsafe-gateway")
        .setSubject("synthetic-user")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);
    const verifier = new IssuerSubjectVerifier(jwt, "https://login.example/synthetic", "customer");
    expect((await verifier.verify(await sign({ customer: 10000 }))).subject).toBe("10000");
    await expect(verifier.verify(await sign({ customer: "x".repeat(201) }))).rejects.toThrow(
      "JWT_SUBJECT_UNKNOWN",
    );
    await expect(verifier.verify(await sign({ customer: true }))).rejects.toThrow(
      "JWT_SUBJECT_UNKNOWN",
    );
  });
});

describe("the identity provider's key set by address", () => {
  let server: Server;
  let jwksUrl = "";
  let served = "";
  beforeAll(async () => {
    const { publicKey } = await generateKeyPair("ES256");
    served = JSON.stringify({ keys: [{ ...(await exportJWK(publicKey)), kid: "k1" }] });
    server = createServer((request, response) => {
      response.writeHead(request.url === "/jwks" ? 200 : 404, {
        "content-type": "application/json",
      });
      response.end(request.url === "/jwks" ? served : "{}");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    jwksUrl = `${LOOPBACK_ORIGIN}:${typeof address === "object" && address !== null ? address.port : 0}`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const config = (path: string) =>
    testConfig("http://127.0.0.1:1", {
      env: { DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" },
      file: {
        version: 1,
        subject: {
          issuer: "https://login.example/synthetic",
          audience: "agentsafe-gateway",
          jwksUrl: `${jwksUrl}${path}`,
        },
      },
    });

  it("is fetched at start through the guarded egress when there is no file", async () => {
    const gateway = await Gateway.create(config("/jwks"), {
      env: {},
      io: collectedIo(),
      version: "9.9.9",
    });
    expect((await gateway.exchange(new URLSearchParams({ grant_type: "password" }))).status).toBe(
      400,
    );
    await gateway.close();
  });

  it("refuses to start, by name, when it cannot be fetched", async () => {
    await expect(
      Gateway.create(config("/missing"), { env: {}, io: collectedIo(), version: "9.9.9" }),
    ).rejects.toThrow("JWKS_UNAVAILABLE: subject.jwksUrl");
  });

  it("answers the exchange with not found on a gateway that pins no subject", async () => {
    const gateway = await Gateway.create(testConfig("http://127.0.0.1:1"), {
      env: {},
      io: collectedIo(),
      version: "9.9.9",
    });
    const answer = await gateway.exchange(new URLSearchParams());
    expect(answer.status).toBe(404);
    expect(JSON.parse(answer.body.toString("utf8"))).toEqual({
      error: "invalid_request",
      error_description: "SUBJECT_NOT_CONFIGURED",
    });
    await gateway.close();
  });
});
