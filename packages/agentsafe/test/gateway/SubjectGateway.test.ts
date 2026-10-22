import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { Gateway } from "../../src/gateway/Gateway.js";
import { GatewayConfigError } from "../../src/gateway/GatewayConfig.js";
import { RouteTable } from "../../src/gateway/RouteTable.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import { ApiProfiles, type JsonObject } from "@decionis/agent-safe-pipeline";
import {
  collectedIo,
  LOOPBACK_ORIGIN,
  testConfig,
  type CollectedIo,
} from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const ISSUER = "https://login.example/synthetic";
const AUDIENCE = "agentsafe-gateway";
const COMPANY = "6f3c1a52-1d2e-4f5a-8b9c-0d1e2f3a4b5c";
const BASE = `/v2.0/production/api/v2.0/companies(${COMPANY})`;
const MINE = "C-10000";
const OTHER = "C-20000";
const EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt";

/**
 * A stand-in for Business Central's reads: each path answers with the JSON a
 * test put there, and every request it saw is kept, headers included.
 */
class BusinessCentralDouble {
  public readonly seen: { method: string; url: string; headers: Record<string, unknown> }[] = [];
  public readonly answers = new Map<string, { status: number; body: unknown }>();
  private server: Server | null = null;
  public port = 0;

  public async start(): Promise<void> {
    this.server = createServer((request, response) => {
      const url = request.url ?? "/";
      this.seen.push({ method: request.method ?? "", url, headers: { ...request.headers } });
      const answer = this.answers.get(url.split("?")[0] ?? url) ?? {
        status: 201,
        body: { ok: true },
      };
      response.writeHead(answer.status, { "content-type": "application/json" });
      response.end(JSON.stringify(answer.body));
    });
    await new Promise<void>((resolve) => this.server?.listen(0, "127.0.0.1", () => resolve()));
    const address = this.server.address();
    this.port = typeof address === "object" && address !== null ? address.port : 0;
  }

  public async stop(): Promise<void> {
    this.server?.closeAllConnections();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }
}

describe("the subject setting", () => {
  const subject = { issuer: ISSUER, audience: AUDIENCE, jwksFile: "/etc/agentsafe/jwks.json" };
  const refused = (file: Record<string, unknown>): string => {
    try {
      testConfig("http://127.0.0.1:1", { file: { version: 1, ...file } });
    } catch (error) {
      if (error instanceof GatewayConfigError) return `${error.code} ${error.setting}`;
      throw error;
    }
    throw new Error("expected a refusal");
  };

  it("is off by default, and reads the issuer, audience, keys, claim and lifetime", () => {
    const off = testConfig("http://127.0.0.1:1");
    expect(off.subject).toBeNull();
    expect(off.interception.refuseUnknownReads).toBe(false);
    const on = testConfig("http://127.0.0.1:1", {
      file: {
        version: 1,
        interception: { profile: "businesscentral/api/v2", refuseUnknownReads: true },
        subject: { ...subject, claim: "customer_number", sessionTtlSeconds: 600 },
      },
    });
    expect(on.subject).toEqual({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksFile: "/etc/agentsafe/jwks.json",
      jwksUrl: null,
      claim: "customer_number",
      sessionTtlSeconds: 600,
    });
    expect(on.interception.refuseUnknownReads).toBe(true);
    expect(
      testConfig("http://127.0.0.1:1", { file: { version: 1, subject } }).subject,
    ).toMatchObject({ claim: "sub", sessionTtlSeconds: 900 });
  });

  it("refuses, by name, a subject without keys and unknown reads refused without a session", () => {
    expect(refused({ subject: { issuer: ISSUER, audience: AUDIENCE } })).toBe(
      "CONFIG_MISSING subject.jwksFile",
    );
    expect(refused({ subject: { ...subject, jwksUrl: "http://login.example/jwks" } })).toBe(
      "CONFIG_INVALID subject.jwksUrl",
    );
    expect(
      refused({ interception: { profile: "businesscentral/api/v2", refuseUnknownReads: true } }),
    ).toBe("CONFIG_INVALID interception.refuseUnknownReads");
    expect(refused({ interception: { refuseUnknownReads: true }, subject })).toBe(
      "CONFIG_INVALID interception.refuseUnknownReads",
    );
    expect(refused({ subject: { ...subject, sessionTtlSeconds: 7_200 } })).toBe(
      "CONFIG_INVALID subject.sessionTtlSeconds",
    );
  });
});

describe("the route table with checked reads", () => {
  const profile = ApiProfiles.get("businesscentral/api/v2")!;
  const checked = new RouteTable([], "GOVERN", true, profile, "FULL", "CHECK");
  const strict = new RouteTable([], "GOVERN", true, profile, "FULL", "REFUSE_UNKNOWN");
  const open = new RouteTable([], "GOVERN", true, profile);

  it("checks a read a profile operation names, and passes or refuses the rest", () => {
    expect(checked.plan("GET", `${BASE}/customers`)).toEqual({
      kind: "CHECK",
      action: "customer.read",
      operation: "customers.list",
    });
    expect(checked.plan("GET", `${BASE}/items`)).toMatchObject({ kind: "PASSTHROUGH" });
    expect(strict.plan("GET", `${BASE}/items`)).toEqual({
      kind: "REFUSE",
      code: "READ_OPERATION_UNMATCHED",
    });
    expect(open.plan("GET", `${BASE}/customers`)).toMatchObject({ kind: "PASSTHROUGH" });
  });

  it("refuses a read that only resembles a checked one, and a HEAD of one", () => {
    expect(checked.plan("GET", `${BASE}/Customers`)).toEqual({
      kind: "REFUSE",
      code: "HTTP_PATH_AMBIGUOUS",
    });
    expect(checked.plan("GET", `${BASE}/%63ustomers`)).toEqual({
      kind: "REFUSE",
      code: "HTTP_PATH_AMBIGUOUS",
    });
    expect(checked.plan("HEAD", `${BASE}/customers`)).toEqual({
      kind: "REFUSE",
      code: "READ_OPERATION_UNMATCHED",
    });
    expect(checked.plan("OPTIONS", `${BASE}/items`)).toMatchObject({ kind: "PASSTHROUGH" });
  });
});

describe("a gateway that pins subjects", () => {
  const upstream = new BusinessCentralDouble();
  const authority = new LocalAuthority({ policy: () => "ALLOW" });
  let directory: string;
  let key: CryptoKey;
  let origin: string;
  let server: GatewayHttpServer;
  let gateway: Gateway;
  let io: CollectedIo;
  let now = Date.now();
  const env = {
    DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
    DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    DECIONIS_TENANT_ID: TENANT_ID,
    AGENTSAFE_MODE: "enforcement",
  };

  async function token(
    claims: Record<string, unknown> = { customer_number: MINE },
    options: { issuer?: string; expiresIn?: string } = {},
  ): Promise<string> {
    return await new SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", kid: "synthetic-idp-1" })
      .setIssuer(options.issuer ?? ISSUER)
      .setAudience(AUDIENCE)
      .setSubject("synthetic-agent-session")
      .setIssuedAt()
      .setExpirationTime(options.expiresIn ?? "10m")
      .sign(key);
  }

  async function build(file: Record<string, unknown>): Promise<void> {
    io = collectedIo();
    const withUrl = { ...env, DECIONIS_API_URL: authority.baseUrl };
    gateway = await Gateway.create(
      testConfig(`${LOOPBACK_ORIGIN}:${upstream.port}`, { env: withUrl, file }),
      { env: withUrl, io, version: "9.9.9", clock: () => now },
    );
    server = new GatewayHttpServer(gateway);
    origin = `${LOOPBACK_ORIGIN}:${(await server.listen(0, "127.0.0.1")).port}`;
  }

  async function teardown(): Promise<void> {
    await server.close(10);
    await gateway.close();
  }

  function fileWith(interception: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      version: 1,
      interception: { profile: "businesscentral/api/v2", ...interception },
      subject: {
        issuer: ISSUER,
        audience: AUDIENCE,
        jwksFile: join(directory, "jwks.json"),
        claim: "customer_number",
      },
    };
  }

  async function exchange(form: Record<string, string>): Promise<Response> {
    return await fetch(`${origin}/_agentsafe/v1/sessions`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form).toString(),
    });
  }

  async function session(): Promise<string> {
    const answer = await exchange({
      grant_type: EXCHANGE,
      subject_token: await token(),
      subject_token_type: JWT_TYPE,
    });
    return ((await answer.json()) as { access_token: string }).access_token;
  }

  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), "agentsafe-subject-"));
    const pair = await generateKeyPair("ES256");
    key = pair.privateKey;
    const jwk = { ...(await exportJWK(pair.publicKey)), kid: "synthetic-idp-1", alg: "ES256" };
    writeFileSync(join(directory, "jwks.json"), JSON.stringify({ keys: [jwk] }));
    await upstream.start();
    await authority.start();
  });
  afterAll(async () => {
    await upstream.stop();
    await authority.stop();
    rmSync(directory, { recursive: true, force: true });
  });

  it("exchanges the identity provider's token for a session, as RFC 8693 says", async () => {
    await build(fileWith());
    const answer = await exchange({
      grant_type: EXCHANGE,
      subject_token: await token(),
      subject_token_type: JWT_TYPE,
      requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
    });
    expect(answer.status).toBe(200);
    expect(answer.headers.get("cache-control")).toBe("no-store");
    const body = (await answer.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "N_A",
    });
    expect(body["access_token"]).toMatch(/^[\w-]{43}$/);
    expect(body["expires_in"]).toBeGreaterThan(500);
    expect(body["expires_in"]).toBeLessThanOrEqual(600);

    const refusals: [Record<string, string>, string, string][] = [
      [{ grant_type: "client_credentials" }, "unsupported_grant_type", "TOKEN_EXCHANGE_ONLY"],
      [
        { grant_type: EXCHANGE, subject_token_type: JWT_TYPE },
        "invalid_request",
        "SUBJECT_TOKEN_MISSING",
      ],
      [
        { grant_type: EXCHANGE, subject_token: await token(), subject_token_type: "urn:x:saml" },
        "invalid_request",
        "SUBJECT_TOKEN_TYPE_UNSUPPORTED",
      ],
      [
        {
          grant_type: EXCHANGE,
          subject_token: await token(),
          subject_token_type: JWT_TYPE,
          actor_token: await token(),
        },
        "invalid_request",
        "ACTOR_TOKEN_UNSUPPORTED",
      ],
      [
        {
          grant_type: EXCHANGE,
          subject_token: await token(
            { customer_number: MINE },
            { issuer: "https://other.example" },
          ),
          subject_token_type: JWT_TYPE,
        },
        "invalid_request",
        "JWT_ISSUER_UNKNOWN",
      ],
      [
        { grant_type: EXCHANGE, subject_token: await token({}), subject_token_type: JWT_TYPE },
        "invalid_request",
        "JWT_SUBJECT_UNKNOWN",
      ],
      [
        { grant_type: EXCHANGE, subject_token: "not.a.token", subject_token_type: JWT_TYPE },
        "invalid_request",
        "JWT_SIGNATURE_INVALID",
      ],
    ];
    for (const [form, error, description] of refusals) {
      const refused = await exchange(form);
      expect(refused.status, description).toBe(400);
      expect(await refused.json()).toEqual({ error, error_description: description });
    }
    const wrongType = await fetch(`${origin}/_agentsafe/v1/sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(wrongType.status).toBe(415);
    await teardown();
    const lines = io.out.join("\n");
    expect(lines).toContain("SUBJECT_SESSION_ISSUED");
    expect(lines).toContain("SUBJECT_SESSION_REFUSED");
    // The evidence names a session by a short digest; never a token or a subject.
    expect(lines).not.toContain(String(body["access_token"]));
    expect(lines).not.toContain(MINE);
  });

  it("relays a read whose every item is the session's customer, and refuses one with another", async () => {
    await build(fileWith());
    const sessionToken = await session();
    upstream.answers.set(`${BASE}/customers`, {
      status: 200,
      body: { value: [{ id: "a", number: MINE, displayName: "Synthetic Customer" }] },
    });
    const mine = await fetch(`${origin}${BASE}/customers?$filter=number eq '${MINE}'`, {
      headers: { "agentsafe-session": sessionToken },
    });
    expect(mine.status).toBe(200);
    expect(mine.headers.get("agentsafe-subject")).toBe("CHECKED");
    expect(mine.headers.get("agentsafe-execution")).toBe("PASSTHROUGH");
    expect(((await mine.json()) as { value: unknown[] }).value).toHaveLength(1);
    // The session ends at the gateway: the upstream never sees it.
    expect(upstream.seen.at(-1)?.headers["agentsafe-session"]).toBeUndefined();

    upstream.answers.set(`${BASE}/customers`, {
      status: 200,
      body: {
        value: [
          { id: "a", number: MINE, displayName: "Synthetic Customer" },
          { id: "b", number: OTHER, displayName: "Another Synthetic Customer" },
        ],
      },
    });
    const theirs = await fetch(`${origin}${BASE}/customers`, {
      headers: { "agentsafe-session": sessionToken },
    });
    expect(theirs.status).toBe(403);
    expect(theirs.headers.get("agentsafe-execution")).toBe("WITHHELD");
    const refusal = await theirs.text();
    expect(JSON.parse(refusal)).toMatchObject({
      state: "REFUSED",
      verdict: null,
      reason_codes: ["RESPONSE_SUBJECT_MISMATCH"],
      execution: "WITHHELD",
    });
    // Refused whole: nothing of either record is relayed.
    expect(refusal).not.toContain(OTHER);
    expect(refusal).not.toContain("Synthetic Customer");

    upstream.answers.set(`${BASE}/salesInvoices`, {
      status: 200,
      body: { value: [{ number: "S-INV-1", totalAmountIncludingTax: 10 }] },
    });
    const unchecked = await fetch(`${origin}${BASE}/salesInvoices?$select=number`, {
      headers: { "agentsafe-session": sessionToken },
    });
    expect(unchecked.status).toBe(403);
    expect(await unchecked.json()).toMatchObject({ reason_codes: ["RESPONSE_SUBJECT_ABSENT"] });

    // An answer that is not a success is relayed as it came.
    upstream.answers.set(`${BASE}/customerLedgerEntries`, {
      status: 404,
      body: { error: { code: "NotFound" } },
    });
    const missing = await fetch(`${origin}${BASE}/customerLedgerEntries`, {
      headers: { "agentsafe-session": sessionToken },
    });
    expect(missing.status).toBe(404);
    await teardown();
    const lines = io.out.map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(
      lines.find((line) => line["event"] === "INTERCEPTED" && line["state"] === "REFUSED"),
    ).toMatchObject({ reason_codes: ["RESPONSE_SUBJECT_MISMATCH"], execution: "WITHHELD" });
    expect(io.out.join("\n")).toContain("SUBJECT_REFUSED");
  });

  it("refuses a checked read without a session, with one that does not stand, or with two", async () => {
    await build(fileWith());
    const before = upstream.seen.length;
    const none = await fetch(`${origin}${BASE}/customers`);
    expect(none.status).toBe(401);
    expect(await none.json()).toMatchObject({ reason_codes: ["SUBJECT_SESSION_REQUIRED"] });
    const forged = await fetch(`${origin}${BASE}/customers`, {
      headers: { "agentsafe-session": "c3ludGhldGljLXNlc3Npb24tdG9rZW4" },
    });
    expect(await forged.json()).toMatchObject({ reason_codes: ["SUBJECT_SESSION_INVALID"] });
    const both = await fetch(`${origin}${BASE}/customers`, {
      headers: { "agentsafe-session": await session(), "agentsafe-subject-token": await token() },
    });
    expect(both.status).toBe(400);
    expect(await both.json()).toMatchObject({ reason_codes: ["SUBJECT_TOKEN_AMBIGUOUS"] });
    const expired = await fetch(`${origin}${BASE}/customers`, {
      headers: {
        "agentsafe-subject-token": await token({ customer_number: MINE }, { expiresIn: "-5m" }),
      },
    });
    expect(await expired.json()).toMatchObject({ reason_codes: ["SUBJECT_TOKEN_INVALID"] });
    expect(upstream.seen.length).toBe(before);
    await teardown();
  });

  it("takes the identity provider's token per request too, and ends a session when it expires", async () => {
    await build(fileWith());
    upstream.answers.set(`${BASE}/salesOrders`, {
      status: 200,
      body: { value: [{ number: "S-ORD-1", customerNumber: MINE }] },
    });
    const direct = await fetch(`${origin}${BASE}/salesOrders`, {
      headers: { "agentsafe-subject-token": await token() },
    });
    expect(direct.status).toBe(200);
    expect(upstream.seen.at(-1)?.headers["agentsafe-subject-token"]).toBeUndefined();
    const sessionToken = await session();
    now += 11 * 60 * 1_000;
    const late = await fetch(`${origin}${BASE}/salesOrders`, {
      headers: { "agentsafe-session": sessionToken },
    });
    expect(late.status).toBe(401);
    expect(await late.json()).toMatchObject({ reason_codes: ["SUBJECT_SESSION_INVALID"] });
    now = Date.now();
    await teardown();
  });

  it("passes an unknown read, or refuses it when unknown reads are refused", async () => {
    await build(fileWith());
    const passed = await fetch(`${origin}${BASE}/items`);
    expect(passed.status).toBe(201);
    const ambiguous = await fetch(`${origin}${BASE}/Customers`, {
      headers: { "agentsafe-session": await session() },
    });
    expect(ambiguous.status).toBe(400);
    expect(await ambiguous.json()).toEqual({ code: "HTTP_PATH_AMBIGUOUS" });
    await teardown();
    await build(fileWith({ refuseUnknownReads: true }));
    const refused = await fetch(`${origin}${BASE}/items`);
    expect(refused.status).toBe(403);
    expect(await refused.json()).toEqual({ code: "READ_OPERATION_UNMATCHED" });
    await teardown();
  });

  async function grantContext(file: Record<string, unknown>, headers: Record<string, string>) {
    await build(file);
    upstream.answers.clear();
    const before = authority.requests.length;
    const answer = await fetch(`${origin}${BASE}/salesOrders`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify({ customerNumber: OTHER, currencyCode: "EUR" }),
    });
    await teardown();
    const sent = authority.requests
      .slice(before)
      .find((seen) => seen.path === "/v1/authority/grants");
    return { status: answer.status, context: (sent?.body as { context: JsonObject }).context };
  }

  it("states the pinned subject to the authority for a write, as session.subject", async () => {
    const withSession = await grantContext(fileWith(), {
      "agentsafe-subject-token": await token(),
    });
    expect(withSession.status).toBe(201);
    expect(withSession.context).toMatchObject({
      customer_number: OTHER,
      session: { subject: MINE },
      api_profile: { id: "businesscentral/api/v2", operation: "salesOrders.create" },
    });
    const factsOnly = await grantContext(fileWith({ privacy: "facts" }), {
      "agentsafe-subject-token": await token(),
    });
    expect(factsOnly.context).toMatchObject({ customer_number: OTHER, session: { subject: MINE } });
    const without = await grantContext(fileWith(), {});
    expect(Object.hasOwn(without.context, "session")).toBe(false);
  });

  it("refuses a write whose session does not stand, before the authority is asked", async () => {
    await build(fileWith());
    const before = authority.requests.length;
    const answer = await fetch(`${origin}${BASE}/salesOrders`, {
      method: "POST",
      headers: { "content-type": "application/json", "agentsafe-session": "forged" },
      body: JSON.stringify({ customerNumber: MINE }),
    });
    await teardown();
    expect(answer.status).toBe(401);
    expect(answer.headers.get("www-authenticate")).toBe("AgentSafe-Session");
    expect(await answer.json()).toMatchObject({
      state: "REFUSED",
      reason_codes: ["SUBJECT_SESSION_INVALID"],
      execution: "NOT_FORWARDED",
    });
    expect(authority.requests.length).toBe(before);
  });
});
