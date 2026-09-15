import { SignJWT, exportJWK, generateKeyPair, type JSONWebKeySet } from "jose";

type KeyLike = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  JwtError,
  WorkloadJwtVerifier,
  type JwtCode,
} from "../../src/identity/WorkloadJwtVerifier.js";
import { collectedEvents } from "../support/Environment.js";

const ISSUER = "https://issuer.synthetic.example";
const SUBJECT = "system:serviceaccount:agents:batch-runner";

interface Signer {
  readonly alg: "ES256" | "RS256" | "EdDSA";
  readonly kid: string;
  readonly privateKey: KeyLike;
  readonly jwk: Record<string, unknown>;
}

async function signer(alg: Signer["alg"], kid: string): Promise<Signer> {
  const keys = await generateKeyPair(alg);
  const jwk = { ...(await exportJWK(keys.publicKey)), kid, alg };
  return { alg, kid, privateKey: keys.privateKey, jwk };
}

async function token(
  by: Signer,
  claims: {
    readonly aud?: string | string[];
    readonly iss?: string;
    readonly sub?: string;
    readonly iat?: number;
    readonly exp?: number;
    readonly extra?: Record<string, unknown>;
  } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1_000);
  const jwt = new SignJWT({ ...(claims.extra ?? {}) })
    .setProtectedHeader({ alg: by.alg, kid: by.kid })
    .setIssuedAt(claims.iat ?? now)
    .setExpirationTime(claims.exp ?? now + 600);
  if (claims.iss !== undefined) jwt.setIssuer(claims.iss);
  if (claims.sub !== undefined) jwt.setSubject(claims.sub);
  if (claims.aud !== undefined) jwt.setAudience(claims.aud);
  return await jwt.sign(by.privateKey);
}

async function code(work: Promise<unknown>): Promise<JwtCode | "OK"> {
  try {
    await work;
    return "OK";
  } catch (error) {
    if (error instanceof JwtError) return error.code;
    throw error;
  }
}

let es: Signer;
let rs: Signer;
let ed: Signer;
let keys: JSONWebKeySet;

beforeAll(async () => {
  [es, rs, ed] = await Promise.all([
    signer("ES256", "es-1"),
    signer("RS256", "rs-1"),
    signer("EdDSA", "ed-1"),
  ]);
  keys = { keys: [es.jwk, rs.jwk, ed.jwk] } as JSONWebKeySet;
});

const verifier = (
  extra: Partial<ConstructorParameters<typeof WorkloadJwtVerifier>[0]> = {},
): WorkloadJwtVerifier =>
  new WorkloadJwtVerifier({ audiences: ["agentsafe"], keys, clockToleranceSeconds: 5, ...extra });

describe("WorkloadJwtVerifier", () => {
  it("verifies a token from each allowed algorithm and returns its issuer, subject, and audiences", async () => {
    for (const by of [es, rs, ed]) {
      const verified = await verifier().verify(
        await token(by, {
          iss: ISSUER,
          sub: SUBJECT,
          aud: "agentsafe",
          extra: { "kubernetes.io/namespace": "agents" },
        }),
      );
      expect(verified).toMatchObject({
        issuer: ISSUER,
        subject: SUBJECT,
        audiences: ["agentsafe"],
      });
      expect(verified.claims["kubernetes.io/namespace"]).toBe("agents");
    }
    const many = await verifier({ audiences: ["agentsafe", "batch"] }).verify(
      await token(es, { iss: ISSUER, sub: SUBJECT, aud: ["other", "batch"] }),
    );
    expect(many.audiences).toEqual(["other", "batch"]);
  });

  it("refuses each way a token can be wrong with its own code, all before the registry is asked", async () => {
    const v = verifier();
    const good = { iss: ISSUER, sub: SUBJECT, aud: "agentsafe" };
    const now = Math.floor(Date.now() / 1_000);
    expect(await code(v.verify(await token(es, { ...good, aud: "elsewhere" })))).toBe(
      "JWT_AUDIENCE_MISMATCH",
    );
    expect(await code(v.verify(await token(es, { ...good, iat: now - 700, exp: now - 100 })))).toBe(
      "JWT_EXPIRED",
    );
    expect(
      await code(v.verify(await token(es, { ...good, iat: now - 100_000, exp: now + 600 }))),
    ).toBe("JWT_EXPIRED");
    expect(await code(v.verify(await token(es, { iss: ISSUER, aud: "agentsafe" })))).toBe(
      "JWT_CLAIM_MISMATCH",
    );
    expect(await code(v.verify(await token(es, { sub: SUBJECT, aud: "agentsafe" })))).toBe(
      "JWT_CLAIM_MISMATCH",
    );
    const forged = await signer("ES256", "es-1");
    expect(await code(v.verify(await token(forged, good)))).toBe("JWT_SIGNATURE_INVALID");
    const unknownKid = await signer("ES256", "es-9");
    expect(await code(v.verify(await token(unknownKid, good)))).toBe("JWT_SIGNATURE_INVALID");
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const body = Buffer.from(JSON.stringify({ ...good, exp: now + 600, iat: now })).toString(
      "base64url",
    );
    expect(await code(v.verify(`${header}.${body}.`))).toBe("JWT_ALGORITHM_REFUSED");
    const hs = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256", kid: "es-1" })
      .setIssuer(ISSUER)
      .setSubject(SUBJECT)
      .setAudience("agentsafe")
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(new TextEncoder().encode("x".repeat(40)));
    expect(await code(v.verify(hs))).toBe("JWT_ALGORITHM_REFUSED");
    expect(await code(v.verify("not.a.token"))).toBe("JWT_SIGNATURE_INVALID");
    expect(await code(v.verify(""))).toBe("JWT_SIGNATURE_INVALID");
    const tolerant = verifier({ clockToleranceSeconds: 120 });
    expect(
      await code(tolerant.verify(await token(es, { ...good, iat: now - 700, exp: now - 100 }))),
    ).toBe("OK");
  });

  it("reads a JWKS document and refuses what is not one", () => {
    expect(WorkloadJwtVerifier.parseJwks(JSON.stringify(keys)).keys).toHaveLength(3);
    for (const bad of [
      "not json",
      "{}",
      '{"keys":[]}',
      '{"keys":"x"}',
      '{"keys":[{"alg":"ES256"}]}',
      "[]",
      "null",
    ]) {
      expect(() => WorkloadJwtVerifier.parseJwks(bad)).toThrow(new JwtError("JWKS_UNAVAILABLE"));
    }
  });

  it("refreshes from the URL through the fetch it is given, keeps the last good set on any failure, and stops", async () => {
    vi.useFakeTimers();
    try {
      const lines: string[] = [];
      const rotated = await signer("ES256", "es-2");
      const answers: (() => Response)[] = [];
      const fetchImpl = vi.fn(async (input: string | URL | Request) => {
        expect(String(input)).toBe("https://issuer.synthetic.example/openid/v1/jwks");
        const next = answers.shift();
        if (next === undefined) throw new Error("unreachable");
        return next();
      }) as unknown as typeof fetch;
      const v = verifier({
        refresh: {
          url: "https://issuer.synthetic.example/openid/v1/jwks",
          fetch: fetchImpl,
          intervalSeconds: 60,
          events: collectedEvents(lines),
        },
      });
      const fresh = await token(rotated, { iss: ISSUER, sub: SUBJECT, aud: "agentsafe" });
      expect(await code(v.verify(fresh))).toBe("JWT_SIGNATURE_INVALID");
      answers.push(() => new Response("oops", { status: 503 }));
      expect(await v.refreshNow()).toBe(false);
      answers.push(() => new Response("not json", { status: 200 }));
      expect(await v.refreshNow()).toBe(false);
      expect(await v.refreshNow()).toBe(false);
      expect(
        await code(v.verify(await token(es, { iss: ISSUER, sub: SUBJECT, aud: "agentsafe" }))),
      ).toBe("OK");
      answers.push(() => new Response(JSON.stringify({ keys: [rotated.jwk] }), { status: 200 }));
      v.start();
      v.start();
      await vi.advanceTimersByTimeAsync(60_000);
      expect(fetchImpl).toHaveBeenCalledTimes(4);
      expect(await code(v.verify(fresh))).toBe("OK");
      expect(
        await code(v.verify(await token(es, { iss: ISSUER, sub: SUBJECT, aud: "agentsafe" }))),
      ).toBe("JWT_SIGNATURE_INVALID");
      v.stop();
      v.stop();
      await vi.advanceTimersByTimeAsync(120_000);
      expect(fetchImpl).toHaveBeenCalledTimes(4);
      expect(
        lines.map((line) => JSON.parse(line) as { event: string; code?: string; keys?: number }),
      ).toEqual([
        expect.objectContaining({ event: "JWKS_REFRESH_FAILED", code: "JWKS_HTTP_503" }),
        expect.objectContaining({ event: "JWKS_REFRESH_FAILED", code: "JWKS_INVALID" }),
        expect.objectContaining({ event: "JWKS_REFRESH_FAILED", code: "JWKS_UNREACHABLE" }),
        expect.objectContaining({ event: "JWKS_REFRESHED", keys: 1 }),
      ]);
      expect(await verifier().refreshNow()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});
