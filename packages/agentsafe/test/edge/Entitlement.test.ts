import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CompactSign } from "jose";
import { describe, expect, it } from "vitest";
import {
  ENTITLEMENT_JWKS_PATH,
  ENTITLEMENT_PATH,
  entitlementTokenOf,
  FileEntitlementSource,
  UrlEntitlementSource,
  verifyEntitlement,
} from "../../src/edge/Entitlement.js";
import { ENTITLEMENT_TYPE } from "../../src/edge/EntitlementEvaluation.js";

const KID = "synthetic-entitlement-key-1";
const ORIGIN = "https://api.decionis.example";
const signer = generateKeyPairSync("ed25519");

function jwks(publicKey: KeyObject = signer.publicKey, kid = KID): string {
  return JSON.stringify({ keys: [{ ...publicKey.export({ format: "jwk" }), kid, use: "sig" }] });
}

const CLAIMS = { aud: "org-synthetic", edge: true, plan: "enterprise" };

async function entitlement(
  header: Record<string, unknown> = {},
  payload: unknown = CLAIMS,
  key: KeyObject = signer.privateKey,
): Promise<string> {
  return await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: "EdDSA", typ: ENTITLEMENT_TYPE, kid: KID, ...header })
    .sign(key);
}

describe("verifyEntitlement", () => {
  it("reads the claims of an entitlement the JWKS signed", async () => {
    await expect(verifyEntitlement({ token: await entitlement(), jwks: jwks() })).resolves.toEqual({
      status: "read",
      claims: CLAIMS,
    });
  });

  it("says missing when there is nothing to read", async () => {
    await expect(verifyEntitlement({ token: null, jwks: jwks() })).resolves.toEqual({
      status: "missing",
    });
  });

  it("establishes no claims from a signature it cannot check", async () => {
    const other = generateKeyPairSync("ed25519");
    const unverified = { status: "read", claims: null };
    for (const material of [
      { token: await entitlement(), jwks: null },
      { token: await entitlement(), jwks: "{" },
      { token: await entitlement(), jwks: JSON.stringify({ keys: "none" }) },
      { token: await entitlement(), jwks: JSON.stringify({}) },
      { token: await entitlement(), jwks: jwks(signer.publicKey, "another-kid") },
      { token: await entitlement(), jwks: jwks(other.publicKey) },
      { token: await entitlement({ typ: "JWT" }), jwks: jwks() },
      { token: await entitlement({}, CLAIMS, other.privateKey), jwks: jwks() },
      { token: "not.a.jws", jwks: jwks() },
    ]) {
      await expect(verifyEntitlement(material)).resolves.toEqual(unverified);
    }
    const hmac = await new CompactSign(new TextEncoder().encode("{}"))
      .setProtectedHeader({ alg: "HS256", typ: ENTITLEMENT_TYPE, kid: KID })
      .sign(new Uint8Array(32));
    await expect(verifyEntitlement({ token: hmac, jwks: jwks() })).resolves.toEqual(unverified);
    const notJson = await new CompactSign(new TextEncoder().encode("{"))
      .setProtectedHeader({ alg: "EdDSA", typ: ENTITLEMENT_TYPE, kid: KID })
      .sign(signer.privateKey);
    await expect(verifyEntitlement({ token: notJson, jwks: jwks() })).resolves.toEqual(unverified);
  });
});

describe("entitlementTokenOf", () => {
  it("takes the JWS on its own or from the response that carries it", async () => {
    const token = await entitlement();
    expect(entitlementTokenOf(` ${token}\n`)).toBe(token);
    expect(entitlementTokenOf(JSON.stringify({ entitlement: token }))).toBe(token);
    expect(entitlementTokenOf(JSON.stringify({ signed_entitlement: token }))).toBe(token);
    expect(entitlementTokenOf("{not json")).toBeNull();
    expect(entitlementTokenOf(JSON.stringify({ entitlement: 7 }))).toBeNull();
    expect(entitlementTokenOf("two.parts")).toBeNull();
    expect(entitlementTokenOf("")).toBeNull();
  });
});

describe("UrlEntitlementSource", () => {
  it("fetches the entitlement with the key and the JWKS without it, on one origin", async () => {
    const token = await entitlement();
    const calls: { url: string; headers: Record<string, string> }[] = [];
    const source = new UrlEntitlementSource({
      baseUrl: "https://api.decionis.example/",
      apiKey: () => "synthetic-api-key",
      fetch: (async (url: string, init: RequestInit) => {
        calls.push({ url, headers: init.headers as Record<string, string> });
        return new Response(
          url.endsWith(ENTITLEMENT_PATH) ? JSON.stringify({ entitlement: token }) : jwks(),
        );
      }) as typeof fetch,
    });
    await expect(source.read()).resolves.toEqual({ token, jwks: jwks() });
    expect(calls).toEqual([
      {
        url: `${ORIGIN}${ENTITLEMENT_PATH}`,
        headers: { accept: "application/json", authorization: "Bearer synthetic-api-key" },
      },
      {
        url: `${ORIGIN}${ENTITLEMENT_JWKS_PATH}`,
        headers: { accept: "application/json" },
      },
    ]);
    expect(ENTITLEMENT_PATH).toBe("/v1/edge/entitlement");
    expect(ENTITLEMENT_JWKS_PATH).toBe("/.well-known/decionis-policy-bundle-jwks.json");
  });

  it("reads nothing from a refusal, a failure, a timeout or an oversized body", async () => {
    const answers: (() => Promise<Response>)[] = [
      async () => new Response("no", { status: 403 }),
      async () => {
        throw new Error("ECONNREFUSED");
      },
      async () => new Response("x".repeat(256 * 1024 + 1)),
    ];
    for (const answer of answers) {
      const source = new UrlEntitlementSource({
        baseUrl: "https://api.decionis.example",
        apiKey: () => "k",
        fetch: answer as unknown as typeof fetch,
      });
      await expect(source.read()).resolves.toEqual({ token: null, jwks: null });
    }
    const slow = new UrlEntitlementSource({
      baseUrl: "https://api.decionis.example",
      apiKey: () => "k",
      timeoutMs: 5,
      fetch: ((_url: string, init: RequestInit) =>
        new Promise((_, reject) => {
          init.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        })) as typeof fetch,
    });
    await expect(slow.read()).resolves.toEqual({ token: null, jwks: null });
  });
});

describe("FileEntitlementSource", () => {
  it("reads the placed entitlement and the pinned JWKS, and nothing that is not there", async () => {
    const directory = mkdtempSync(join(tmpdir(), "entitlement-"));
    const token = await entitlement();
    writeFileSync(join(directory, "entitlement.jws"), `${token}\n`);
    writeFileSync(join(directory, "jwks.json"), jwks());
    writeFileSync(join(directory, "huge.json"), "x".repeat(256 * 1024 + 1));
    await expect(
      new FileEntitlementSource(
        join(directory, "entitlement.jws"),
        join(directory, "jwks.json"),
      ).read(),
    ).resolves.toEqual({ token, jwks: jwks() });
    await expect(
      new FileEntitlementSource(
        join(directory, "missing.jws"),
        join(directory, "huge.json"),
      ).read(),
    ).resolves.toEqual({ token: null, jwks: null });
    await expect(new FileEntitlementSource(null, null).read()).resolves.toEqual({
      token: null,
      jwks: null,
    });
  });
});
