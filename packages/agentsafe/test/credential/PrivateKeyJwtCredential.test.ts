import { generateKeyPairSync } from "node:crypto";
import { importSPKI, jwtVerify } from "jose";
import { describe, expect, it, vi } from "vitest";
import { CredentialError } from "../../src/credential/CredentialError.js";
import {
  CLIENT_ASSERTION_TYPE,
  PrivateKeyJwtCredential,
} from "../../src/credential/PrivateKeyJwtCredential.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";

const TOKEN_URL = "https://payouts.provider.example/oauth/token";

function material(type: "ec" | "rsa"): { readonly pem: string; readonly publicPem: string } {
  const keys =
    type === "ec"
      ? generateKeyPairSync("ec", { namedCurve: "P-256" })
      : generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    pem: keys.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicPem: keys.publicKey.export({ type: "spki", format: "pem" }) as string,
  };
}

interface Endpoint {
  readonly fetch: typeof fetch;
  readonly calls: {
    readonly url: string;
    readonly form: URLSearchParams;
    readonly headers: Headers;
  }[];
  answer(next: () => Response | Promise<Response>): void;
}

function endpoint(): Endpoint {
  const calls: Endpoint["calls"] = [];
  let next: () => Response | Promise<Response> = () =>
    new Response(
      JSON.stringify({
        access_token: "synthetic-access-token-1",
        token_type: "Bearer",
        expires_in: 120,
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: String(input),
      form: new URLSearchParams(String(init?.body ?? "")),
      headers: new Headers(init?.headers),
    });
    return await next();
  }) as unknown as typeof fetch;
  return {
    fetch: fetchImpl,
    calls,
    answer: (answer) => {
      next = answer;
    },
  };
}

async function refusal(work: Promise<unknown>): Promise<string> {
  try {
    await work;
    return "";
  } catch (error) {
    if (error instanceof CredentialError) return error.code;
    throw error;
  }
}

describe("PrivateKeyJwtCredential", () => {
  it("proves the client with a signed assertion, holds the token until shortly before it expires, and refreshes once at a time", async () => {
    const { pem, publicPem } = material("ec");
    const token = endpoint();
    let now = 1_726_000_000_000;
    const credential = new PrivateKeyJwtCredential(
      {
        tokenUrl: TOKEN_URL,
        clientId: "synthetic-client",
        keyId: "synthetic-kid",
        algorithm: "ES256",
        audience: null,
        scope: "payouts:write",
        timeoutMs: 2_000,
      },
      () => SecretHandle.fromString("DOWNSTREAM_PRIVATE_KEY", pem),
      token.fetch,
      () => now,
    );
    expect(credential.kind).toBe("PRIVATE_KEY_JWT");
    expect(credential.fresh).toBe(false);
    const [first, second] = await Promise.all([
      credential.headersFor({
        method: "POST",
        url: "https://payouts.provider.example/v1/payouts",
        body: "{}",
        idempotencyKey: "k",
        intentHash: "h",
      }),
      credential.headersFor({
        method: "POST",
        url: "https://payouts.provider.example/v1/payouts",
        body: "{}",
        idempotencyKey: "k",
        intentHash: "h",
      }),
    ]);
    expect(first).toEqual({ authorization: "Bearer synthetic-access-token-1" });
    expect(second).toEqual(first);
    expect(token.calls).toHaveLength(1);
    expect(credential.fresh).toBe(true);
    const call = token.calls[0];
    expect(call?.url).toBe(TOKEN_URL);
    expect(call?.headers.get("content-type")).toBe("application/x-www-form-urlencoded");
    expect(call?.form.get("grant_type")).toBe("client_credentials");
    expect(call?.form.get("client_id")).toBe("synthetic-client");
    expect(call?.form.get("client_assertion_type")).toBe(CLIENT_ASSERTION_TYPE);
    expect(call?.form.get("scope")).toBe("payouts:write");
    const assertion = call?.form.get("client_assertion") ?? "";
    const verified = await jwtVerify(assertion, await importSPKI(publicPem, "ES256"), {
      audience: TOKEN_URL,
      issuer: "synthetic-client",
      subject: "synthetic-client",
      currentDate: new Date(now),
    });
    expect(verified.protectedHeader).toEqual({ alg: "ES256", kid: "synthetic-kid" });
    expect(verified.payload.jti).toMatch(/^[0-9a-f-]{36}$/);
    expect((verified.payload.exp ?? 0) - (verified.payload.iat ?? 0)).toBe(60);
    now += 89_000;
    await credential.headersFor({
      method: "GET",
      url: "https://payouts.provider.example/v1/payouts/k",
      body: null,
      idempotencyKey: "k",
      intentHash: "h",
    });
    expect(token.calls).toHaveLength(1);
    now += 2_000;
    token.answer(
      () =>
        new Response(
          JSON.stringify({
            access_token: "synthetic-access-token-2",
            token_type: "bearer",
            expires_in: "300",
            refresh_token: "ignored",
          }),
          { status: 200 },
        ),
    );
    const refreshed = await credential.headersFor({
      method: "GET",
      url: "https://payouts.provider.example/v1/payouts/k",
      body: null,
      idempotencyKey: "k",
      intentHash: "h",
    });
    expect(refreshed).toEqual({ authorization: "Bearer synthetic-access-token-2" });
    expect(token.calls).toHaveLength(2);
    credential.close();
    expect(credential.fresh).toBe(false);
  });

  it("signs with PS256 and an RSA key, without a key id or scope, for the audience it is given", async () => {
    const { pem, publicPem } = material("rsa");
    const token = endpoint();
    const credential = new PrivateKeyJwtCredential(
      {
        tokenUrl: TOKEN_URL,
        clientId: "synthetic-client",
        keyId: null,
        algorithm: "PS256",
        audience: "https://payouts.provider.example/",
        scope: null,
        timeoutMs: 2_000,
      },
      () => SecretHandle.fromString("DOWNSTREAM_PRIVATE_KEY", pem),
      token.fetch,
    );
    await credential.headersFor({
      method: "POST",
      url: "x",
      body: null,
      idempotencyKey: "k",
      intentHash: "h",
    });
    const call = token.calls[0];
    expect(call?.form.has("scope")).toBe(false);
    const verified = await jwtVerify(
      call?.form.get("client_assertion") ?? "",
      await importSPKI(publicPem, "PS256"),
      { audience: "https://payouts.provider.example/" },
    );
    expect(verified.protectedHeader).toEqual({ alg: "PS256" });
    credential.close();
  });

  it("fails before dispatch when the endpoint is unreachable, refuses, or answers with something that is not a token", async () => {
    const { pem } = material("ec");
    const build = (token: Endpoint): PrivateKeyJwtCredential =>
      new PrivateKeyJwtCredential(
        {
          tokenUrl: TOKEN_URL,
          clientId: "synthetic-client",
          keyId: null,
          algorithm: "ES256",
          audience: null,
          scope: null,
          timeoutMs: 2_000,
        },
        () => SecretHandle.fromString("DOWNSTREAM_PRIVATE_KEY", pem),
        token.fetch,
      );
    const request = {
      method: "POST" as const,
      url: "x",
      body: null,
      idempotencyKey: "k",
      intentHash: "h",
    };
    const down = endpoint();
    down.answer(() => {
      throw new Error("ECONNREFUSED");
    });
    expect(await refusal(build(down).headersFor(request))).toBe("DOWNSTREAM_TOKEN_UNREACHABLE");
    const refusing = endpoint();
    refusing.answer(() => new Response('{"error":"invalid_client"}', { status: 401 }));
    expect(await refusal(build(refusing).headersFor(request))).toBe("DOWNSTREAM_TOKEN_REFUSED");
    for (const body of [
      "not json",
      "{}",
      '{"access_token":"","token_type":"Bearer","expires_in":60}',
      '{"access_token":"t","token_type":"mac","expires_in":60}',
      '{"access_token":"t","token_type":"Bearer","expires_in":0}',
    ]) {
      const odd = endpoint();
      odd.answer(() => new Response(body, { status: 200 }));
      expect(await refusal(build(odd).headersFor(request))).toBe("DOWNSTREAM_TOKEN_INVALID");
    }
    const flaky = endpoint();
    let attempts = 0;
    flaky.answer(() => {
      attempts += 1;
      if (attempts === 1) throw new Error("first");
      return new Response(
        JSON.stringify({
          access_token: "synthetic-access-token-3",
          token_type: "Bearer",
          expires_in: 60,
        }),
        { status: 200 },
      );
    });
    const credential = build(flaky);
    expect(await refusal(credential.headersFor(request))).toBe("DOWNSTREAM_TOKEN_UNREACHABLE");
    expect(await credential.headersFor(request)).toEqual({
      authorization: "Bearer synthetic-access-token-3",
    });
    expect(vi.isMockFunction(flaky.fetch)).toBe(false);
  });
});
