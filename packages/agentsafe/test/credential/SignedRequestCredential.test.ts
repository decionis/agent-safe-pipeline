import { generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  SIGNATURE_LABEL,
  SIGNED_COMPONENTS,
  SignedRequestCredential,
} from "../../src/credential/SignedRequestCredential.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";

const request = {
  method: "POST" as const,
  url: "https://payouts.provider.example/v1/payouts?trace=1",
  body: '{"amountMinor":2500}',
  idempotencyKey: "payout-7-v1",
  intentHash: `sha256:${"e".repeat(64)}`,
};
const material = { ...request, path: "/v1/payouts" };

describe("SignedRequestCredential", () => {
  it("signs the fixed components with Ed25519 so the downstream can verify them with the public key", async () => {
    const keys = generateKeyPairSync("ed25519");
    const pem = keys.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const publicKeyPem = keys.publicKey.export({ type: "spki", format: "pem" }) as string;
    const credential = new SignedRequestCredential(
      { algorithm: "ed25519", keyId: "synthetic-key-1" },
      () => SecretHandle.fromString("DOWNSTREAM_SIGNING_KEY", pem),
      () => 1_726_000_000_000,
    );
    expect(credential.kind).toBe("SIGNED_REQUEST");
    const headers = await credential.headersFor(request);
    expect(Object.keys(headers)).toEqual(["content-digest", "signature-input", "signature"]);
    expect(headers["content-digest"]).toBe(SignedRequestCredential.contentDigest(request.body));
    expect(headers["signature-input"]).toBe(
      `${SIGNATURE_LABEL}=("@method" "@path" "content-digest" "idempotency-key" "x-agent-safe-intent-hash");created=1726000000;keyid="synthetic-key-1";alg="ed25519"`,
    );
    expect(headers["signature"]).toMatch(/^agentsafe=:[A-Za-z0-9+/]+=*:$/);
    expect(SignedRequestCredential.verify(material, headers, { publicKeyPem })).toBe(true);
    expect(
      SignedRequestCredential.verify({ ...material, body: '{"amountMinor":2501}' }, headers, {
        publicKeyPem,
      }),
    ).toBe(false);
    expect(
      SignedRequestCredential.verify({ ...material, path: "/v1/refunds" }, headers, {
        publicKeyPem,
      }),
    ).toBe(false);
    expect(
      SignedRequestCredential.verify({ ...material, method: "GET" }, headers, { publicKeyPem }),
    ).toBe(false);
    expect(
      SignedRequestCredential.verify({ ...material, idempotencyKey: "payout-8-v1" }, headers, {
        publicKeyPem,
      }),
    ).toBe(false);
    expect(
      SignedRequestCredential.verify(
        { ...material, intentHash: `sha256:${"f".repeat(64)}` },
        headers,
        { publicKeyPem },
      ),
    ).toBe(false);
    const other = generateKeyPairSync("ed25519").publicKey.export({
      type: "spki",
      format: "pem",
    }) as string;
    expect(SignedRequestCredential.verify(material, headers, { publicKeyPem: other })).toBe(false);
    expect(SignedRequestCredential.verify(material, headers, { secret: Buffer.from("x") })).toBe(
      false,
    );
    expect(SIGNED_COMPONENTS).toHaveLength(5);
  });

  it("signs with HMAC-SHA256 over the same base when the downstream holds a shared secret", async () => {
    const secret = randomBytes(32);
    const credential = new SignedRequestCredential(
      { algorithm: "hmac-sha256", keyId: "synthetic-hmac-1" },
      () => SecretHandle.fromBuffer("DOWNSTREAM_SIGNING_KEY", Buffer.from(secret)),
    );
    const headers = await credential.headersFor({ ...request, method: "GET", body: null });
    expect(headers["content-digest"]).toBe(SignedRequestCredential.contentDigest(""));
    expect(headers["signature-input"]).toContain('alg="hmac-sha256"');
    const got = { ...material, method: "GET", body: null };
    expect(SignedRequestCredential.verify(got, headers, { secret })).toBe(true);
    expect(SignedRequestCredential.verify(got, headers, { secret: randomBytes(32) })).toBe(false);
    expect(SignedRequestCredential.verify(got, headers, { publicKeyPem: "" })).toBe(false);
    expect(
      SignedRequestCredential.verify(got, { ...headers, signature: "other=:AA==:" }, { secret }),
    ).toBe(false);
    expect(
      SignedRequestCredential.verify(got, { ...headers, "signature-input": "x" }, { secret }),
    ).toBe(false);
    expect(
      SignedRequestCredential.verify(
        got,
        { ...headers, "content-digest": "sha-256=:AA==:" },
        { secret },
      ),
    ).toBe(false);
    expect(SignedRequestCredential.verify(got, {}, { secret })).toBe(false);
  });

  it("builds the base exactly as documented", () => {
    const parameters = SignedRequestCredential.parameters(1, "k", "ed25519");
    expect(SignedRequestCredential.base({ ...material, method: "post" }, parameters)).toBe(
      [
        '"@method": POST',
        '"@path": /v1/payouts',
        `"content-digest": ${SignedRequestCredential.contentDigest(material.body)}`,
        '"idempotency-key": payout-7-v1',
        `"x-agent-safe-intent-hash": sha256:${"e".repeat(64)}`,
        `"@signature-params": ${parameters}`,
      ].join("\n"),
    );
    expect(SignedRequestCredential.contentDigest(null)).toBe(
      SignedRequestCredential.contentDigest(""),
    );
    expect(SignedRequestCredential.contentDigest("")).toBe(
      "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
    );
  });
});
