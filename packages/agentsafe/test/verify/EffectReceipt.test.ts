/**
 * The receipt a verifying provider signs (VP-3): built from the attestation
 * it verified, canonical before signing so every implementation signs the
 * same bytes, and read back by an authority the way Decionis reads one.
 */
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  EFFECT_RECEIPT_HEADER,
  EFFECT_RECEIPT_TYPE,
  EffectReceiptError,
  effectReceiptClaims,
  effectReceiptSigningInput,
  signEffectReceipt,
  type EffectReceiptInput,
} from "../../src/verify/EffectReceipt.js";

function receiptsDirectory(): string {
  let directory = dirname(new URL(import.meta.url).pathname);
  for (;;) {
    const candidate = join(directory, "conformance", "provider", "receipts");
    if (existsSync(candidate)) return candidate;
    const parent = dirname(directory);
    if (parent === directory) {
      throw new Error("conformance/provider/receipts not found above this test");
    }
    directory = parent;
  }
}
const RECEIPTS = receiptsDirectory();

interface ReceiptVector {
  readonly vector: string;
  readonly level: string;
  readonly input: {
    readonly kid: string;
    readonly issuer: string;
    readonly audience: string;
    readonly attestation: EffectReceiptInput["attestation"];
    readonly idempotency_key?: string;
    readonly effect: EffectReceiptInput["effect"];
    readonly iat: number;
    readonly jti: string;
  };
  readonly expect: {
    readonly protected_header: Record<string, unknown>;
    readonly claims: Record<string, unknown>;
    readonly signing_input: string;
    readonly provider_jwk: Record<string, unknown>;
    readonly token: string;
  };
}

const provider = generateKeyPairSync("ed25519");
const decode = (segment: string): unknown =>
  JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));

function inputOf(vector: ReceiptVector): EffectReceiptInput {
  const { input } = vector;
  return {
    key: provider.privateKey,
    kid: input.kid,
    issuer: input.issuer,
    audience: input.audience,
    attestation: input.attestation,
    ...(input.idempotency_key === undefined ? {} : { idempotencyKey: input.idempotency_key }),
    effect: input.effect,
    issuedAt: input.iat,
    jti: input.jti,
  };
}

describe("the effect receipt vectors", () => {
  const files = readdirSync(RECEIPTS).filter((name) => name.endsWith(".json"));
  it("exist, and every one is VP-3", () => {
    expect(files.length).toBeGreaterThanOrEqual(4);
  });
  for (const file of files) {
    const vector = JSON.parse(readFileSync(join(RECEIPTS, file), "utf8")) as ReceiptVector;
    it(`${vector.vector}: signs exactly the bytes the vector names`, () => {
      expect(vector.level).toBe("VP-3");
      const input = inputOf(vector);
      expect(effectReceiptClaims(input)).toEqual(vector.expect.claims);
      // The canonical header and payload are what every implementation agrees on.
      expect(effectReceiptSigningInput(input)).toBe(vector.expect.signing_input);
      const token = signEffectReceipt(input);
      const [header, payload, signature] = token.split(".") as [string, string, string];
      expect(`${header}.${payload}`).toBe(vector.expect.signing_input);
      expect(decode(header)).toEqual(vector.expect.protected_header);
      expect(decode(payload)).toEqual(vector.expect.claims);
      // The signature is this provider's, under this provider's key.
      expect(
        verify(
          null,
          Buffer.from(`${header}.${payload}`, "ascii"),
          provider.publicKey,
          Buffer.from(signature, "base64url"),
        ),
      ).toBe(true);
      // And the vector's own token verifies under the public half it carries.
      const [vh, vp, vs] = vector.expect.token.split(".") as [string, string, string];
      expect(`${vh}.${vp}`).toBe(vector.expect.signing_input);
      expect(
        verify(
          null,
          Buffer.from(`${vh}.${vp}`, "ascii"),
          createPublicKey({ key: vector.expect.provider_jwk as never, format: "jwk" }),
          Buffer.from(vs, "base64url"),
        ),
      ).toBe(true);
    });
  }
});

describe("signEffectReceipt", () => {
  const attestation = {
    sub: "grant-1",
    decision_id: "decision-1",
    dossier_id: "dossier-1",
    claim_token_digest: `sha256:${"c".repeat(64)}`,
    jti: "attestation-1",
    binding: { intent_hash: `sha256:${"a".repeat(64)}` },
  };
  const input: EffectReceiptInput = {
    key: provider.privateKey,
    kid: "provider-1",
    issuer: "https://provider.example",
    audience: "https://authority.example",
    attestation,
    effect: { status: "EFFECTED", effected_at: "2026-09-19T12:00:01Z" },
    issuedAt: 1_789_819_202,
    jti: "receipt-1",
  };

  it("carries only what it was given, in canonical order, and names the header it travels in", () => {
    expect(EFFECT_RECEIPT_HEADER).toBe("x-agent-safe-effect-receipt");
    const claims = effectReceiptClaims(input);
    expect(Object.keys(claims)).not.toContain("idempotency_key");
    expect(Object.keys(claims.effect as object)).toEqual(["status", "effected_at"]);
    const signingInput = effectReceiptSigningInput(input);
    const [header, payload] = signingInput.split(".") as [string, string];
    expect(Buffer.from(header, "base64url").toString("utf8")).toBe(
      `{"alg":"EdDSA","kid":"provider-1","typ":"${EFFECT_RECEIPT_TYPE}"}`,
    );
    expect(Buffer.from(payload, "base64url").toString("utf8")).toBe(
      '{"attestation_jti":"attestation-1","aud":"https://authority.example",' +
        `"claim_token_digest":"sha256:${"c".repeat(64)}","decision_id":"decision-1",` +
        '"dossier_id":"dossier-1","effect":{"effected_at":"2026-09-19T12:00:01Z","status":"EFFECTED"},' +
        `"iat":1789819202,"intent_hash":"sha256:${"a".repeat(64)}","iss":"https://provider.example",` +
        '"jti":"receipt-1","sub":"grant-1"}',
    );
  });

  it("takes the key as a PEM too, and refuses a key that is not Ed25519", () => {
    const pem = provider.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    expect(signEffectReceipt({ ...input, key: pem })).toBe(signEffectReceipt(input));
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(() => signEffectReceipt({ ...input, key: rsa.privateKey })).toThrow(
      new EffectReceiptError("KEY_NOT_ED25519"),
    );
  });

  it("refuses to build a receipt it could not stand behind", () => {
    const cases: Array<[Partial<EffectReceiptInput>, string]> = [
      [
        { effect: { status: "DONE" as never, effected_at: "2026-09-19T12:00:01Z" } },
        "EFFECT_STATUS_UNKNOWN",
      ],
      [
        {
          effect: { status: "EFFECTED", digest: "sha256:zz", effected_at: "2026-09-19T12:00:01Z" },
        },
        "EFFECT_DIGEST_MALFORMED",
      ],
      [
        {
          effect: {
            status: "EFFECTED",
            digest: `xsha256:${"a".repeat(64)}`,
            effected_at: "2026-09-19T12:00:01Z",
          },
        },
        "EFFECT_DIGEST_MALFORMED",
      ],
      [
        {
          effect: {
            status: "EFFECTED",
            digest: `sha256:${"a".repeat(64)}x`,
            effected_at: "2026-09-19T12:00:01Z",
          },
        },
        "EFFECT_DIGEST_MALFORMED",
      ],
      [{ effect: { status: "EFFECTED", effected_at: "yesterday" } }, "EFFECTED_AT_MALFORMED"],
      [{ issuedAt: 1.5 }, "ISSUED_AT_MALFORMED"],
      [{ issuedAt: -1 }, "ISSUED_AT_MALFORMED"],
      [{ kid: "" }, "KID_EMPTY"],
      [{ issuer: "" }, "ISSUER_EMPTY"],
      [{ audience: "" }, "AUDIENCE_EMPTY"],
      [{ jti: "" }, "JTI_EMPTY"],
    ];
    for (const [overrides, code] of cases) {
      let thrown: unknown;
      try {
        signEffectReceipt({ ...input, ...overrides });
      } catch (error) {
        thrown = error;
      }
      expect(thrown, code).toBeInstanceOf(EffectReceiptError);
      expect((thrown as EffectReceiptError).code, code).toBe(code);
      expect((thrown as EffectReceiptError).name).toBe("EffectReceiptError");
    }
    // Epoch zero is an instant like any other.
    expect(effectReceiptClaims({ ...input, issuedAt: 0 })).toMatchObject({ iat: 0 });
  });
});
