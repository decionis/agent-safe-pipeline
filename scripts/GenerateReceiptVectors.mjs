/**
 * Generates the effect-receipt vectors (Verifying Provider Profile, VP-3) in
 * conformance/provider/receipts: one JSON file per case. A receipt is built
 * by the provider from the attestation it verified, and signed with the
 * provider's own key, so a vector pins what every implementation must agree
 * on before signing: the protected header, the claims, and the exact
 * `header.payload` bytes, both segments RFC 8785 canonical. The signature is
 * the provider's; an implementation checks its own with its own key. The
 * token written here is signed with a key made for this run, and only the
 * public half is written: a vector holds nothing that was ever a credential.
 *
 *   node scripts/GenerateReceiptVectors.mjs
 */
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  effectReceiptClaims,
  effectReceiptSigningInput,
  EFFECT_RECEIPT_TYPE,
  signEffectReceipt,
} from "../packages/agentsafe/dist/Index.js";

const PROFILE = "agent-safe.verifying-provider/1";
const VERSION = "0.1";
const ISSUER = "https://authority.example";
/** The instant the receipts are issued at: 2026-09-19T12:00:02Z, two seconds after the dispatch. */
const NOW = 1_789_819_202;
const out = join(fileURLToPath(new URL("../conformance/provider/receipts/", import.meta.url)));

const digest = (text) => `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
const iso = (seconds) => new Date(seconds * 1_000).toISOString();

const provider = generateKeyPairSync("ed25519");
const PROVIDER_KEY_ID = "vector-provider-receipts-1";
const PROVIDER_ISSUER = "https://provider.example";
const providerJwk = {
  ...provider.publicKey.export({ format: "jwk" }),
  kid: PROVIDER_KEY_ID,
  alg: "EdDSA",
  use: "sig",
};

// The attestation the provider verified before effecting: the same claim the
// request vectors carry, so a receipt here answers the dispatch there.
const attestation = {
  iss: ISSUER,
  sub: "11111111-1111-4111-8111-000000000001",
  decision_id: "vector-decision-0001",
  dossier_id: "22222222-2222-4222-8222-000000000001",
  binding: {
    intent_hash: digest("verifying provider vector intent 1"),
    execution_payload_digest: digest("verifying provider vector payload 1"),
    execution_payload_canonicalization_profile: "RFC8785/JCS",
  },
  claim_token_digest: digest("verifying provider vector claim token 1"),
  jti: "33333333-3333-4333-8333-000000000001",
  exp: 1_789_819_225,
};
const IDEMPOTENCY_KEY = "vpp-wire-0001";
const EFFECT_DIGEST = digest("verifying provider vector expected effect 1");

const vectors = [];
function vector(name, description, { idempotencyKey, effect, jti }) {
  const input = {
    key: provider.privateKey,
    kid: PROVIDER_KEY_ID,
    issuer: PROVIDER_ISSUER,
    audience: ISSUER,
    attestation,
    ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
    effect,
    issuedAt: NOW,
    jti,
  };
  vectors.push({
    profile: PROFILE,
    version: VERSION,
    vector: name,
    level: "VP-3",
    description,
    input: {
      kid: PROVIDER_KEY_ID,
      issuer: PROVIDER_ISSUER,
      audience: ISSUER,
      attestation,
      ...(idempotencyKey === undefined ? {} : { idempotency_key: idempotencyKey }),
      effect,
      iat: NOW,
      jti,
    },
    expect: {
      protected_header: { alg: "EdDSA", kid: PROVIDER_KEY_ID, typ: EFFECT_RECEIPT_TYPE },
      claims: effectReceiptClaims(input),
      signing_input: effectReceiptSigningInput(input),
      provider_jwk: providerJwk,
      token: signEffectReceipt(input),
    },
  });
}

vector(
  "receipt-effected-with-digest",
  "The provider effected the claimed request and says so with everything a receipt can carry: its reference, the digest of the effect in the grant's terms, and the idempotency key it effected under.",
  {
    idempotencyKey: IDEMPOTENCY_KEY,
    effect: {
      status: "EFFECTED",
      reference: "ledger:entry:9081",
      digest: EFFECT_DIGEST,
      effected_at: iso(NOW - 1),
    },
    jti: "44444444-4444-4444-8444-000000000001",
  },
);
vector(
  "receipt-refused-reference-only",
  "The provider refused the claimed request for its own reasons and signs that too: a refusal has a reference and no effect digest.",
  {
    idempotencyKey: IDEMPOTENCY_KEY,
    effect: {
      status: "REFUSED",
      reference: "core:refused:limit-exceeded",
      effected_at: iso(NOW - 1),
    },
    jti: "44444444-4444-4444-8444-000000000002",
  },
);
vector(
  "receipt-indeterminate-minimal",
  "The provider does not know what happened and says exactly that, with nothing optional: the smallest receipt the profile allows.",
  {
    effect: { status: "INDETERMINATE", effected_at: iso(NOW - 1) },
    jti: "44444444-4444-4444-8444-000000000003",
  },
);
vector(
  "receipt-reference-unicode",
  "A reference outside ASCII is written as UTF-8 and left unescaped by RFC 8785, so the payload segment is the base64url of those bytes and nothing else.",
  {
    idempotencyKey: IDEMPOTENCY_KEY,
    effect: {
      status: "EFFECTED",
      reference: "ledger:entry:Übertrag ✓ €250",
      digest: EFFECT_DIGEST,
      effected_at: iso(NOW - 1),
    },
    jti: "44444444-4444-4444-8444-000000000004",
  },
);

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const entry of vectors) {
  writeFileSync(join(out, `${entry.vector}.json`), `${JSON.stringify(entry, null, 2)}\n`);
}
console.log(`${String(readdirSync(out).length)} receipt vectors written to ${out}`);
