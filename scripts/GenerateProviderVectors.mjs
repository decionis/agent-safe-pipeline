/**
 * Generates the Verifying Provider Profile vectors in conformance/provider/vectors:
 * one JSON file per case, each self-contained (the provider's settings, the
 * executor keys it knows, the authority JWKS, and a sequence of requests with
 * the outcome the procedure must reach). The requests are signed by the
 * executor's own credential, `SignedRequestCredential`, so a vector is what
 * `@decionis/agentsafe` actually sends; the attestations are signed here with
 * `node:crypto` alone, the way the authority signs one, so the two signers are
 * independent. Keys are fresh on every run and only the public halves are
 * written: a vector holds nothing that was ever a credential.
 *
 *   node scripts/GenerateProviderVectors.mjs
 */
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  jcsDigest,
  SecretHandle,
  SignedRequestCredential,
} from "../packages/agentsafe/dist/Index.js";

const PROFILE = "agent-safe.verifying-provider/1";
const VERSION = "0.1";
// A synthetic issuer: the vectors prove the procedure, not that the authority
// signed them, and a provider configured for Decionis trusts https://decionis.com.
const ISSUER = "https://authority.example";
const JCS_PROFILE = "RFC8785/JCS";
const ATTESTATION_TYPE = "decionis-claim-attestation+jwt";
/** The instant every vector is verified at: 2026-09-19T12:00:00Z. */
const NOW = 1_789_819_200;
const WINDOW = 300;
const LEASE = 30;
const out = join(fileURLToPath(new URL("../conformance/provider/vectors/", import.meta.url)));

const digest = (text) => createHash("sha256").update(text, "utf8").digest("hex");
const b64url = (value) => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
const iso = (seconds) => new Date(seconds * 1_000).toISOString();

// One executor key of each kind the profile knows, and the authority's key.
const executor = generateKeyPairSync("ed25519");
const executorPem = executor.privateKey.export({ type: "pkcs8", format: "pem" });
const executorPublicPem = executor.publicKey.export({ type: "spki", format: "pem" });
const EXECUTOR_KEY_ID = "vector-executor-ed25519-1";
const HMAC_KEY_ID = "vector-executor-hmac-1";
const HMAC_MATERIAL = "verifying provider vector shared material one";
const authority = generateKeyPairSync("ed25519");
const AUTHORITY_KEY_ID = "vector-execution-grant-1";
const authorityJwk = {
  ...authority.publicKey.export({ format: "jwk" }),
  kid: AUTHORITY_KEY_ID,
  alg: "EdDSA",
  use: "sig",
};
const rogue = generateKeyPairSync("ed25519");

const executorKeys = [
  { keyid: EXECUTOR_KEY_ID, alg: "ed25519", public_pem: executorPublicPem },
  { keyid: HMAC_KEY_ID, alg: "hmac-sha256", shared_material_utf8: HMAC_MATERIAL },
];
const authorityJwks = { keys: [authorityJwk] };

// The one dispatch every vector varies: a wire the authority claimed a grant for.
const wire = {
  amountMinor: 250_000,
  currency: "USD",
  beneficiary: "synthetic-vendor-7781",
  reference: "vector-wire-1",
};
const BODY = JSON.stringify(wire);
const PATH = "/v1/wires";
const URL_ = `https://provider.invalid${PATH}`;
const IDEMPOTENCY_KEY = "vpp-wire-0001";
const INTENT_HASH = `sha256:${digest("verifying provider vector intent 1")}`;
const GRANT_ID = "11111111-1111-4111-8111-000000000001";
const DECISION_ID = "vector-decision-0001";
const DOSSIER_ID = "22222222-2222-4222-8222-000000000001";
const ORG_ID = "00000000-0000-4000-8000-000000000008";
const ATTESTATION_JTI = "33333333-3333-4333-8333-000000000001";

/** The claims the authority signs on a live claim, per `ClaimAttestationClaims`. */
function claimsFor(overrides = {}) {
  return {
    iss: ISSUER,
    sub: GRANT_ID,
    org_id: ORG_ID,
    dossier_id: DOSSIER_ID,
    decision_id: DECISION_ID,
    binding: {
      intent_hash: INTENT_HASH,
      execution_payload_digest: jcsDigest(wire),
      execution_payload_canonicalization_profile: JCS_PROFILE,
      execution_nonce: Buffer.from(digest("verifying provider vector nonce 1"), "hex").toString(
        "base64url",
      ),
      execution_correlation_id: "vector-correlation-1",
    },
    claim_token_digest: `sha256:${digest("verifying provider vector claim token 1")}`,
    claim_validated_at: iso(NOW - 5),
    jti: ATTESTATION_JTI,
    iat: NOW - 5,
    nbf: NOW - 5,
    exp: NOW - 5 + LEASE,
    ...overrides,
  };
}

/** A compact EdDSA JWS over the claims, as the authority signs one. */
function attest(claims = claimsFor(), { key = authority.privateKey, header = {} } = {}) {
  const protectedHeader = b64url({
    alg: "EdDSA",
    kid: AUTHORITY_KEY_ID,
    typ: ATTESTATION_TYPE,
    ...header,
  });
  const payload = b64url(claims);
  const signature = sign(null, Buffer.from(`${protectedHeader}.${payload}`, "ascii"), key);
  return `${protectedHeader}.${payload}.${signature.toString("base64url")}`;
}

/** The headers the executor sends for a request, signed with the key and clock given. */
async function signed({
  method = "POST",
  body = BODY,
  grant = { id: GRANT_ID, decisionId: DECISION_ID, claimAttestation: attest() },
  algorithm = "ed25519",
  keyId = EXECUTOR_KEY_ID,
  createdAt = NOW - 5,
  material = algorithm === "ed25519" ? executorPem : HMAC_MATERIAL,
} = {}) {
  const credential = new SignedRequestCredential(
    { algorithm, keyId },
    () => SecretHandle.fromString("DOWNSTREAM_SIGNING_KEY", material),
    () => createdAt * 1_000,
  );
  const headers = await credential.headersFor({
    method,
    url: URL_,
    body,
    idempotencyKey: IDEMPOTENCY_KEY,
    intentHash: INTENT_HASH,
    ...(grant === null ? {} : { grant }),
  });
  return { ...(body === null ? {} : { "content-type": "application/json" }), ...headers };
}

const accept = { outcome: "ACCEPT" };
const refuse = (code) => ({ outcome: "REFUSE", reason_code: code });
const request = (headers, expect, { method = "POST", path = PATH, body = BODY } = {}) => ({
  method,
  path,
  headers,
  body,
  expect,
});

const vectors = [];
function vector(name, level, description, requests, provider = {}) {
  vectors.push({
    profile: PROFILE,
    version: VERSION,
    vector: name,
    level,
    description,
    provider: {
      effects: true,
      clock_window_seconds: WINDOW,
      now: iso(NOW),
      authority_issuer: ISSUER,
      ...provider,
    },
    executor_keys: executorKeys,
    authority_jwks: authorityJwks,
    requests,
  });
}

const dispatch = await signed();
vector(
  "dispatch-attested-accepts",
  "VP-2",
  "A dispatch the executor signed over all eight components, carrying the authority's attestation of the claim, is accepted once.",
  [request(dispatch, accept)],
);
vector(
  "dispatch-replayed-within-lease",
  "VP-2",
  "The same accepted dispatch presented again inside the lease is refused: the grant was consumed once, and this is its second presentation.",
  [request(dispatch, accept), request(dispatch, refuse("GRANT_REPLAYED"))],
);
vector(
  "dispatch-hmac-attested-accepts",
  "VP-2",
  "The executor's signature may be an HMAC over the same base; the attestation is the authority's either way.",
  [request(await signed({ algorithm: "hmac-sha256", keyId: HMAC_KEY_ID }), accept)],
);
vector(
  "dispatch-hmac-wrong-material",
  "VP-1",
  "An HMAC made with other material than the provider holds for that keyid is refused.",
  [
    request(
      await signed({ algorithm: "hmac-sha256", keyId: HMAC_KEY_ID, material: "other material" }),
      refuse("SIGNATURE_INVALID_OR_INCOMPLETE"),
    ),
  ],
);
const read = await signed({ method: "GET", body: null, grant: null });
vector(
  "read-base-components-accepts-for-read",
  "VP-1",
  "A read signed over the base alone is accepted by a provider that effects nothing.",
  [request(read, accept, { method: "GET", body: null })],
  { effects: false },
);
vector(
  "read-base-components-refused-by-effecting-provider",
  "VP-1",
  "The same read is refused by a provider that effects: the grant pair and the attestation are required to be covered.",
  [request(read, refuse("SIGNATURE_INVALID_OR_INCOMPLETE"), { method: "GET", body: null })],
);
vector(
  "copied-headers-unsigned",
  "VP-1",
  "Every header of a real dispatch copied by something that cannot sign: no signature, no effect.",
  [
    request(
      Object.fromEntries(
        Object.entries(dispatch).filter(
          ([name]) => name !== "signature" && name !== "signature-input",
        ),
      ),
      refuse("SIGNATURE_INVALID_OR_INCOMPLETE"),
    ),
  ],
);
vector(
  "body-altered-after-signing",
  "VP-1",
  "The body changed after the executor signed it; the content digest no longer matches.",
  [
    request(dispatch, refuse("SIGNATURE_INVALID_OR_INCOMPLETE"), {
      body: JSON.stringify({ ...wire, amountMinor: 2_500_000 }),
    }),
  ],
);
vector(
  "covered-header-altered-after-signing",
  "VP-1",
  "A covered header, the grant id, changed after signing; the base the provider rebuilds is not the one signed.",
  [
    request(
      { ...dispatch, "x-agent-safe-grant-id": "11111111-1111-4111-8111-000000000002" },
      refuse("SIGNATURE_INVALID_OR_INCOMPLETE"),
    ),
  ],
);
vector(
  "signature-omits-grant-components",
  "VP-1",
  "A valid signature over the base only, with grant and attestation headers present but uncovered: an effecting provider refuses, because an uncovered header proves nothing.",
  [
    request(
      {
        ...(await signed({ grant: null })),
        "x-agent-safe-grant-id": GRANT_ID,
        "x-agent-safe-decision-id": DECISION_ID,
        "x-agent-safe-claim-attestation": attest(),
      },
      refuse("SIGNATURE_INVALID_OR_INCOMPLETE"),
    ),
  ],
);
vector(
  "unknown-keyid",
  "VP-1",
  "A signature under a keyid the provider never issued to the executor.",
  [
    request(
      await signed({ keyId: "vector-executor-unknown" }),
      refuse("SIGNATURE_INVALID_OR_INCOMPLETE"),
    ),
  ],
);
vector(
  "created-outside-window",
  "VP-1",
  "A signature created an hour before the provider's clock, outside its 300-second window.",
  [request(await signed({ createdAt: NOW - 3_600 }), refuse("SIGNATURE_INVALID_OR_INCOMPLETE"))],
);
vector(
  "attestation-signed-by-unknown-key",
  "VP-2",
  "An attestation signed by a key that is not in the authority's JWKS, under the authority's kid.",
  [
    request(
      await signed({
        grant: {
          id: GRANT_ID,
          decisionId: DECISION_ID,
          claimAttestation: attest(claimsFor(), { key: rogue.privateKey }),
        },
      }),
      refuse("ATTESTATION_INVALID"),
    ),
  ],
);
vector(
  "attestation-wrong-typ",
  "VP-2",
  "A JWS the authority's key signed, but not of the attestation type.",
  [
    request(
      await signed({
        grant: {
          id: GRANT_ID,
          decisionId: DECISION_ID,
          claimAttestation: attest(claimsFor(), { header: { typ: "JWT" } }),
        },
      }),
      refuse("ATTESTATION_INVALID"),
    ),
  ],
);
{
  const [header, , signature] = attest().split(".");
  const tampered = `${header}.${b64url(claimsFor({ exp: NOW + 3_600 }))}.${signature}`;
  vector(
    "attestation-payload-tampered",
    "VP-2",
    "The attestation's payload edited after the authority signed it; the signature no longer covers it.",
    [
      request(
        await signed({
          grant: { id: GRANT_ID, decisionId: DECISION_ID, claimAttestation: tampered },
        }),
        refuse("ATTESTATION_INVALID"),
      ),
    ],
  );
}
vector(
  "attestation-issuer-differs",
  "VP-2",
  "A well-formed attestation from an issuer the provider does not trust.",
  [
    request(
      await signed({
        grant: {
          id: GRANT_ID,
          decisionId: DECISION_ID,
          claimAttestation: attest(claimsFor({ iss: "https://other-authority.example" })),
        },
      }),
      refuse("ATTESTATION_INVALID"),
    ),
  ],
);
{
  // The claims a receipt is built from are required of every attestation:
  // without them a provider could verify the claim yet have nothing to
  // answer it with, so their absence is a malformed attestation, not a
  // well-formed one that happens to be short.
  const { claim_token_digest: _digest, ...withoutClaimTokenDigest } = claimsFor();
  void _digest;
  vector(
    "attestation-lacks-claim-token-digest",
    "VP-2",
    "A signed attestation from the trusted issuer that omits claim_token_digest, the claim a receipt is built from: a required claim is missing, and the attestation is invalid.",
    [
      request(
        await signed({
          grant: {
            id: GRANT_ID,
            decisionId: DECISION_ID,
            claimAttestation: attest(withoutClaimTokenDigest),
          },
        }),
        refuse("ATTESTATION_INVALID"),
      ),
    ],
  );
}
vector(
  "attestation-for-another-grant",
  "VP-2",
  "The authority's attestation of another grant, presented with this grant id.",
  [
    request(
      await signed({
        grant: {
          id: GRANT_ID,
          decisionId: DECISION_ID,
          claimAttestation: attest(claimsFor({ sub: "11111111-1111-4111-8111-000000000002" })),
        },
      }),
      refuse("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"),
    ),
  ],
);
vector(
  "attestation-for-another-decision",
  "VP-2",
  "The authority's attestation names another decision than the one the executor presented.",
  [
    request(
      await signed({
        grant: {
          id: GRANT_ID,
          decisionId: DECISION_ID,
          claimAttestation: attest(claimsFor({ decision_id: "vector-decision-0002" })),
        },
      }),
      refuse("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"),
    ),
  ],
);
vector(
  "attestation-intent-hash-differs",
  "VP-2",
  "The authority's attestation binds another intent than the one the executor presented.",
  [
    request(
      await signed({
        grant: {
          id: GRANT_ID,
          decisionId: DECISION_ID,
          claimAttestation: attest(
            claimsFor({
              binding: {
                ...claimsFor().binding,
                intent_hash: `sha256:${digest("another intent")}`,
              },
            }),
          ),
        },
      }),
      refuse("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"),
    ),
  ],
);
vector(
  "payload-changed-after-claim",
  "VP-2",
  "The amount raised after the claim: the executor signed the changed body, the authority attested the original parameters, and the canonical digests disagree. This is the attack a verifying provider exists to refuse.",
  [
    request(
      await signed({ body: JSON.stringify({ ...wire, amountMinor: 2_500_000 }) }),
      refuse("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"),
      { body: JSON.stringify({ ...wire, amountMinor: 2_500_000 }) },
    ),
  ],
);
vector(
  "attestation-expired",
  "VP-2",
  "An attestation whose lease ended before the provider's clock.",
  [
    request(
      await signed({
        grant: {
          id: GRANT_ID,
          decisionId: DECISION_ID,
          claimAttestation: attest(claimsFor({ exp: NOW - 1 })),
        },
      }),
      refuse("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"),
    ),
  ],
);
vector(
  "attestation-canonicalization-profile-unknown",
  "VP-2",
  "An attestation naming a canonicalization profile this version does not define; the provider cannot know what the digest is over.",
  [
    request(
      await signed({
        grant: {
          id: GRANT_ID,
          decisionId: DECISION_ID,
          claimAttestation: attest(
            claimsFor({
              binding: {
                ...claimsFor().binding,
                execution_payload_canonicalization_profile: "RFC8785/JCS-2",
              },
            }),
          ),
        },
      }),
      refuse("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"),
    ),
  ],
);
{
  // The same parameters as canonical JSON, sent in another key order with
  // whitespace: the executor signed these bytes, the authority bound the
  // canonical digest, and both hold. A provider that hashed the raw bytes for
  // step 7 would refuse this, wrongly.
  const raw = JSON.stringify(
    {
      reference: wire.reference,
      currency: wire.currency,
      beneficiary: wire.beneficiary,
      amountMinor: wire.amountMinor,
    },
    null,
    2,
  );
  vector(
    "attestation-digest-is-canonical-not-raw",
    "VP-2",
    "The body carries the bound parameters in another key order and with whitespace; step 1 binds these bytes, step 7 the canonical parameters, and both pass.",
    [request(await signed({ body: raw }), accept, { body: raw })],
  );
}
{
  const body =
    '{"amountMinor":250000,"amountMinor":250000,"currency":"USD","beneficiary":"synthetic-vendor-7781","reference":"vector-wire-1"}';
  vector(
    "body-not-i-json",
    "VP-2",
    "A body whose JSON repeats a name is not I-JSON: parsers disagree about what it says, so there is no canonical form to digest and the attestation cannot describe it.",
    [
      request(await signed({ body }), refuse("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"), {
        body,
      }),
    ],
  );
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const entry of vectors) {
  writeFileSync(join(out, `${entry.vector}.json`), `${JSON.stringify(entry, null, 2)}\n`);
}
console.log(`${String(readdirSync(out).length)} vectors written to ${out}`);
