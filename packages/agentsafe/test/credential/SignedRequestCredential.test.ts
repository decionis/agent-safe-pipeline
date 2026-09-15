import { generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ATTESTATION_COMPONENT,
  BASE_COMPONENTS,
  GRANT_COMPONENTS,
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
const attestation = ["header", "payload", "signature"]
  .map((part) => Buffer.from(part).toString("base64url"))
  .join(".");
const grant = {
  id: "fixture_grant_7",
  decisionId: "fixture_decision_7",
  claimAttestation: attestation,
};

function ed25519() {
  const keys = generateKeyPairSync("ed25519");
  const pem = keys.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = keys.publicKey.export({ type: "spki", format: "pem" }) as string;
  const credential = new SignedRequestCredential(
    { algorithm: "ed25519", keyId: "synthetic-key-1" },
    () => SecretHandle.fromString("DOWNSTREAM_SIGNING_KEY", pem),
    () => 1_726_000_000_000,
  );
  return { credential, publicKeyPem };
}

/** What a provider does with a request it received: material from the headers. */
const received = (headers: Readonly<Record<string, string>>, overrides = {}) =>
  SignedRequestCredential.materialFrom({
    method: "POST",
    path: "/v1/payouts",
    body: request.body,
    headers,
    ...overrides,
  });

describe("SignedRequestCredential", () => {
  it("signs the base components with Ed25519 so the downstream can verify them with the public key", async () => {
    const { credential, publicKeyPem } = ed25519();
    expect(credential.kind).toBe("SIGNED_REQUEST");
    const headers = await credential.headersFor(request);
    // The covered headers come back beside the signature, with the values it
    // covers, so a handler that only spreads these sends a verifiable request.
    expect(Object.keys(headers).sort()).toEqual(
      [
        "content-digest",
        "idempotency-key",
        "signature",
        "signature-input",
        "x-agent-safe-intent-hash",
      ].sort(),
    );
    expect(headers["idempotency-key"]).toBe(request.idempotencyKey);
    expect(headers["x-agent-safe-intent-hash"]).toBe(request.intentHash);
    expect(headers["content-digest"]).toBe(SignedRequestCredential.contentDigest(request.body));
    expect(headers["signature-input"]).toBe(
      `${SIGNATURE_LABEL}=("@method" "@path" "content-digest" "idempotency-key" "x-agent-safe-intent-hash");created=1726000000;keyid="synthetic-key-1";alg="ed25519"`,
    );
    expect(headers["signature"]).toMatch(/^agentsafe=:[A-Za-z0-9+/]+=*:$/);
    expect(SignedRequestCredential.verify(material, headers, { publicKeyPem })).toBe(true);
    expect(SignedRequestCredential.verify(received(headers), headers, { publicKeyPem })).toBe(true);
    for (const changed of [
      { body: '{"amountMinor":2501}' },
      { path: "/v1/refunds" },
      { method: "GET" },
      { idempotencyKey: "payout-8-v1" },
      { intentHash: `sha256:${"f".repeat(64)}` },
    ]) {
      expect(
        SignedRequestCredential.verify({ ...material, ...changed }, headers, { publicKeyPem }),
        JSON.stringify(changed),
      ).toBe(false);
    }
    const other = generateKeyPairSync("ed25519").publicKey.export({
      type: "spki",
      format: "pem",
    }) as string;
    expect(SignedRequestCredential.verify(material, headers, { publicKeyPem: other })).toBe(false);
    expect(SignedRequestCredential.verify(material, headers, { secret: Buffer.from("x") })).toBe(
      false,
    );
    expect(SIGNED_COMPONENTS).toEqual([
      ...BASE_COMPONENTS,
      ...GRANT_COMPONENTS,
      ATTESTATION_COMPONENT,
    ]);
    expect(SIGNED_COMPONENTS).toHaveLength(8);
  });

  it("covers the grant, the decision and the attestation on a dispatch, and a provider can require them", async () => {
    const { credential, publicKeyPem } = ed25519();
    const headers = await credential.headersFor({ ...request, grant });
    expect(headers["signature-input"]).toBe(
      `${SIGNATURE_LABEL}=("@method" "@path" "content-digest" "idempotency-key" "x-agent-safe-intent-hash" "x-agent-safe-grant-id" "x-agent-safe-decision-id" "x-agent-safe-claim-attestation");created=1726000000;keyid="synthetic-key-1";alg="ed25519"`,
    );
    expect(headers["x-agent-safe-grant-id"]).toBe(grant.id);
    expect(headers["x-agent-safe-decision-id"]).toBe(grant.decisionId);
    expect(headers["x-agent-safe-claim-attestation"]).toBe(attestation);
    const strict = { require: SIGNED_COMPONENTS };
    expect(
      SignedRequestCredential.verify(received(headers), headers, { publicKeyPem }, strict),
    ).toBe(true);
    // Swapping any of the three for another value, in the header or in the
    // material, breaks the signature: the grant is bound to this request.
    for (const [name, value] of [
      ["x-agent-safe-grant-id", "fixture_grant_8"],
      ["x-agent-safe-decision-id", "fixture_decision_8"],
      ["x-agent-safe-claim-attestation", `${attestation}x`],
    ] as const) {
      const swapped = { ...headers, [name]: value };
      expect(
        SignedRequestCredential.verify(received(swapped), swapped, { publicKeyPem }, strict),
        name,
      ).toBe(false);
    }
    // A header the request carries but the signature does not cover proves
    // nothing about it, and a provider that requires it refuses.
    const unsigned = await credential.headersFor(request);
    const decorated = {
      ...unsigned,
      "x-agent-safe-grant-id": grant.id,
      "x-agent-safe-decision-id": grant.decisionId,
    };
    expect(SignedRequestCredential.verify(received(decorated), decorated, { publicKeyPem })).toBe(
      true,
    );
    expect(
      SignedRequestCredential.verify(
        received(decorated),
        decorated,
        { publicKeyPem },
        {
          require: GRANT_COMPONENTS,
        },
      ),
    ).toBe(false);
    // A covered header that is missing from the request, or that differs
    // from the material, is refused before any signature is checked.
    const { "x-agent-safe-grant-id": _dropped, ...missing } = headers;
    void _dropped;
    expect(SignedRequestCredential.verify(received(missing), missing, { publicKeyPem })).toBe(
      false,
    );
    expect(
      SignedRequestCredential.verify(
        { ...received(headers), grantId: "fixture_grant_9" },
        headers,
        { publicKeyPem },
      ),
    ).toBe(false);
  });

  it("covers the grant pair without an attestation when the authority gave none, and neither on a read", async () => {
    const { credential, publicKeyPem } = ed25519();
    const noAttestation = await credential.headersFor({
      ...request,
      grant: { id: grant.id, decisionId: grant.decisionId },
    });
    expect(
      SignedRequestCredential.coveredComponents(noAttestation["signature-input"]!.slice(10)),
    ).toEqual([...BASE_COMPONENTS, ...GRANT_COMPONENTS]);
    expect(noAttestation).not.toHaveProperty("x-agent-safe-claim-attestation");
    expect(
      SignedRequestCredential.verify(
        received(noAttestation),
        noAttestation,
        { publicKeyPem },
        {
          require: GRANT_COMPONENTS,
        },
      ),
    ).toBe(true);
    expect(
      SignedRequestCredential.verify(
        received(noAttestation),
        noAttestation,
        { publicKeyPem },
        {
          require: [ATTESTATION_COMPONENT],
        },
      ),
    ).toBe(false);
    // A read-only lookup executes under no grant and covers only the base.
    const lookup = await credential.headersFor({ ...request, method: "GET", body: null });
    expect(SignedRequestCredential.coveredComponents(lookup["signature-input"]!.slice(10))).toEqual(
      [...BASE_COMPONENTS],
    );
    expect(SignedRequestCredential.componentsFor({ ...material, grantId: "g" })).toEqual([
      ...BASE_COMPONENTS,
    ]);
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

  it("refuses a signature-input naming a component it does not know, twice, or none", async () => {
    const { credential, publicKeyPem } = ed25519();
    const headers = await credential.headersFor(request);
    const rewrite = (list: string) => ({
      ...headers,
      "signature-input": headers["signature-input"]!.replace(
        /^agentsafe=\([^)]*\)/,
        `agentsafe=(${list})`,
      ),
    });
    for (const list of [
      '"@method" "@path" "content-digest" "idempotency-key" "x-agent-safe-intent-hash" "x-forwarded-for"',
      '"@method" "@method" "@path" "content-digest" "idempotency-key" "x-agent-safe-intent-hash"',
      '"@method" "@path" "content-digest"',
      "",
    ]) {
      const tampered = rewrite(list);
      expect(
        SignedRequestCredential.verify(received(tampered), tampered, { publicKeyPem }),
        list,
      ).toBe(false);
    }
    expect(SignedRequestCredential.coveredComponents("nonsense")).toBeNull();
    expect(SignedRequestCredential.coveredComponents('("x-forwarded-for");created=1')).toBeNull();
    expect(SignedRequestCredential.coveredComponents("();created=1")).toEqual([]);
    expect(
      SignedRequestCredential.base(
        material,
        SignedRequestCredential.parameters(1, "k", "ed25519", GRANT_COMPONENTS),
      ),
    ).toBeNull();
  });

  it("reads the label anchored at the start, so a header that merely contains it is refused", async () => {
    const { credential, publicKeyPem } = ed25519();
    const headers = await credential.headersFor(request);
    // Prefixing either header keeps every byte the signer used, so an
    // unanchored parse would rebuild the same base and accept it.
    for (const tampered of [
      { ...headers, "signature-input": `x${headers["signature-input"]}` },
      { ...headers, signature: `x${headers["signature"]}` },
      { ...headers, signature: `${headers["signature"]}x` },
      { ...headers, "signature-input": "" },
      { ...headers, signature: "" },
    ]) {
      expect(SignedRequestCredential.verify(received(tampered), tampered, { publicKeyPem })).toBe(
        false,
      );
    }
    const { "signature-input": _input, ...noInput } = headers;
    void _input;
    expect(SignedRequestCredential.verify(received(noInput), noInput, { publicKeyPem })).toBe(
      false,
    );
    const { signature: _signature, ...noSignature } = headers;
    void _signature;
    expect(
      SignedRequestCredential.verify(received(noSignature), noSignature, { publicKeyPem }),
    ).toBe(false);
    const { "content-digest": _digest, ...noDigest } = headers;
    void _digest;
    expect(SignedRequestCredential.verify(received(noDigest), noDigest, { publicKeyPem })).toBe(
      false,
    );
  });

  it("refuses parameters that name no algorithm, and a MAC of the wrong length, without throwing", async () => {
    const secret = randomBytes(32);
    const credential = new SignedRequestCredential(
      { algorithm: "hmac-sha256", keyId: "synthetic-hmac-1" },
      () => SecretHandle.fromBuffer("DOWNSTREAM_SIGNING_KEY", Buffer.from(secret)),
    );
    const headers = await credential.headersFor(request);
    // The default clock stamps a real `created`.
    expect(headers["signature-input"]).toMatch(/;created=\d{10};/);
    const noAlgorithm = {
      ...headers,
      "signature-input": headers["signature-input"]!.replace(/;alg="[^"]+"/, ""),
    };
    expect(SignedRequestCredential.verify(received(noAlgorithm), noAlgorithm, { secret })).toBe(
      false,
    );
    const { publicKeyPem } = ed25519();
    expect(
      SignedRequestCredential.verify(received(noAlgorithm), noAlgorithm, { publicKeyPem }),
    ).toBe(false);
    // One byte is not a SHA-256 MAC; sixty-four bytes is an Ed25519 signature
    // presented to a verifier holding a secret. Neither throws.
    for (const signature of ["agentsafe=:AA==:", `agentsafe=:${"A".repeat(88)}:`]) {
      const wrong = { ...headers, signature };
      expect(SignedRequestCredential.verify(received(wrong), wrong, { secret })).toBe(false);
    }
  });

  it("returns no base for a component the material lacks, one component at a time", () => {
    const parameters = (components: readonly (typeof SIGNED_COMPONENTS)[number][]) =>
      SignedRequestCredential.parameters(1, "k", "ed25519", components);
    const withGrant = { ...material, grantId: grant.id, decisionId: grant.decisionId };
    expect(
      SignedRequestCredential.base(
        material,
        parameters([...BASE_COMPONENTS, "x-agent-safe-grant-id"]),
      ),
    ).toBeNull();
    expect(
      SignedRequestCredential.base(
        material,
        parameters([...BASE_COMPONENTS, "x-agent-safe-decision-id"]),
      ),
    ).toBeNull();
    expect(SignedRequestCredential.base(withGrant, parameters([...SIGNED_COMPONENTS]))).toBeNull();
    expect(
      SignedRequestCredential.base(
        withGrant,
        parameters([...BASE_COMPONENTS, ...GRANT_COMPONENTS]),
      ),
    ).not.toBeNull();
    expect(SignedRequestCredential.base(material, "nonsense")).toBeNull();
    // The grant pair is covered together or not at all; a decision id alone is
    // not a grant, exactly as a grant id alone is not.
    expect(SignedRequestCredential.componentsFor({ ...material, decisionId: "d" })).toEqual([
      ...BASE_COMPONENTS,
    ]);
    expect(
      SignedRequestCredential.componentsFor({ ...withGrant, claimAttestation: attestation }),
    ).toEqual([...SIGNED_COMPONENTS]);
  });

  it("parses the covered list strictly: anchored, known names only, no duplicates", () => {
    expect(SignedRequestCredential.coveredComponents('x("@method");created=1')).toBeNull();
    expect(SignedRequestCredential.coveredComponents('("@method" "@method");created=1')).toBeNull();
    expect(SignedRequestCredential.coveredComponents('("@method" "x-other");created=1')).toBeNull();
    expect(SignedRequestCredential.coveredComponents('("@method");created=1')).toEqual(["@method"]);
  });

  it("builds material from the headers a request carried, and only those", () => {
    const base = SignedRequestCredential.materialFrom({
      method: "POST",
      path: "/v1/payouts",
      body: null,
      headers: {},
    });
    expect(base).toEqual({
      method: "POST",
      path: "/v1/payouts",
      body: null,
      idempotencyKey: "",
      intentHash: "",
    });
    for (const key of ["grantId", "decisionId", "claimAttestation"]) {
      expect(base).not.toHaveProperty(key);
    }
    const full = SignedRequestCredential.materialFrom({
      method: "POST",
      path: "/v1/payouts",
      body: request.body,
      headers: {
        "idempotency-key": request.idempotencyKey,
        "x-agent-safe-intent-hash": request.intentHash,
        "x-agent-safe-grant-id": grant.id,
        "x-agent-safe-decision-id": grant.decisionId,
        "x-agent-safe-claim-attestation": attestation,
      },
    });
    const { url: _url, ...expected } = material;
    void _url;
    expect(full).toEqual({
      ...expected,
      grantId: grant.id,
      decisionId: grant.decisionId,
      claimAttestation: attestation,
    });
    // The covered headers a handler sends: nothing for a read, the pair for a
    // grant, and the attestation only when there is one.
    expect(SignedRequestCredential.coveredHeaders(request)).toEqual({
      "idempotency-key": request.idempotencyKey,
      "x-agent-safe-intent-hash": request.intentHash,
    });
    const pair = SignedRequestCredential.coveredHeaders({
      ...request,
      grant: { id: grant.id, decisionId: grant.decisionId },
    });
    expect(pair).not.toHaveProperty("x-agent-safe-claim-attestation");
    expect(Object.keys(pair)).toHaveLength(4);
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
    const full = SignedRequestCredential.parameters(1, "k", "ed25519", SIGNED_COMPONENTS);
    expect(
      SignedRequestCredential.base(
        {
          ...material,
          grantId: grant.id,
          decisionId: grant.decisionId,
          claimAttestation: attestation,
        },
        full,
      ),
    ).toBe(
      [
        '"@method": POST',
        '"@path": /v1/payouts',
        `"content-digest": ${SignedRequestCredential.contentDigest(material.body)}`,
        '"idempotency-key": payout-7-v1',
        `"x-agent-safe-intent-hash": sha256:${"e".repeat(64)}`,
        '"x-agent-safe-grant-id": fixture_grant_7',
        '"x-agent-safe-decision-id": fixture_decision_7',
        `"x-agent-safe-claim-attestation": ${attestation}`,
        `"@signature-params": ${full}`,
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
