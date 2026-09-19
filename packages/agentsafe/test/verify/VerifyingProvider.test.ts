import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { jcsDigest } from "../../src/adapters/JcsDigest.js";
import { SignedRequestCredential } from "../../src/credential/SignedRequestCredential.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";
import {
  ATTESTATION_TYPE,
  JCS_PROFILE,
  MemoryReplayStore,
  parseIJson,
  refusalBody,
  verifyProviderRequest,
  type ExecutorKey,
  type ProviderVerdict,
  type ReceivedRequest,
  type VerifyingProviderOptions,
} from "../../src/verify/VerifyingProvider.js";

/**
 * The vectors live at the repository root, found by walking up from this
 * file: the mutation runner copies the package into a sandbox four levels
 * deeper, and the walk finds the same vectors from there.
 */
function vectorsDirectory(): string {
  let directory = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    const candidate = join(directory, "conformance", "provider", "vectors");
    if (existsSync(candidate)) return candidate;
    const parent = dirname(directory);
    if (parent === directory)
      throw new Error("conformance/provider/vectors not found above this test");
    directory = parent;
  }
}
const VECTORS = vectorsDirectory();

interface Vector {
  readonly profile: string;
  readonly version: string;
  readonly vector: string;
  readonly level: "VP-1" | "VP-2";
  readonly provider: {
    readonly effects: boolean;
    readonly clock_window_seconds: number;
    readonly now: string;
    readonly authority_issuer: string;
  };
  readonly executor_keys: ReadonlyArray<
    | { readonly keyid: string; readonly alg: "ed25519"; readonly public_pem: string }
    | { readonly keyid: string; readonly alg: "hmac-sha256"; readonly shared_material_utf8: string }
  >;
  readonly authority_jwks: { readonly keys: ReadonlyArray<Readonly<Record<string, unknown>>> };
  readonly requests: ReadonlyArray<
    ReceivedRequest & {
      readonly expect: { readonly outcome: "ACCEPT" | "REFUSE"; readonly reason_code?: string };
    }
  >;
}

function executorKey(key: Vector["executor_keys"][number]): ExecutorKey {
  return key.alg === "ed25519"
    ? { keyId: key.keyid, algorithm: "ed25519", publicKeyPem: key.public_pem }
    : {
        keyId: key.keyid,
        algorithm: "hmac-sha256",
        secret: new TextEncoder().encode(key.shared_material_utf8),
      };
}

function optionsFor(vector: Vector): VerifyingProviderOptions {
  const now = Date.parse(vector.provider.now);
  return {
    effects: vector.provider.effects,
    executorKeys: vector.executor_keys.map(executorKey),
    authorityJwks: vector.authority_jwks,
    authorityIssuer: vector.provider.authority_issuer,
    clockWindowSeconds: vector.provider.clock_window_seconds,
    replay: new MemoryReplayStore(() => now),
    now: () => now,
  };
}

describe("agent-safe.verifying-provider/1 conformance", () => {
  const files = readdirSync(VECTORS).filter((name) => name.endsWith(".json"));

  it("finds the vectors", () => {
    expect(files.length).toBeGreaterThanOrEqual(20);
  });

  for (const file of files) {
    const vector = JSON.parse(readFileSync(join(VECTORS, file), "utf8")) as Vector;
    it(`${vector.vector} (${vector.level}) reaches the outcomes it names`, () => {
      expect(vector.profile).toBe("agent-safe.verifying-provider/1");
      expect(vector.version).toBe("0.1");
      const options = optionsFor(vector);
      for (const request of vector.requests) {
        const verdict = verifyProviderRequest(request, options);
        if (request.expect.outcome === "ACCEPT") {
          expect(verdict).toMatchObject({ accepted: true, reasonCode: null });
        } else {
          expect(verdict).toEqual({
            accepted: false,
            reasonCode: request.expect.reason_code,
            attestation: null,
          });
        }
      }
    });
  }
});

// What the vectors cannot express: a clock, a store, an attestation of every
// wrong shape signed under a valid request signature, and the exact shape of
// an accepted verdict. Built with the executor's own signer and an authority
// key of this test's own.
const NOW = 1_789_819_200_000;
const authority = generateKeyPairSync("ed25519");
const decoy = generateKeyPairSync("ed25519");
const executor = generateKeyPairSync("ed25519");
const executorPem = executor.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const jwkOf = (key: typeof authority, kid: string): Record<string, unknown> => ({
  ...(key.publicKey.export({ format: "jwk" }) as Record<string, unknown>),
  kid,
});
const JWK = jwkOf(authority, "test-grant-key");
const GRANT = "test-grant-1";
const DECISION = "test-decision-1";
const INTENT = `sha256:${"a".repeat(64)}`;
const body = '{"amountMinor":5000,"currency":"USD"}';
const bodyDigest = `sha256:${createHash("sha256").update(body).digest("hex")}`;

const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");

function attestation(
  claims: unknown,
  header: Record<string, unknown> = {},
  key = authority.privateKey,
): string {
  const head = encode({ alg: "EdDSA", kid: "test-grant-key", typ: ATTESTATION_TYPE, ...header });
  const payload = encode(claims);
  const signature = sign(null, Buffer.from(`${head}.${payload}`, "ascii"), key);
  return `${head}.${payload}.${signature.toString("base64url")}`;
}

const claims = {
  iss: "https://authority.example",
  sub: GRANT,
  decision_id: DECISION,
  binding: {
    intent_hash: INTENT,
    execution_payload_digest: bodyDigest,
    execution_payload_canonicalization_profile: JCS_PROFILE,
  },
  exp: NOW / 1_000 + 25,
};

/** A dispatch the executor signed, over the body and attestation given. */
async function dispatch({
  claimAttestation = attestation(claims),
  requestBody = body as string | null,
  method = "POST" as "GET" | "POST",
  createdAt = NOW - 5_000,
}: {
  claimAttestation?: string;
  requestBody?: string | null;
  method?: "GET" | "POST";
  createdAt?: number;
} = {}): Promise<ReceivedRequest> {
  const credential = new SignedRequestCredential(
    { algorithm: "ed25519", keyId: "test-executor" },
    () => SecretHandle.fromString("DOWNSTREAM_SIGNING_KEY", executorPem),
    () => createdAt,
  );
  const headers = await credential.headersFor({
    method,
    url: "https://provider.invalid/v1/payouts",
    body: requestBody,
    idempotencyKey: "test-1",
    intentHash: INTENT,
    grant: { id: GRANT, decisionId: DECISION, claimAttestation },
  });
  return { method, path: "/v1/payouts", body: requestBody, headers };
}

function options(
  overrides: Partial<VerifyingProviderOptions> = {},
  clock: (() => number) | null = () => NOW,
): VerifyingProviderOptions {
  return {
    ...(clock === null ? {} : { now: clock }),
    effects: true,
    executorKeys: [
      {
        keyId: "test-executor",
        algorithm: "ed25519",
        publicKeyPem: executor.publicKey.export({ type: "spki", format: "pem" }) as string,
      },
    ],
    authorityJwks: { keys: [JWK] },
    authorityIssuer: "https://authority.example",
    clockWindowSeconds: 300,
    replay: new MemoryReplayStore(() => NOW),
    ...overrides,
  };
}

const code = (verdict: ProviderVerdict): string | null => verdict.reasonCode;

describe("verifyProviderRequest", () => {
  it("accepts a dispatch and hands the provider the claims it acted on", async () => {
    expect(verifyProviderRequest(await dispatch(), options())).toEqual({
      accepted: true,
      reasonCode: null,
      attestation: {
        iss: "https://authority.example",
        sub: GRANT,
        decision_id: DECISION,
        binding: {
          intent_hash: INTENT,
          execution_payload_digest: bodyDigest,
          execution_payload_canonicalization_profile: JCS_PROFILE,
        },
        exp: NOW / 1_000 + 25,
      },
    } satisfies ProviderVerdict);
  });

  it("uses the wall clock when none is given, and refuses a signature made years ago against it", async () => {
    expect(code(verifyProviderRequest(await dispatch(), options({}, null)))).toBe(
      "SIGNATURE_INVALID_OR_INCOMPLETE",
    );
  });

  it("holds `created` to the window from both sides, and refuses one that is not a number", async () => {
    // At VP-1 the verdict is the signature's alone, so only the window moves it.
    const request = await dispatch();
    const at = (now: number): boolean =>
      verifyProviderRequest(request, options({ effects: false, now: () => now })).accepted;
    expect(at(NOW + 295_000)).toBe(true);
    expect(at(NOW + 296_000)).toBe(false);
    expect(at(NOW - 305_000)).toBe(true);
    expect(at(NOW - 306_000)).toBe(false);
    const input = request.headers["signature-input"] as string;
    const rewritten = (signatureInput: string): ReceivedRequest => ({
      ...request,
      headers: { ...request.headers, "signature-input": signatureInput },
    });
    expect(
      code(
        verifyProviderRequest(rewritten(input.replace(/created=\d+/, "created=soon")), options()),
      ),
    ).toBe("SIGNATURE_INVALID_OR_INCOMPLETE");
    expect(
      code(verifyProviderRequest(rewritten(input.replace(/;created=\d+/, "")), options())),
    ).toBe("SIGNATURE_INVALID_OR_INCOMPLETE");
  });

  it("refuses a signature-input with no keyid, and a key the signature's algorithm is not for", async () => {
    const request = await dispatch();
    const input = request.headers["signature-input"] as string;
    expect(
      code(
        verifyProviderRequest(
          {
            ...request,
            headers: { ...request.headers, "signature-input": input.replace(/;keyid="[^"]*"/, "") },
          },
          options(),
        ),
      ),
    ).toBe("SIGNATURE_INVALID_OR_INCOMPLETE");
    expect(
      code(
        verifyProviderRequest(
          request,
          options({
            executorKeys: [
              { keyId: "test-executor", algorithm: "hmac-sha256", secret: new Uint8Array(32) },
            ],
          }),
        ),
      ),
    ).toBe("SIGNATURE_INVALID_OR_INCOMPLETE");
  });

  it("verifies a read at VP-1 alone for a provider that effects nothing, and never records a grant for it", async () => {
    const replay = new MemoryReplayStore(() => NOW);
    const verdict = verifyProviderRequest(await dispatch(), options({ effects: false, replay }));
    expect(verdict).toEqual({ accepted: true, reasonCode: null, attestation: null });
    expect(replay.size).toBe(0);
  });

  it("refuses the second presentation of a grant, and records the first before effecting", async () => {
    const replay = new MemoryReplayStore(() => NOW);
    const request = await dispatch();
    expect(verifyProviderRequest(request, options({ replay })).accepted).toBe(true);
    expect(replay.size).toBe(1);
    expect(verifyProviderRequest(request, options({ replay }))).toEqual({
      accepted: false,
      reasonCode: "GRANT_REPLAYED",
      attestation: null,
    });
  });

  it("refuses an attestation of the wrong form, each signed into a valid request", async () => {
    const valid = attestation(claims);
    const [head, payload, signature] = valid.split(".") as [string, string, string];
    for (const compact of [
      `${head}.${payload}`,
      `${valid}.extra`,
      `${Buffer.from("{").toString("base64url")}.${payload}.${signature}`,
      `${head}.${Buffer.from("[").toString("base64url")}.${signature}`,
      `${encode("EdDSA")}.${payload}.${signature}`,
      `${encode(null)}.${payload}.${signature}`,
      attestation(claims, { alg: "ES256" }),
      attestation(claims, { typ: "JWT" }),
      attestation(claims, { kid: "unknown" }),
      attestation(claims, {}, decoy.privateKey),
      attestation("claims"),
      attestation({ ...claims, iss: "https://other-authority.example" }),
      attestation({ ...claims, iss: 7 }),
    ]) {
      expect(
        code(verifyProviderRequest(await dispatch({ claimAttestation: compact }), options())),
      ).toBe("ATTESTATION_INVALID");
    }
  });

  it("looks the key up by kid, not position, and refuses a JWKS entry that is not a key", async () => {
    const request = await dispatch();
    expect(
      verifyProviderRequest(
        request,
        options({ authorityJwks: { keys: [jwkOf(decoy, "other"), JWK] } }),
      ).accepted,
    ).toBe(true);
    expect(
      code(
        verifyProviderRequest(
          request,
          options({ authorityJwks: { keys: [{ kid: "test-grant-key", kty: "?" }] } }),
        ),
      ),
    ).toBe("ATTESTATION_INVALID");
  });

  it("refuses claims of the wrong shape, or of another request, under the authority's own signature", async () => {
    for (const wrong of [
      { ...claims, binding: "none" },
      { ...claims, binding: null },
      { ...claims, sub: 7 },
      { ...claims, decision_id: null },
      { ...claims, binding: { ...claims.binding, intent_hash: 1 } },
      { ...claims, binding: { ...claims.binding, execution_payload_digest: undefined } },
      {
        ...claims,
        binding: { ...claims.binding, execution_payload_canonicalization_profile: "JCS" },
      },
      { ...claims, exp: "later" },
      { ...claims, exp: NOW / 1_000 },
    ]) {
      expect(
        code(
          verifyProviderRequest(
            await dispatch({ claimAttestation: attestation(wrong) }),
            options(),
          ),
        ),
      ).toBe("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST");
    }
    expect(
      verifyProviderRequest(
        await dispatch({ claimAttestation: attestation({ ...claims, exp: NOW / 1_000 + 1 }) }),
        options(),
      ).accepted,
    ).toBe(true);
  });

  it("refuses a body that is not JSON, not I-JSON, or absent, whatever the attestation digests", async () => {
    const digestOf = (value: unknown): string => jcsDigest(value as never);
    const withDigest = (digest: string): string =>
      attestation({ ...claims, binding: { ...claims.binding, execution_payload_digest: digest } });
    for (const claimAttestation of [attestation(claims), withDigest(digestOf(null))]) {
      expect(
        code(
          verifyProviderRequest(
            await dispatch({ requestBody: "not json", claimAttestation }),
            options(),
          ),
        ),
      ).toBe("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST");
    }
    const surrogate = '{"amountMinor":5000,"currency":"\\udc00"}';
    expect(
      code(
        verifyProviderRequest(
          await dispatch({
            requestBody: surrogate,
            claimAttestation: withDigest(`sha256:${"b".repeat(64)}`),
          }),
          options(),
        ),
      ),
    ).toBe("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST");
    for (const [requestBody, digested] of [
      [null, null],
      ["5", 5],
      ['"a"', "a"],
      ["[1]", [1]],
    ] as const) {
      expect(
        code(
          verifyProviderRequest(
            await dispatch({ requestBody, claimAttestation: withDigest(digestOf(digested)) }),
            options(),
          ),
        ),
      ).toBe("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST");
    }
  });

  it("names the refusal body the profile gives", () => {
    expect(refusalBody("GRANT_REPLAYED")).toBe(
      '{"status":"REJECTED","reason_code":"GRANT_REPLAYED"}',
    );
  });
});

describe("MemoryReplayStore", () => {
  it("forgets a grant once its attestation expired, and not before", () => {
    let now = NOW;
    const store = new MemoryReplayStore(() => now);
    expect(store.record("g", NOW + 1_000)).toBe(true);
    expect(store.record("g", NOW + 1_000)).toBe(false);
    now = NOW + 999;
    expect(store.record("g", NOW + 5_000)).toBe(false);
    now = NOW + 1_000;
    expect(store.record("g", NOW + 5_000)).toBe(true);
    expect(store.size).toBe(1);
  });

  it("reads the wall clock when given none", () => {
    const store = new MemoryReplayStore();
    expect(store.record("expired", Date.now() - 1)).toBe(true);
    expect(store.record("live", Date.now() + 60_000)).toBe(true);
    expect(store.record("live", Date.now() + 60_000)).toBe(false);
    expect(store.record("expired", Date.now() + 60_000)).toBe(true);
  });
});

describe("parseIJson", () => {
  it("accepts JSON whose names are unique within each object, wherever they repeat elsewhere", () => {
    expect(parseIJson('{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}],"d":[],"e":{}}')).toEqual({
      a: 1,
      b: { a: 2 },
      c: [{ a: 3 }, { a: 4 }],
      d: [],
      e: {},
    });
    expect(parseIJson('{"a":1,"b":{"a":2}}')).not.toBeNull();
    expect(parseIJson('[{"a":1},{"a":1}]')).not.toBeNull();
    expect(parseIJson('{"x":["a","a"],"b":"}{"}')).not.toBeNull();
    expect(parseIJson("5")).not.toBeNull();
    expect(parseIJson('"a"')).not.toBeNull();
  });

  it("refuses a repeated name at the top, nested, in an object inside an array, or spelled with an escape", () => {
    expect(parseIJson('{"a":1,"a":2}')).toBeNull();
    expect(parseIJson('{"x":{"a":1,"b":2,"a":3}}')).toBeNull();
    expect(parseIJson('{"x":[1,{"a":1,"a":2}]}')).toBeNull();
    expect(parseIJson('{"\\u0061":1,"a":2}')).toBeNull();
    expect(parseIJson('{"a\\"":1,"a\\"":2}')).toBeNull();
  });

  it("reads names through each kind of whitespace", () => {
    for (const space of [" ", "\n", "\r", "\t"]) {
      expect(
        parseIJson(`{${space}"a"${space}:${space}1${space},${space}"a"${space}:2}`),
      ).toBeNull();
      expect(parseIJson(`{"a":[${space}1${space}]${space},"b":{${space}}}`)).not.toBeNull();
    }
  });

  it("closes an object or array only at its own bracket, so a name after a nested value still counts", () => {
    expect(parseIJson('{"x":{"a":1},"x":2}')).toBeNull();
    expect(parseIJson('{"x":[1],"x":2}')).toBeNull();
    expect(parseIJson('{"x":"\\"","x":1}')).toBeNull();
    expect(parseIJson('{"x":true,"y":null,"x":1}')).toBeNull();
  });

  it("does not mistake a string value for a name, even when it looks like one", () => {
    expect(parseIJson('{"a":"a","b":"a:","c":"\\"a\\":"}')).not.toBeNull();
  });

  it("returns null for text that is not JSON", () => {
    expect(parseIJson("{")).toBeNull();
  });
});
