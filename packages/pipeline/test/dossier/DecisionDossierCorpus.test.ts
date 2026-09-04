import { spawnSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, type webcrypto } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { Jwks, ReproducibilityAssessment, VerifyResult } from "@decionis/verify";
import { describe, expect, it } from "vitest";

interface VerifyModule {
  readonly assessDossierReproducibility: (
    dossierPayload: Record<string, unknown>,
  ) => ReproducibilityAssessment;
  readonly stableJsonStringify: (value: unknown) => string;
  readonly verifyDossierProofBundle: (input: {
    dossier_payload: Record<string, unknown>;
    public_jwks?: Jwks | null;
  }) => VerifyResult;
}

// The published package's development export names source files that are intentionally
// absent from its npm tarball. Load the package's shipped production module so Vitest does
// not select that development-only condition.
const { assessDossierReproducibility, stableJsonStringify, verifyDossierProofBundle } =
  (await import(
    new URL("../../../../node_modules/@decionis/verify/dist/index.js", import.meta.url).href
  )) as VerifyModule;

interface ExpectedArtifact {
  readonly artifact_kind: string;
  readonly document_path: string;
  readonly canonical_json: string;
  readonly canonical_document_sha256: string;
  readonly signature: string;
}

interface DossierVector {
  readonly vector_version: string;
  readonly description: string;
  readonly expected: {
    readonly verified: true;
    readonly artifacts_checked: number;
    readonly key_id: string;
    readonly reproducibility: string;
  };
  readonly expected_artifacts: readonly ExpectedArtifact[];
  readonly dossier_payload: Record<string, unknown>;
}

interface CorpusJwk extends Record<string, unknown> {
  readonly alg?: string;
  readonly crv?: string;
  readonly d?: string;
  readonly kid?: string;
  readonly kty?: string;
  readonly use?: string;
  readonly x?: string;
}

interface CorpusJwks {
  readonly keys: CorpusJwk[];
}

const REPOSITORY_ROOT = new URL("../../../../", import.meta.url);
const DOSSIERS_DIRECTORY = new URL("dossiers/", REPOSITORY_ROOT);
const VECTORS_DIRECTORY = new URL("vectors/", DOSSIERS_DIRECTORY);
const KEY_ID = "agent-safe-synthetic-dossier-corpus-v1";

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a JSON object");
  }
  return value as Record<string, unknown>;
}

function resolveJsonPointer(root: unknown, pointer: string): unknown {
  if (!pointer.startsWith("/")) return undefined;
  return pointer
    .split("/")
    .slice(1)
    .reduce<unknown>((current, rawSegment) => {
      const segment = rawSegment.replaceAll("~1", "/").replaceAll("~0", "~");
      return record(current)[segment];
    }, root);
}

async function readJson<T>(url: URL): Promise<T> {
  return JSON.parse(await readFile(url, "utf8")) as T;
}

describe("Decision Dossier conformance corpus", () => {
  it("publishes a dedicated synthetic public key derived from the disclosed corpus key", async () => {
    const privateJwk = await readJson<CorpusJwk>(
      new URL("synthetic-corpus-private.jwk.json", DOSSIERS_DIRECTORY),
    );
    const jwks = await readJson<CorpusJwks>(new URL("corpus-jwks.json", DOSSIERS_DIRECTORY));

    expect(privateJwk).toMatchObject({
      kty: "OKP",
      crv: "Ed25519",
      alg: "EdDSA",
      use: "sig",
      kid: KEY_ID,
    });
    expect(privateJwk.d).toBeTypeOf("string");
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).not.toHaveProperty("d");

    const derived = createPublicKey(
      createPrivateKey({ key: privateJwk as webcrypto.JsonWebKey, format: "jwk" }),
    ).export({ format: "jwk" });
    expect(jwks.keys[0]).toMatchObject({
      kty: derived.kty,
      crv: derived.crv,
      x: derived.x,
      alg: "EdDSA",
      use: "sig",
      kid: KEY_ID,
    });
  });

  it("auto-discovers and verifies every signed dossier vector", async () => {
    const jwks = await readJson<CorpusJwks>(new URL("corpus-jwks.json", DOSSIERS_DIRECTORY));
    const files = (await readdir(VECTORS_DIRECTORY)).filter((name) => name.endsWith(".json"));
    const outcomes = new Set<string>();
    expect(files).toHaveLength(3);

    for (const file of files) {
      const vector = await readJson<DossierVector>(new URL(file, VECTORS_DIRECTORY));
      expect(vector.vector_version).toBe("agent-safe.decision-dossier-conformance/1");
      expect(vector.description).toContain("Synthetic");
      expect(vector.expected).toMatchObject({
        verified: true,
        artifacts_checked: 2,
        key_id: KEY_ID,
        reproducibility: "reproduction_ready",
      });

      const verification = verifyDossierProofBundle({
        dossier_payload: vector.dossier_payload,
        public_jwks: jwks,
      });
      expect(verification, `${file}: dossier verification failed`).toMatchObject({
        verified: true,
        available: true,
        key_id: KEY_ID,
        artifacts_checked: vector.expected.artifacts_checked,
      });
      expect(verification.checks.every(({ verified }) => verified)).toBe(true);
      expect(assessDossierReproducibility(vector.dossier_payload).posture).toBe(
        vector.expected.reproducibility,
      );

      const proofBundle = record(record(vector.dossier_payload["integrity"])["proof_bundle"]);
      const proofArtifacts = proofBundle["artifacts"] as Array<Record<string, unknown>>;
      expect(proofArtifacts).toHaveLength(vector.expected_artifacts.length);
      for (const expectedArtifact of vector.expected_artifacts) {
        const document = resolveJsonPointer(vector.dossier_payload, expectedArtifact.document_path);
        const canonicalJson = stableJsonStringify(document);
        const digest = createHash("sha256").update(canonicalJson, "utf8").digest("hex");
        expect(canonicalJson, `${file}: canonical bytes changed`).toBe(
          expectedArtifact.canonical_json,
        );
        expect(digest, `${file}: canonical digest changed`).toBe(
          expectedArtifact.canonical_document_sha256,
        );
        expect(proofArtifacts).toContainEqual(
          expect.objectContaining({
            artifact_kind: expectedArtifact.artifact_kind,
            document_path: expectedArtifact.document_path,
            canonical_document_sha256: expectedArtifact.canonical_document_sha256,
            signature: expectedArtifact.signature,
          }),
        );
      }

      const portableArtifact = record(vector.dossier_payload["portable_artifact"]);
      expect(portableArtifact["routing_decision"]).toEqual(
        vector.dossier_payload["routing_decision"],
      );
      expect(portableArtifact["governance"]).toEqual(vector.dossier_payload["governance"]);
      expect(portableArtifact["inputs_snapshot"]).toEqual(
        vector.dossier_payload["inputs_snapshot"],
      );
      outcomes.add(String(record(vector.dossier_payload["routing_decision"])["outcome"]));
    }

    expect(outcomes).toEqual(new Set(["ALLOW", "BLOCK", "ESCALATE"]));
  });

  it("fails closed for a mutated signed artifact or an unrelated JWKS", async () => {
    const vector = await readJson<DossierVector>(new URL("allow.json", VECTORS_DIRECTORY));
    const jwks = await readJson<CorpusJwks>(new URL("corpus-jwks.json", DOSSIERS_DIRECTORY));
    const mutated = structuredClone(vector.dossier_payload);
    const routingDecision = record(record(mutated["portable_artifact"])["routing_decision"]);
    routingDecision["outcome"] = "BLOCK";

    const mutationResult = verifyDossierProofBundle({
      dossier_payload: mutated,
      public_jwks: jwks,
    });
    expect(mutationResult.verified).toBe(false);
    expect(
      mutationResult.checks.some(
        ({ key, verified }) => key === "portable_artifact:sha256" && !verified,
      ),
    ).toBe(true);
    expect(
      mutationResult.checks.some(
        ({ key, verified }) => key === "portable_artifact:signature" && !verified,
      ),
    ).toBe(true);

    const wrongKeyResult = verifyDossierProofBundle({
      dossier_payload: vector.dossier_payload,
      public_jwks: { keys: [] },
    });
    expect(wrongKeyResult).toMatchObject({
      verified: false,
      available: true,
      artifacts_checked: 0,
    });
  });

  it("regenerates byte-identical vectors from the published private key", () => {
    const result = spawnSync(process.execPath, ["scripts/GenerateDossierCorpus.mjs", "--check"], {
      cwd: fileURLToPath(REPOSITORY_ROOT),
      encoding: "utf8",
    });
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Verified 3 reproducible synthetic dossier vectors.");
  });
});
