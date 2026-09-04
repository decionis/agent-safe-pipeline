import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { format } from "prettier";

const DOSSIERS_DIRECTORY = new URL("../dossiers/", import.meta.url);
const VECTORS_DIRECTORY = new URL("../dossiers/vectors/", import.meta.url);
const PRIVATE_KEY_PATH = new URL("../dossiers/synthetic-corpus-private.jwk.json", import.meta.url);
const PUBLIC_JWKS_PATH = new URL("../dossiers/corpus-jwks.json", import.meta.url);
const KEY_ID = "agent-safe-synthetic-dossier-corpus-v1";
const FIXED_TIME = "2026-09-04T10:00:00.000Z";
const FIXTURE_TENANT_ID = "00000000-0000-4000-8000-000000000004";

const CASES = [
  {
    slug: "allow",
    outcome: "ALLOW",
    action: "payment.capture",
    target: "synthetic-merchant-order-1001",
    amountMinor: 4_200,
    reasonCodes: ["SYNTHETIC_POLICY_ALLOW"],
    executionGrantIssued: true,
  },
  {
    slug: "block",
    outcome: "BLOCK",
    action: "deployment.promote",
    target: "synthetic-production-service-1002",
    amountMinor: 0,
    reasonCodes: ["SYNTHETIC_CHANGE_WINDOW_CLOSED"],
    executionGrantIssued: false,
  },
  {
    slug: "escalate",
    outcome: "ESCALATE",
    action: "vendor.payout",
    target: "synthetic-vendor-1003",
    amountMinor: 250_000,
    reasonCodes: ["SYNTHETIC_DUAL_APPROVAL_REQUIRED"],
    executionGrantIssued: false,
  },
];

function canonicalize(value) {
  if (Array.isArray(value)) return value.map((item) => canonicalize(item));
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalize(value[key])]),
  );
}

function stableJsonStringify(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function signedArtifact(privateKey, artifactKind, mediaType, documentPath, document) {
  const canonicalJson = stableJsonStringify(document);
  const digest = sha256(canonicalJson);
  const signature = sign(null, Buffer.from(canonicalJson, "utf8"), privateKey).toString(
    "base64url",
  );
  return {
    proof: {
      artifact_kind: artifactKind,
      media_type: mediaType,
      document_path: documentPath,
      canonical_document_sha256: digest,
      signature,
    },
    expected: {
      artifact_kind: artifactKind,
      document_path: documentPath,
      canonical_json: canonicalJson,
      canonical_document_sha256: digest,
      signature,
    },
  };
}

function createVector(testCase, privateKey) {
  const dossierId = `synthetic-dossier-${testCase.slug}-001`;
  const decisionId = `synthetic-decision-${testCase.slug}-001`;
  const policyId = `synthetic-policy-${testCase.slug}-v1`;
  const rules = {
    policy_id: policyId,
    condition: `synthetic-${testCase.slug}-condition`,
    outcome: testCase.outcome,
  };
  const inputsSnapshot = {
    tenant_id: FIXTURE_TENANT_ID,
    actor_id: "synthetic-dossier-corpus-agent",
    action: testCase.action,
    target: testCase.target,
    amount_minor: testCase.amountMinor,
  };
  const routingDecision = {
    decision_id: decisionId,
    outcome: testCase.outcome,
    authority: "AUTHORITATIVE",
    policy_version: policyId,
    reason_codes: testCase.reasonCodes,
    execution_grant_issued: testCase.executionGrantIssued,
    policy_evaluation: { evaluated_at: FIXED_TIME },
  };
  const governance = {
    policy_snapshot: {
      policy_id: policyId,
      policy_version: policyId,
      rules_sha256: sha256(stableJsonStringify(rules)),
      evaluated_at: FIXED_TIME,
    },
  };
  const portableArtifact = {
    artifact_type: "decionis.decision_dossier.portable",
    version: "2.0",
    dossier_id: dossierId,
    generated_at: FIXED_TIME,
    routing_decision: routingDecision,
    governance,
    inputs_snapshot: inputsSnapshot,
  };
  const jsonLd = {
    "@context": "https://schema.example/decionis/decision-dossier/v2",
    "@type": "DecisionDossier",
    dossierId,
    decisionId,
    decision: testCase.outcome,
    policyVersion: policyId,
    generatedAt: FIXED_TIME,
    intentHash: `sha256:${sha256(stableJsonStringify(inputsSnapshot))}`,
  };
  const artifacts = [
    signedArtifact(
      privateKey,
      "portable_artifact",
      "application/json",
      "/portable_artifact",
      portableArtifact,
    ),
    signedArtifact(privateKey, "json_ld", "application/ld+json", "/json_ld", jsonLd),
  ];
  const dossierPayload = {
    schema_version: "decionis.decision_dossier/2.0",
    dossier_id: dossierId,
    generated_at: FIXED_TIME,
    routing_decision: routingDecision,
    governance,
    inputs_snapshot: inputsSnapshot,
    portable_artifact: portableArtifact,
    json_ld: jsonLd,
    integrity: {
      proof_bundle: {
        bundle_type: "decionis.decision_dossier.proof_bundle",
        version: "2.0",
        issued_at: FIXED_TIME,
        algorithm: "Ed25519",
        key_id: KEY_ID,
        rotation_policy: {
          strategy: "STATIC_PUBLIC_CORPUS_KEY",
          active_key_id: KEY_ID,
          previous_key_ids: [],
          verification_grace_period_days: 0,
          rotated_at: null,
          public_jwks_path: "/dossiers/corpus-jwks.json",
        },
        artifacts: artifacts.map(({ proof }) => proof),
      },
    },
  };

  return {
    vector_version: "agent-safe.decision-dossier-conformance/1",
    description: `Synthetic ${testCase.outcome} Decision Dossier with portable JSON and JSON-LD artifacts.`,
    expected: {
      verified: true,
      artifacts_checked: artifacts.length,
      key_id: KEY_ID,
      reproducibility: "reproduction_ready",
    },
    expected_artifacts: artifacts.map(({ expected }) => expected),
    dossier_payload: dossierPayload,
  };
}

async function render(value) {
  return await format(JSON.stringify(value), { parser: "json", endOfLine: "lf" });
}

async function expectedFiles() {
  const privateJwk = JSON.parse(await readFile(PRIVATE_KEY_PATH, "utf8"));
  if (
    privateJwk.kty !== "OKP" ||
    privateJwk.crv !== "Ed25519" ||
    privateJwk.alg !== "EdDSA" ||
    privateJwk.use !== "sig" ||
    privateJwk.kid !== KEY_ID ||
    typeof privateJwk.d !== "string"
  ) {
    throw new Error("DOSSIER_CORPUS_PRIVATE_KEY_INVALID");
  }

  const privateKey = createPrivateKey({ key: privateJwk, format: "jwk" });
  const exportedPublicJwk = createPublicKey(privateKey).export({ format: "jwk" });
  const publicJwk = {
    crv: exportedPublicJwk.crv,
    x: exportedPublicJwk.x,
    kty: exportedPublicJwk.kty,
    alg: "EdDSA",
    use: "sig",
    kid: KEY_ID,
  };
  const files = new Map([[PUBLIC_JWKS_PATH, await render({ keys: [publicJwk] })]]);
  for (const testCase of CASES) {
    files.set(
      new URL(`${testCase.slug}.json`, VECTORS_DIRECTORY),
      await render(createVector(testCase, privateKey)),
    );
  }
  return files;
}

async function check(files) {
  const failures = [];
  for (const [path, expected] of files) {
    let actual;
    try {
      actual = await readFile(path, "utf8");
    } catch {
      failures.push(`${path.pathname}: missing`);
      continue;
    }
    if (actual !== expected) failures.push(`${path.pathname}: differs from regenerated corpus`);
  }

  const expectedVectorNames = new Set(CASES.map(({ slug }) => `${slug}.json`));
  const actualVectorNames = (await readdir(VECTORS_DIRECTORY)).filter((name) =>
    name.endsWith(".json"),
  );
  for (const name of actualVectorNames) {
    if (!expectedVectorNames.has(name)) failures.push(`${name}: unexpected dossier vector`);
  }
  if (failures.length > 0) throw new Error(failures.join("\n"));
}

async function write(files) {
  await mkdir(DOSSIERS_DIRECTORY, { recursive: true });
  await mkdir(VECTORS_DIRECTORY, { recursive: true });
  await Promise.all([...files].map(async ([path, contents]) => await writeFile(path, contents)));
}

const files = await expectedFiles();
if (process.argv.includes("--check")) {
  await check(files);
  process.stdout.write(`Verified ${CASES.length} reproducible synthetic dossier vectors.\n`);
} else {
  await write(files);
  process.stdout.write(
    `Regenerated ${CASES.length} synthetic dossier vectors and their public JWKS.\n`,
  );
}
