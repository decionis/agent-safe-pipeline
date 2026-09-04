import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { format } from "prettier";

const DOSSIERS_DIRECTORY = new URL("../dossiers/", import.meta.url);
const VECTORS_DIRECTORY = new URL("../dossiers/vectors/", import.meta.url);
const PRIVATE_KEY_PATH = new URL("../dossiers/synthetic-corpus-private.jwk.json", import.meta.url);
const PUBLIC_JWKS_PATH = new URL("../dossiers/corpus-jwks.json", import.meta.url);
const KEY_ID = "agent-safe-synthetic-dossier-corpus-v1";
const FIXED_TIME = "2026-09-04T10:00:00.000Z";
const FIXED_EXPIRY = "2026-09-04T10:05:00.000Z";
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
  {
    slug: "owned-execution-bound",
    outcome: "ALLOW",
    action: "wire.transfer",
    target: "synthetic-account-daily-limit-1004",
    amountMinor: 125_000,
    reasonCodes: ["SYNTHETIC_EXECUTION_BINDING_VALID"],
    executionGrantIssued: true,
    issuerTier: "owned",
    executionBound: true,
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

function jcsCanonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JCS_NUMBER_MUST_BE_FINITE");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => jcsCanonicalize(item)).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${jcsCanonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("JCS_VALUE_MUST_BE_JSON");
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function signedArtifact(
  privateKey,
  artifactKind,
  mediaType,
  documentPath,
  document,
  canonicalizationProfile,
) {
  const canonicalJson =
    canonicalizationProfile === "RFC8785/JCS"
      ? jcsCanonicalize(document)
      : stableJsonStringify(document);
  const digest = sha256(canonicalJson);
  const signature = sign(null, Buffer.from(canonicalJson, "utf8"), privateKey).toString(
    "base64url",
  );
  return {
    proof: {
      artifact_kind: artifactKind,
      media_type: mediaType,
      document_path: documentPath,
      ...(canonicalizationProfile ? { canonicalization_profile: canonicalizationProfile } : {}),
      canonical_document_sha256: digest,
      signature,
    },
    expected: {
      artifact_kind: artifactKind,
      document_path: documentPath,
      ...(canonicalizationProfile ? { canonicalization_profile: canonicalizationProfile } : {}),
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
  const issuerContext = testCase.issuerTier ? { tier: testCase.issuerTier } : null;
  const portableArtifact = {
    artifact_type: "decionis.decision_dossier.portable",
    version: "2.0",
    dossier_id: dossierId,
    generated_at: FIXED_TIME,
    routing_decision: routingDecision,
    governance,
    inputs_snapshot: inputsSnapshot,
    ...(issuerContext
      ? {
          machine_readable: {
            issuer_context: issuerContext,
          },
        }
      : {}),
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
  const executionBinding = testCase.executionBound
    ? {
        binding_schema_version: "1.0",
        dossier_id: dossierId,
        evaluation_id: decisionId,
        payload: {
          digest: `sha256:${sha256(jcsCanonicalize(inputsSnapshot))}`,
          digest_algorithm: "SHA-256",
          canonicalization_profile: "RFC8785/JCS",
        },
        execution_target: {
          system: "synthetic-bank-core",
          environment: "synthetic-production",
          operation: testCase.action,
          resource: testCase.target,
          endpoint: "/synthetic/wires",
        },
        policy: {
          identifier: policyId,
          version: policyId,
          digest: `sha256:${sha256(jcsCanonicalize(rules))}`,
          digest_algorithm: "SHA-256",
        },
        material_signals: [
          {
            signal_id: "synthetic-daily-limit-signal",
            version: "synthetic-signal-v1",
            observed_at: FIXED_TIME,
            value_digest: `sha256:${sha256(jcsCanonicalize({ remaining_minor: 500_000 }))}`,
            evidence_digest: null,
          },
        ],
        issued_at: FIXED_TIME,
        not_before: FIXED_TIME,
        expires_at: FIXED_EXPIRY,
        nonce: "s".repeat(43),
        idempotency_key: "fixture_0001",
        execution_correlation_id: "synthetic-execution-correlation-owned-001",
        concurrency_scope_digest: `sha256:${sha256(
          jcsCanonicalize({ resource: testCase.target }),
        )}`,
        authorization_state_digest: `sha256:${sha256(
          jcsCanonicalize({ policy: policyId, outcome: testCase.outcome }),
        )}`,
        presence_approval: null,
      }
    : null;
  const artifacts = [
    signedArtifact(
      privateKey,
      "portable_artifact",
      "application/json",
      "/portable_artifact",
      portableArtifact,
    ),
    signedArtifact(
      privateKey,
      "inputs_snapshot",
      "application/json",
      "/inputs_snapshot",
      inputsSnapshot,
    ),
    signedArtifact(privateKey, "json_ld", "application/ld+json", "/linked_data/document", jsonLd),
    ...(executionBinding
      ? [
          signedArtifact(
            privateKey,
            "execution_binding",
            "application/json",
            "/execution_binding",
            executionBinding,
            "RFC8785/JCS",
          ),
        ]
      : []),
  ];
  const dossierPayload = {
    schema_version: executionBinding
      ? "decionis.decision_dossier/2.1"
      : "decionis.decision_dossier/2.0",
    dossier_id: dossierId,
    generated_at: FIXED_TIME,
    routing_decision: routingDecision,
    governance,
    inputs_snapshot: inputsSnapshot,
    portable_artifact: portableArtifact,
    linked_data: { document: jsonLd },
    ...(executionBinding ? { execution_binding: executionBinding } : {}),
    integrity: {
      proof_bundle: {
        bundle_type: "decionis.decision_dossier.proof_bundle",
        version: executionBinding ? "2.1" : "2.0",
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
    description: executionBinding
      ? "Synthetic ALLOW Decision Dossier from an owned workspace with signed portable JSON, inputs snapshot, JSON-LD, and RFC 8785/JCS execution-binding artifacts."
      : `Synthetic ${testCase.outcome} Decision Dossier with signed portable JSON, inputs snapshot, and JSON-LD artifacts.`,
    expected: {
      verified: true,
      artifacts_checked: artifacts.length,
      key_id: KEY_ID,
      reproducibility: "reproduction_ready",
      proof_bundle_version: executionBinding ? "2.1" : "2.0",
      issuer: issuerContext
        ? {
            tier: testCase.issuerTier,
            unknown_tier: null,
            signature_covered: true,
            provisional: false,
            label: "Owned workspace",
          }
        : {
            tier: null,
            unknown_tier: null,
            signature_covered: false,
            provisional: false,
            label: "Issuer not stated",
          },
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
