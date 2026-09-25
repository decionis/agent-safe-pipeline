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
  },
  {
    slug: "runtime-signals",
    outcome: "ALLOW",
    action: "payment.send",
    target: "synthetic-beneficiary-1005",
    amountMinor: 50_000,
    reasonCodes: ["SYNTHETIC_POLICY_ALLOW"],
    executionGrantIssued: true,
    issuerTier: "owned",
    // The enforcement boundary that admitted the effect and the workload that
    // proposed it, as they reach evidence: inside the intent, which the inputs
    // snapshot carries as its context, so the proof bundle signs them. The
    // offline verifier needs no change to check them, because it verifies the
    // artifacts it is given rather than a fixed set of fields.
    signals: {
      enforcement_boundary: {
        boundary_id: "synthetic-boundary-prod-eu",
        agentsafe_version: "0.0.0-synthetic",
        protocol_version: "agent-safe.intent/1",
        deployment_type: "kubernetes",
        environment: "synthetic-production",
        conformance_version: "agent-safe-intent-v1",
        placement: { cluster_id: "synthetic-eu-1", namespace: "synthetic-payments" },
      },
      workload: {
        runtime: "kubernetes",
        artifact_type: "oci",
        image: "ghcr.io/example/synthetic-payments-agent:1.4.2",
        digest: `sha256:${"5".repeat(64)}`,
        provenance: { source: "kubernetes", trust_level: "supplied" },
      },
    },
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

/** The ledger outcome each wire verdict is recorded under (Decionis AuthoritySemantics). */
const LEDGER_OUTCOME = { ALLOW: "APPROVE", BLOCK: "REJECT", ESCALATE: "ESCALATE" };

/** Protocol 1.1's evaluator commitments, as the Decionis authority signs them. */
const EVALUATION_SEMANTICS = {
  protocol_version: "1.1",
  evaluator_version: "policy-graph/1.1",
  policy_schema_version: "1.0",
  canonicalization: "RFC8785/JCS",
  digest_algorithm: "SHA-256",
  signal_normalization_version: "external-signal-envelope/1.0",
};

/**
 * One synthetic Decision Dossier in the shape the Decionis authority issues
 * under Protocol 1.1: the signed portable artifact carries the verdict, the
 * immutable policy reference, the evaluator semantics and a commitment to the
 * inputs snapshot, so a verifier can check that the record is complete enough
 * to reproduce. Every ALLOW is execution-eligible and so carries an RFC 8785
 * execution binding (proof bundle 2.1); BLOCK and ESCALATE are not eligible and
 * carry none (2.0). The proof bundle declares the same JWKS_OVERLAP rotation
 * policy production does; the synthetic key itself is published in
 * corpus-jwks.json and passed to a verifier explicitly.
 */
function createVector(testCase, privateKey) {
  const dossierId = `synthetic-dossier-${testCase.slug}-001`;
  const evaluationId = `synthetic-decision-${testCase.slug}-001`;
  const policyId = `synthetic-policy-${testCase.slug}-v1`;
  const verdict = testCase.outcome;
  const executionEligible = verdict === "ALLOW";
  const rules = {
    policy_id: policyId,
    condition: `synthetic-${testCase.slug}-condition`,
    outcome: verdict,
  };
  const parameters = { policy_id: policyId, synthetic_case: testCase.slug };
  const rulesSha256 = sha256(stableJsonStringify(rules));
  const parametersSha256 = sha256(stableJsonStringify(parameters));
  const policySnapshot = {
    policy_bundle_id: policyId,
    policy_version: policyId,
    rules_sha256: rulesSha256,
    parameters_sha256: parametersSha256,
    evaluated_at: FIXED_TIME,
  };
  const policyReference = {
    policy_id: policyId,
    revision_id: policyId,
    version: policyId,
    digest: `sha256:${sha256(
      jcsCanonicalize({
        identifier: policyId,
        version: policyId,
        rules_sha256: rulesSha256,
        parameters_sha256: parametersSha256,
      }),
    )}`,
  };
  // The evaluator's canonical input, which Protocol 1.1 replays, with the
  // proposed action itself embedded as its context.
  const inputsSnapshot = {
    decision_type: testCase.action.toUpperCase().replace(/[.-]/g, "_"),
    amount: testCase.amountMinor / 100,
    risk_score: 0.1,
    channel: "api",
    source: "agent-safe-dossier-corpus",
    policy_version: policyId,
    objective_profile: "synthetic",
    vertical_pack: null,
    workflow_key: null,
    mode: "ENFORCEMENT",
    decision_band: null,
    transaction_type: testCase.action,
    context: {
      tenant_id: FIXTURE_TENANT_ID,
      actor_id: "synthetic-dossier-corpus-agent",
      action: testCase.action,
      target: testCase.target,
      amount_minor: testCase.amountMinor,
      ...(testCase.signals ? { signals: testCase.signals } : {}),
    },
  };
  const inputSnapshotDigest = `sha256:${sha256(jcsCanonicalize(inputsSnapshot))}`;
  const executionBinding = executionEligible
    ? {
        binding_schema_version: "1.0",
        dossier_id: dossierId,
        evaluation_id: evaluationId,
        payload: {
          digest: `sha256:${sha256(jcsCanonicalize(inputsSnapshot.context))}`,
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
          digest: policyReference.digest,
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
        idempotency_key: `fixture_${testCase.slug}`,
        execution_correlation_id: `synthetic-execution-correlation-${testCase.slug}-001`,
        concurrency_scope_digest: `sha256:${sha256(
          jcsCanonicalize({ resource: testCase.target }),
        )}`,
        authorization_state_digest: `sha256:${sha256(
          jcsCanonicalize({ policy: policyId, outcome: verdict }),
        )}`,
        presence_approval: null,
      }
    : null;
  const executionBindingDigest = executionBinding
    ? `sha256:${sha256(jcsCanonicalize(executionBinding))}`
    : null;
  // What the authority committed to, exactly as AuthorityEvidenceSchema
  // states it: the signed portable artifact carries the same fields.
  const authorityEvidence = {
    protocol_version: "1.1",
    evaluation_id: evaluationId,
    dossier_id: dossierId,
    evaluation_mode: "ENFORCEMENT",
    authority_classification: "AUTHORITATIVE",
    verdict,
    execution_eligible: executionEligible,
    policy_reference: policyReference,
    evaluation_semantics: EVALUATION_SEMANTICS,
    input_snapshot_digest: inputSnapshotDigest,
    execution_binding_digest: executionBindingDigest,
  };
  const routingDecision = {
    decision_id: evaluationId,
    evaluation_id: evaluationId,
    outcome: LEDGER_OUTCOME[verdict],
    authority: "AUTHORITATIVE",
    policy_version: policyId,
    policy_snapshot: policySnapshot,
    reason_codes: testCase.reasonCodes,
    execution_grant_issued: testCase.executionGrantIssued,
    policy_evaluation: { evaluated_at: FIXED_TIME },
  };
  const governance = { policy_snapshot: policySnapshot };
  const issuerContext = testCase.issuerTier ? { tier: testCase.issuerTier } : null;
  const portableArtifact = {
    artifact_type: "decionis.decision_dossier.portable",
    version: "2.0",
    dossier_id: dossierId,
    generated_at: FIXED_TIME,
    routing_decision: routingDecision,
    governance,
    inputs_snapshot: inputsSnapshot,
    machine_readable: {
      dossier_id: dossierId,
      evaluation_id: evaluationId,
      protocol_version: "1.1",
      outcome: LEDGER_OUTCOME[verdict],
      policy_version: policyId,
      policy_snapshot: policySnapshot,
      generated_at: FIXED_TIME,
      mode: "ENFORCEMENT",
      verdict,
      authority_classification: "AUTHORITATIVE",
      execution_eligible: executionEligible,
      policy_reference: policyReference,
      evaluation_semantics: EVALUATION_SEMANTICS,
      input_snapshot_digest: inputSnapshotDigest,
      execution_binding_digest: executionBindingDigest,
      ...(issuerContext ? { issuer_context: issuerContext } : {}),
    },
  };
  const jsonLd = {
    "@context": "https://schema.example/decionis/decision-dossier/v2",
    "@type": "DecisionDossier",
    dossierId,
    decisionId: evaluationId,
    decision: verdict,
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
    evaluation_id: evaluationId,
    generated_at: FIXED_TIME,
    routing_decision: routingDecision,
    governance,
    inputs_snapshot: inputsSnapshot,
    portable_artifact: portableArtifact,
    authority_evidence: authorityEvidence,
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
          strategy: "JWKS_OVERLAP",
          active_key_id: KEY_ID,
          previous_key_ids: [],
          verification_grace_period_days: 30,
          rotated_at: null,
          public_jwks_path: "/.well-known/decision-dossier-jwks.json",
        },
        artifacts: artifacts.map(({ proof }) => proof),
      },
    },
  };

  const issuer = issuerContext ? " from an owned workspace" : "";
  return {
    vector_version: "agent-safe.decision-dossier-conformance/1",
    description: executionBinding
      ? `Synthetic ALLOW Decision Dossier (Protocol 1.1)${issuer}, execution-eligible, with signed portable JSON, inputs snapshot, JSON-LD, and an RFC 8785/JCS execution binding.`
      : `Synthetic ${verdict} Decision Dossier (Protocol 1.1) with signed portable JSON, inputs snapshot, and JSON-LD artifacts; not execution-eligible, so it carries no execution binding.`,
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
            // A caller-selected key cannot establish who issued a dossier, so
            // a signed owned-workspace claim is reported as a claim.
            label: "Claimed owned workspace",
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
