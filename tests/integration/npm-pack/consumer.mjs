/**
 * External consumer test for @decionis/agent-safe-pipeline.
 * Imports every public export and exercises one ALLOW + one BLOCK path.
 * This file runs against the *packed tarball*, not source.
 */
import assert from "node:assert";
import console from "node:console";

// --- 1. Import every public export (must not throw) ---
const mod = await import("@decionis/agent-safe-pipeline");
const exports = Object.keys(mod).sort();
console.log(`Imported ${exports.length} exports:`, exports);

// Verify all expected runtime exports are present (types are not in Object.keys)
const EXPECTED_RUNTIME = [
  "ActionRegistry",
  "AgentProposalSchema",
  "AuditPolicyRevisionVerifier",
  "AuditRecorder",
  "AuthorityIntentBindingSchema",
  "BoundaryPlacementSchema",
  "CanonicalIntentHasher",
  "DecionisGate",
  "DecionisGrantVerifier",
  "DossierFetchError",
  "DownstreamTargetSchema",
  "EnforcementBoundarySignalSchema",
  "ExecutionIntentSchema",
  "ExecutionSignalsSchema",
  "FailClosedDecision",
  "FixtureAuthorizationVerifier",
  "FixtureDecisionAuthority",
  "HOSTED_HINT",
  "INTENT_SCHEMA_ID",
  "InMemoryReplayStore",
  "IntentActorSchema",
  "IntentCapture",
  "JsonObjectSchema",
  "JsonValueSchema",
  "PresenceApprovalCoordinator",
  "ProviderRefusal",
  "ProvisionError",
  "RESERVED_CONTEXT_BOUNDARY",
  "RESERVED_CONTEXT_IDEMPOTENCY_KEY",
  "RESERVED_CONTEXT_KEYS",
  "RESERVED_CONTEXT_WORKLOAD",
  "SafeExecutor",
  "ShadowGate",
  "ShadowPipeline",
  "TrustedIntentContextSchema",
  "WORKLOAD_TRUST_LEVELS",
  "WorkloadProvenanceSchema",
  "WorkloadSignalSchema",
  "boundaryOf",
  "createFixtureAuthorityPair",
  "createGate",
  "createHostedGate",
  "credentialsDirectory",
  "credentialsPath",
  "fetchSignedDossier",
  "hostedRequested",
  "intentBindingJsonSchema",
  "nodeCredentialFiles",
  "printDecision",
  "printHostedOutcome",
  "printSignedDossier",
  "provisionWorkspace",
  "readStoredCredentials",
  "resolveHostedCredentials",
  "signalContext",
  "summarizeDossier",
  "workloadOf",
  "writeStoredCredentials",
];
assert.deepStrictEqual(exports, EXPECTED_RUNTIME);
console.log(`All ${exports.length} runtime exports imported successfully.`);

// --- 1b. The local testing entry ships with the tarball ---
const testing = await import("@decionis/agent-safe-pipeline/testing");
for (const name of [
  "LocalAuthority",
  "LocalPresence",
  "createFixtureAuthorityPair",
  "InMemoryReplayStore",
  "hashBinding",
]) {
  assert.ok(name in testing, `testing entry is missing ${name}`);
}
console.log("Testing entry exports present.");

// --- 2. ALLOW path: capture with valid binding ---
const { CanonicalIntentHasher } = mod;
const hasher = new CanonicalIntentHasher();
const validInput = { action: "test.op", resource: "test:res" };
hasher.assertInputBounded(validInput);
const valid = CanonicalIntentHasher.stringify(validInput);
assert.ok(typeof valid === "string" && valid.length > 0, "stringify returned empty");
console.log("ALLOW path passed:", valid.slice(0, 60));

// --- 3. BLOCK path: forbidden key must throw ---
const unsafeInput = JSON.parse('{"safe":{"__proto__":"injected"}}');
assert.throws(
  () => hasher.assertInputBounded(unsafeInput),
  (error) => error instanceof Error && error.message === "UNSAFE_INTENT_KEY",
);
console.log("BLOCK path passed: UNSAFE_INTENT_KEY");

console.log("✅ consumer.mjs: all checks passed");
