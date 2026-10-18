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
  "AuthorityPaths",
  "BoundaryPlacementSchema",
  "CanonicalIntentHasher",
  "DEFAULT_JOURNAL_TABLE",
  "DEFAULT_REPLAY_TABLE",
  "DecionisGate",
  "DecionisGrantVerifier",
  "DossierFetchError",
  "DownstreamTargetSchema",
  "EDGE_MODULE_ABI_VERSION",
  "EXECUTOR_EVIDENCE_VERSION",
  "EdgeBundleManager",
  "EdgeDecisionAuthority",
  "EdgeModule",
  "EdgeModuleError",
  "EnforcementBoundarySignalSchema",
  "ExecutionCapabilitySchema",
  "ExecutionIntentSchema",
  "ExecutionOutcomeSchema",
  "ExecutionRequestSchema",
  "ExecutionResponseSchema",
  "ExecutionSignalsSchema",
  "ExecutorEvidenceLineSchema",
  "ExecutorIdentitySchema",
  "ExecutorVectorSchema",
  "FailClosedDecision",
  "FileBundleSource",
  "FixtureAuthorizationVerifier",
  "FixtureDecisionAuthority",
  "GovernedExecutionRunner",
  "HOSTED_HINT",
  "IDEMPOTENCY_KEY_DISPATCHED",
  "INTENT_SCHEMA_ID",
  "InMemoryReplayStore",
  "IndeterminateOutcome",
  "IntentActorSchema",
  "IntentCapture",
  "JOURNAL_VERSION",
  "JournalError",
  "JournalRecordSchema",
  "JsonObjectSchema",
  "JsonValueSchema",
  "LocalAuthorizationVerifier",
  "LocalGrants",
  "MonotonicDeadline",
  "NATIVE_EXECUTOR_CONTRACT",
  "NATIVE_EXECUTOR_SCHEMA_ID",
  "NativeReceiptSchema",
  "PostgresExecutionJournal",
  "PostgresReplayStore",
  "PreDispatchRefusal",
  "PresenceApprovalCoordinator",
  "ProviderRefusal",
  "ProvisionError",
  "RESERVED_CONTEXT_BOUNDARY",
  "RESERVED_CONTEXT_IDEMPOTENCY_KEY",
  "RESERVED_CONTEXT_KEYS",
  "RESERVED_CONTEXT_WORKLOAD",
  "ReceiptResponseSchema",
  "ReconciliationRequestSchema",
  "ReconciliationResponseSchema",
  "RegistryExecutor",
  "STRICT_POSTURE",
  "SafeExecutor",
  "ShadowGate",
  "ShadowPipeline",
  "TrustedIntentContextSchema",
  "UrlBundleSource",
  "WORKLOAD_TRUST_LEVELS",
  "WorkloadProvenanceSchema",
  "WorkloadSignalSchema",
  "authorizationsFrom",
  "boundaryOf",
  "createFixtureAuthorityPair",
  "createGate",
  "createHostedGate",
  "credentialsDirectory",
  "credentialsPath",
  "dispatchBudgetMs",
  "dispatchedUnderFrom",
  "evidenceScope",
  "fetchSignedDossier",
  "hostedRequested",
  "intentBindingJsonSchema",
  "nativeExecutorJsonSchema",
  "nodeCredentialFiles",
  "openAttemptsFrom",
  "printDecision",
  "printHostedOutcome",
  "printSignedDossier",
  "provisionWorkspace",
  "readStoredCredentials",
  "resolveHostedCredentials",
  "signalContext",
  "summarizeDossier",
  "unavailableDisposition",
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
