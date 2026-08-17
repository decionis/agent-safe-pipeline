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
  "CanonicalIntentHasher",
  "DecionisGate",
  "DecionisGrantVerifier",
  "DownstreamTargetSchema",
  "ExecutionIntentSchema",
  "FailClosedDecision",
  "FixtureAuthorizationVerifier",
  "FixtureDecisionAuthority",
  "InMemoryReplayStore",
  "IntentActorSchema",
  "IntentCapture",
  "JsonObjectSchema",
  "JsonValueSchema",
  "PresenceApprovalCoordinator",
  "SafeExecutor",
  "ShadowPipeline",
  "TrustedIntentContextSchema",
  "createFixtureAuthorityPair",
];
assert.deepStrictEqual(exports, EXPECTED_RUNTIME);
console.log(`All ${exports.length} runtime exports imported successfully.`);

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
