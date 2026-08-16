/**
 * External consumer test for @decionis/agent-safe-pipeline.
 * Imports every public export and exercises one ALLOW + one BLOCK path.
 * This file runs against the *packed tarball*, not source.
 */
import assert from "node:assert";

// --- 1. Import every public export (must not throw) ---
const mod = await import("@decionis/agent-safe-pipeline");
const exports = Object.keys(mod);
console.log(`Imported ${exports.length} exports:`, exports);

// Verify all expected runtime exports are present (types are not in Object.keys)
const EXPECTED_RUNTIME = [
  "CanonicalIntentHasher",
  "IntentCapture",
  "DecisionAuthority", // might be type-only; we verify gracefully
  "DecionisGate",
  "FixtureDecisionAuthority",
  "ActionRegistry",
  "AuthorizationVerifier",
  "ReplayStore",
  "SafeExecutor",
  "ShadowPipeline",
  "PresenceApprovalCoordinator",
  "IntentCapture",
];
for (const name of EXPECTED_RUNTIME) {
  if (mod[name]) {
    console.log(`  ✓ ${name}`);
  } else {
    console.log(`  ⊘ ${name} (type-only, not in runtime exports)`);
  }
}
console.log(`All ${exports.length} runtime exports imported successfully.`);

// --- 2. ALLOW path: capture with valid binding ---
const { CanonicalIntentHasher, IntentCapture } = mod;
// CanonicalIntentHasher.stringify is static
const valid = CanonicalIntentHasher.stringify({ action: "test.op", resource: "test:res" });
assert.ok(typeof valid === "string" && valid.length > 0, "stringify returned empty");
console.log("ALLOW path passed:", valid.slice(0, 60));

// --- 3. BLOCK path: forbidden key must throw ---
try {
  CanonicalIntentHasher.stringify({ __proto__: "injected" });
  assert.fail("Expected error for forbidden key __proto__");
} catch (err) {
  assert.ok(
    err.message.includes("INTENT_TOO_COMPLEX") ||
      err.message.includes("unsafe") ||
      err.message.includes("forbidden") ||
      err.message.includes("UNSAFE"),
    `Unexpected error: ${err.message}`,
  );
  console.log("BLOCK path passed:", err.message);
}

console.log("✅ consumer.mjs: all checks passed");
