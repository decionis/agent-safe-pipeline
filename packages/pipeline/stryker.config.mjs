export default {
  packageManager: "pnpm",
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  // SafeExecutor is the boundary. The bundle window decides when an edge
  // bundle may be evaluated and when the next one is fetched, and the local
  // authorization verifier decides whether an edge ALLOW runs, and only once:
  // a mutant in either is an execution on a lapsed bundle or a replay.
  mutate: [
    "src/execution/SafeExecutor.ts",
    "src/decision/edge/BundleWindow.ts",
    "src/execution/LocalAuthorizationVerifier.ts",
  ],
  reporters: ["clear-text", "progress"],
  coverageAnalysis: "perTest",
  thresholds: { high: 100, low: 100, break: 100 },
  vitest: { configFile: "vitest.config.ts" },
};
