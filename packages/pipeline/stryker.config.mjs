export default {
  packageManager: "pnpm",
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  // GovernedExecutionRunner is the boundary: SafeExecutor is its registry
  // face, the registry executor is how the runtime reaches it, and the
  // Postgres journal is the durable claim and the single-use idempotency key
  // replicas share. The bundle window decides when an edge
  // bundle may be evaluated and when the next one is fetched, and the local
  // authorization verifier decides whether an edge ALLOW runs, and only once:
  // a mutant in either is an execution on a lapsed bundle or a replay. The
  // Postgres replay store is single use shared by replicas: a mutant there is
  // the same intent claimed twice, on two replicas.
  mutate: [
    "src/execution/SafeExecutor.ts",
    "src/execution/GovernedExecutionRunner.ts",
    "src/execution/RegistryExecutor.ts",
    "src/execution/PostgresExecutionJournal.ts",
    "src/decision/edge/BundleWindow.ts",
    "src/execution/LocalAuthorizationVerifier.ts",
    "src/execution/PostgresReplayStore.ts",
  ],
  reporters: ["clear-text", "progress"],
  coverageAnalysis: "perTest",
  thresholds: { high: 100, low: 100, break: 100 },
  vitest: { configFile: "vitest.config.ts" },
};
