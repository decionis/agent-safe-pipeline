export default {
  packageManager: "pnpm",
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  // The listener is the door: caller authentication, body bounds, and the
  // refusal shape. The egress policy is the wall: what this process may
  // reach. The hash chain is the evidence's integrity. Every mutant of
  // each must die.
  mutate: [
    "src/http/ExecutorHttpServer.ts",
    "src/egress/EgressPolicy.ts",
    "src/audit/HashChain.ts",
  ],
  reporters: ["clear-text", "progress"],
  coverageAnalysis: "perTest",
  thresholds: { high: 100, low: 100, break: 100 },
  vitest: { configFile: "vitest.config.ts" },
};
