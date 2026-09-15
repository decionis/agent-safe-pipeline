export default {
  packageManager: "pnpm",
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  // The listener is the door: caller authentication, body bounds, and the
  // refusal shape. The egress policy is the wall: what this process may
  // reach. The hash chain is the evidence's integrity. The registry and the
  // authenticator decide who is who. The journal's fold decides what a
  // restart must resolve, the ceilings decide what this host will never run,
  // and the halt decides whether anything runs at all. Every mutant of each
  // must die.
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
