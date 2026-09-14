export default {
  packageManager: "pnpm",
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  // The listener is the door: caller authentication, body bounds, and the
  // refusal shape. Every mutant of it must die.
  mutate: ["src/http/ExecutorHttpServer.ts"],
  reporters: ["clear-text", "progress"],
  coverageAnalysis: "perTest",
  thresholds: { high: 100, low: 100, break: 100 },
  vitest: { configFile: "vitest.config.ts" },
};
