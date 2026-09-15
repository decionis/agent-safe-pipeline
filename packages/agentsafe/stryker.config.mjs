export default {
  packageManager: "pnpm",
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  // Every mutant of each of these must die, and this list is exactly what
  // the gate covers. The listener is the door: caller authentication, body
  // bounds, and the refusal shape. The egress policy is the wall: what this
  // process may reach. The hash chain is the evidence's integrity. The
  // canonical digest decides what two implementations agree a value is, and
  // the comparison decides whether an observed effect is the authorised one.
  // Money is arithmetic that must not round. The banking binder is the gate
  // between the transport and the profile: a mutant there is a caller
  // describing one thing and asking for another.
  mutate: [
    "src/http/ExecutorHttpServer.ts",
    "src/egress/EgressPolicy.ts",
    "src/audit/HashChain.ts",
    "src/adapters/JcsDigest.ts",
    "src/adapters/EffectComparison.ts",
    "src/adapters/banking/Money.ts",
    "src/adapters/banking/BankingIntentBinder.ts",
  ],
  reporters: ["clear-text", "progress"],
  coverageAnalysis: "perTest",
  thresholds: { high: 100, low: 100, break: 100 },
  vitest: { configFile: "vitest.config.ts" },
};
