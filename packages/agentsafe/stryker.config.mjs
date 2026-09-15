export default {
  packageManager: "pnpm",
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  // Every mutant of each of these must die, and this list is exactly what the
  // gate covers. Each file is one place where a single wrong operator would
  // be a security failure rather than a bug:
  //
  // The listener is the door: caller authentication, body bounds, the refusal
  // shape. The registry decides which credential is whose, and the
  // authenticator decides in which order a request is turned away. The egress
  // policy is the wall: what this process may reach at all. The hash chain is
  // the evidence's integrity. The journal's fold decides what a restart must
  // resolve, the ceilings decide what this host will never run whatever
  // policy says, and the halt decides whether anything runs. The canonical
  // digest decides what two implementations agree a value is, and the
  // comparison decides whether an observed effect is the authorised one.
  // Money is arithmetic that must not round. The banking binder is the gate
  // between the transport and the profile: a mutant there is a caller
  // describing one thing and asking for another. The containment probe is
  // here because its failure mode is false assurance: a mutant that reads a
  // reachable system of record as contained tells an operator the boundary
  // holds when it does not. The signed-request credential is here for the
  // same reason from the other side: its `verify` is the procedure a system
  // of record copies, and a mutant that accepts a signature it should refuse
  // is a provider that effects what the authority never claimed.
  mutate: [
    "src/http/ExecutorHttpServer.ts",
    "src/identity/PrincipalRegistry.ts",
    "src/identity/Authenticator.ts",
    "src/egress/EgressPolicy.ts",
    "src/audit/HashChain.ts",
    "src/journal/ExecutionJournal.ts",
    "src/limits/HardLimits.ts",
    "src/incident/HaltSwitch.ts",
    "src/adapters/JcsDigest.ts",
    "src/adapters/EffectComparison.ts",
    "src/adapters/banking/Money.ts",
    "src/adapters/banking/BankingIntentBinder.ts",
    "src/containment/ContainmentProbe.ts",
    "src/credential/SignedRequestCredential.ts",
  ],
  reporters: ["clear-text", "progress"],
  coverageAnalysis: "perTest",
  thresholds: { high: 100, low: 100, break: 100 },
  vitest: { configFile: "vitest.config.ts" },
};
