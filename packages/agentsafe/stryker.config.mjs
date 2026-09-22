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
  // is a provider that effects what the authority never claimed. The verifying
  // provider is the rest of that provider's procedure, the attestation and
  // the single presentation of a grant, and a mutant there is the same
  // failure from the same side. The receipt builder is here because a receipt
  // that copies the wrong claim binds the provider's signature to the wrong
  // grant or claim, and the authority would record it as such. The
  // interceptor's two parsers and the reading built on them are here because
  // they decide where a redirected connection's bytes are sent, from those
  // bytes alone: a mutant that reads a host where there is none, or a
  // different host than the client named, sends a workload's request to a
  // destination the workload never addressed. The leaf issuer and its DER are
  // here because a certificate the governing interceptor presents is the
  // boundary's own claim to be the destination: a leaf that names the wrong
  // host, chains to the wrong issuer, or is not strict DER is one a workload's
  // runtime accepts wrongly or refuses rightly, and a cache that returns a leaf
  // about to expire fails a client at the handshake. The governor is the seam
  // where that leaf is presented and the plaintext handed to the gateway: a
  // mutant there hands bytes past the boundary, or holds a connection the
  // client has left. The boundary identity is here because it is what a
  // Decision Dossier names as having admitted an effect: a mutant that lets
  // an id move with a container, or that carries an ephemeral instance into
  // the signal an intent binds, either attributes an effect to a boundary
  // that never admitted it or writes the host into signed evidence. The
  // provenance contract is here for the claim it makes on AgentSafe's behalf:
  // it decides what trust level reaches a policy, and a mutant that let a
  // declared value through as anything stronger than `supplied` would have
  // this package asserting it verified something it never looked at. The MCP
  // binder is the banking binder's counterpart for tool calls: it decides
  // which action a tool name becomes and which resource the arguments point
  // at, so a mutant there is a model describing one thing and a system of
  // record being asked for another.
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
    "src/verify/VerifyingProvider.ts",
    "src/verify/EffectReceipt.ts",
    "src/intercept/ClientHello.ts",
    "src/intercept/RequestHead.ts",
    "src/intercept/Destination.ts",
    "src/intercept/Der.ts",
    "src/intercept/LeafIssuer.ts",
    "src/http/InterceptGovernor.ts",
    "src/boundary/BoundaryIdentity.ts",
    "src/provenance/ProvenanceProvider.ts",
    "src/adapters/mcp/McpIntentBinder.ts",
  ],
  reporters: ["clear-text", "progress"],
  coverageAnalysis: "perTest",
  thresholds: { high: 100, low: 100, break: 100 },
  vitest: { configFile: "vitest.config.ts" },
};
