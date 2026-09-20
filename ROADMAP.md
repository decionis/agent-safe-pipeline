# Roadmap

This roadmap is current as of 2026-09-20. It distinguishes work maintainers intend to deliver from
ideas that still require design or resourcing. It is not a promise of dates or hosted-service
availability; priorities can change when security or compatibility work intervenes.

## Released

- `v0.1.0` established immutable intent capture, independent ALLOW/ESCALATE/BLOCK decisions,
  Presence evidence, single-use execution grants, and a sealed trusted action registry.
- `v0.1.2` added a verifiable release path with SBOM, license inventory, provenance, checksums, and
  clean-consumer installation.
- `v0.1.3` added signed release tags, reproducible package builds, citable release metadata, and a
  synthetic Decision Dossier conformance corpus.
- `v0.1.4` conformed the pipeline to the Decionis execution contract with a wire-contract harness
  and packed-package public API comparison, isolated test-only authorization helpers behind the
  `@decionis/agent-safe-pipeline/testing` subpath, made shadow evaluation failure-isolated, bounded,
  and observational, modelled auditable provider outcomes, added local and managed Presence
  escalation demos, and housed the CommerceGate MCP (`@decionis/commerce`) in
  `packages/commerce-mcp` ([tag v0.1.4](https://github.com/decionis/agent-safe-pipeline/releases/tag/v0.1.4)).
- `v0.2.0` made the runtime installable (`@decionis/agentsafe`: `agentsafe proxy`, the boundary
  test, Homebrew, Linux packages, an installer, the image, the Helm chart) and put the hosted gate
  in every example's run path: one variable, a key issued in the run, and each run ending with the
  signed Decision Dossier Decionis left.
- `v0.3.0` stated the provider's half as the Verifying Provider Profile, with implementations for
  Envoy, Kong, Spring, .NET and Rust, made its effect receipt normative (`v0.2`, the Kong plugin
  signing it in the response phase and the executor comparing a receipt with its own observation),
  and added the Compromised Principal Test as a canonical example, a conformance vector and a
  stated threat ([tag v0.3.0](https://github.com/decionis/agent-safe-pipeline/releases/tag/v0.3.0)).

See [GitHub Releases](https://github.com/decionis/agent-safe-pipeline/releases) and the
[release-verification guide](./CONTRIBUTING.md#releases) for immutable artifacts and verification
instructions.

## Committed next work

Committed means accepted maintenance or security work that maintainers intend to complete. It does
not imply a release date.

- Continue closing documented OpenSSF Silver evidence gaps without overstating controls that are
  not yet independently exercised.
- Keep the trusted executor image at one digest under its two names, `ghcr.io/decionis/agentsafe`
  (pushed and attested by every release since `v0.2.0`) and `docker.io/decionis/agentsafe` (copied
  by digest and attested by the `Docker Hub image` workflow from the first release after its
  credential is set), so the kit under `deploy/` can be verified before it is mirrored; the executor
  itself is `@decionis/agentsafe` in `packages/agentsafe`.
- Turn the trusted executor into a bank security boundary in eight pull requests
  ([#136](https://github.com/decionis/agent-safe-pipeline/issues/136)): the package promotion,
  verified host posture and secret handling, sealed egress with chained evidence, caller principals,
  a durable attempt journal with a halt switch and host ceilings, an adapter tree whose first family
  speaks the BEAP v0.1 vocabulary, a conformance-tested deployment kit, and incident-response
  capabilities with offline drills. Each phase says "verified" or "shipped" where that is what it
  is, and never claims a control the host still owns.

- Make native verification a deployment location rather than a product: the
  [Verifying Provider Profile](./docs/authority/verifying-provider.md) states the provider's half
  of the boundary normatively, with [vectors](./conformance/provider/README.md) any implementation
  runs and independent verifiers that run them, for [Envoy `ext_authz`](./verifiers/envoy/README.md)
  and [Kong](./verifiers/kong/README.md) in Go, for
  [Spring and an Apigee callout](./verifiers/spring/README.md) in Java, for
  [Rust services](./verifiers/rust/README.md) with a tower layer, and for
  [ASP.NET Core](./verifiers/dotnet/README.md); and, now that the Decionis OpenAPI carries it,
  the effect receipt (VP-3): each verifier builds one, the executor forwards it at finalization,
  and the authority verifies and records it, so the effect plane is provider-attested rather than
  executor-reconciled; the Kong plugin signs one in its response phase for a system of record that
  reports its effect to the hop, and the executor's effect plane compares what a receipt states
  with what it observed itself, so two witnesses' disagreement is an exception rather than a
  silence.

The open issue tracker is the source of truth for scope, acceptance criteria, and progress. An item
leaves this section when it is released, rejected with rationale, or explicitly moved back to
exploration.

## Exploratory

Exploratory items have no delivery commitment. They require protocol, threat-model, or ecosystem
validation before maintainers accept an implementation plan.

- Cross-language implementations of the canonical intent and execution-evidence contracts.
- Additional provider adapters and deployment reference architectures.
- Decision-chain visualization and offline audit tooling beyond the current dossier verifier.
- A future stable `1.0` compatibility contract after real integration feedback.

## Updating this roadmap

Roadmap changes use reviewed pull requests. Each change must preserve the distinction between
released, committed, and exploratory work; link a tracking issue for newly committed scope; and
avoid dates unless an accountable maintainer has accepted them. Release pull requests move shipped
items to **Released** and link the resulting tag or release evidence.
