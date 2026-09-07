# Roadmap

This roadmap is current as of 2026-09-07. It distinguishes work maintainers intend to deliver from
ideas that still require design or resourcing. It is not a promise of dates or hosted-service
availability; priorities can change when security or compatibility work intervenes.

## Released

- `v0.1.0` established immutable intent capture, independent ALLOW/ESCALATE/BLOCK decisions,
  Presence evidence, single-use execution grants, and a sealed trusted action registry.
- `v0.1.2` added a verifiable release path with SBOM, license inventory, provenance, checksums, and
  clean-consumer installation.
- `v0.1.3` added signed release tags, reproducible package builds, citable release metadata, and a
  synthetic Decision Dossier conformance corpus.

See [GitHub Releases](https://github.com/decionis/agent-safe-pipeline/releases) and the
[release-verification guide](./CONTRIBUTING.md#releases) for immutable artifacts and verification
instructions.

## Committed next work

Committed means accepted maintenance or security work that maintainers intend to complete. It does
not imply a release date.

- Isolate test-only authorization helpers behind an explicit package subpath.
- Add packed-package public API compatibility and real HTTP contract gates.
- Make shadow evaluation failure-isolated, bounded, and unambiguously observational.
- Continue closing documented OpenSSF Silver evidence gaps without overstating controls that are
  not yet independently exercised.

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
