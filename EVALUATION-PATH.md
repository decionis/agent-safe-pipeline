# Evaluation path

How to evaluate this repository as an adopter: which artefact you are looking at, who owns which
control, what each piece of evidence establishes and what it does not, and what to run. Every
sentence here that makes a claim is taken from the document that owns it and links to it; this page
adds no capability claim of its own.

## The artefact

The reference implementation is one artefact in three forms:

- the published package `@decionis/agent-safe-pipeline` on npm, whose `latest` dist-tag is the
  supported release;
- the matching GitHub release and its signed tag, with the tarball, SBOM, inventories, checksums,
  Sigstore bundles and provenance attached
  ([releases](https://github.com/decionis/agent-safe-pipeline/releases));
- the archived, citable copy under the Zenodo concept DOI
  [`10.5281/zenodo.22312955`](https://doi.org/10.5281/zenodo.22312955).

The repository also holds `@decionis/commerce`, a local MCP server over the CommerceGate contract,
and a synthetic Decision Dossier corpus under `dossiers/`. It holds no hosted service: "This
repository is a library and runnable reference implementation, not a hosted authorization
service."

## Which version you are looking at

Two things carry a version and they are not the same thing. The npm `latest` dist-tag and the
GitHub Releases page name the published release; `master` is "Unreleased … Development … not a
supported release" ([MAINTENANCE.md](./MAINTENANCE.md)). A document read on `master` may describe
behaviour that the published package does not yet ship. When you cite what the package does, cite
the release; when you cite what the repository says, cite the commit. `llms.txt` closes with the
same rule: "Do not infer availability of an npm release from the source version."

## Who owns which control

Three parties hold controls, and the seam between them is written down in
[OPEN-CORE.md](./OPEN-CORE.md).

| Control                                                                                                                         | Owner                                                                                                       | Where it is stated                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Intent capture, the gate client, the trusted executor, claim-before-handler dispatch, the audit contract, shadow mode           | This library (Apache-2.0)                                                                                   | [OPEN-CORE.md](./OPEN-CORE.md), [ARCHITECTURE.md](./ARCHITECTURE.md)                                      |
| Policy evaluation, grant issuance and atomic consumption, Decision Dossier signing and retention, Presence receipt verification | The authority behind `DecionisGate`: the Decionis service, or your own implementation of the two interfaces | [OPEN-CORE.md](./OPEN-CORE.md) "The seam"                                                                 |
| Executor isolation, agent egress denial, provider credential scoping, monitoring of direct provider calls, incident response    | Your host                                                                                                   | [THREAT-MODEL.md](./THREAT-MODEL.md) "Accepted risks", [docs/trust-boundary.md](./docs/trust-boundary.md) |

Two sentences to keep. "Anyone can implement the interfaces. The library does not check a plan,
key, or entitlement." And: "There is no open-source production policy engine in this repository
today. A production deployment needs a `DecisionAuthority` and `AuthorizationVerifier`
implementation: the Decionis service, or your own implementation of the interfaces above." Neither
a compulsory-service description nor a fully self-hosted-production description is accurate; the
seam is the accurate description.

The fixture authority is a development aid, not a smaller product: it "refuses to construct under
`NODE_ENV=production` by design: it is a test double, not a crippled community edition."

## What each piece of evidence establishes, and what it does not

| Evidence                                                                                                                                                                        | Establishes                                                                                                                                                                                                                            | Does not establish                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `pnpm verify` green in CI on a commit                                                                                                                                           | That commit passed formatting, lint, metadata, fixture, corpus, licence, security, discovery, performance, type, automation, unit and build checks on a clean checkout                                                                 | Anything about the published package unless the commit is the release commit; independent certification                     |
| The executor test "allows exactly one execution under one grant across 100 concurrent claims"                                                                                   | Under the in-process replay store and the fixture authority, one grant admits one execution however many claims race for it                                                                                                            | Throughput, latency, or behaviour of a distributed consume service; production uses the authority's atomic consume endpoint |
| The self-checking demos (`examples/golden-adversarial-demo`, `examples/whisper-boundary-demo`, `examples/crm-outreach-demo`), run by `pnpm examples:prove` in the CI verify job | Against synthetic policy, a fixture authority and in-process doubles, every legitimate leg executed once and every attack leg did not execute; each demo exits non-zero on any failed leg, and CI runs all three on every pull request | That a hosted integration exists; that any real provider, model, or deployment behaves this way                             |
| The synthetic Decision Dossier corpus (`dossiers/`)                                                                                                                             | The offline verification contract: exact canonical bytes, digests, detached Ed25519 signatures and a public JWKS regenerate and verify                                                                                                 | That a production dossier verifies; that needs a live dossier and the live JWKS, and neither is committed here              |
| [SECURITY-EVIDENCE.md](./SECURITY-EVIDENCE.md)                                                                                                                                  | A control-to-artifact map with the command that checks each row, and the published gaps                                                                                                                                                | Independent certification; the OpenSSF record is a public self-assessment                                                   |
| [ROADMAP.md](./ROADMAP.md)                                                                                                                                                      | What is released, committed, and exploratory, and the rule that a release moves items between them                                                                                                                                     | Dates, or hosted-service availability                                                                                       |
| A Decision Dossier identifier on an executed result                                                                                                                             | Which decision the attempt correlates to; see [docs/decision-dossiers.md](./docs/decision-dossiers.md)                                                                                                                                 | An execution credential, or that the underlying business judgement was right                                                |

## Beside what you already run

This library does not replace the systems an adopter already has; it sits at one point between
them. A policy engine or an authority decides; this library makes sure nothing consequential
executes without that decision at the moment of action, and that the decision is bound to the
exact action. An identity provider says who the actor is; the library takes that identity from
"authenticated server context", never from the model. An approval tool collects a signature;
Presence turns a signature into evidence that a named person approved this exact intent, and the
authority re-evaluates with it, so "Presence never directly authorizes execution." An audit system
stores the record; the library's contribution is that "execution cannot bypass it." Which policy
engine, identity provider, approval tool or audit store is the better one is not a question this
repository answers.

## What to run, in order

1. `pnpm install --frozen-lockfile && pnpm verify` — the release bar, on a clean checkout.
2. `pnpm examples:prove` — the three offline self-checking demos (golden adversarial, whisper
   boundary, CRM outreach); read each `PROVEN` / `NOT PROVEN` line and the exit code.
3. `pnpm dossiers:check` and the corpus README's verifier command — the offline verification
   contract.
4. Read [THREAT-MODEL.md](./THREAT-MODEL.md) "Accepted risks" and decide, for each row, what your
   host supplies as the compensating control. That table is the list of things the library does not
   do for you.
5. Read [docs/shadow-mode.md](./docs/shadow-mode.md) before planning a rollout: shadow mode
   observes what the authority would have decided about actions that already run; it "is an
   adoption path, not a safety control."
