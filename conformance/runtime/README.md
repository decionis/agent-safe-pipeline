# Cross-runtime conformance

Deployment-independent enforcement, as a vector.

AgentSafe ships as a Homebrew formula, a Linux package, a container, a Helm chart, an npm package
and a single-file executable. The claim this directory holds it to is one sentence:

> The same intent, under the same policy, with the same trusted signals, produces the same
> authority outcome wherever AgentSafe runs.

## What is and is not expected to be identical

This is the nuance worth stating precisely, because the naive version of the claim is false.

**Identical, in every runtime:** the verdict, the gateway state, the execution disposition, the
reason codes, and the `action` the authority decided over.

**Expected to differ:** the intent hash, and the `enforcement_boundary` and `workload` inside the
context. Each runtime binds its own — that is what those signals are for. A container reports a
digest a pod does not; a pod reports a namespace a laptop does not.

So four runtimes produce four different hashes and one decision. **A different hash is not a
different decision.** If the hashes were identical the signals would not be bound, and if the
verdicts differed the boundary would depend on where it happened to be installed.

## The suite

`demo-policy.json` carries the runtimes, the cases and the expectation. The runner is
`packages/agentsafe/test/conformance/CrossRuntime.test.ts`, and it is not a simulation: each
runtime is a real `Gateway` built from a real configuration, in enforcement, against one
`LocalAuthority` on loopback running the demo policy, with the request going through the ordinary
lifecycle.

| Runtime      | What it stands for                                                           |
| ------------ | ---------------------------------------------------------------------------- |
| `native`     | a host or a laptop; nothing describes an artifact, so no `workload` is bound |
| `docker`     | a container whose operator declared the image and digest                     |
| `kubernetes` | a pod with the downward API wired, and a different digest                    |
| `hosted`     | the runtime installed from npm, in front of the same upstream                |

The Kubernetes shape declares a pod and a node deliberately: the suite asserts they appear in no
bound boundary, because an effect's evidence should name the boundary that admitted it and not the
pod that happened to serve it.

## Adding a runtime

Add an entry to `runtimes` with its surface and the environment that runtime would set. Nothing
else changes: the cases and the expectation are shared, which is the point.

## See also

- [The enforcement boundary](../../docs/authority/enforcement-boundary.md)
- [Workload provenance](../../docs/authority/workload-provenance.md)
- [`conformance/vectors/`](../vectors) — the canonicalization and hash vectors
