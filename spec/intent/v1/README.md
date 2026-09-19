# Agent-Safe Intent v1

**Identifier:** `agent-safe.intent/1` · **Status:** published, in force · **Publisher:** Decionis ·
**Reference implementation:** `CanonicalIntentHasher` and `IntentCapture` in
[`@decionis/agent-safe-pipeline`](../../../packages/pipeline) · **Schema:**
[`schema.json`](./schema.json) · **Vectors:** [`conformance/`](../../../conformance) ·
**Changes:** [`CHANGELOG.md`](./CHANGELOG.md)

Agent-Safe Intent is the portable statement of one consequential action an agent proposes: who
is acting, on what, with which parameters, through which downstream system, for how long, and
under which retry identity, canonicalized to bytes and digested to one hash. Execution authority
is bound to that hash and to nothing looser. The profile is published by Decionis and implemented
by its reference runtime; it is not a standard approved by any standards body, and nothing here
claims otherwise. Adoption, not this document, earns the word.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119 and RFC 8174.

## 1. Scope

This profile defines three things and only these:

1. **The binding**: the properties of an execution intent and their constraints (§3).
2. **The canonical form**: how a binding becomes one sequence of bytes (§4).
3. **The intent hash**: the digest over those bytes that authority is bound to (§5).

It does not define policy, verdicts, grants, claims, finalization, dossiers or transport. Those
are the Decionis execution-authority contract, which carries this binding as its
`ExecutionIntentBinding` and recomputes the hash on receipt. Where this document and that
contract differ, the contract is authoritative and this document is in error; the changelog
records the correction.

## 2. Terms

- **Agent**: whatever proposes an action. It supplies the action, the target and the parameters,
  and MUST NOT supply anything else in the binding.
- **Producer**: the trusted runtime that captures the proposal, adds the trusted context, and
  computes the binding, the canonical form and the hash. `IntentCapture` is the reference
  producer; a gateway, an executor or an SDK integration is a producer.
- **Authority**: the party that decides over the binding and issues authority for exactly that
  hash. Decionis is the authority the reference runtime asks.
- **Binding**: the JSON object of §3.
- **Canonical form**: the bytes of §4. **Intent hash**: the digest of §5.
- **Mutation**: a binding that differs from another in one property. Every mutation is another
  intent (§6).
- **Vector**: a file under `conformance/` that pins a binding or a JSON object, its canonical
  bytes and its hash, so that two implementations can be shown to agree.

## 3. The binding

The binding is one JSON object with exactly these top-level properties. [`schema.json`](./schema.json)
states the same constraints as JSON Schema 2020-12 and is generated from the reference
implementation's own validator, so the two cannot disagree.

| Property                 | Type   | Required | Supplied by | Constraint                                                                                                                     |
| ------------------------ | ------ | -------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `protocol_version`       | string | yes      | producer    | the literal `agent-safe.intent/1`                                                                                              |
| `tenant_id`              | string | yes      | producer    | UUID of the organization the intent belongs to                                                                                 |
| `intent_id`              | string | yes      | producer    | UUID, fresh per capture; the grant-issuance boundary                                                                           |
| `captured_at`            | string | yes      | producer    | RFC 3339 UTC instant with a `Z` designator, as ECMAScript `toISOString()` writes it                                            |
| `expires_at`             | string | yes      | producer    | as `captured_at`; after it the intent is void, whatever authority was issued                                                   |
| `actor`                  | object | yes      | producer    | `id`, `type` (1–200 chars each), optional `runtime` (1–200) and `trust_level` (1–80); no other key                             |
| `action.type`            | string | yes      | agent       | 1–120 chars matching `^[a-z][a-z0-9._:-]*$`: the stable name of the action                                                     |
| `action.resource`        | string | yes      | agent       | 1–500 chars: the identity of what is acted on, apart from the parameters                                                       |
| `action.parameters`      | object | yes      | agent       | any JSON object; every value is inside the hash                                                                                |
| `context`                | object | yes      | producer    | any JSON object the producer trusts; MUST carry `idempotency_key` (1–180 chars); an agent-supplied key of that name is refused |
| `downstream_target`      | object | yes      | producer    | `system`, `operation` (1–200 each), optional `environment` (1–200) and `endpoint` (1–500); no other key                        |
| `expected_effect_digest` | string | no       | producer    | `sha256:` and 64 lowercase hex characters: a commitment to the predicted downstream state; absent when none is made            |

Rules:

- An object with a fixed key set (`actor`, `downstream_target`, the binding itself) MUST NOT carry
  any other key. A consumer MUST refuse a binding that does.
- The agent's proposal is `action.type`, `action.resource` and `action.parameters`, and nothing
  else. A producer MUST refuse a proposal that carries any other property, in particular a
  context, an actor, an expiry or an expected-effect digest: an agent that could name its own
  expected effect could name the one it intends to cause.
- The idempotency key is the producer's, never the agent's. It rides inside `context` under the
  reserved key `idempotency_key` because the authority contract has no top-level property for it
  and refuses unknown properties; it is inside the hash for that reason, so a retry is the same
  intent and a new attempt is a new one.
- Numbers MUST be finite. Objects MUST be plain: a key named `__proto__`, `constructor` or
  `prototype`, a non-object prototype, or a cycle is refused before anything is hashed.
- A producer MUST refuse, never truncate or repair, a binding beyond these bounds: 100 KiB of
  canonical bytes, nesting depth 20, 5,000 entries, 1,000 elements in one array.

## 4. Canonical form

The canonical form of a JSON value is the string ECMAScript `JSON.stringify` produces for the
value after every object at every depth has had its keys sorted, and nothing else:

1. **Key order.** Keys sort by UTF-16 code unit, ascending, case-sensitive: `"Z"` (0x5A) before
   `"za"` (0x7A) before `"zé"` before `"Éclair"` (0xC9). This is the ECMAScript default sort of
   strings. Keys are not folded, trimmed or normalized.
2. **No whitespace** between tokens.
3. **Strings verbatim.** No Unicode normalization: NFC and NFD forms of the same text are
   different strings with different hashes. Characters are encoded as `JSON.stringify` encodes
   them: `"` and `\` escaped, control characters U+0000–U+001F as `\b`, `\f`, `\n`, `\r`, `\t` or
   `\u00XX`, a lone surrogate as `\uXXXX`, and every other character, astral characters included,
   as itself.
4. **Numbers** as `JSON.stringify` writes them: `-0` becomes `0`, `1.5` stays `1.5`, `1e21`
   becomes `1e+21`. An implementation in a language whose number formatting differs MUST produce
   these bytes anyway; the vectors pin them.
5. **Arrays** keep their order; only object keys are sorted.
6. A property whose value is `undefined` in the producer's language is absent, not `null`.

The vectors under [`conformance/vectors/`](../../../conformance/vectors) state each of these as a
JSON object with its bytes and hash: `utf16-sort-order`, `composed-vs-decomposed`,
`unicode-astral`, `negative-zero`, `fractional-exponent`, `nested-arrays`.

## 5. The intent hash

The intent hash is the string `sha256:` followed by the lowercase hexadecimal SHA-256 digest of
the UTF-8 encoding of the canonical form of the whole binding. The authority recomputes it from
the binding it receives and refuses a request whose stated hash differs. The pinned vector
[`conformance/agent-safe-intent-v1.json`](../../../conformance/agent-safe-intent-v1.json) is the
first binding of this profile and its hash; an implementation that cannot reproduce it does not
implement this profile.

## 6. What is inside the hash: the Compromised Principal requirement

Every property of the binding is inside the hash, and a producer MUST NOT hash a projection,
summary or subset of it. The consequence is the property this profile exists for: authority is
bound to the exact action and never to the identity that proposed it. The realistic adversary is
not a forged credential but a valid one, an agent whose identity is real, whose credential is
current, and whose request is not what anyone authorized:

```text
valid principal → valid credential → permitted API → unauthorized consequential intent → BLOCK | ESCALATE
```

A change to any bound property after authorization is another intent with another hash, which
the authority never decided over and the grant does not cover. An implementation MUST therefore
produce a different hash for every single-property change to a binding.
[`conformance/vectors/compromised-principal.json`](../../../conformance/vectors/compromised-principal.json)
holds it to that: an infrastructure agent's `deployment.scale` intent and eight mutations a valid
principal could make after authorization (the replica count, the service, the cluster, the
resource, the principal, the expiry, the idempotency key, the environment), nine distinct hashes.
An implementation MUST reproduce all nine, and they MUST all differ. The same test runs end to
end in [`examples/infra-scale-demo`](../../../examples/infra-scale-demo) and is stated as a threat
in [`THREAT-MODEL.md`](../../../THREAT-MODEL.md#the-compromised-principal-test).

## 7. Conformance

An implementation **conforms to Agent-Safe Intent v1** when, for every vector under
`conformance/agent-safe-intent-v1.json`, `conformance/vectors/` and `conformance/frameworks/`, it:

1. produces the vector's `canonical_json` bytes from the vector's `binding`;
2. produces the vector's `intent_hash` from those bytes;
3. for a vector whose `binding` is a whole binding (`protocol_version` present), accepts it under
   §3 and refuses each of the refusals of §3;
4. for a vector with `mutations`, produces each mutation's bytes and hash, and produces no two
   equal hashes across the base and the mutations.

A vector whose `binding` is a JSON object that is not a binding pins only points 1 and 2: it is
a canonicalization case, and the schema does not apply to it.

The reference implementation runs the corpus in `IntentConformance.test.ts`, and the installed
runtime runs it offline against any file or directory:

```bash
agentsafe verify intent conformance/vectors conformance/agent-safe-intent-v1.json
agentsafe verify intent conformance/frameworks
agentsafe verify intent my-binding.json     # a binding of your own: prints its bytes and hash to compare
```

Exit `0` is every pinned hash reproduced; `1` is a vector that did not reproduce, named with the
expected and computed values; `2` is a file the command could not read or parse. `--json` is
the report as one line.

A conformance claim MUST name the version of the corpus it was made against: the release tag or
commit of this repository, since the corpus grows. A claim made against an older corpus stays
true of that corpus. Nothing in a conformance claim implies anything about the authority's
decisions, which are policy, or about a runtime's enforcement, which the boundary test
(`agentsafe test`) and the adversarial examples cover.

## 8. Producer capability coverage

A producer starts from what its framework gives it and adds the rest. This profile names eight
capabilities a producer needs and the binding property each becomes, so a framework can be
described by what it represents natively and what the adapter supplies, rather than passed or
failed:

| Capability           | Binding property          | The question it answers                                                                    |
| -------------------- | ------------------------- | ------------------------------------------------------------------------------------------ |
| `action_identity`    | `action.type`             | Is the action named by a stable identifier the policy can refer to?                        |
| `parameters`         | `action.parameters`       | Are the arguments a JSON object that canonicalizes as they are, or text to be parsed?      |
| `target_identity`    | `action.resource`         | Is what is acted on named apart from the parameters?                                       |
| `principal`          | `actor`                   | Is the acting identity carried with the action, by the runtime and not by the agent?       |
| `expiry`             | `expires_at`              | Is the intent bounded in time?                                                             |
| `idempotency`        | `context.idempotency_key` | Does a retry present the same intent and a new attempt a new one, by a runtime-chosen key? |
| `intent_digest`      | the hash                  | Is there one digest over the whole of the above that authority can be bound to?            |
| `effect_correlation` | the result                | Can the effect that followed be tied to exactly this call?                                 |

Labels: **native**, the framework's own record carries it; **adapter**, the producer adds it
(`IntentCapture` and its trusted context, in the reference); **not represented**, neither does;
**not tested**, no vector exists yet. [`frameworks.md`](./frameworks.md) applies the rubric to
the OpenAI Responses API and Agents SDK, the Vercel AI SDK and LangChain, from the vectors under
[`conformance/frameworks/`](../../../conformance/frameworks), each of which carries the
framework's own record, the proposal it becomes, the trusted context, and the binding and hash
that result. The Model Context Protocol is covered by [`examples/mcp-tool-gate`](../../../examples/mcp-tool-gate).

## 9. Versioning

`protocol_version` is the version of the binding, and a consumer MUST refuse a version it does
not implement rather than interpret it.

Within `/1`, a change MAY add an optional property that is absent by default and leaves the
bytes and the hash of every existing binding unchanged; `expected_effect_digest` was added that
way on 2026-09-12. Such a change MUST come with a vector that pins a binding carrying the
property and with the statement, tested, that the pinned vector reproduces unchanged.

A change that alters the bytes of any existing binding, the canonical form, the digest, or the
meaning or constraint of an existing property is `agent-safe.intent/2`, published beside `/1`,
which stays in force for as long as bindings under it are accepted.

## 10. Changes to this profile

Changes are proposed and decided in the open, in this repository:

1. Open an issue labelled `spec` stating the change, the reason, and whether it is additive (§9).
2. Open a pull request against `spec/intent/v1/` that changes this text, the schema, the vectors
   and the reference implementation together, with a changelog entry dated and signed off. A
   change with no vector is not a change to the profile.
3. The pull request stays open for comment for at least fourteen days from the day it is
   announced on the issue; a security correction MAY be merged sooner and is marked as such in
   the changelog.
4. Decionis maintainers decide, and record a rejected proposal and its reason in the changelog
   as they record an accepted one.

A mistake in this document, a vector that cannot be reproduced, or a framework described
unfairly in `frameworks.md` is reported the same way, or, where it touches security, through the
[security policy](https://github.com/decionis/agent-safe-pipeline/security/policy).

## 11. References

- The reference producer: [`IntentCapture`](../../../packages/pipeline/src/intent/IntentCapture.ts)
  and [`CanonicalIntentHasher`](../../../packages/pipeline/src/intent/CanonicalIntentHasher.ts);
  the validator the schema is generated from:
  [`IntentBindingSchema`](../../../packages/pipeline/src/intent/IntentBindingSchema.ts).
- What the binding is for, in the runtime: [execution intent](../../../docs/execution-intent.md),
  [ExecutionBinding](../../../docs/authority/execution-binding.md).
- The test everyone runs against it:
  [the Compromised Principal Test](../../../docs/compromised-principal-test.md).
- The research the architecture comes from: Jejelowo, Festus. "The Execution Verifiability
  Gap." Decionis Research, 2026. <https://decionis.com/research/execution-verifiability-gap>.
