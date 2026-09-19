# Agent-Safe Intent v1: changes

Every entry names the pull request that made it and the vector that pins it. The binding's bytes
and hash have not changed for any existing binding since the first vector; the additions were
optional and absent by default (see §9 of the [specification](./README.md)).

## 2026-09-19: the specification, the schema, the offline command, framework coverage

- The profile is written down: this directory, with the binding, the canonical form, the hash,
  the Compromised Principal requirement, conformance, capability coverage, versioning and the
  change process ([README.md](./README.md)).
- [`schema.json`](./schema.json), JSON Schema 2020-12 of the binding, generated from the
  reference implementation's strict validator (`AuthorityIntentBindingSchema`, new in
  `@decionis/agent-safe-pipeline`); a test holds the file to the generator.
- `agentsafe verify intent <file|dir>`: the corpus, or a binding of your own, checked offline by
  the installed runtime.
- `conformance/frameworks/{openai,vercel,langchain}.json`: the same refund proposal as an OpenAI
  Responses API `function_call` item, a Vercel AI SDK `tool-call` part and a LangChain
  `ToolCall`, each with the proposal it becomes, the trusted context, the binding and the hash,
  and a coverage row over the eight producer capabilities ([frameworks.md](./frameworks.md)).

## 2026-09-19: the Compromised Principal vector (#207)

- `conformance/vectors/compromised-principal.json`: a `deployment.scale` binding and eight
  single-property mutations, nine distinct hashes. Vectors may carry `mutations`; the reference
  test holds every mutation to its own bytes and hash and to distinctness from the base and from
  one another.

## 2026-09-12: `expected_effect_digest` (#113)

- An optional top-level property, `sha256:` and 64 lowercase hex characters, a digest-only
  commitment to the predicted downstream state, supplied by the producer only. Added through a
  conditional spread, so a binding without it produces exactly the bytes and hash it produced
  before; `conformance/agent-safe-intent-v1.json` reproduces unchanged.

## 2026-09-07: conformance to the Decionis execution contract (#100)

- The binding is stated as exactly the contract's `ExecutionIntentBinding`, less the optional
  `policy_projection` the reference does not produce. The `Idempotency-Key` header of the
  authority request carries the `intent_id`.

## 2026-08-16: the idempotency key inside the hash (#28)

- The producer's idempotency key rides in `context` under the reserved key `idempotency_key`,
  and is therefore inside the hash; an agent-supplied context key of that name is refused.

## 2026-08-15: canonicalization edge cases (#23)

- `conformance/vectors/`: UTF-16 key order, NFC against NFD, astral characters, negative zero,
  fractional and exponent numbers, nested arrays, each pinned to its bytes and hash.

## 2026-08-14: the first vector

- `conformance/agent-safe-intent-v1.json`: a `refund_order` binding and its hash, the
  cross-implementation vector every implementation reproduces first.
