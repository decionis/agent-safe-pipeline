# API Intent Profile v1: changes

Every entry names the pull request that made it and the vectors that pin it.

## 2026-10-31: effects, as `agent-safe.profile.api/1.1`

The definition is closed, so the new field is a new minor version: every 1 definition, match and
vector is a 1.1 one with the same answer, and a reader of 1 refuses a 1.1 definition by its
`profile` rather than ignore a field it does not know.

- A write that names a `precondition` may name its `effect` (§9): pairs of a pointer into the
  read's answer and a pointer into the call, so the read after the write states whether it did
  what was authorised. A 1 definition naming one, one without a precondition, an answer pointer
  named twice, a pointer through `*` or rooted elsewhere are refused (§2.3).
- [`schema.json`](./schema.json): `profile` admits `agent-safe.profile.api/1.1`; an operation
  admits `effect`.
- [`vectors/`](./vectors): an effect read back as expected, one that differs, a partial update, a
  write that names none, and five definition refusals. The Business Central profile is 1.1, and its
  `customers.update` names `blocked` as its effect.

## 2026-10-23: preconditions

- A write may name a `precondition`: the read in the same profile that states the target's
  version, and pointers into that read's answer (`{ headers, body }`) for the version and, when a
  transition rule reads one, the target's state (§8). The read is made from the write's own call.
  A read naming one, a read that is not one, a placeholder the write lacks, a pointer through `*`
  or rooted elsewhere are refused (§2.3).
- [`schema.json`](./schema.json): an operation admits `precondition`.
- [`vectors/`](./vectors): the version from an ETag header, from a body with the state beside it
  under a prefix with its own placeholder, as a number, an answer that states none, a write that
  names none, and five definition refusals. The Business Central profile's `customers.update`
  names `customers.get`, its `@odata.etag` and `blocked`.

## 2026-10-22: subject queries, parameters, envelopes and write answers

The subjects of 2026-10-21 had not been released. Review found two ways around them, closed here
before any release:

- A list read had no request-side check, so a filter naming another subject and a second predicate
  made an empty answer a yes or no about that subject's fields, and `$count` reported records no
  item showed. A read now names its subject `query` (a template the call must state exactly), the
  `parameters` it may carry, and the `envelope` keys its list may stand beside; anything else is
  `QUERY_PARAMETER_REFUSED` or `RESPONSE_KEY_REFUSED` (§7.2).
- A write's answer was never checked, so a change addressed by another subject's id relayed that
  subject's record. A write may now name a `response` pointer, and its successful answer is checked
  as a read's is (§7.3); the rule that refused a write's `response` is withdrawn, with its vector.
- [`schema.json`](./schema.json): `subject` admits `query`, `parameters` and `envelope`.
- [`vectors/`](./vectors): the query held exactly (`subject-query-*.json`), a refused parameter, a
  refused envelope key, a write's answer, and three definition refusals.
- `businesscentral/api/v2` holds its list reads to `number eq '{subject}'` or
  `customerNumber eq '{subject}'`, names their parameters and envelope, and checks the answers of
  `customers.update` and `salesOrders.create`.

## 2026-10-21: subjects

Additive: every definition, match and vector that was valid stays so, with the same answer.

- An operation may name where its subject sits (`subject.request`, `subject.response`), and a `GET`
  operation, a read, is checked for its subject and never decided (§7). `session` is reserved.
- [`schema.json`](./schema.json): `method` admits `GET`; an operation admits `subject`.
- [`vectors/`](./vectors): reads and answers checked both ways (`subject-*.json`), a write's
  subject, and six refusals (`refuses-read-*`, `refuses-response-*`, `refuses-request-subject-*`,
  `refuses-empty-subject`). A vector may pin a `session` and state `request_check`, a `response`
  and its `response_check`.
- `businesscentral/api/v2` names its customer, sales document and customer ledger entry reads, and
  the subject of `salesOrders.create`.

## 2026-10-21: facts-only privacy

- `request_hmac_sha256` is reserved (§4.2): the gateway states it in facts-only privacy, where an
  operation's id, path template and facts are all the authority receives (§4.3). No definition,
  match or vector changes.

## 2026-10-20: the profile, two platform profiles, the gateway

- The profile is written down: a closed definition, ordered matching by method, path template and
  exact query value, facts by RFC 6901 pointer with one `*` collecting an array, and the reserved
  fact names ([README.md](./README.md)).
- [`schema.json`](./schema.json), JSON Schema 2020-12 of the definition, generated from the
  reference implementation's validator; a test holds the file to the generator.
- [`vectors/`](./vectors): ordering and query selection, OData keys and decoding, fact collection
  and absence, and five refusals.
- The first profiles, each with its own vectors: `walmart/api/v3` and `businesscentral/api/v2`.
- The gateway governs by a profile (`interception.profile`) and states its facts in the intent's
  trusted context; `agentsafe profile openapi` writes a profile as the OpenAPI document an AgentCore
  Gateway target is created from.
