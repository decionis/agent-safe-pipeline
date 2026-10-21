# API Intent Profile v1: changes

Every entry names the pull request that made it and the vectors that pin it.

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
