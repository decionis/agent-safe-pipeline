# API Intent Profile v1

**Identifier:** `agent-safe.profile.api/1` · **Status:** draft · **Publisher:** Decionis ·
**Reference implementation:** `ApiProfile` and `ApiProfiles` in
[`@decionis/agent-safe-pipeline`](../../../../packages/pipeline) · **Schema:**
[`schema.json`](./schema.json) · **Vectors:** [`vectors/`](./vectors) · **Changes:**
[`CHANGELOG.md`](./CHANGELOG.md)

An API intent profile describes a platform API as data: which of its calls are consequential, the
action type each one is, and the facts an authority decides it with. It exists so that every
component that turns one of those calls into an intent turns it into the same intent. The gateway
reads a profile to govern an agent's call; a native executor
([`agent-safe.executors.native/1`](../../../executors/native/v1/README.md)) reads the same profile
in `prepare` to describe the call it is about to make. There is one mapping and no code coupling
between them. It is published by Decionis and implemented by its reference runtime; it is not a
standard approved by any standards body.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119 and RFC 8174.

## 1. Scope

This profile defines:

1. **The definition** (§2): a closed JSON document, validated by [`schema.json`](./schema.json)
   and by the rules in §2.3 that a schema cannot state.
2. **Matching** (§3): how one call selects an operation, deterministically.
3. **Facts** (§4): how an operation's facts are read from the call.
4. **Conformance** (§5): the vectors every implementation is held to.

It does not define policy, verdicts, the canonical intent or its hash; those are
[Agent-Safe Intent v1](../../../intent/v1/README.md) and the Decionis execution-authority contract.
A profile carries no credential, header or secret, and never reads one.

## 2. The definition

### 2.1 Fields

| Field        | Meaning                                                                                                |
| ------------ | ------------------------------------------------------------------------------------------------------ |
| `profile`    | Always `agent-safe.profile.api/1`.                                                                     |
| `id`         | `<platform>/<api>/<version>`, the profile's directory under `profiles/`, for example `walmart/api/v3`. |
| `platform`   | The platform identifier the native executor contract uses, for example `walmart-marketplace`.          |
| `title`      | Plain words.                                                                                           |
| `prefixes`   | One to eight path templates an operation's path may follow, tried in order; `""` is the bare path.     |
| `operations` | One to two hundred operations, tried in order.                                                         |

An operation:

| Field               | Meaning                                                                                                                           |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `id`                | Unique within the profile, dotted lower camel case (`salesInvoices.post`).                                                        |
| `method`            | `POST`, `PUT`, `PATCH` or `DELETE`. A read is never an operation.                                                                 |
| `path`              | A path template: literal text and `{name}` placeholders, each placeholder within one segment.                                     |
| `query`             | Optional. Exact values the call's query must carry, for an API that overloads one path (`promo=true`).                            |
| `action`            | The intent's action type.                                                                                                         |
| `summary`           | Plain words; what an agent's tool description says.                                                                               |
| `facts`             | Fact name → RFC 6901 JSON pointer into the call (§4).                                                                             |
| `policy_projection` | The policy path the authority decides the call under (`decision_type`, `transaction_type`, `workflow_key`, `channel`), or `null`. |

### 2.2 Templates

A placeholder `{name}` matches one or more characters that are not `/`, `(` or `)`. Literal text,
parentheses included, matches itself exactly, so an OData key segment `companies({companyId})`
is written as it appears. Matching is case sensitive.

### 2.3 Rules a schema cannot state

A definition MUST be refused (`API_PROFILE_INVALID`) when:

- two operations share an `id`;
- two operations share method, path (placeholders ignored) and query;
- a template repeats a placeholder or has a malformed one;
- a fact name is reserved (§4.2);
- a fact pointer is not rooted at `/path`, `/query` or `/body`, has an invalid escape, or has more
  than one `*` token.

## 3. Matching

A call is its method, its URL path as sent, its query (each name to one value or a list) and its
parsed JSON body. Its operation is the first operation, in profile order, such that:

1. the method, upper-cased, equals the operation's method;
2. every `query` value the operation names equals the call's single value for that name (a
   repeated name is not an exact value);
3. for the first prefix, in prefix order, under which `prefix + path` matches the call's path
   entirely, every placeholder's text percent-decodes, and, after a pair of enclosing single quotes
   is removed, is not empty, `.` or `..` and contains no `/`.

A call no operation matches is not described by the profile; the component decides what that
means (the gateway's `unmatched` policy). A path containing `?` or `#` matches nothing.

## 4. Facts

### 4.1 Reading

Each pointer is read from `{ "path": <placeholders>, "query": <query>, "body": <body> }`. A value
is stated only when it is a string of at most 1000 characters, a finite number or a boolean. One
`*` token collects a statable value from every element of an array of 1 to 100 elements; when any
element has none, the fact is absent. An object, a null, a missing member or an over-long value is
absent. Absent facts are not stated at all: never as `null`.

### 4.2 Reserved names

A fact name is snake case, 1 to 64 characters, and MUST NOT be one the gateway states itself
(`request_sha256`, `body_sha256`, `body_bytes`, `content_type`, `body_embedded`, `ingress`,
`claimed_principal`, `api_profile`) or one the authority states or reads from the request rather
than the context (`agent_safe`, `action_context`, `amount`, `risk_score`, `channel`,
`objective_profile`, `mode`, `decision_band`, `transaction_type`, `workflow_key`, `vertical_pack`,
`policy_version`, `org_id`, `decision_type`, `decision_domain`, `signals`, `signal_provenance`,
`history`, `override`, `evidence`, `attachments`, `attachment_count`, `policy`, `context`,
`intake`, `runtime_attribution`). A fact of such a name would be shadowed, or refused, there.

### 4.3 Where facts go

A component states an operation's facts in the intent's trusted context, each at the top level
under its name, beside `api_profile: { "id": <profile id>, "operation": <operation id> }`. A
policy rule therefore reads `purchase_order_id` whether the call came through the gateway or from
an executor.

## 5. Conformance

[`vectors/`](./vectors) holds the definition-level vectors: a `definition`, a `request` and the
`expected` match (or `null`), or a `definition` and the `error` it is refused with. Each shipped
profile carries its own vectors in `profiles/<id>/vectors/`, in the same form with `profile`
naming it. An implementation conforms when, for every vector, it returns the expected match
exactly, or refuses the definition with the expected code.

## 6. Profiles this build ships

| Profile                                                                           | What it governs                                                                                  |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [`walmart/api/v3`](../../../../profiles/walmart/api/v3/README.md)                 | Order acknowledge, cancel, refund and ship; base and promotional price; inventory; feeds.        |
| [`businesscentral/api/v2`](../../../../profiles/businesscentral/api/v2/README.md) | Sales and purchase postings, journal posting, vendor payment lines, vendor and customer changes. |
