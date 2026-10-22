# API Intent Profile v1

**Identifier:** `agent-safe.profile.api/1` · **Status:** draft · **Publisher:** Decionis ·
**Reference implementation:** `ApiProfile` and `ApiProfiles` in
[`@decionis/agent-safe-pipeline`](../../../../packages/pipeline) · **Schema:**
[`schema.json`](./schema.json) · **Vectors:** [`vectors/`](./vectors) · **Changes:**
[`CHANGELOG.md`](./CHANGELOG.md)

An API intent profile describes a platform API as data: which of its calls are consequential, the
action type each one is, and the facts an authority decides it with. It may also say where each
call's subject sits (the customer a call is for), so that a component can hold an agent's session
to one subject. It exists so that every
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
5. **Subjects** (§7): where a call's subject sits, and how a read and its answer are checked.

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
| `method`            | `POST`, `PUT`, `PATCH` or `DELETE`, decided by the authority; or `GET`, a read, checked for its subject and never decided (§7).   |
| `path`              | A path template: literal text and `{name}` placeholders, each placeholder within one segment.                                     |
| `query`             | Optional. Exact values the call's query must carry, for an API that overloads one path (`promo=true`).                            |
| `action`            | The intent's action type.                                                                                                         |
| `summary`           | Plain words; what an agent's tool description says.                                                                               |
| `facts`             | Fact name → RFC 6901 JSON pointer into the call (§4).                                                                             |
| `policy_projection` | The policy path the authority decides the call under (`decision_type`, `transaction_type`, `workflow_key`, `channel`), or `null`. |
| `subject`           | Optional; required of a read. Where the call's subject sits (`request`, `response`, `query`) and what may stand around it (§7).   |

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
  than one `*` token;
- a read names no subject, or names a fact or a policy projection;
- a write names a subject `query` or `parameters`;
- a subject names none of `request`, `response` and `query`; a `request` pointer is not rooted like
  a fact's or has a `*` token; a `response` pointer is not rooted at `/body` or has more than one
  `*` token; a `query` template does not hold `{subject}` exactly once; or an `envelope` stands
  without a `response` pointer through `*`.

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
(`request_sha256`, `request_hmac_sha256`, `body_sha256`, `body_bytes`, `content_type`,
`body_embedded`, `ingress`, `claimed_principal`, `api_profile`) or one the authority states or reads from the request rather
than the context (`agent_safe`, `action_context`, `amount`, `risk_score`, `channel`,
`objective_profile`, `mode`, `decision_band`, `transaction_type`, `workflow_key`, `vertical_pack`,
`policy_version`, `org_id`, `decision_type`, `decision_domain`, `signals`, `signal_provenance`,
`history`, `override`, `evidence`, `attachments`, `attachment_count`, `policy`, `context`,
`intake`, `runtime_attribution`), or `session`, where a component states the subject a session is
pinned to (§7.3). A fact of such a name would be shadowed, or refused, there.

### 4.3 Where facts go

A component states an operation's facts in the intent's trusted context, each at the top level
under its name, beside `api_profile: { "id": <profile id>, "operation": <operation id> }`. A
policy rule therefore reads `purchase_order_id` whether the call came through the gateway or from
an executor.

A component MAY send only that: the operation id and its path template as the action's parameters,
and the facts as its context, with no raw part of the call. The reference gateway does so in
facts-only privacy ([`interception.privacy: facts`](../../../../docs/gateway/http-interception.md#facts-only-privacy)),
which is why an operation's facts are the whole of what an authority can decide on there.

## 5. Conformance

[`vectors/`](./vectors) holds the definition-level vectors: a `definition`, a `request` and the
`expected` match (or `null`), or a `definition` and the `error` it is refused with. Each shipped
profile carries its own vectors in `profiles/<id>/vectors/`, in the same form with `profile`
naming it. A vector may also pin a `session` (the subject a session holds) and state the
`request_check` of the call against it, and a `response` (the answer's JSON body) with its
`response_check` (§7.2). An implementation conforms when, for every vector, it returns the expected
match exactly and the expected checks, or refuses the definition with the expected code.

## 6. Profiles this build ships

| Profile                                                                           | What it governs                                                                                                                                                                        |
| --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`walmart/api/v3`](../../../../profiles/walmart/api/v3/README.md)                 | Order acknowledge, cancel, refund and ship; base and promotional price; inventory; feeds.                                                                                              |
| [`businesscentral/api/v2`](../../../../profiles/businesscentral/api/v2/README.md) | Sales and purchase postings, journal posting, vendor payment lines, vendor and customer changes; customer, sales document and customer ledger entry reads, checked for their customer. |

## 7. Subjects

### 7.1 Where a subject sits

An operation's `subject` says where the call's subject sits: the one party the call is for, such as
the customer whose records a read returns or a write changes.

- `request` is an RFC 6901 pointer into the call, rooted at `/path`, `/query` or `/body` like a
  fact's, with no `*`: a call has one subject. The subject is the value there when it is a string,
  or a finite number written as its decimal string, of 1 to 200 characters; otherwise the call
  names none (`null`).
- `response` is a pointer into the JSON body of a successful answer, to a read or a write, rooted
  at `/body`. One `*` reaches every element of a list, so `/body/value/*/customerNumber` is each
  item's `customerNumber`; without one, the pointer reaches the single item the answer is.
- `query`, for a read only, is `{ "name", "template" }`: the one query parameter that states the
  subject, and how, with `{subject}` where the subject goes (`customerNumber eq '{subject}'`).
- `parameters`, for a read only, names every other query parameter the read may carry, beside the
  `query` parameter and any exact `query` value the operation names. Absent, a read may carry any.
- `envelope`, beside a `response` pointer through `*`, names the keys the object that holds the list
  may carry besides the list (`@odata.context`, `@odata.nextLink`). Absent, it may carry none.

A match states the call's subject as `subject` when the operation names a `request` pointer, and
not at all otherwise. Vectors state it the same way.

### 7.2 Checking a read

A component that pins a session to one subject, and serves a read that matches an operation, MUST:

1. when the operation names `parameters`, refuse a call that carries any other query parameter
   (`QUERY_PARAMETER_REFUSED`), so a count, a search or an aggregation is never asked;
2. when the operation names a `query`, refuse a call without that parameter (`SUBJECT_ABSENT`),
   with it twice or with anything but the template with one literal in place of `{subject}`
   (`QUERY_PARAMETER_REFUSED`), and with a literal naming another subject (`SUBJECT_MISMATCH`).
   The template is matched whole and never parsed, so a second predicate is refused even beside
   the session's own subject: it would make an empty answer a yes or no about another subject. A
   `'` inside the literal is written doubled, as an OData string literal writes it; a single one
   ends the literal and refuses the call;
3. refuse the read when the operation names a `request` subject and the call's is `null`
   (`SUBJECT_ABSENT`) or not the session's (`SUBJECT_MISMATCH`);
4. when the operation names a `response` subject and the answer is a success, check it before any of
   it is relayed, and refuse it whole when the pointer cannot be walked into it, such as an answer
   that is not JSON or has no list where the `*` stands (`RESPONSE_UNREADABLE`), when the object
   holding the list carries a key the `envelope` does not name (`RESPONSE_KEY_REFUSED`), when an
   item names no subject (`RESPONSE_SUBJECT_ABSENT`), or when an item names another subject
   (`RESPONSE_SUBJECT_MISMATCH`). It MUST NOT filter the answer: a partial answer looks complete.
   An empty list names no one, and passes.

Steps 1 to 3 come before the read is sent. A component MUST read the query as the platform will:
the reference gateway decodes each name and value once, as RFC 3986 writes them, and refuses a `+`,
which platforms read differently. A read is never sent to an authority and states no facts.
Subjects compare as exact strings.

### 7.3 Writes

A write may name a `request` subject too. It is decided by the authority as any write is: the
component states the session's pinned subject in the intent's trusted context as
`session: { "subject": <string> }`, so a policy reads the fact `session.subject` and compares it
with the operation's own facts. The subject is the identity provider's statement, never a value of
the request, and is absent, never `null`, when no session was presented. A component that pins
sessions SHOULD refuse a write whose operation names a subject when no session was presented, and
MUST check a write's successful answer by its `response` pointer as step 4 checks a read's,
withholding it on a refusal: the effect has happened, but no other subject's record is relayed.

### 7.4 Coverage

An operation with no subject is not scoped. A call a profile does not describe cannot be checked, so
a component that holds sessions to a subject SHOULD refuse it by default: a read, a path beneath an
operation's (a count, a navigation), and a write, a batch of calls included, whose parts it could
not check. It SHOULD refuse a read whose path only resembles a checked one (another letter case, or
a literal percent-encoded), since the platform may serve it as that operation.
