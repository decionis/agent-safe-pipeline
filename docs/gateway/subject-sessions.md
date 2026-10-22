# Subject-bound sessions

An agent with access to an ERP or a customer system can read every customer's records. A
subject-bound session limits it to the one customer it is serving, without code of yours: the app
that starts the agent names the customer with a token from your identity provider, the gateway pins
that customer for the session, and an [API profile](../../spec/profiles/api/v1/README.md#7-subjects)
says, as data, where the customer sits in each call and in each item of each answer.

## Turning it on

```yaml
interception:
  profile: businesscentral/api/v2 # a profile whose operations name their subject
  # refuseUnknownReads: true is the default here: a call the profile cannot check is refused
subject:
  issuer: https://login.example.com/ # the token's iss, exactly
  audience: agentsafe-gateway # one of the token's aud
  jwksFile: /etc/agentsafe/idp-jwks.json # the provider's keys; or jwksUrl, or both
  jwksUrl: https://login.example.com/.well-known/jwks.json # refreshed every 5 minutes
  claim: customer_number # the claim naming the customer; sub by default
  sessionTtlSeconds: 900 # 60 to 3600; never past the token's own expiry
```

The provider's keys come from `jwksFile`, or from `jwksUrl` at start when there is no file; the
address is fetched through the guarded egress, sealed to its origin, and a failed refresh keeps the
last good set. A token whose key id the set does not hold asks for one refresh at once, at most
every 30 seconds, so a key the provider just rotated in is not refused for five minutes. A token is
accepted when its signature is from one of those keys (`RS256`, `ES256` or `EdDSA`), its `iss` is
`issuer` exactly, its `aud` holds `audience`, it carries `sub`, `iat` and `exp`, it is at most an
hour old, and `claim` holds a string or a number of 1 to 200 characters.

## Two ways to present the customer

**Token exchange (RFC 8693).** The app exchanges the provider's token at the gateway and gives the
agent the session token it gets back; the agent never holds the provider's token.

```bash
curl -s https://gateway.example/_agentsafe/v1/sessions \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$ID_TOKEN" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt'
```

```json
{
  "access_token": "<43 characters>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "N_A",
  "expires_in": 900
}
```

The agent sends it on every call in `AgentSafe-Session`. The gateway keeps only its SHA-256 beside
the customer, so the agent cannot change whose session it is. `subject_token_type` may be the
`jwt`, `id_token` or `access_token` type; an `actor_token` is refused. A token that does not verify
is `400 invalid_request` with the reason as `error_description` (`JWT_EXPIRED`,
`JWT_ISSUER_UNKNOWN`, `JWT_SUBJECT_UNKNOWN`, …), as RFC 8693 §2.2.2 says. Exchanging the same token
again replaces its session rather than add one. The route takes the tenant key and the rate like any
tenant traffic.

**The provider's token per request.** The agent sends the token itself in `AgentSafe-Subject-Token`
and the gateway verifies it on every call. Nothing is held, so this is the way behind several
replicas: a session from the exchange is held in the memory of the gateway process that issued it,
and ends with it.

Both headers end at the gateway: they are never forwarded, and evidence names a session by
`sha256:` and 12 hex characters of its token's digest, never the token or the customer. Neither may
be `interception.principalHeader`, whose value the authority receives: the configuration refuses
it by name, as it refuses the tenant key.

## Reads

A `GET` a profile operation names is checked, and never sent to the authority:

1. It must present a session that stands: none is `401 SUBJECT_SESSION_REQUIRED`, an unknown or
   expired session `401 SUBJECT_SESSION_INVALID`, a token that does not verify
   `401 SUBJECT_TOKEN_INVALID`, both headers `400 SUBJECT_TOKEN_AMBIGUOUS`.
2. Its query is checked before it is sent, as RFC 3986 writes a query: each name and value
   percent-decoded once, and a `+` refused, since one server reads it as a space and another as a
   plus. When the operation names the parameters a read may carry, any other is
   `403 QUERY_PARAMETER_REFUSED`: for Business Central, `$count`, `$search`, `$apply` and every
   option it does not list.
3. When the operation names a subject query, a list read must carry it, exactly as the profile's
   template writes it with the session's customer: `$filter=number eq 'C-10000'` and nothing else.
   Without it the read is `403 SUBJECT_ABSENT`; with another customer's number
   `403 SUBJECT_MISMATCH`; given twice, or with any second predicate, even beside the session's own
   number, `403 QUERY_PARAMETER_REFUSED`. A filter such as
   `number eq 'C-20000' and startswith(phoneNumber,'+4479')` would otherwise make an empty answer a
   yes or no about another customer's fields. A `'` in the customer is written doubled.
4. When the operation names where the customer sits in the call, it must be the session's:
   `403 SUBJECT_MISMATCH`, or `403 SUBJECT_ABSENT` when the call names none. Nothing is sent.
5. When the operation names where the customer sits in each item of the answer, a successful answer
   is checked before any of it is relayed, as a second line behind the query. One item for another
   customer is `403 RESPONSE_SUBJECT_MISMATCH`; an item that names no customer
   `403 RESPONSE_SUBJECT_ABSENT`; an answer the pointer cannot be walked into
   `403 RESPONSE_UNREADABLE`. Beside the list, the answer may carry only the keys the operation's
   envelope names (`@odata.context`, `@odata.nextLink`): a count or any other key about records
   no item shows is `403 RESPONSE_KEY_REFUSED`. The answer is refused whole, never filtered, since a
   partial answer looks complete, and the response says `agentsafe-execution: WITHHELD` and gives
   the upstream's status. An answer that is not a success is relayed as it came.

A read that passes is relayed with `agentsafe-execution: PASSTHROUGH` and `agentsafe-subject:
CHECKED`. A refusal is the gateway's own answer (`state: REFUSED`, `verdict: null`, the reason in
`reason_codes`), a report line, and a `SUBJECT_REFUSED` line on the gateway's evidence chain with
the operation, the reason and the session's short digest. These are the gateway's own refusals, like
the tenant key's: they hold in shadow and in enforcement.

## What is checked, exactly

With `refuseUnknownReads` on, which it is by default once `subject` and a profile are configured, a
call the profile cannot check is refused before it is sent:

- a read no profile operation names, or a path beneath one (`/customers/$count`, a navigation, a
  picture), and a `HEAD` or `OPTIONS`: `403 READ_OPERATION_UNMATCHED`;
- a write no profile operation and no route names, whatever `unmatched` says, and so any `$batch`,
  whose parts no subject rule could check: `403 PROFILE_OPERATION_UNMATCHED`.

What an agent can then read through the gateway is exactly the profile's read operations, each held
to the checks above, and the answers to the profile's writes, checked where the operation names
where the customer sits in them. The checks cover what the profile points at: an operation that
names no subject is not scoped, and an answer is checked by the field its pointer names, so a record
that names the session's customer there is relayed with everything else it carries.

`refuseUnknownReads: false` lets an unnamed read pass unchecked and an unnamed write go to the
authority as `http.<method>`. A `GET` that only resembles a checked read (the same path in another
letter case, or with a literal percent-encoded) is still refused as `400 HTTP_PATH_AMBIGUOUS`, and a
path beneath one or a `HEAD` or `OPTIONS` of one as `403 READ_OPERATION_UNMATCHED`. A gateway that
holds the upstream's credential (`gateway.upstreamCredential`) is the agent's only way to the
upstream, so with `subject` set it refuses `false` at start.

## Writes

A write is decided by the authority as always. A write whose operation names a subject is for one
customer, so it needs a session: without one it is `401 SUBJECT_SESSION_REQUIRED`, before the
authority is asked. When the request presents a session that stands, the gateway states its
customer in the intent's trusted context as `session: { "subject": "C-10000" }`,
which a policy reads as the fact `session.subject`: a rule compares it with the operation's own fact,
such as `customer_number EQ_FACT session.subject`, where the authority's policy core has fact-to-fact
operators (hosted only: the [edge evaluator](../edge-evaluator.md#limits) cannot yet decide them). It is a verified claim of your identity provider, never a value of the request, so it is
sent in [facts-only privacy](./http-interception.md#facts-only-privacy) too. A session that does not
stand is refused before the authority is asked; a write with no session states no `session`.

A write's successful answer is checked like a read's, when its operation names where the customer
sits in it: in enforcement, in shadow and when failing open. Business Central answers
`PATCH …/customers(<id>)` with the customer's whole record, so a change addressed by another
customer's id would otherwise relay that record. The answer is withheld with
`403 RESPONSE_SUBJECT_MISMATCH`, `agentsafe-execution: WITHHELD` and the upstream's status: the
change itself has been made if the authority allowed it, so stop it in policy too (block or escalate
a change by id when `session.subject` is present).

## Where the edge is

- An operation with no subject is not scoped. Each shipped profile lists what it covers and what it
  does not, such as [Business Central's](../../profiles/businesscentral/api/v2/README.md#customer-scoped-reads).
- The gateway checks what the profile points at. A system without a shipped profile needs one: a
  JSON file, drafted from its OpenAPI document and reviewed, with no code.
- Scoping limits what the gateway relays. When the agent holds the upstream's credential itself it
  can call the upstream directly, so let the gateway hold it instead (`gateway.upstreamCredential`):
  the gateway presents it on every forward and drops any the agent sends.
