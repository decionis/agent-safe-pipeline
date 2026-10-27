# Routes

A route names a consequential action so policy can be written about it. Without routes every
`POST`, `PUT`, `PATCH` and `DELETE` is still governed, under `http.<method>`; routes give the
actions the names the policy uses.

Only `GET`, `HEAD` and `OPTIONS` are classified as safe. While interception is enabled, methods
outside these and the four supported consequential methods are refused with
`405 HTTP_METHOD_UNSUPPORTED`, including on an unmatched passthrough route. Method-override
headers are also refused; see [HTTP interception](./http-interception.md).

```yaml
interception:
  routes:
    - path: /payments/**
      action: payment.create
      methods: [POST]
    - path: /orders/:id
      action: order.change
      methods: [PUT, PATCH]
    - path: /orders/:id
      action: order.cancel
      methods: [DELETE]
  unmatched: govern
```

## Patterns

Matching walks the path one segment at a time; nothing backtracks.

Literal path characters are percent-decoded once for matching, so `/%70ayments` cannot evade a
`/payments` rule; the request sent upstream keeps its original spelling and digest. Encoded
separators, nested percent encoding, path parameters (`;`), control characters, dot segments and
malformed encoding are refused for consequential requests with `400 HTTP_PATH_AMBIGUOUS`.
Write configured patterns with decoded literal characters. Encoded or ambiguous patterns fail
construction with `ROUTE_PATH_AMBIGUOUS`. Integrations must
not introduce additional application-specific routing rewrites behind this boundary.

| Pattern       | Matches                        | Does not match                |
| ------------- | ------------------------------ | ----------------------------- |
| `/payments`   | `/payments`, `/payments/`      | `/payments/1`                 |
| `/payments/*` | `/payments/1`                  | `/payments`, `/payments/1/x`  |
| `/orders/:id` | `/orders/42` (any one segment) | `/orders`, `/orders/42/lines` |
| `/admin/**`   | `/admin` and anything below it | `/administration`             |

The first route whose pattern and methods match wins, in the order written. A route's `methods`
default to all four consequential methods. Action names follow the intent contract:
`^[a-z][a-z0-9._:-]*$`, at most 120 characters.

## Selecting a policy

A route may also select which published Decionis policy evaluates its action. `action` names the
transaction for rules to match; it does not select a policy bundle. Configure `policyId` with the
immutable published bundle UUID, `policyVersion` with an exact published version, or both:

```yaml
interception:
  routes:
    - path: /decide
      action: payment.decide
      methods: [POST]
      policyId: "00000000-0000-4000-8000-000000000010" # synthetic; replace with your published bundle
      policyVersion: "payments-v1" # optional when policyId is set
```

The gateway adds `policy_id` and `policy_version` to the action's top-level parameters, beside
`method`, `path`, `query` and `body`, before the canonical intent hash is computed. Decionis resolves
that bundle within the configured tenant. When both are provided, both must match. `policyId` is
not a workspace policy head, draft revision, rule ID or display name; `policyVersion` is the exact
version string, not a policy title. The loader validates UUIDs, normalizes their case, and trims
selectors; versions must be nonempty, at most 100 characters, with no internal control characters.

Selectors come only from operator configuration. A body field, query parameter or request header
cannot supply or override one; body fields remain under `parameters.body`. The upstream receives
the original body unchanged. A different selector changes the intent hash and therefore the
authorization binding. The gateway never retries a policy refusal by dropping the selector.

Only the first matching route supplies a selector; unmatched actions and routes without selectors
retain the authority's default selection. A direct `Gateway.govern()` caller that changes a pinned
route's action gets `400 ROUTE_ACTION_MISMATCH` before any authority call. As with all explicit
routes, these settings are unavailable in `privacy: facts`, which uses API profiles alone.

## By an API profile

A platform's API can be governed by its API intent profile
([`agent-safe.profile.api/1`](../../spec/profiles/api/v1/README.md)) instead of routes you write:

```yaml
interception:
  profile: walmart/api/v3 # or businesscentral/api/v2; AGENTSAFE_PROFILE in the environment wins
  unmatched: govern
```

- An explicit route is tried first. The profile's operations come next, in the profile's order,
  matched by method, path template and, where an API overloads a path, an exact query value
  (`PUT /v3/price?promo=true` is `promotion.change`, `PUT /v3/price` is `price.change`). The
  unmatched policy decides the rest.
- The profile names the facts each operation is decided with. The gateway states them at the top
  of the intent's trusted context, beside `api_profile: { id, operation }`, reading the body for
  them even when `maxEmbeddedBodyBytes` keeps it out of the intent. A native executor that reads
  the same profile states the same facts, so one policy rule reads `purchase_order_id` however the
  call arrived.
- `agentsafe profile list` names the profiles this build ships; an unknown name is refused when
  the configuration loads.
- An operation may name where its subject sits, and a `GET` operation is a read the gateway checks
  against a [subject-bound session](./subject-sessions.md) rather than a call it governs.
- `privacy: facts` sends the authority the operation id, its path template and the named facts,
  never the raw path, query, headers or body, and refuses with `403 PROFILE_OPERATION_UNMATCHED` a
  write the profile does not name ([facts-only privacy](./http-interception.md#facts-only-privacy)).

## Unmatched requests

`interception.unmatched` is `govern` by default: an unsafe request no route names is evaluated
under its derived name. `passthrough` forwards it without evaluation, which narrows the boundary to
what the routes name and is therefore an explicit choice, refused nowhere but recorded in the
effective configuration `agentsafe config` prints.

`interception.http: false` turns interception off entirely; every request passes through. It
exists so a deployment can be rolled out with the gateway in place and nothing governed yet.

## From an OpenAPI document

`agentsafe init` reads `openapi.yaml`, `openapi.yml` or `openapi.json` from the current directory
and writes one route per consequential operation, `{id}` segments as `*`, the action named from
the `operationId` (`createPayment` becomes `create.payment`) or, failing that, from the last path
segment and the method (`orders.delete`). Edit the names; the file is yours.
