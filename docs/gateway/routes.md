# Routes

A route names a consequential action so policy can be written about it. Without routes every
`POST`, `PUT`, `PATCH` and `DELETE` is still governed, under `http.<method>`; routes give the
actions the names the policy uses.

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

| Pattern       | Matches                        | Does not match                |
| ------------- | ------------------------------ | ----------------------------- |
| `/payments`   | `/payments`, `/payments/`      | `/payments/1`                 |
| `/payments/*` | `/payments/1`                  | `/payments`, `/payments/1/x`  |
| `/orders/:id` | `/orders/42` (any one segment) | `/orders`, `/orders/42/lines` |
| `/admin/**`   | `/admin` and anything below it | `/administration`             |

The first route whose pattern and methods match wins, in the order written. A route's `methods`
default to all four consequential methods. Action names follow the intent contract:
`^[a-z][a-z0-9._:-]*$`, at most 120 characters.

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
