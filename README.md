# CommerceGate MCP

CommerceGate MCP gives operations agents a narrow, tenant-bound way to evaluate proposed commerce actions and inspect their evidence. It is the operations-facing companion to the broader Decionis Protocol MCP: this package focuses only on order acceptance, price changes, signed Decision Dossiers, proof packets, and Shadow Mode reports.

The server is local STDIO. It calls the Decionis API for tenant operations but contains no marketplace client and exposes no order, price, refund, fulfillment, or inventory mutation tool.

Package: [@decionis/commerce](https://www.npmjs.com/package/@decionis/commerce)

## Install

CommerceGate requires Node.js 20 or later. Start the pinned public package with:

```sh
npx -y @decionis/commerce@0.1.1
```

The process starts without credentials so an MCP client can discover its capabilities. Tenant evaluation and evidence tools require `DECIONIS_API_KEY` and `DECIONIS_ORG_ID` in the process environment. Store `DECIONIS_API_KEY` in the MCP client's secret or environment manager; never place it in command arguments, source control, prompts, or logs. `DECIONIS_API_BASE` is optional and defaults to `https://api.decionis.com`.

For a capability-only startup, omit both tenant variables and call `commercegate_describe_capabilities`. Every tenant call will fail closed until both required tenant values are available.

### Codex client configuration

Forward the three named variables from the environment that launches Codex:

```toml
[mcp_servers.commercegate]
command = "npx"
args = ["-y", "@decionis/commerce@0.1.1"]
env_vars = ["DECIONIS_API_KEY", "DECIONIS_ORG_ID", "DECIONIS_API_BASE"]
enabled = true
required = false
startup_timeout_sec = 20
tool_timeout_sec = 45
default_tools_approval_mode = "writes"
enabled_tools = [
  "commercegate_describe_capabilities",
  "commercegate_evaluate_action",
  "commercegate_get_dossier",
  "commercegate_get_proof_packet",
  "commercegate_list_shadow_reports",
  "commercegate_summarize_shadow_reports",
]
```

## Safety contract

- `commercegate_evaluate_action` is hard-locked to `SHADOW`. It can create an evaluation and Decision Dossier, but it never executes the proposed action.
- `APPROVE` is evidence, not user consent and not permission to mutate a marketplace.
- `REJECT` means stop. `REVIEW` or `ESCALATE` means hold and involve an authorized human.
- Tenant calls are bound to `DECIONIS_ORG_ID`; tools never accept an organization override.
- The process starts without credentials so clients can inspect its capabilities. Every tenant call then fails closed with a redacted configuration error.
- API credentials are never returned. Fail-closed errors omit configured organization values and upstream response bodies.

## Tools

| Tool                                    | Purpose                                                  | External effect                                      |
| --------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------- |
| `commercegate_describe_capabilities`    | Inspect support, safety guarantees, and connection state | None; local only                                     |
| `commercegate_evaluate_action`          | Evaluate `ORDER_ACCEPTANCE` or `PRICE_CHANGE`            | Writes only a Shadow Mode evaluation/evidence record |
| `commercegate_get_dossier`              | Read a signed Decision Dossier by UUID                   | Tenant read                                          |
| `commercegate_get_proof_packet`         | Read a dossier proof packet by UUID                      | Tenant read                                          |
| `commercegate_list_shadow_reports`      | Read recent Shadow Mode evaluation reports               | Tenant read                                          |
| `commercegate_summarize_shadow_reports` | Read aggregate Shadow Mode outcomes and near misses      | Tenant read                                          |

`commercegate_evaluate_action` accepts a discriminated action object. Order acceptance requires `order_id`, `gross_amount`, `discount_amount`, `estimated_cost`, and an ISO-4217 `currency`. Price changes require `sku`, nullable `from_price`, `to_price`, `estimated_cost`, and `currency`. Both require a stable actor, platform, and bounded `idempotency_key`. CommerceGate computes net revenue, net margin amount, and net margin fraction before sending the Shadow Mode evaluation.

The two Shadow Report tools accept an optional `days` window from 1–365 and `limit` from 1–100. Both read the canonical `/v1/protocol/shadow-reports` document; the list tool presents operational rows while the summary tool presents its aggregate view.

CommerceGate normalizes Protocol outcomes for operations agents:

| Protocol outcome     | CommerceGate disposition | Agent behavior                                                                |
| -------------------- | ------------------------ | ----------------------------------------------------------------------------- |
| `APPROVE`            | `PROCEED`                | Preflight passed; proceed only when the user separately authorized execution. |
| `REJECT`             | `BLOCK`                  | Stop.                                                                         |
| `REVIEW`, `ESCALATE` | `HOLD`                   | Hold and route to an authorized human.                                        |
| Missing or unknown   | `HOLD`                   | Fail closed and ask an operator to inspect the dossier.                       |

## Configuration

| Environment variable | Required         | Secret | Meaning                                            |
| -------------------- | ---------------- | ------ | -------------------------------------------------- |
| `DECIONIS_API_KEY`   | For tenant calls | Yes    | Decionis organization API key                      |
| `DECIONIS_ORG_ID`    | For tenant calls | No     | UUID that permanently scopes this server process   |
| `DECIONIS_API_BASE`  | No               | No     | API origin; defaults to `https://api.decionis.com` |

The API base must use HTTPS. HTTP is accepted only for loopback development.

## Example action

```json
{
  "action": {
    "action_type": "ORDER_ACCEPTANCE",
    "actor": { "type": "AGENT", "id": "order-ops-agent" },
    "platform": "walmart-marketplace",
    "idempotency_key": "order:123:acceptance:v1",
    "payload": {
      "order_id": "123",
      "gross_amount": 100,
      "discount_amount": 10,
      "estimated_cost": 60,
      "currency": "USD"
    }
  },
  "policy_version": "commerce-2026-09"
}
```

The response explicitly states that no downstream action was executed and tells the agent how to handle the returned outcome.

## Develop from source

Run the repository checkout through the workspace command when developing an unreleased change:

```sh
pnpm --filter @decionis/commerce typecheck
pnpm --filter @decionis/commerce test
pnpm --filter @decionis/commerce build
pnpm --silent --filter @decionis/commerce mcp
```

## Support and license

- Support: [Contact Decionis](https://decionis.com/contact)
- License: [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
