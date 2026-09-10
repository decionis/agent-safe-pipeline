# CommerceGate MCP

CommerceGate MCP gives operations agents a tenant-bound Shadow Mode preflight for price, inventory, order, fulfillment, promotion, refund, and return actions, plus enforced Dynamics 365 transaction authorization, signed decision evidence, and reports.

The server runs locally over STDIO and calls the Decionis API. `commercegate_evaluate_action` records a Shadow Mode policy evaluation; it does not execute the proposed action in a marketplace or ERP. `commercegate_validate_erp_transaction` performs enforced binary policy and agent-budget authorization for a complete Dynamics 365 transaction, but it does not post, release, modify, or otherwise write that transaction. Refund, oversell, and other connector execution paths remain separate and are available only when the connected platform exposes the required API, the merchant grants its required scope, and the Commerce Gate connector implements and enables that path.

Package: [@decionis/commerce](https://www.npmjs.com/package/@decionis/commerce)

## What operators use it for

- “Would repricing this SKU to $89 still clear our margin floor?” → `PRICE_CHANGE`
- “Would reducing this location from 47 to 7 units breach the inventory floor?” → `INVENTORY_MUTATION`
- “Would accepting this discounted order clear its supplied economics?” → `ORDER_ACCEPTANCE`
- “May this order be acknowledged, shipped, cancelled, or held?” → `FULFILLMENT_ACTION`
- “Does this proposed promotion need review?” → `PROMOTION_CHANGE`
- “Does this refund request fit the active policy?” → `REFUND_REQUEST`
- “May this return or RMA be authorized?” → `RETURN_AUTHORIZATION`
- “Does this complete Dynamics 365 transaction clear policy and the agent budget?” → `commercegate_validate_erp_transaction`
- “What would Shadow Mode have held this month, and why?” → the Shadow Report tools
- “Finance needs the signed evidence for this dossier.” → the dossier and proof-packet tools

Outcomes map to the operator vocabulary used across Commerce Gate: APPROVE → PROCEED, REVIEW → HOLD, ESCALATE → HOLD, and REJECT → BLOCK. Stop on HOLD, BLOCK, an error, or an ambiguous response. PROCEED is a policy result, not consent to execute.

## Install

CommerceGate requires Node.js 20 or later. Start the pinned public package with:

```sh
npx -y @decionis/commerce@0.1.2
```

The process starts without credentials so an MCP client can discover its capabilities. The ERP guard requires `DECIONIS_API_KEY`; Protocol evaluation and evidence tools require both `DECIONIS_API_KEY` and `DECIONIS_ORG_ID`. Store `DECIONIS_API_KEY` in the MCP client’s secret or environment manager; never place it in command arguments, source control, prompts, or logs. `DECIONIS_API_BASE` is optional and defaults to `https://api.decionis.com`.

For a capability-only startup, omit the credential variables and call `commercegate_describe_capabilities`. Every authenticated call fails closed until its required configuration is available.

### Codex client configuration

Forward the three named variables from the environment that launches Codex:

```toml
[mcp_servers.commercegate]
command = "npx"
args = ["-y", "@decionis/commerce@0.1.2"]
env_vars = ["DECIONIS_API_KEY", "DECIONIS_ORG_ID", "DECIONIS_API_BASE"]
enabled = true
required = false
startup_timeout_sec = 20
tool_timeout_sec = 45
default_tools_approval_mode = "writes"
enabled_tools = [
  "commercegate_describe_capabilities",
  "commercegate_validate_erp_transaction",
  "commercegate_evaluate_action",
  "commercegate_get_dossier",
  "commercegate_get_proof_packet",
  "commercegate_list_shadow_reports",
  "commercegate_summarize_shadow_reports",
]
```

## Tools

| Tool                                    | Purpose                                                                                  | External effect                                                |
| --------------------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `commercegate_describe_capabilities`    | Inspect action coverage, safety guarantees, connector boundaries, and connection state   | None; local only                                               |
| `commercegate_validate_erp_transaction` | Enforced binary authorization for one complete D365 transaction                          | Policy decision and idempotent agent-budget authorization only |
| `commercegate_evaluate_action`          | Check a price change, stock change, order, fulfillment step, promotion, refund or return | Writes only a Shadow Mode evaluation/evidence record           |
| `commercegate_get_dossier`              | Read a signed Decision Dossier by UUID                                                   | Protocol tenant read                                           |
| `commercegate_get_proof_packet`         | Read a dossier proof packet by UUID                                                      | Protocol tenant read                                           |
| `commercegate_list_shadow_reports`      | Read recent Shadow Mode evaluation rows                                                  | Protocol tenant read                                           |
| `commercegate_summarize_shadow_reports` | Read aggregate Shadow Mode outcomes and near misses                                      | Protocol tenant read                                           |

### Action contract

Every action includes a stable `actor`, a `platform`, and a bounded `idempotency_key`. The payload is selected by `action_type`:

| Action type            | Payload                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| `ORDER_ACCEPTANCE`     | nullable `order_id`, `gross_amount`, `discount_amount`, `estimated_cost`, optional `currency`     |
| `PRICE_CHANGE`         | `sku`, nullable `from_price`, `to_price`, optional nullable `estimated_cost`, optional `currency` |
| `INVENTORY_MUTATION`   | `sku`, nullable `from`, `to`, optional `location_id`                                              |
| `FULFILLMENT_ACTION`   | `order_id`, `action` (`acknowledge`, `ship`, `cancel`, or `hold`)                                 |
| `PROMOTION_CHANGE`     | nullable `promotion_id`, `percentage_fraction`, `ends_at`, `status`, and `combines_with`          |
| `REFUND_REQUEST`       | `order_id`, `amount`, optional `currency` and `reason_code`                                       |
| `RETURN_AUTHORIZATION` | `order_id`, optional `rma_id` and `amount`                                                        |

Order acceptance and price change have native CommerceGate margin mappings. The other five action types are generic Protocol Shadow evaluations: the server validates and normalizes their shape, but the result is only as complete as the active tenant policy and the submitted facts. A verdict says whether the action clears policy, not whether the platform's connector can carry it out.

The ERP guard accepts a bounded `erp_region` and the complete canonical D365 request: `transaction_id`, `erp_type`, `tenant_id`, `timestamp`, `agent_id`, `currency`, and 1–200 line records. It sends the configured API key as `X-Decionis-API-Key` and the region as `X-ERP-Region`. An `ALLOW` response means the exact request cleared enforced policy and its idempotent agent-budget authorization; it is not user consent and the MCP still performs no ERP write. The guard returns a reason code and message but does not promise a retrievable Decision Dossier or proof packet for that call.

The Shadow Report tools accept an optional `days` window from 1–365 and `limit` from 1–100. Both read the canonical `/v1/protocol/shadow-reports` document; the list tool presents operational rows while the summary tool presents its aggregate view.

## Minimal end-to-end example

With `DECIONIS_API_KEY` and `DECIONIS_ORG_ID` set in the MCP process environment, call `commercegate_evaluate_action` with:

```json
{
  "action": {
    "action_type": "REFUND_REQUEST",
    "actor": { "type": "AGENT", "id": "support-agent" },
    "platform": "walmart-marketplace",
    "idempotency_key": "order:123:refund:line-1:v1",
    "payload": {
      "order_id": "123",
      "amount": 180,
      "currency": "USD",
      "reason_code": "CustomerReturn"
    }
  },
  "policy_version": "commerce-2026-09"
}
```

The response contains the Protocol evaluation, the normalized CommerceGate disposition, and explicit agent guidance. It also states that no downstream action was executed. A separate Walmart connector can submit a product-line refund only for an eligible shipped or delivered line and only up to its remaining refundable product amount; this MCP call neither checks that live order state nor submits the refund.

## Safety contract

- `commercegate_evaluate_action` is hard-locked to `SHADOW`. It may create an evaluation and Decision Dossier, but it never executes the proposed action.
- `commercegate_validate_erp_transaction` is an enforced `ALLOW`/`BLOCK` decision and can reserve agent budget idempotently. It never writes the transaction to Dynamics 365.
- `APPROVE` is evidence, not user consent and not permission to mutate a marketplace.
- `REJECT` means stop. `REVIEW` or `ESCALATE` means hold and involve an authorized human.
- Protocol calls are bound to `DECIONIS_ORG_ID`; tools never accept an organization override. The ERP guard instead authenticates the submitted `tenant_id` with the configured API key.
- Tenant failures and unknown outcomes fail closed to HOLD. The process never silently routes around CommerceGate.
- API credentials are never returned. Safe errors omit configured organization values and upstream response bodies.
- Connector execution is conditional and separate. Do not translate an unavailable action into a different action type.

## Connector boundary

Refund and oversell controls are connector-gated. Depending on the connector, Commerce Gate may return a decision, withhold order release, or submit an explicitly confirmed action. A connected status alone is not enough: execution requires the marketplace API, merchant-granted scope, implemented and enabled connector path, and explicit execution authority. If any condition is missing, the capability remains evaluation-only or unavailable.

Current shipped examples:

- Walmart supports order reads, policy-evaluated acknowledgment, and operator-confirmed ship, cancel, and product-line refund paths. Refunds are limited to eligible shipped or delivered lines and the remaining refundable product amount. None of those writes are exposed through this MCP.
- Shopify Functions enforce configured margin rules at checkout, in discount handling, and in payment-method selection. A separate Shopify Flow action performs a post-order Shopify inventory-floor check and records a decision; it does not hold, cancel, modify, or refund the order, and it does not currently compare another marketplace’s inventory.

## Outcome semantics

| Protocol outcome     | CommerceGate disposition | Agent behavior                                                                                                   |
| -------------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `APPROVE`            | `PROCEED`                | Preflight passed; proceed only when the user separately authorized execution and the connector confirms support. |
| `REJECT`             | `BLOCK`                  | Stop.                                                                                                            |
| `REVIEW`, `ESCALATE` | `HOLD`                   | Hold and route to an authorized human.                                                                           |
| Missing or unknown   | `HOLD`                   | Fail closed and ask an operator to inspect the dossier.                                                          |

The ERP guard uses a separate binary vocabulary: `ALLOW` maps to `PROCEED` for the exact validated transaction, while `BLOCK` means stop. `ALLOW` remains authorization evidence rather than user consent, and no ERP write occurs inside the MCP.

## Configuration

| Environment variable | Required                     | Secret | Meaning                                                         |
| -------------------- | ---------------------------- | ------ | --------------------------------------------------------------- |
| `DECIONIS_API_KEY`   | For every authenticated call | Yes    | Sent as bearer for Protocol or X-Decionis-API-Key for ERP guard |
| `DECIONIS_ORG_ID`    | For Protocol calls           | No     | UUID that permanently scopes Protocol evaluation and evidence   |
| `DECIONIS_API_BASE`  | No                           | No     | API origin; defaults to `https://api.decionis.com`              |

The API base must use HTTPS. HTTP is accepted only for loopback development.

## Develop from source

```sh
pnpm --filter @decionis/commerce typecheck
pnpm --filter @decionis/commerce test
pnpm --filter @decionis/commerce build
pnpm --silent --filter @decionis/commerce mcp
```

## Support and license

- Support: [Contact Decionis](https://decionis.com/contact)
- License: [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
