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
npx -y @decionis/commerce@0.1.5
```

The process starts without credentials for capability discovery. For an unconfigured local STDIO client on macOS or Linux, the first valid `commercegate_evaluate_action` call creates a provisional Shadow workspace without a registration form. It reuses that workspace on later calls and restarts. Discovery, invalid input, evidence reads, and ERP calls never create a workspace. Provisional access is subject to the service's trial limits and cannot authorize ERP transactions.

Automatic local provisioning is unavailable on Windows until equivalent secure credential persistence is supported; configure existing credentials there.

Local access is stored separately from AgentSafe in `$AGENTOPS_HOME/credentials.json`, or `$XDG_CONFIG_HOME/agentops/credentials.json` (default `~/.config/agentops/credentials.json`). On POSIX systems the directory is owner-only (`0700`) and the file is owner-only (`0600`). A private exclusive lock coordinates concurrent processes. A persistent attempt marker prevents a second mint after an uncertain response, crash, or lost credential. Corrupt, permissive, missing-after-attempt, or revoked credentials fail closed: restore the owned credential or contact support rather than deleting setup files to obtain another trial. Safe tool results identify provisional access and provide claim guidance without exposing the key or claim tokens.

Existing `DECIONIS_API_KEY` and `DECIONIS_ORG_ID` configuration takes precedence. Store keys in the MCP client's secret manager; never place them in command arguments, source control, prompts, or logs. `DECIONIS_API_BASE` defaults to `https://api.decionis.com` and also accepts the exact `/aws` gateway prefix. Set `AGENTOPS_AUTO_PROVISION=0` to disable new trial creation; already stored credentials remain usable. `NODE_ENV=production` and HTTP transport never provision anonymous access. For capability-only use, disable automatic provisioning and supply no stored or configured credentials.

### Codex client configuration

Optionally forward existing credentials and local access preferences from the environment that launches Codex:

```toml
[mcp_servers.commercegate]
command = "npx"
args = ["-y", "@decionis/commerce@0.1.5"]
env_vars = ["DECIONIS_API_KEY", "DECIONIS_ORG_ID", "DECIONIS_API_BASE", "AGENTOPS_HOME", "AGENTOPS_AUTO_PROVISION"]
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

| Action type            | Payload                                                                                                |
| ---------------------- | ------------------------------------------------------------------------------------------------------ |
| `ORDER_ACCEPTANCE`     | nullable `order_id`, `gross_amount`, `discount_amount`, `estimated_cost`, optional `currency`          |
| `PRICE_CHANGE`         | `sku`, nullable `from_price`, `to_price`, optional nullable `estimated_cost`, optional `currency`      |
| `INVENTORY_MUTATION`   | `sku`, nullable `from`, `to`, optional `location_id`                                                   |
| `FULFILLMENT_ACTION`   | `order_id`, `action` (`acknowledge`, `ship`, `cancel`, or `hold`)                                      |
| `PROMOTION_CHANGE`     | nullable `promotion_id`, `percentage_fraction`, `ends_at`, `status`, and `combines_with`               |
| `REFUND_REQUEST`       | `order_id`, `amount`, optional `currency`, `reason_code`, `remaining_refundable`, `prior_refund_count` |
| `RETURN_AUTHORIZATION` | `order_id`, optional `rma_id` and `amount`                                                             |

Order acceptance and price change have native CommerceGate margin mappings. The other five action types are generic Protocol Shadow evaluations: the server validates and normalizes their shape, but the result is only as complete as the active tenant policy and the submitted facts. A verdict says whether the action clears policy, not whether the platform's connector can carry it out.

The ERP guard accepts a bounded `erp_region` and the complete canonical D365 request: `transaction_id`, `erp_type`, `tenant_id`, `timestamp`, `agent_id`, `currency`, and 1–200 line records. It sends the configured API key as `X-Decionis-API-Key` and the region as `X-ERP-Region`. An `ALLOW` response means the exact request cleared enforced policy and its idempotent agent-budget authorization; it is not user consent and the MCP still performs no ERP write. The guard returns a reason code and message but does not promise a retrievable Decision Dossier or proof packet for that call.

The Shadow Report tools accept an optional `days` window from 1–365 and `limit` from 1–100. Both read the canonical `/v1/protocol/shadow-reports` document; the list tool presents operational rows while the summary tool presents its aggregate view.

## Minimal end-to-end example

With existing credentials, or to create a provisional local Shadow workspace on first use, call `commercegate_evaluate_action` with:

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

| Environment variable         | Required                          | Secret | Meaning                                                                                                 |
| ---------------------------- | --------------------------------- | ------ | ------------------------------------------------------------------------------------------------------- |
| `DECIONIS_API_KEY`           | Existing workspace option         | Yes    | Sent as bearer for Protocol or X-Decionis-API-Key for ERP guard                                         |
| `DECIONIS_ORG_ID`            | With an explicit key for Protocol | No     | UUID that scopes Protocol evaluation and evidence                                                       |
| `DECIONIS_API_BASE`          | No                                | No     | HTTPS API origin or exact `/aws` prefix; raw AWS secret defaults to `https://commerce.decionis.com/aws` |
| `AGENTOPS_ACCESS_SECRET_ARN` | Managed access option             | No     | AWS Secrets Manager secret read through the execution role                                              |
| `AGENTOPS_HOME`              | No                                | No     | Private local trial directory; separate from AgentSafe                                                  |
| `AGENTOPS_AUTO_PROVISION`    | No                                | No     | Set `0` to disable new local trial creation                                                             |

The API base must use HTTPS. HTTP is accepted only for loopback development.

## Run it as a remote server (Amazon Bedrock AgentCore Runtime)

AgentOps is the container delivery of the same CommerceGate MCP server,
listed as "AgentOps MCP Server for Amazon Bedrock AgentCore" on AWS Marketplace.
It speaks streamable HTTP for buyers who run their agents in Amazon Bedrock AgentCore Runtime. Start it with
`--http` (or `MCP_TRANSPORT=http`): it listens on `0.0.0.0:8000`, answers
`POST /mcp` with one JSON-RPC message per request (stateless; the
runtime's `Mcp-Session-Id` is echoed), and `GET /ping` with
`{"status":"Healthy"}`. There is no server-initiated stream.

The AgentOps container is free on Marketplace; service usage is billed
through the AgentSaaS subscription, the API-based Marketplace product. Buyers
pay their own AWS runtime and related infrastructure charges. No measured
compute-cost, latency or throughput improvement is claimed here.

For local use, put your workspace's `DECIONIS_API_KEY` and `DECIONIS_ORG_ID`
in an untracked `agentops.env` file. `DECIONIS_API_BASE` is optional and
defaults to `https://api.decionis.com`. Keep this file private and bind the
published local port to loopback:

```sh
chmod 600 agentops.env
docker buildx build -f packages/commerce-mcp/Dockerfile --platform linux/arm64 -t agentops-core:latest .
docker run -p 127.0.0.1:8000:8000 --env-file ./agentops.env agentops-core:latest
curl -X POST http://127.0.0.1:8000/mcp -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

For managed AgentCore, configure `AGENTOPS_ACCESS_SECRET_ARN` with a durable Secrets Manager secret and grant the execution role `secretsmanager:GetSecretValue` on that secret (and `kms:Decrypt` if it uses a customer-managed KMS key). The AWS SDK uses its default execution-role credential chain; the image contains no AWS access key. The secret may contain JSON with `api_key`, `org_id`, and `api_base_url`, or the raw `dcn_aws_` Marketplace key. For a raw key, the server discovers its tenant through authenticated `GET https://commerce.decionis.com/aws/commerce/session`. An explicit `DECIONIS_API_BASE` may select another trusted deployment's exact `/aws` gateway. Redirects and any returned change to the configured origin or prefix are rejected.

The secret is loaded once on the first authenticated tool call and retained in memory for that process; errors never trigger key rotation or anonymous fallback. New AgentCore instances load the same durable secret, so ephemeral restarts retain the tenant. A deliberate credential rotation requires restarting the runtime. Existing `DECIONIS_API_KEY` and `DECIONIS_ORG_ID` launch variables remain supported and take precedence. HTTP requires configured access and never creates a trial. Capability discovery works without access. This client does not itself subscribe a buyer, create the durable secret, or grant its execution role; the deployment must supply those bindings. Requests are limited to 1 MiB,
with eight in flight including uploads still being read; further requests
receive 503 with `Retry-After`. JSON-RPC batches receive 400 without invoking
a tool. Browser access is unsupported: every request carrying an `Origin`
header receives 403. HTTP supports MCP versions `2025-03-26`, `2025-06-18`,
and `2025-11-25`; unsupported `MCP-Protocol-Version` headers receive 400,
and a missing header uses the `2025-03-26` compatibility default.
Keep this server behind AgentCore's authenticated runtime in production.
`.github/workflows/commerce-mcp-agentcore.yml` builds, smoke-tests,
publishes and attests the image. Publication tags the same digest with the
package version and `latest`; listing versions use the pinned digest.

### Historical assessment in managed HTTP

Managed HTTP retains all seven tools above and adds a 90-day historical
assessment feature. This feature does not replace proposal evaluation,
Dynamics 365 authorization or their existing permission boundaries. The STDIO
package and Claude Desktop wrapper retain their seven-tool contract.

| Additional HTTP tool                       | Purpose                                                                        |
| ------------------------------------------ | ------------------------------------------------------------------------------ |
| `commercegate_list_history_sources`        | List the synthetic dataset and already connected stores available to the buyer |
| `commercegate_start_historical_assessment` | Persist an idempotent assessment of the previous 90 days                       |
| `commercegate_get_historical_assessment`   | Read its immutable summary, provenance, policy and bounded evidence            |

These tools require the Commerce Gate `/aws` gateway with its historical
service deployed and enabled, plus a currently valid, server-verified AWS
grant. A package or image release alone does not enable the service. Use the
durable AgentSaaS access secret described above, or explicitly configure its
key and `DECIONIS_API_BASE=https://commerce.decionis.com/aws`. History requests
derive the workspace from the credential and never send an organization
override. Grant eligibility and expiry are verified by the service on each
request; the container does not invent an expiry or extend a trial.

The AWS trial lasts **14 days** and uses a synthetic dataset representing
90 days of commerce history. It does not require live customer data. Real
assessments currently read an already verified Adobe Commerce store connection; there is no CSV,
generic transaction upload or store-connection tool in this contract. The
client never creates an anonymous HTTP trial.

First list sources, then call the start tool with:

```json
{
  "source": { "kind": "synthetic" },
  "idempotency_key": "history-demo-1"
}
```

For real history, use `{"kind":"connected_store","connection_id":"<listed UUID>"}`
as the source. The service fixes the 90-day window, timestamps, policy and
transactions. Callers cannot supply replacement dates, policies or raw
transactions. Reuse the same idempotency key only for a retry of the same
assessment, then read its `assessment_id` to retrieve the stored result.

Summaries retain missing costs, excluded timestamps and evaluation failures.
Synthetic results identify a sample policy; real-store results identify the
merchant policy. Historical `PROCEED` is a retrospective classification, not
permission to execute an action. Evidence includes at most 100 records with
hashed identifiers. The initial service scans at most 100 source records, so
`coverage.complete` and `truncated` must be checked before treating a result as
complete for the interval. Missing costs or unavailable policy must not be
presented as successful evaluation. A failed assessment may have `policy: null`.
A null `proof_ref` means no
signed proof is available; sample margin calculations must not be described
as signed Decision Dossiers. No history tool executes a platform write.

The history transport accepts only the exact `/aws` prefix, rejects redirects,
limits responses to 100 KiB and validates returned source, policy, window,
assessment identity and evidence. Errors omit upstream bodies and credentials.
There is no fallback to another tenant, source or prospective evaluation.

## Develop from source

```sh
pnpm --filter @decionis/commerce typecheck
pnpm --filter @decionis/commerce test
pnpm --filter @decionis/commerce build
pnpm --silent --filter @decionis/commerce mcp
```

## Privacy Policy

CommerceGate MCP talks to the configured Decionis API. Managed deployments using `AGENTOPS_ACCESS_SECRET_ARN` also contact AWS Secrets Manager through the AWS SDK credential chain. It has no telemetry, analytics, or crash reporting. The full Decionis privacy policy is at <https://decionis.com/privacy>; this section describes what this server specifically does.

**What it collects.** The first valid unconfigured local Shadow call sends the fixed agent name "AgentOps MCP Shadow" to obtain a provisional workspace. Other application data comes from tool inputs: the commerce facts being checked (SKU, current and new price or quantity, landed cost, order amounts, discount, refund amount and reason, promotion facts, actor type and a non-secret actor identifier, platform, idempotency key), a dossier UUID for evidence reads, and a report window for Shadow reports. The additional managed HTTP history tools send only a selected synthetic source or connected-store UUID, idempotency key, or assessment UUID; they do not accept uploaded customer transactions. The service reads authorized connected-store history separately. The server reads only its configured credentials and local access files; it does not read browser data, the clipboard, or unrelated machine data.

**Where it goes and why.** Tool inputs are sent over HTTPS to the Decionis API to evaluate them against your organization's policy and to read evidence you already own. The request carries your `DECIONIS_API_KEY` as a bearer token, your `DECIONIS_ORG_ID` to scope the call to your organization, and a `user-agent` naming this package and version. Credentials come from the process environment, private local access storage, or the configured AWS secret. Keys and claim tokens are never returned in tool results or written to logs.

**What is stored.** Existing Protocol policy evaluations may produce signed Decision Dossiers in your organization's workspace. Historical assessments instead persist their immutable summary, source and policy provenance, hashed record identifiers, and inline evaluation results; those results are unsigned when `proof_ref` is null. Do not describe a synthetic assessment as a signed dossier. Retention follows your Decionis plan and the Decionis privacy policy. Local trial access persists its credential, tenant binding, and setup marker in the private AgentOps directory. Managed AWS credentials remain in Secrets Manager and process memory; the server does not persist them locally. There is no tool-input cache, log file, or local evidence database. On a failed request it writes one fixed line to stderr with no request contents.

**Third parties.** Managed secret access uses AWS; commerce tool inputs still go only to the configured Decionis API. Decionis does not sell or share tool inputs. Your MCP client (Claude Desktop, Codex, VS Code or another host) may log tool calls under its own policy.

**Personal data.** Commerce facts can include order identifiers and, if you pass them, customer-related amounts. Send only what the policy check needs; the server accepts a bounded, typed action and rejects unknown fields.

**Your controls.** Set `AGENTOPS_AUTO_PROVISION=0` to disable new local trial creation. To leave only capability discovery, also remove configured access and securely remove the stored credential; keep the attempt marker to prevent accidental reminting. Revocation and deletion of the server-side workspace are separate operations. Uninstall the package or extension to stop all processing. To access, correct or delete dossiers held by Decionis, or to ask anything about this policy, write to <mailto:commerce@decionis.com>; security reports go to <mailto:security@decionis.com> (see <https://commerce.decionis.com/.well-known/security.txt>).

## Support and license

- Support: [Contact Decionis](https://decionis.com/contact)
- License: [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
