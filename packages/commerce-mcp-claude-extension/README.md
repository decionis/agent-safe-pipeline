# Decionis Commerce Gate for Claude Desktop

Seven commerce actions default to non-blocking Shadow Mode, with Walmart mappings, a D365 guard, and a marketplace SaaS offer preflight. No marketplace or ERP writes.

This workspace package is the dedicated MIT-licensed Claude Desktop extension wrapper for
[`@decionis/commerce@0.1.6`](https://github.com/decionis/agent-safe-pipeline/tree/master/packages/commerce-mcp),
the Apache-2.0 Commerce Gate MCP runtime. The licenses do not blend: the small loader, extension
manifest, packaging checks, and extension documentation are MIT; the separately bundled
Commerce Gate runtime remains Apache-2.0 and ships with its own package metadata, license, and
notice.

## Directory description

<!-- markdownlint-disable MD034 -->

Decionis Commerce Gate gives an AI agent a policy checkpoint before a marketplace action or a manual Microsoft Partner Center or AWS Marketplace SaaS offer submission.

The seven commerce actions use tenant-scoped facts in Shadow Mode by default: a price change, a stock change, accepting an order, a fulfillment step, a promotion change, a refund, or a return authorization. Shadow Mode evaluates and records what policy would decide without blocking the native commerce flow; it is not a synthetic-data mode. When the customer activates an implemented, connected native enforcement path, that executor can block or hold the platform action outside this MCP. The Walmart Marketplace capability maps Commerce Evaluation, Price Guard, Order Guard, order intercept, margin protection, release, hold, and cancel to those bounded action contracts. A separate Dynamics 365 tool returns enforced ALLOW or BLOCK for one complete transaction within the agent’s spend budget.

A separate marketplace SaaS offer-submission preflight validates a bounded release packet before a person submits it. The packet carries no customer commerce records and requires preview or test evidence plus public URLs, plan and market configuration, marketplace identity, and digest-backed release evidence. Microsoft packets require Microsoft Entra tenant and application IDs. AWS packets require a Login with Amazon identity that is linked to the seller AWS account and IAM role.

Every policy decision can be recorded in a signed Decision Dossier. The marketplace-offer tool never calls a marketplace, uploads an artifact, creates or changes an offer, or submits an offer for review.

Setup: runs locally as a Node.js process. Capability discovery works with no credentials. On macOS, the first valid local Shadow evaluation can create a provisional workspace without registration and securely reuse it. Windows requires existing credentials until secure local persistence is supported. Trial limits apply; ERP requires owned access. Existing DECIONIS_API_KEY and DECIONIS_ORG_ID remain supported.

Built by Decionis for marketplace operations, pricing, finance and automation teams on Walmart Marketplace, Shopify, Adobe Commerce, Dynamics 365 Business Central, Microsoft Marketplace, and AWS Marketplace. Documentation: https://commerce.decionis.com/mcp

<!-- markdownlint-enable MD034 -->

## Safety boundary

Shadow Mode is the default non-blocking evaluation mode. It evaluates the supplied tenant-scoped facts and records the decision; it does not mean synthetic data. When the customer activates a supported native enforcement path, that executor can block or hold the platform action outside this MCP.

`commercegate_evaluate_action` evaluates the supplied customer-scoped proposal in default Shadow Mode but never executes the
proposed action. `commercegate_validate_erp_transaction` returns an enforced policy and agent-budget
decision for the complete submitted Dynamics 365 transaction but performs no ERP write. PROCEED or
ALLOW is a policy result, not consent. Stop on HOLD, BLOCK, ESCALATE, errors, or ambiguous results.

Refund, oversell, and other connector execution paths are separate. Execution is available only
when the specific marketplace exposes the required API, the merchant grants the required scope,
and a connector implements and enables that path.

## Tools

- `commercegate_describe_capabilities` — inspect coverage, Walmart mappings, boundaries, and connection state without credentials.
- `commercegate_evaluate_action` — evaluate a customer-scoped price, stock, order, fulfillment, promotion, refund, or return proposal in default Shadow Mode.
- `commercegate_validate_erp_transaction` — validate one complete Dynamics 365 Business Central transaction against policy and the agent budget.
- `commercegate_get_dossier` — read the signed Decision Dossier for a decision.
- `commercegate_get_proof_packet` — read a dossier proof packet.
- `commercegate_list_shadow_reports` — list recent Shadow Mode evaluations.
- `commercegate_summarize_shadow_reports` — summarize Shadow Mode outcomes and near misses.
- `commercegate_evaluate_marketplace_offer_submission` — preflight a bounded Microsoft Partner Center or AWS Marketplace SaaS offer packet before manual submission.

## Configuration

The extension can start without credentials. On macOS, its first valid Shadow evaluation can create a provisional workspace, stored privately under `~/.config/agentops` (or `AGENTOPS_HOME`, honoring `XDG_CONFIG_HOME`). Discovery, reads, ERP, and invalid input never provision access. Automatic provisioning is unavailable on Windows; use existing credentials there. Existing environment configuration takes precedence:

| Variable            | Secret | Purpose                                                      |
| ------------------- | ------ | ------------------------------------------------------------ |
| `DECIONIS_API_KEY`  | Yes    | Authenticates policy and evidence calls.                     |
| `DECIONIS_ORG_ID`   | No     | Binds Protocol calls to one organization.                    |
| `DECIONIS_API_BASE` | No     | Optional API origin; defaults to `https://api.decionis.com`. |

Never put credentials in tool arguments, source control, prompts, logs, fixtures, or screenshots.

## Build and validate

Use Node.js 22.14 or later and pnpm 9.15.3 from the repository root:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm --filter @decionis/commerce build
pnpm --filter @decionis/commercegate-claude-extension build
pnpm --filter @decionis/commercegate-claude-extension test
```

Then run `node scripts/VerifyMcpb.mjs`. The bundle is validated, packed and unpacked by
`scripts/McpbArchive.mjs` with Node's own zlib, so no packaging CLI or its dependencies are
installed. The CI workflow contains the exact cross-platform commands and compares the macOS and
Windows bundle bytes.

The verifier allows only the reviewed MIT wrapper files and the separately attributed Apache-2.0
runtime files into the bundle. It validates the manifest against MCPB 0.3, packs twice, proves the
two archives are byte-identical and already in canonical ZIP form, unpacks, compares every file,
and runs initialize, tool-list, and capability JSON-RPC requests against the unpacked extension.

## Privacy Policy

Commerce Gate runs on your machine and talks to one service: the Decionis API at
`https://api.decionis.com` (or the origin configured in `DECIONIS_API_BASE`). It has no telemetry,
analytics, crash reporting, or other network destination. The full Decionis privacy policy is at
<https://decionis.com/privacy>; this section describes this extension specifically.

**What it collects.** Nothing on its own. It sends only the facts supplied in a tool call: commerce
facts being checked, an actor identifier, platform, idempotency key, dossier UUID for evidence
reads, and report window for Shadow reports. It reads its own private access files; it does not read browser data, the clipboard, or unrelated machine data. Initial trial setup sends the fixed agent name "AgentOps MCP Shadow" to Decionis.

**Where it goes and why.** Tool inputs go over HTTPS to the Decionis API for policy evaluation or to
read evidence owned by the configured organization. Existing credentials come from the extension environment; provisional credentials are persisted in the private AgentOps directory (0700 directory and 0600 file on POSIX). Keys and claim tokens are never returned in tool results.

**What is stored and retention.** Decionis stores policy evaluations as signed Decision Dossiers in
the organization's workspace. Retention follows the customer's Decionis plan and the Decionis
privacy policy. The local extension stores only provisional access and setup coordination files, with no tool-input cache, log file, analytics record, or evidence database. It reuses credentials after restart and never silently replaces them after revocation, quota errors, or failed setup.

**Third parties.** None. The extension contacts no third-party service. Claude Desktop may retain
tool-call history under Anthropic's own policy.

**Personal data.** Commerce facts can include order identifiers and customer-related amounts if
supplied. Submit only the bounded facts needed for the policy check.

**Your controls.** Set `AGENTOPS_AUTO_PROVISION=0` in the launch environment to disable new trial creation. To leave only capability discovery, also remove configured access and securely remove the stored credential while keeping its attempt marker. Uninstall the extension to stop processing. For access, correction,
deletion, or privacy questions, email <commerce@decionis.com>. Security reports go to
<security@decionis.com>.

## Support and licenses

- Product documentation: <https://commerce.decionis.com/mcp>
- Support: <https://decionis.com/contact>
- Extension source: <https://github.com/decionis/agent-safe-pipeline/tree/master/packages/commerce-mcp-claude-extension>
- Extension wrapper: [MIT](./LICENSE)
- Bundled Commerce Gate runtime: `@decionis/commerce@0.1.6`, [Apache-2.0 source](https://github.com/decionis/agent-safe-pipeline/tree/master/packages/commerce-mcp), retained in the MCPB with its package metadata at `vendor/commerce-mcp/package.json`, license at `vendor/commerce-mcp/LICENSE`, and attribution notice at `vendor/commerce-mcp/NOTICE`
