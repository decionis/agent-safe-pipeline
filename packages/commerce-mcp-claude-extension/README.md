# Decionis CommerceGate for Claude Desktop

Check a price change, order, refund or return against your commerce policy before an agent acts. Never writes to a marketplace.

This workspace package is the dedicated MIT-licensed Claude Desktop extension wrapper for
[`@decionis/commerce@0.1.3`](https://github.com/decionis/agent-safe-pipeline/tree/master/packages/commerce-mcp),
the Apache-2.0 CommerceGate MCP runtime. The licenses do not blend: the small loader, extension
manifest, packaging checks, and extension documentation are MIT; the separately bundled
CommerceGate runtime remains Apache-2.0 and ships with its own package metadata, license, and
notice.

## Directory description

<!-- markdownlint-disable MD034 -->

Decionis CommerceGate lets an AI agent ask one question before it touches a marketplace: is this allowed under our policy?

It checks seven kinds of commerce action in Shadow Mode: a price change, a stock change, accepting an order, a fulfillment step, a promotion change, a refund, or a return authorization. The answer is PROCEED, HOLD or BLOCK with the math behind it: net margin after landed cost and marketplace fees against your margin floor, quantity against your inventory floor, refund amount against what the order has left to refund. Every policy decision is recorded in a signed Decision Dossier that finance can verify months later.

Ask it things like:

- "Would repricing this SKU to $89 on Walmart still clear our margin floor after the referral fee?"
- "Is it safe to accept this 40-unit order with the stock we have left?"
- "Can the support bot refund $2,850 on this order?"
- "What would Shadow Mode have held this month, and why?"

For Dynamics 365 Business Central, a separate tool returns an enforced ALLOW or BLOCK for one complete transaction within the agent's spend budget.

What it never does: CommerceGate does not accept, ship, cancel, refund, reprice or change stock on any platform. It evaluates and reads evidence; a person or the connected system still executes. A PROCEED is a policy result, not consent.

Setup: runs locally as a Node.js process. Capability discovery works with no credentials. Tenant checks need DECIONIS_API_KEY and DECIONIS_ORG_ID from your Decionis workspace (free Shadow Mode, no time limit).

Built by Decionis for marketplace operations, pricing, finance and automation teams on Walmart Marketplace, Shopify, Adobe Commerce and Dynamics 365 Business Central. Documentation: https://commerce.decionis.com/mcp

<!-- markdownlint-enable MD034 -->

## Safety boundary

Shadow Mode evaluation only. CommerceGate never accepts, ships, cancels, refunds, reprices or changes stock on Walmart, Shopify, Adobe Commerce or Business Central; your tools act on the verdict.

`commercegate_evaluate_action` records a Shadow Mode policy evaluation but never executes the
proposed action. `commercegate_validate_erp_transaction` returns an enforced policy and agent-budget
decision for the complete submitted Dynamics 365 transaction but performs no ERP write. PROCEED or
ALLOW is a policy result, not consent. Stop on HOLD, BLOCK, ESCALATE, errors, or ambiguous results.

Refund, oversell, and other connector execution paths are separate. Execution is available only
when the specific marketplace exposes the required API, the merchant grants the required scope,
and a connector implements and enables that path.

## Tools

- `commercegate_describe_capabilities` — inspect coverage, boundaries, and connection state without credentials.
- `commercegate_evaluate_action` — evaluate a price, stock, order, fulfillment, promotion, refund, or return proposal in Shadow Mode.
- `commercegate_validate_erp_transaction` — validate one complete Dynamics 365 Business Central transaction against policy and the agent budget.
- `commercegate_get_dossier` — read the signed Decision Dossier for a decision.
- `commercegate_get_proof_packet` — read a dossier proof packet.
- `commercegate_list_shadow_reports` — list recent Shadow Mode evaluations.
- `commercegate_summarize_shadow_reports` — summarize Shadow Mode outcomes and near misses.

## Configuration

The extension can start without credentials for capability discovery. Authenticated tools read
configuration only from the extension environment:

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

The workspace pins `@anthropic-ai/mcpb` 2.1.2 in `pnpm-lock.yaml`. Point `MCPB_CLI_PATH` at its
resolved JavaScript entry point and run `scripts/VerifyMcpb.mjs`. The verifier invokes that
JavaScript through the current Node executable; it never launches a shell or a platform-specific
`.cmd` shim. The CI workflow contains the exact cross-platform commands and compares the macOS and
Windows bundle bytes.

The verifier allows only the reviewed MIT wrapper files and the separately attributed Apache-2.0
runtime files into the bundle. It validates, packs twice, normalizes ZIP timestamps, proves the two
archives are byte-identical, unpacks, compares every file, and runs initialize, tool-list, and
capability JSON-RPC requests against the unpacked extension.

## Privacy Policy

CommerceGate runs on your machine and talks to one service: the Decionis API at
`https://api.decionis.com` (or the origin configured in `DECIONIS_API_BASE`). It has no telemetry,
analytics, crash reporting, or other network destination. The full Decionis privacy policy is at
<https://decionis.com/privacy>; this section describes this extension specifically.

**What it collects.** Nothing on its own. It sends only the facts supplied in a tool call: commerce
facts being checked, an actor identifier, platform, idempotency key, dossier UUID for evidence
reads, and report window for Shadow reports. It never reads files, browser data, the clipboard, or
unrelated machine data.

**Where it goes and why.** Tool inputs go over HTTPS to the Decionis API for policy evaluation or to
read evidence owned by the configured organization. Credentials come from the extension environment
and are never written to disk or returned in tool results.

**What is stored and retention.** Decionis stores policy evaluations as signed Decision Dossiers in
the organization's workspace. Retention follows the customer's Decionis plan and the Decionis
privacy policy. The local extension stores no cache, log file, analytics record, or database.

**Third parties.** None. The extension contacts no third-party service. Claude Desktop may retain
tool-call history under Anthropic's own policy.

**Personal data.** Commerce facts can include order identifiers and customer-related amounts if
supplied. Submit only the bounded facts needed for the policy check.

**Your controls.** Remove `DECIONIS_API_KEY` and `DECIONIS_ORG_ID` to leave only unauthenticated
capability discovery, or uninstall the extension to stop processing. For access, correction,
deletion, or privacy questions, email <commerce@decionis.com>. Security reports go to
<security@decionis.com>.

## Support and licenses

- Product documentation: <https://commerce.decionis.com/mcp>
- Support: <https://decionis.com/contact>
- Extension source: <https://github.com/decionis/agent-safe-pipeline/tree/master/packages/commerce-mcp-claude-extension>
- Extension wrapper: [MIT](./LICENSE)
- Bundled CommerceGate runtime: `@decionis/commerce@0.1.3`, [Apache-2.0 source](https://github.com/decionis/agent-safe-pipeline/tree/master/packages/commerce-mcp), retained in the MCPB with its package metadata at `vendor/commerce-mcp/package.json`, license at `vendor/commerce-mcp/LICENSE`, and attribution notice at `vendor/commerce-mcp/NOTICE`
