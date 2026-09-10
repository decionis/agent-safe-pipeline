---
name: Decionis CommerceGate
description: Check a price change, stock change, order, refund or return against the merchant's margin, stock and refund policy before acting. Use before any commerce action on Walmart, Shopify, Adobe Commerce or Business Central.
---

# Decionis CommerceGate

Before you change a price, publish a stock quantity, accept an order, ship, change a promotion, refund or authorize a return, ask CommerceGate whether the action clears policy. It answers PROCEED, HOLD or BLOCK with the margin, stock or refund math and records a signed Decision Dossier.

## Setup

Add the MCP server (local STDIO):

    command: npx
    args: ["-y", "@decionis/commerce@0.1.3"]
    env: DECIONIS_API_KEY (secret), DECIONIS_ORG_ID, DECIONIS_API_BASE (optional)

Run `commercegate_describe_capabilities` first; it works without credentials.

## Rules

- Call `commercegate_evaluate_action` before the commerce action, with the exact facts (SKU, current and new price or quantity, landed cost, order amounts, refund amount).
- PROCEED is a policy result, not permission: the merchant's own tool or a person still performs the action.
- Stop on HOLD, BLOCK, an error or an ambiguous answer and show the reason to the operator.
- CommerceGate never writes to a marketplace or ERP. Do not route around it with another tool.
- For a Business Central transaction, use `commercegate_validate_erp_transaction`; ALLOW or BLOCK is enforced there.
- When finance asks why, fetch the dossier with `commercegate_get_dossier` or `commercegate_get_proof_packet`.
