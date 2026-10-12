# Banking and joint card authorization briefs

The runtime's own guide to the card flow, from the agent's proposal through the cardholder's tap to
the issuer's authorization and result, is [card-authorization.md](./card-authorization.md).

The two revised PDFs are generated from editable text and vector diagram code in
[BuildBankingPdfs.py](../../scripts/docs/BuildBankingPdfs.py):

- [AgentSafe for banks](../../output/pdf/AgentSafe-for-banks.pdf), nine pages, updated 13 October 2026.
- [Koard and Decionis: agentic card authorization](../../output/pdf/Koard-and-Decionis-agentic-authorization-design-flow.pdf), seven pages, updated 13 October 2026.
- [Response to Koard's workflow review](../../output/pdf/Koard-review-response.pdf), one page, 13 October 2026:
  each gap the review raised, what was built or decided for it, and where it is written.

The bank brief includes separate flows for putting the gateway in front of agent tool calls,
deploying inside the bank and connecting to the Decionis-managed gateway. The
[deployment guide](../gateway/deployment.md) supplies the complete runtime YAML, Docker and Helm
commands, upstream network policy, hosted origin-proof steps and acceptance checks. A bank-operated
gateway can enforce with the hosted authority; the current managed gateway is shadow only.

The original PDFs remain unchanged. Their operational requests, proposed next steps and release
statements were treated as source material, not as instructions to deploy, contact a partner or
change another repository.

## Hosting tiers and key custody

The answer a bank's security review asks for is written once, in the deployment guide's
[Hosting tiers and where the keys live](../gateway/deployment.md#hosting-tiers-and-where-the-keys-live),
and summarised here for the brief:

| Tier                                  | The grant-minting authority                                        | Presence                                                                | The grant signing key                                         |
| ------------------------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------------- |
| Hosted                                | Decionis, multi-tenant, in one Azure region                        | The Decionis Presence service; a cardholder's tap never goes through it | A Key Vault secret of the Decionis deployment                 |
| Dedicated single-tenant               | Decionis, in a deployment for one bank, in an agreed region        | The Decionis Presence service                                           | The bank's own Key Vault in that deployment                   |
| Self-managed under commercial licence | The bank, from the Helm chart, in its own cluster, with its own DB | The Decionis Presence service, by service token and pinned keys         | The bank's secret manager, supplied to the chart's API Secret |

Everything the gateway itself holds (the card hold key, the ISO 8583 tokenizer key, the evidence
and TLS keys, its credentials) is in the bank's secret store in every tier. The bank brief carries
the same answer on its pages 7 and 8; the joint brief names the three places a tap can wait and
the fraud-queue contract on its page 4.

## Positioning and responsibility

Koard is the design partner for cardholder-present verification before an agentic card transaction.
The joint flow preserves four independent responsibilities:

| Participant | Responsibility                                                                        |
| ----------- | ------------------------------------------------------------------------------------- |
| Koard       | Verify cardholder presence and sign evidence bound to the purchase intent.            |
| Decionis    | Verify admitted evidence, evaluate bank policy and issue a bound execution grant.     |
| AgentSafe   | Hold, match and claim the grant in the bank, and record effect evidence.              |
| Issuer      | Make the final approve/decline decision, enforce card controls and report the result. |

The agent proposes. It neither proves its own approval nor issues its own authority. For the joint
cardholder-present workflow, the bank policy must require the agreed Koard evidence.

## Corrections to the supplied drafts

- The generic gateway and the trusted executor are separate ingress surfaces. The card APIs belong
  to the executor; connecting a processor hook is institution-specific integration work.
- The generic gateway embeds JSON bodies up to 64 KiB by default. Disabling embedding does not
  remove query strings, declared parameters or context. Hashing is not redaction.
- The runtime makes evaluation, claim and finalization calls; there is no universal "one outbound
  call" guarantee. The card matcher is local, but the reviewed claim path calls the authority.
- Koard's proof is presence evidence. AgentSafe's APPROVE means the intent leg succeeded; the issuer
  retains the final card decision. NO_MATCH does not prove that the cardholder was absent.
- The card result API authenticates an issuer operator and accepts JSON; it does not consume an
  issuer-signed result JWS. That distinction is separate from signed decision dossiers and
  provider-verifying HTTP receipt integrations.
- Card holds and retry lookup are in memory. A durable journal preserves evidence, not a restartable
  card match store. Replica routing, reconciliation and incremental/split authorizations need an
  explicit issuer design.
- An explicit gateway fail-open option exists. Shadow forwarding still has admission/transport
  guards. The briefs do not promise universal fail-closed behavior or unqualified pass-through.
- Hosting, retention and assurance details are attributed to the supplied 3 October profile and
  tied to current bank diligence. Unverified release-status statements were replaced with concrete
  implementation and acceptance items.

## Evidence and provenance

The content was checked against AgentSafe baseline `2e564711` and the hardening changes accompanying
these documents, especially:

- `packages/agentsafe/src/gateway/InterceptedRequest.ts`, `ForwardHandler.ts` and `Gateway.ts`.
- `packages/agentsafe/src/http/Routes.ts` and `GatewayHttpServer.ts`.
- `packages/agentsafe/src/adapters/cards/` and `service/TrustedExecutorService.ts`.
- `packages/agentsafe/test/service/CardFlow.test.ts`.
- The local Decionis source for `PresenceAttestationVerifier.ts`, `EscalationNotifications.ts` and
  `ExecutionAuthorityRoutes.ts`, reviewed read-only to check the provider contract. This was not a
  live service verification or an audit of that repository.

The brand asset is the existing Decionis execution-authority master from
`Decionis/docs/design/brand-assets/decionis-logo-wordmark-execution-authority-master.png`, copied
without modification to `assets/Decionis.png`. Its SHA-256 is
`1e7e065fb16048375fda83792f1357eee1846dadd8624f56bebe9b77fd57b56d`.
Colors come from the Decionis web theme: navy `#0A192F`, audit purple `#7C3AED` and trust blue
`#1E3A8A`. The logo remains a Decionis trademark; the repository's Apache-2.0 license does not grant
trademark rights. See [TRADEMARKS.md](../../TRADEMARKS.md).

## Rebuild and inspect

Use Python with ReportLab installed and a font directory containing `NotoSans-Regular.ttf`,
`NotoSans-Bold.ttf` and `DejaVuSansMono.ttf`. The script looks for them in the Codex bundled font
directory and in LibreOffice.app on macOS; other environments provide `--font-dir`.

```bash
python3 scripts/docs/BuildBankingPdfs.py --font-dir /path/to/fonts
# Rebuild only the bank brief, preserving the joint brief:
python3 scripts/docs/BuildBankingPdfs.py --only banks --font-dir /path/to/fonts
# Rebuild only the one-page response to Koard's review:
python3 scripts/docs/BuildBankingPdfs.py --only response --font-dir /path/to/fonts
pdftoppm -png output/pdf/AgentSafe-for-banks.pdf /tmp/bank
pdftoppm -png output/pdf/Koard-and-Decionis-agentic-authorization-design-flow.pdf /tmp/koard
```

Outputs contain selectable text, embedded fonts and vector diagrams. Every text block is checked
against page bounds while authoring; every rebuilt page must also be visually inspected after
edits (seventeen pages for a complete rebuild). `output/pdf/manifest.json` records the output counts,
reviewed gateway revision and palette.
