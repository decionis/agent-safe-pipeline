# Decionis Banking Execution Authority Profile (BEAP) v0.1

| Field                       | Value                                 |
| --------------------------- | ------------------------------------- |
| Version                     | 0.1                                   |
| Status                      | Draft, Design Partner Review          |
| Profile identifier          | `decionis.beap/v0.1`                  |
| Protocol                    | Decionis Execution Authority Protocol |
| Intended canonical location | `banking.decionis.com/spec/v0.1`      |
| Document date               | 2026-09-11                            |
| License                     | Apache-2.0                            |

## 1. Abstract

The Banking Execution Authority Profile (BEAP) defines a deterministic execution-authority model for consequential actions performed within banking and financial-service systems.

BEAP specifies how applications, employees, automated processes, AI agents, batch processes, middleware, and other actors propose banking actions without implicitly acquiring authority to execute those actions.

A BEAP-conformant implementation binds an exact proposed action to:

- an execution domain;
- an applicable policy version;
- the actor and represented principal;
- relevant banking evidence and signals;
- required human or institutional approvals;
- the intended downstream target;
- a bounded execution grant; and
- evidence of the resulting downstream effect.

The profile separates **reasoning and action proposal** from **authority and execution**.

A valid identity, authenticated session, API credential, service account, model decision, workflow state, or downstream system capability MUST NOT by itself constitute execution authority under BEAP.

BEAP does not replace a core banking platform, payment hub, lending platform, identity system, fraud engine, workflow engine, credit-decision system, or banking application. BEAP defines the authority boundary immediately preceding consequential execution.

## 2. Status of This Document

This is a **draft** published for design-partner review. It is not a finished standard. Sections, field names, and requirements may change incompatibly before version 1.0, and no implementation claim should describe conformance to this draft as conformance to a standard.

Feedback is invited from banks, fintechs, core-banking implementers, payment platforms, lending platforms, and risk and compliance teams. The most useful feedback tests whether the execution-domain and authority semantics survive an institution's actual lending, onboarding, and payment workflows: where money or bank state becomes irreversible, which transitions carry authority, which evidence is required, and where the execution boundary sits.

After design-partner review, version 0.1 will be frozen, published at its canonical location, and archived with a persistent identifier. A frozen draft is never edited; corrections appear in a subsequent version. The change history is kept in the change log (Appendix D).

### 2.1 Requirement identifiers

Every testable requirement carries an inline identifier, written in square brackets, of the form `BEAP-L2-BND-03`: the profile, the minimum conformance level at which the requirement applies (`L1`, `L2`, or `L3`; section 24), a three-letter area code, and an ordinal that is unique within the area and level. A machine-readable index of all identifiers, `requirements.json`, is generated from this document and published beside it. Conformance tests and implementation notes reference requirements by identifier.

### 2.2 Conventions

JSON examples are informative unless a sentence says otherwise. Field names are lower snake case. Monetary amounts are decimal strings. Digests are written as `sha256:` followed by sixty-four lowercase hexadecimal characters. Identifiers in registries are upper snake case. Times are RFC 3339 timestamps in UTC.

## 3. Design Principle

The central invariant of BEAP is:

> A system's ability to perform an action MUST NOT be interpreted as authority to perform that specific action.

A banking actor MAY possess valid credentials, API access, an authenticated identity, delegated application permissions, an active workflow, an approved AI model, access to banking tools, or connectivity to a core banking system. None of these independently proves that a particular consequential action is authorized.

BEAP therefore requires execution authority to be established against the exact action being attempted:

```text
Actor
  │ proposes
  ▼
BankingAction ──► Intent Digest
  │
  ▼
ExecutionDomain ──► applicable policy
  │
  ├───────────────┬───────────────┐
  ▼               ▼               ▼
ALLOW          ESCALATE          BLOCK
  │               │
  │         authority evidence
  │         (approvals, Presence)
  └───────┬───────┘
          ▼
   execution grant (single use, intent-bound)
          ▼
   trusted executor ──► banking adapter ──► downstream system
          ▼
   effect evidence ──► Decision Dossier
```

## 4. Scope

BEAP applies to consequential banking operations where incorrect, unauthorized, manipulated, or insufficiently approved execution may:

- move money;
- create financial obligations;
- modify a ledger;
- create or alter a customer;
- create or alter an account;
- originate or modify credit;
- change transaction or credit limits;
- modify beneficiaries or payment instructions;
- change institutional configuration;
- alter access or privileges;
- release a payment;
- approve or disburse a loan;
- submit or execute a transaction batch; or
- otherwise create material financial, operational, legal, regulatory, or customer consequences.

BEAP MAY also be applied to non-financial state changes when an institution considers the operation sufficiently consequential to require explicit execution authority.

## 5. Non-Goals

BEAP does not define:

1. how a bank performs know-your-customer verification;
2. how credit risk is calculated;
3. how fraud is detected;
4. how anti-money-laundering screening is performed;
5. how a language model reasons;
6. how a payment is cleared or settled;
7. how a core banking ledger operates;
8. how an institution authenticates users;
9. institution-specific approval hierarchies; or
10. jurisdiction-specific banking regulation.

These systems produce signals, evidence, identities, decisions, or execution capabilities consumed by BEAP policies. BEAP governs whether the resulting proposed action has authority to execute.

BEAP also does not define a policy language. Institutions own their policies; the profile constrains how a policy is resolved, identified, and evidenced (section 12).

## 6. Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in all capitals.

A BEAP implementation claiming conformance MUST satisfy all requirements associated with its declared conformance level (section 24) and every lower level.

## 7. Terminology

### 7.1 Actor

An **Actor** is the entity proposing or initiating an action. An Actor MAY be a `HUMAN`, `APPLICATION`, `AGENT`, `SERVICE`, `WORKFLOW`, `BATCH_PROCESS`, `MIDDLEWARE`, or `SYSTEM`.

Actor identity MUST NOT imply execution authority. [BEAP-L1-ACT-01]

### 7.2 Principal

A **Principal** is the person, organization, service, or institutional function on whose behalf an Actor operates. An Actor and Principal MAY be identical. Where they differ, delegated execution MUST identify both. [BEAP-L1-ACT-02]

### 7.3 BankingAction

A **BankingAction** is the canonical representation of a proposed consequential banking operation. It describes what is intended to happen, independently of how the downstream banking system represents the operation (section 9).

### 7.4 ExecutionDomain

An **ExecutionDomain** identifies the institutional authority context governing a BankingAction (section 11).

### 7.5 Policy

A **Policy** defines the deterministic authority requirements applicable to a BankingAction within an ExecutionDomain. Policy MAY evaluate amount, currency, jurisdiction, customer classification, account state, transaction type, credit exposure, identity-verification status, screening signals, fraud signals, actor type, actor authority, institutional role, approval mandates, signatory requirements, model or agent identity, risk score, beneficiary characteristics, transaction velocity, business hours, evidence freshness, execution target, batch characteristics, and other externally supplied signals.

### 7.6 Intent Digest

The **Intent Digest** is the SHA-256 digest of the canonical form of a BankingAction (section 10). It is the authoritative identifier of the proposed intent. Approvals, execution grants, and effect evidence bind to it.

### 7.7 ExecutionBinding

An **ExecutionBinding** is the protocol object through which the Decionis Execution Authority Protocol cryptographically binds execution authority to one canonical payload, one target, one policy state, and one validity window. BEAP does not define or extend the ExecutionBinding; it defines what the canonical BankingAction must contain so that the unchanged protocol binding covers every material banking field (section 14). The term is reserved for the protocol object throughout this document.

### 7.8 Authority Evidence

**Authority Evidence** is evidence required to establish that execution may proceed: human approval, dual approval, corporate mandate, authorized-signatory evidence, Presence evidence, committee approval, risk approval, credit approval, or externally signed authorization evidence.

Authority Evidence MUST be distinguishable from informational signals. [BEAP-L1-ACT-03]

### 7.9 Execution Grant

An **Execution Grant** is a bounded authorization artifact permitting a Trusted Executor to attempt the exact action identified by an Intent Digest (section 18). A grant MUST NOT constitute a general-purpose banking credential. [BEAP-L2-GRT-01]

### 7.10 Trusted Executor

A **Trusted Executor** is the component permitted to claim an Execution Grant and invoke a downstream banking system through a Banking Adapter. The proposing Actor SHOULD NOT directly control downstream execution credentials in BEAP-L3 deployments (section 21).

### 7.11 Banking Adapter

A **Banking Adapter** translates a canonical BankingAction into the operation expected by a downstream banking platform and maps the platform's response back into effect evidence (section 20). Adapters MUST NOT independently expand the authority represented by an Execution Grant. [BEAP-L3-ADP-01]

### 7.12 Effect Evidence

**Effect Evidence** records verifiable information about the downstream result of an attempted execution (section 22). It establishes the relationship between authorized intent, execution attempt, and observed downstream result.

### 7.13 Decision Dossier

A **Decision Dossier** is the signed evidence artifact representing an authority evaluation and its associated evidence. A dossier SHOULD permit an independent verifier to determine what was proposed, by whom, on whose behalf, which policy applied, which signals were considered, which authority evidence was supplied, what verdict was returned, whether execution authority was granted, and, where applicable, what execution effect was observed. [BEAP-L1-DOS-01]

### 7.14 AuthoritySet

An **AuthoritySet** is the set of independent approvals a policy requires for one Intent Digest together with the approvals collected against it (section 16).

### 7.15 Batch Manifest

A **Batch Manifest** is the canonical representation of a transaction batch whose digest binds the batch as a whole (section 17).

## 8. Profile Identification

Every BEAP artifact (BankingAction, Batch Manifest, AuthoritySet, Effect Evidence, grant claims, dossier projection) MUST carry the field `profile` with the value `decionis.beap/v0.1`. [BEAP-L1-ACT-04]

An implementation MUST reject an artifact whose `profile` names a version it does not implement. [BEAP-L1-ACT-05]

Versions are identified as `decionis.beap/v<major>.<minor>`. Within a major version, a later minor version MAY add optional fields and registry entries and MUST NOT change the canonicalization rule, the meaning of an existing field, or the meaning of an existing verdict or outcome token. Draft versions before 1.0 make no compatibility promise.

## 9. Canonical BankingAction

A BankingAction MUST have the canonical representation defined by the JSON Schema `banking-action.schema.json` (Appendix A). [BEAP-L1-ACT-06]

A representative instance:

```json
{
  "profile": "decionis.beap/v0.1",
  "domain": "LOAN_DISBURSEMENT",
  "action": { "type": "DISBURSE_LOAN", "request_id": "synthetic-req-0001" },
  "actor": { "type": "AGENT", "id": "synthetic-underwriting-agent-17" },
  "principal": { "type": "ORGANIZATIONAL_FUNCTION", "id": "synthetic-credit-operations" },
  "subject": { "type": "CUSTOMER", "ref": "fixture_customer_28491" },
  "target": { "type": "LOAN", "ref": "fixture_loan_84721" },
  "financial_context": { "amount": "250000.00", "currency": "CHF" },
  "requested_effect": { "operation": "DISBURSE", "destination_ref": "fixture_account_1921" },
  "downstream": {
    "provider": "SYNTHETIC_CORE",
    "product": "LENDING",
    "operation": "LOAN_DISBURSEMENT"
  },
  "evidence_refs": [
    { "kind": "KYC_VERIFICATION", "ref": "fixture_kyc_98127", "digest": "sha256:…" }
  ]
}
```

### 9.1 Fields

| Field               | Required | Meaning                                                                                                                               |
| ------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `profile`           | yes      | `decionis.beap/v0.1`                                                                                                                  |
| `domain`            | yes      | The ExecutionDomain identifier (section 11)                                                                                           |
| `action.type`       | yes      | The action type registered for the domain (section 26)                                                                                |
| `action.request_id` | yes      | The caller's stable identifier for this proposal; it is the idempotency identity of the action                                        |
| `actor`             | yes      | Who or what proposes the action                                                                                                       |
| `principal`         | yes      | On whose behalf the action is proposed                                                                                                |
| `subject`           | no       | The party the action concerns (a customer, an organization)                                                                           |
| `target`            | yes      | The protected resource the action changes (a loan, an account, a payment batch)                                                       |
| `financial_context` | no       | Amount and currency where the action carries a monetary value                                                                         |
| `requested_effect`  | yes      | The operation, optional source and destination references, and flat scalar parameters that determine the effect                       |
| `downstream`        | yes      | The provider, optional product, operation, and optional environment the action is intended to execute against                         |
| `batch`             | no       | The Batch Manifest digest, item count, and source-file digest when the action releases a batch (section 17)                           |
| `evidence_refs`     | yes      | References to evidence the proposer relies on, each optionally carrying the digest of the referenced evidence; the array MAY be empty |

### 9.2 Content rules

The canonical BankingAction MUST NOT contain secrets required to authenticate against the downstream banking system. [BEAP-L1-ACT-07]

The canonical BankingAction MUST NOT contain capture timestamps, transport identifiers, or any digest of itself, so that the same intent proposed twice produces the same Intent Digest. [BEAP-L1-ACT-08]

Monetary amounts MUST be decimal strings whose fractional scale equals the minor-unit scale of the ISO 4217 currency, so that a value has exactly one canonical spelling. [BEAP-L1-ACT-09] An implementation MUST reject an amount whose scale differs from the currency's minor units. [BEAP-L1-ACT-10]

References to customers, accounts, beneficiaries, loans, and documents SHOULD be opaque references or digests rather than raw identifying values (section 23). [BEAP-L1-ACT-11]

A `requested_effect.parameters` object, where present, MUST contain only scalar values (string, number, boolean, null). Domain action registries define which parameters an action type carries. [BEAP-L1-ACT-12]

## 10. Canonicalization and Intent Digest

Before policy evaluation capable of producing execution authority, the BankingAction MUST be canonicalized with the RFC 8785 JSON Canonicalization Scheme (JCS) and the resulting bytes hashed with SHA-256. [BEAP-L1-DIG-01]

```text
BankingAction ──► RFC 8785 JCS ──► canonical bytes ──► SHA-256 ──► Intent Digest
```

The Intent Digest MUST be written as `sha256:` followed by the lowercase hexadecimal digest. [BEAP-L1-DIG-02]

The resulting digest is the authoritative identifier of the proposed intent. Any material mutation of the BankingAction MUST produce a different digest. [BEAP-L1-DIG-03]

An implementation MUST reject, rather than normalize, a BankingAction whose content is outside I-JSON: non-finite numbers, lone Unicode surrogates, or values that are not plain JSON objects, arrays, strings, numbers, booleans, or null. [BEAP-L1-DIG-04]

An implementation MUST recompute the Intent Digest from the BankingAction it actually evaluates or executes, and MUST NOT trust a digest supplied by the proposing Actor. [BEAP-L1-DIG-05]

Where the transport that carries a BankingAction to an execution authority computes its own binding hash over an envelope, the canonical BankingAction MUST be carried inside that envelope unchanged, so that the transport binding commits to the Intent Digest by construction (Appendix B). [BEAP-L2-DIG-01]

## 11. ExecutionDomain

An ExecutionDomain identifier MUST match `^[A-Z][A-Z0-9_]{1,63}$` and MUST name a business authority boundary rather than a vendor product. [BEAP-L1-DOM-01] For example, `CORPORATE_PAYMENTS` is an ExecutionDomain; a payment hub product is an execution target or adapter associated with that domain.

The registered domains for version 0.1 are listed in the execution-domain registry (section 26):

```text
CUSTOMER_ORIGINATION     ACCOUNT_ORIGINATION     LOAN_ORIGINATION
LOAN_DISBURSEMENT        LENDING                 CREDIT_LIMITS
CORPORATE_PAYMENTS       PAYMENT_PROCESSING      TREASURY
CUSTOMER_ADMINISTRATION  ACCOUNT_ADMINISTRATION  CORE_ADMINISTRATION
```

An institution MAY register additional domains that follow the same rule. An implementation MUST reject a BankingAction whose `action.type` is not registered for its `domain`. [BEAP-L1-DOM-02]

The same domain and action semantics apply regardless of provider. A loan disbursement executed through a core banking product and one executed through a bespoke lending platform share the domain `LOAN_DISBURSEMENT` and the action type `DISBURSE_LOAN`; only `downstream` differs.

## 12. Policy Resolution

Each BankingAction MUST resolve to exactly one effective policy before execution authority can be issued. [BEAP-L1-POL-01]

Policy resolution SHOULD support the following order, each level narrowing the previous:

```text
organization ──► execution domain ──► action type ──► institutional overlay ──► jurisdictional overlay ──► effective policy version
```

The effective policy MUST be identified by a stable identifier, a version, and a digest of its content, and a Decision Dossier MUST record all three. [BEAP-L1-POL-02]

Policy changes MUST NOT retroactively alter the meaning of previously issued Decision Dossiers. [BEAP-L1-POL-03]

Where no effective policy can be resolved for a domain, the evaluation MUST return `BLOCK` with the reason code `POLICY_UNAVAILABLE`. [BEAP-L1-POL-04]

Where the effective policy names required signals and one is absent, the evaluation MUST return `ESCALATE` with the reason code `MISSING_REQUIRED_SIGNALS` and MUST NOT match rules against absent facts. [BEAP-L1-POL-05]

Policy evaluation MUST be deterministic: a pure function of the effective policy, the canonical BankingAction, and the supplied signals and authority evidence, with no clock, randomness, or hidden mutable state in rule matching. [BEAP-L1-POL-06] Time-dependent rules read a time value supplied as an input and recorded in the dossier.

BEAP does not prescribe a policy language. The reference implementation that accompanies this profile evaluates policy bundles conforming to the Decionis Protocol policy-bundle schema (vendored in Appendix A); other implementations MAY use any deterministic policy representation that satisfies this section.

## 13. Verdict Model

BEAP uses the Decionis verdict model. Every evaluation MUST return exactly one of `ALLOW`, `ESCALATE`, or `BLOCK`. [BEAP-L1-VER-01]

### 13.1 ALLOW

`ALLOW` means all authority requirements represented by the effective policy have been satisfied. At BEAP-L2 or higher, `ALLOW` MAY result in issuance of a bounded Execution Grant. `ALLOW` MUST NOT itself be interpreted as evidence that downstream execution occurred. [BEAP-L1-VER-02]

### 13.2 ESCALATE

`ESCALATE` means execution authority has not yet been established but MAY be established through additional authority evidence. Examples of accompanying reason codes: `CREDIT_OFFICER_APPROVAL_REQUIRED`, `DUAL_AUTHORITY_REQUIRED`, `TREASURY_APPROVAL_REQUIRED`, `AUTHORIZED_SIGNATORY_REQUIRED`, `PRESENCE_REQUIRED`, `MISSING_REQUIRED_SIGNALS`.

An `ESCALATE` verdict MUST NOT create an executable grant. [BEAP-L1-VER-03] An `ESCALATE` verdict SHOULD carry the machine-readable authority requirement that would allow re-evaluation. [BEAP-L1-VER-04]

### 13.3 BLOCK

`BLOCK` means execution authority MUST NOT be issued under the evaluated policy state. [BEAP-L1-VER-05] The downstream action MUST NOT be attempted through a conformant executor. [BEAP-L1-VER-06]

### 13.4 Fail-closed mapping

An implementation that cannot obtain a verdict, whether because the execution authority is unreachable, returns a malformed response, times out, or reports a transport error, MUST treat the result as `BLOCK` with the reason code `AUTHORITY_UNAVAILABLE` and MUST NOT infer `ALLOW` from the absence of a refusal. [BEAP-L1-VER-07]

Where an underlying protocol layer uses a wider vocabulary, an implementation MUST project it onto the BEAP triad without inventing a fourth verdict: review-type outcomes project to `ESCALATE`, rejection-type outcomes to `BLOCK`, and error or unavailable outcomes to fail-closed `BLOCK` (Appendix B). [BEAP-L1-VER-08]

Every verdict MUST be accompanied by at least one reason code from the reason-code registry or an institution-registered extension, so that a verdict is explainable without disclosing raw signal values. [BEAP-L1-VER-09]

## 14. Binding Requirements

BEAP binds execution authority through the Decionis ExecutionBinding (section 7.7). This section states what the canonical BankingAction and the authority's binding of it must cover so that authority granted for one action cannot be reused for a materially different action.

The execution authority MUST bind execution authority to the Intent Digest and, directly or through the canonical BankingAction it digests, at minimum: profile, organization, execution domain, action type, actor, principal, target, requested effect, effective policy identity, and downstream execution target. [BEAP-L2-BND-01]

Where relevant to the action, the BankingAction MUST additionally carry, and the binding therefore covers, amount, currency, customer, account, beneficiary, loan, batch manifest digest, and jurisdiction. [BEAP-L2-BND-02]

A grant generated for one intent MUST NOT authorize a materially different intent. [BEAP-L2-BND-03] A grant for

```text
CHF 50,000 → beneficiary A
```

authorizes neither

```text
CHF 500,000 → beneficiary A
```

nor

```text
CHF 50,000 → beneficiary B
```

Every binding MUST carry a validity window, and the window MUST end no later than the earliest of the intent expiry, the effective policy's validity, and the expiry of any approval the binding relies on. [BEAP-L2-BND-04]

Where the action type has an expected-effect projection (section 22.7), the implementation SHOULD compute the expected-effect digest at authorization time and bind it alongside the Intent Digest so that a later confirmation can be established against a pre-committed value. [BEAP-L2-BND-05]

Where the execution authority exposes the digest it bound over the canonical payload, the Trusted Executor MUST verify that it equals the Intent Digest the executor computed itself, and MUST fail closed on a difference. [BEAP-L3-BND-01]

## 15. Escalation and Presence

Where policy requires human authority, BEAP uses intent-bound approval evidence.

Approval evidence MUST bind to the Intent Digest of the exact BankingAction being approved. [BEAP-L2-ESC-01] An approval for one intent MUST NOT authorize another intent. [BEAP-L2-ESC-02]

The following sequence is RECOMMENDED:

```text
BankingAction ──► Intent Digest ──► ESCALATE
                                       │
                                       ▼
                               approval request
                                       │
                                       ▼
                                human ceremony
                                       │
                                       ▼
                          signed approval evidence
                                       │
                                       ▼
                          verify intent binding
                                       │
                                       ▼
                               re-evaluate ──► ALLOW ──► Execution Grant
```

Approval evidence MUST enter a new policy evaluation as evidence; it MUST NOT change a verdict directly and MUST NOT be accepted as an asserted `ALLOW`. [BEAP-L2-ESC-03]

Approval evidence MUST identify the approver reference, the approver's role, the approval time, the approval expiry, the evidence kind, and a digest of the evidence artifact. [BEAP-L2-ESC-04]

Approval evidence SHOULD present the approver with sufficient context to understand the consequential action being authorized: at least the domain, action type, target, and, where present, amount, currency, and destination. [BEAP-L2-ESC-05]

An approval MUST NOT be accepted after its own expiry, and MUST NOT be accepted for an intent whose Intent Digest differs from the digest the approval binds. [BEAP-L2-ESC-06]

Where a Presence ceremony (a verified human-authority ceremony that produces a signed receipt) supplies the approval, the receipt MUST bind the Intent Digest, and the implementation MUST verify the receipt before it enters re-evaluation. [BEAP-L2-ESC-07] Presence proves that a specific person completed a required ceremony for a specific intent; it is evidence, never authority in itself.

## 16. Multi-Party Authority

BEAP MUST support policies requiring multiple independent authorities, for example maker and checker, two signatories, credit officer and risk officer, or treasury and compliance. [BEAP-L2-MPA-01]

### 16.1 AuthoritySet

The requirements for one Intent Digest and the approvals collected against them form an AuthoritySet with the structure defined by `authority-set.schema.json` (Appendix A). Each requirement names a role, a quorum, the requirements it must be held distinctly from, and the evidence kinds it accepts. Each approval names the requirement it satisfies, the approver, the role, the Intent Digest, a decision, an expiry, and verifiable evidence.

Each approval in an AuthoritySet MUST bind the same Intent Digest as the set. [BEAP-L2-MPA-02]

The execution grant MUST NOT be issued until every requirement of the AuthoritySet has been satisfied by verified approvals. [BEAP-L2-MPA-03]

Changing the bound BankingAction after one or more approvals have been collected MUST invalidate every approval whose bound digest no longer matches the resulting intent; the set moves to `INVALIDATED` and the superseded approvals are retained as evidence, never deleted. [BEAP-L2-MPA-04]

Requirements that a policy marks as distinct from one another MUST NOT be satisfied by the same approver. [BEAP-L2-MPA-05] The same approver MUST NOT be counted more than once toward one requirement's quorum. [BEAP-L2-MPA-06]

A `REJECT` decision from any required party MUST move the set to `REJECTED`; no grant is issued and re-collection requires a new set. [BEAP-L2-MPA-07]

### 16.2 States

```text
COLLECTING ──► SATISFIED ──► BOUND ──► CONSUMED
     │              │
     ├──► REJECTED  │  (a required party rejects)
     ├──► EXPIRED ◄─┘  (the set or a counted approval expires before binding)
     └──► INVALIDATED  (the intent digest changed; from any non-terminal state)
```

The transport-level binding with the execution authority SHOULD be created only once the set is `SATISFIED`, so that approval cycles measured in hours or days are never constrained by the short validity window of a transport intent or grant. [BEAP-L2-MPA-08]

The verified AuthoritySet MUST be presented to the execution authority as evidence bound by its digest, never as an asserted verdict; the authority re-evaluates policy with the evidence present. [BEAP-L2-MPA-09]

Rejections are reported with the reason codes `APPROVAL_INTENT_MISMATCH`, `APPROVAL_DUPLICATE_APPROVER`, `SEPARATION_OF_DUTIES_VIOLATED`, `APPROVAL_EXPIRED`, `APPROVAL_ROLE_NOT_REQUIRED`, `APPROVAL_EVIDENCE_INVALID`, and `AUTHORITY_SET_INVALIDATED` (section 26).

## 17. Batch Execution Binding

Banking systems frequently process payment instructions as files or transaction batches. A file represents many consequential actions under one approval structure.

An implementation MUST NOT treat possession of, approval of, or reference to a file name as sufficient binding for batch execution. [BEAP-L2-BAT-01]

### 17.1 Batch Manifest

A batch MUST be transformed into a canonical Batch Manifest with the structure defined by `batch-manifest.schema.json` (Appendix A). [BEAP-L2-BAT-02]

```text
uploaded file ──► parse and validate ──► Batch Manifest ──► RFC 8785 JCS ──► SHA-256 ──► Batch Intent Digest
```

The manifest carries the batch identifier, the originating organization and account, the requested execution date and rail, the source file's digest, length, media type, and format, per-currency totals, and the canonical items.

Items MUST be sorted by `item_ref` in ascending byte order, and `item_ref` MUST be unique within the manifest. [BEAP-L2-BAT-03]

Per-currency totals MUST be sorted by `currency` in ascending byte order, and each currency MUST appear at most once, so that the canonical form of a manifest does not depend on the order in which currencies were encountered in the source file. [BEAP-L2-BAT-11]

Each item MUST carry `item_digest`, the SHA-256 digest of the RFC 8785 canonical form of the item with `item_digest` removed. [BEAP-L2-BAT-04]

The Batch Intent Digest is the SHA-256 digest of the RFC 8785 canonical form of the complete manifest, and MUST be computed over the manifest with items inline. [BEAP-L2-BAT-05]

The manifest MUST record the digest of the source file as received, so that a re-ordered or edited file is detectable even where the canonical items are unchanged. [BEAP-L2-BAT-06]

Beneficiary account numbers MUST appear in the manifest only as digests, never as raw values. [BEAP-L2-BAT-07]

### 17.2 The batch action

The BankingAction that releases a batch (for example `RELEASE_PAYMENT_BATCH` in `CORPORATE_PAYMENTS`) MUST carry the `batch` object with the manifest digest, item count, and source-file digest, together with the aggregate amount and currency in `financial_context`, and MUST NOT embed the items themselves. [BEAP-L2-BAT-08] The full manifest is retained in the evidence plane and is attributable through its digest.

A batch-releasing action that carries no `financial_context` names no aggregate, and an implementation MUST refuse to bind it (`BATCH_AGGREGATE_REQUIRED`) rather than bind it with no amount; otherwise every amount-banded policy rule evaluates against an absent amount and no value threshold applies. [BEAP-L2-BAT-12]

The aggregate is a single amount in a single currency and can therefore cover a manifest carrying totals in only one currency. A manifest carrying totals in more than one currency has no single aggregate the action could name, so an implementation MUST refuse to bind such a batch in this version of the profile (`BATCH_TOTALS_MISMATCH`); every currency leg the action does not name would otherwise move unaggregated and unthresholded. A multi-currency payment run is released in this version as one batch per currency. [BEAP-L2-BAT-13]

Approval of a batch MUST bind the Intent Digest of the batch action, which commits to the Batch Intent Digest. [BEAP-L2-BAT-09]

Any material modification to a transaction within the batch MUST invalidate the previous batch binding: the item digest, the manifest digest, the batch action, and therefore the Intent Digest all change, and collected approvals are invalidated under section 16. [BEAP-L2-BAT-10]

The consequential commit authorized by a batch grant is the submission of the batch as a whole; per-item outcomes MUST be recorded as batch effect evidence (section 22.11) as they become known, and an implementation MUST NOT execute items individually under one claim. [BEAP-L3-BAT-01]

A future version MAY define an items commitment (for example a Merkle root) enabling selective disclosure of one item's membership without the full manifest. Version 0.1 defines none and reserves no field for it.

## 18. Execution Grant

A BEAP Execution Grant MUST be intent-bound, target-bound, operation-bound, time-bounded, non-transferable between unrelated execution contexts, and single-use where the downstream operation is consequential. [BEAP-L2-GRT-02]

The grant SHOULD include or cryptographically bind the claims defined by `execution-grant-claims.schema.json` (Appendix A): grant identifier, organization, execution binding identifier, Intent Digest, domain, action, downstream target, permitted operation, issuance and expiry times, and, where computed, the expected-effect digest. [BEAP-L2-GRT-03]

An Execution Grant MUST NOT contain downstream banking credentials. [BEAP-L2-GRT-04]

The validity window of a grant SHOULD be short, measured in minutes, because the grant expresses that a specific policy, signal, and approval state was current when it was issued. [BEAP-L2-GRT-05]

A grant MUST NOT be issued for an `ESCALATE` or `BLOCK` verdict, and an evaluation performed in an observational or shadow mode MUST NOT yield an executable grant. [BEAP-L2-GRT-06]

## 19. Claim-Before-Commit

BEAP-L3 requires claim-before-commit semantics.

Before a consequential downstream operation is committed, the Trusted Executor MUST successfully claim the corresponding Execution Grant with the execution authority. [BEAP-L3-CLM-01]

```text
Execution Grant ──► CLAIM ──┬── rejected ──► STOP
                            │
                            ▼
                      claim token
                            ▼
                    downstream commit
                            ▼
                     effect evidence
                            ▼
                        FINALIZE
```

A claim MUST be atomic and single-use: a grant that has already been successfully claimed MUST NOT authorize a second execution. [BEAP-L3-CLM-02]

Duplicate, replayed, expired, mismatched, and previously consumed grants MUST be deterministically rejected at the claim. [BEAP-L3-CLM-03]

The claim MUST revalidate the Intent Digest, target, and operation being committed against the bound values, and, where the execution authority supports it, the current policy version, material signals, and approval state. [BEAP-L3-CLM-04]

The Trusted Executor MUST execute only when the claim response affirmatively authorizes execution, and MUST NOT execute on the absence of a refusal, a transport error, or a diagnostic verification that does not consume the grant. [BEAP-L3-CLM-05]

A claim carries a lease. The downstream commit MUST complete within the lease; where the lease expires before the outcome is known, the outcome MUST be finalized as `INDETERMINATE`. [BEAP-L3-CLM-06]

After every successful claim the executor MUST finalize the attempt with the execution authority as `COMMITTED`, `FAILED`, or `INDETERMINATE`. [BEAP-L3-CLM-07] Finalization is evidence and MUST NOT alter the outcome, revive the consumed grant, or authorize a further attempt. [BEAP-L3-CLM-08]

Where two claims race for the same grant, exactly one MUST succeed. [BEAP-L3-CLM-09]

## 20. Banking Adapter Contract

A Banking Adapter is deliberately small. Conceptually:

```text
prepare(action)              → downstream request digest, expected effect     (pure)
execute(authorized action)   → provider result                                (inside the dispatch boundary)
observeEffect(result)        → observed effect                                (pure)
reconcile(correlation)       → COMPLETED | NOT_EXECUTED | UNKNOWN             (read-only)
```

A BEAP-L3 Banking Adapter MUST NOT execute a consequential downstream operation unless invoked through a valid Trusted Executor context. [BEAP-L3-ADP-02]

A conformant adapter MUST verify, or receive verified assurance of, grant validity, intent binding, target binding, operation binding, expiration, and claim status before it executes. [BEAP-L3-ADP-03]

The adapter MUST NOT broaden the requested action. [BEAP-L3-ADP-04] An adapter receiving authority to

```text
DISBURSE fixture_loan_123 CHF 20,000
```

translates that into neither `MODIFY fixture_loan_123` nor `DISBURSE fixture_loan_456` unless separately authorized.

The adapter MUST keep the provider side effect inside a single dispatch boundary that records the point after which a transport failure has an unknown outcome, and MUST use the intent-bound idempotency key for that side effect. [BEAP-L3-ADP-05]

The adapter MUST propagate a correlation or idempotency identifier to the downstream system where the system supports one. [BEAP-L3-ADP-06]

The adapter MUST capture the downstream execution outcome, compute a digest over the material response evidence, and distinguish `COMMITTED`, `FAILED`, and `INDETERMINATE`. [BEAP-L3-ADP-07]

The adapter MUST preserve evidence provenance, distinguishing provider-generated evidence from its own observations. [BEAP-L3-ADP-08]

The adapter MUST submit Effect Evidence to the decision chain for every claimed attempt. [BEAP-L3-ADP-09]

The adapter SHOULD support reconciliation where the downstream system permits authoritative status retrieval. [BEAP-L3-ADP-10]

The adapter MUST NOT represent an unverified business effect as `CONFIRMED`. [BEAP-L3-ADP-11]

The adapter's reconciliation operation MUST be read-only and MUST NOT initiate or retry a side effect. [BEAP-L3-ADP-12]

The adapter SHOULD compare the observed effect against the authorized effect and surface material mismatches (section 22.8). [BEAP-L3-ADP-13]

The adapter MUST NOT receive the execution token or the proposing Actor's identity as an execution credential; it receives the verified authorization identifiers and the idempotency key. [BEAP-L3-ADP-14]

## 21. Credential Isolation

Downstream banking credentials SHOULD reside within the Trusted Executor or another isolated execution environment, not with the proposing Actor. [BEAP-L3-CRD-01]

An autonomous Actor SHOULD be capable of proposing `CREATE_CUSTOMER`, `CREATE_ACCOUNT`, `APPROVE_LOAN`, `DISBURSE_LOAN`, `SEND_PAYMENT`, and every other registered action without possessing credentials sufficient to perform those operations directly against the banking system. [BEAP-L3-CRD-02]

```text
agent / application ── no core credential ──► proposed BankingAction
                                                     │
                                                     ▼
                                              execution authority
                                                     │
                                                     ▼
                                              execution grant
                                                     │
                                                     ▼
                       trusted executor ── protected credential ──► banking adapter ──► core / hub / lending
```

The component that supplies downstream credentials to an adapter MUST NOT be reachable from the proposing side of the boundary. [BEAP-L3-CRD-03]

Downstream credentials MUST NOT enter a BankingAction, an AuthoritySet, an Execution Grant, Effect Evidence, a Decision Dossier, or operational logs. [BEAP-L3-CRD-04]

This separation is RECOMMENDED for autonomous and semi-autonomous systems and REQUIRED for BEAP-L3 conformance.

## 22. Effect Evidence

### 22.1 Purpose

BEAP distinguishes between **authorization evidence** and **effect evidence**. Authorization evidence establishes that a precisely identified banking action was permitted to proceed under a particular policy, evidence set, approval state, target, and validity window. Effect evidence establishes what is known about the downstream consequence after execution authority has been claimed.

A successful authorization MUST NOT, by itself, be interpreted as evidence that the authorized banking effect occurred. [BEAP-L3-EFF-01] Successful delivery of a request to a banking system MUST NOT, by itself, be interpreted as evidence that the intended business effect was completed. [BEAP-L3-EFF-02]

BEAP therefore defines an explicit execution lifecycle:

```text
PROPOSED ──► EVALUATED ──► AUTHORIZED ──► CLAIMED ──► DOWNSTREAM ATTEMPT
                                                            │
                                    ┌───────────────────────┼───────────────────────┐
                                    ▼                       ▼                       ▼
                                COMMITTED                 FAILED              INDETERMINATE
                                    │                                               │
                                    ▼                                               ▼
                                CONFIRMED                                    RECONCILIATION
```

`COMMITTED` and `CONFIRMED` are distinct states.

### 22.2 EffectEvidence

An EffectEvidence object is a cryptographically attributable record describing the observed outcome of an execution attempt made under one execution-authority claim.

Effect evidence MUST be associated with exactly one execution-authority claim. [BEAP-L3-EFF-03]

An EffectEvidence object MUST identify the Decision Dossier, the Intent Digest, the execution binding, the claimed execution authority, the execution domain and action, the downstream adapter and target, the execution correlation identifier and idempotency key, the attempt number, the observed outcome, the observation time, and cryptographic evidence sufficient to detect alteration of material downstream response data. [BEAP-L3-EFF-04]

A conforming implementation MUST NOT construct EffectEvidence in a manner that permits evidence from one execution attempt to be attached to another execution binding. [BEAP-L3-EFF-05]

### 22.3 Canonical structure

A conforming EffectEvidence object MUST have the structure defined by `effect-evidence.schema.json` (Appendix A). [BEAP-L3-EFF-06] A representative instance:

```json
{
  "profile": "decionis.beap/v0.1",
  "type": "EFFECT_EVIDENCE",
  "dossier_id": "fixture_dossier_0001",
  "evaluation_id": "fixture_evaluation_0001",
  "intent_digest": "sha256:…",
  "execution_binding": { "binding_id": "fixture_binding_0001", "binding_digest": "sha256:…" },
  "authority_claim": {
    "claim_id": "fixture_claim_0001",
    "nonce_digest": "sha256:…",
    "claimed_at": "2026-09-11T12:01:31.442Z"
  },
  "domain": "LOAN_DISBURSEMENT",
  "action": "DISBURSE_LOAN",
  "execution": {
    "adapter": "synthetic-core-adapter",
    "target": "lending/loan-disbursement",
    "correlation_id": "fixture_corr_0001",
    "idempotency_key": "synthetic-req-0001",
    "attempt": 1,
    "started_at": "2026-09-11T12:01:31.501Z",
    "completed_at": "2026-09-11T12:01:31.884Z"
  },
  "outcome": {
    "status": "COMMITTED",
    "provider_status": "ACCEPTED",
    "provider_reference": "fixture_txn_0001",
    "response_digest": "sha256:…"
  },
  "effect": {
    "effect_type": "LOAN_DISBURSEMENT",
    "resource_ref": "fixture_loan_84721",
    "expected_effect_digest": "sha256:…",
    "observed_effect_digest": "sha256:…",
    "observation_method": "READ_AFTER_WRITE",
    "comparison": "MATCH"
  },
  "confirmation": { "status": "CONFIRMED", "confirmed_at": "2026-09-11T12:03:15.004Z" },
  "provenance": {
    "source": "CORE_LEDGER_QUERY",
    "provider_generated": true,
    "observer": { "id": "synthetic-core-adapter", "version": "0.1.0" }
  },
  "observed_at": "2026-09-11T12:03:15.004Z"
}
```

Implementations MAY retain additional provider-specific fields outside the signed object, provided such fields cannot modify the meaning of signed BEAP fields. [BEAP-L3-EFF-07]

Sensitive downstream data SHOULD be represented by references or cryptographic digests where disclosure of raw values is unnecessary. [BEAP-L3-EFF-08]

### 22.4 Execution outcome states

BEAP defines three mandatory immediate execution outcomes.

#### 22.4.1 COMMITTED

`COMMITTED` means the adapter obtained sufficient evidence that the downstream system accepted the authorized operation at its execution boundary: a core banking interface accepting an account creation, a lending platform accepting a disbursement, a payment hub accepting a payment instruction, a core system accepting a customer-state transition.

`COMMITTED` MUST NOT automatically mean that the ultimate business effect has been completed. [BEAP-L3-EFF-09]

```text
payment submitted to the hub      → COMMITTED
payment settled externally        → potentially CONFIRMED later

loan disbursement accepted        → COMMITTED
funds credited and posted         → potentially CONFIRMED later
```

#### 22.4.2 FAILED

`FAILED` means sufficient evidence exists that the downstream attempt did not produce the requested protected effect: a deterministic rejection, a validation failure, an explicit refusal, an adapter failure before the protected commit boundary, or a confirmed rollback in which the protected effect did not survive.

The failure reason SHOULD be recorded as a stable reason code. A `FAILED` execution does not restore or recreate the consumed execution authority; a new execution attempt MUST obtain authority according to the applicable retry and re-evaluation policy. [BEAP-L3-EFF-10]

#### 22.4.3 INDETERMINATE

`INDETERMINATE` means the executor cannot prove whether the protected effect occurred: connection loss after transmission, a timeout after the downstream system may have accepted the action, a lost hub response, an unavailable status interface, asynchronous processing without sufficient acknowledgement, or conflicting downstream observations.

An `INDETERMINATE` outcome MUST be treated as potentially committed. [BEAP-L3-EFF-11] It MUST NOT cause the original execution grant to become reusable. [BEAP-L3-EFF-12] It MUST NOT trigger an automatic repeat of the consequential operation unless downstream idempotency semantics make such repetition provably safe and the applicable policy explicitly permits it. [BEAP-L3-EFF-13] An `INDETERMINATE` execution SHOULD enter reconciliation. [BEAP-L3-EFF-14]

This requirement prevents uncertainty from becoming duplicate execution.

### 22.5 Confirmation

BEAP distinguishes execution acceptance from business-effect confirmation. A confirmation records independently observable evidence that the intended protected state change occurred, did not occur, or reached another terminal state. The confirmation states are:

| State          | Meaning                                                                                           |
| -------------- | ------------------------------------------------------------------------------------------------- |
| `PENDING`      | The execution was committed but final business-effect evidence is not yet available               |
| `CONFIRMED`    | Authoritative downstream evidence demonstrates that the expected protected effect occurred        |
| `NOT_EFFECTED` | Authoritative evidence demonstrates that the attempted action did not produce the expected effect |
| `REVERSED`     | The protected effect occurred but was subsequently reversed through a separate state transition   |
| `UNKNOWN`      | The confirmation process cannot establish the final state with sufficient confidence              |

A reversal MUST NOT rewrite the original effect evidence. [BEAP-L3-EFF-15] Where the reversal itself requires execution authority, it SHOULD produce a new BankingAction and a corresponding Decision Dossier. [BEAP-L3-EFF-16]

Where an underlying protocol layer records only a two-valued confirmation, `CONFIRMED` maps to its confirmed state and every other BEAP state maps to its unconfirmed state, while the BEAP state is retained in the evidence plane (Appendix B).

### 22.6 Response digest

The adapter MUST compute a cryptographic digest over the material downstream response evidence used to determine the execution outcome, and SHA-256 MUST be supported. [BEAP-L3-EFF-17] Where the response is structured JSON, RFC 8785 canonicalization SHOULD be applied before hashing. [BEAP-L3-EFF-18]

The digest SHOULD cover the downstream transaction identifier, resource identifier, processing status, accepted amount and currency, destination or beneficiary reference where applicable, downstream sequence or version, provider timestamp, and provider result or reason code. The raw downstream response MAY be retained separately according to the institution's security, privacy, and retention requirements; the Decision Dossier does not require disclosure of the complete raw response where its integrity is represented by a digest and an independently resolvable evidence reference.

### 22.7 Expected-effect projection

For every registered action type, the action-type registry (section 26) defines an **effect projection**: the fields of the BankingAction that are material to the authorized effect. The base projection is the effect type, domain, action, and target; the registry adds per-type fields.

| Action type             | Additional projected fields                             |
| ----------------------- | ------------------------------------------------------- |
| `DISBURSE_LOAN`         | subject, amount, currency, destination reference        |
| `SEND_PAYMENT`          | amount, currency, source, destination, value date, rail |
| `RELEASE_PAYMENT_BATCH` | amount, currency, source, manifest digest, item count   |
| `CREATE_ACCOUNT`        | subject, currency, product, account type                |
| `SET_CREDIT_LIMIT`      | amount, currency                                        |

The implementation MUST derive the expected effect from the canonical BankingAction according to the registered projection, and the expected-effect digest is the SHA-256 digest of its RFC 8785 canonical form. [BEAP-L3-EFF-19]

The adapter SHOULD map the observed downstream result to the same projection and compare the two field by field. [BEAP-L3-EFF-20]

A materially different effect MUST NOT be reported as successful confirmation of the authorized action; such a condition MUST generate an effect mismatch. [BEAP-L3-EFF-21]

### 22.8 Effect mismatch

An `EFFECT_MISMATCH` occurs when authoritative downstream evidence demonstrates that the resulting protected effect differs materially from the effect authorized by the binding:

```text
authorized  CHF 250,000            observed  CHF 2,500,000
authorized  beneficiary account A  observed  beneficiary account B
authorized  CREATE_ACCOUNT         observed  CREATE_AND_ACTIVATE_ACCOUNT
authorized  limit CHF 50,000       observed  limit CHF 500,000
```

An effect mismatch MUST be recorded in the decision chain, preserve the original authorization evidence, preserve the observed effect evidence, identify the mismatched material fields, prevent the execution from being represented as correctly confirmed, and invoke the institution's configured exception, incident, or reconciliation policy. [BEAP-L3-EFF-22]

The original Decision Dossier MUST NOT be mutated to make the authorization appear consistent with the observed effect. [BEAP-L3-EFF-23]

### 22.9 Reconciliation

Reconciliation resolves execution outcomes that cannot be conclusively established at the original execution boundary. A Banking Adapter MAY support a provider-specific reconciliation operation keyed by the correlation identifier, provider reference, and idempotency key.

Reconciliation MUST use authoritative downstream identifiers where available. [BEAP-L3-EFF-24] The reconciler MUST NOT infer successful execution solely from the absence of an error. [BEAP-L3-EFF-25]

A reconciliation result MAY transition:

```text
INDETERMINATE → CONFIRMED        COMMITTED → CONFIRMED
INDETERMINATE → NOT_EFFECTED     COMMITTED → NOT_EFFECTED
INDETERMINATE → UNKNOWN          COMMITTED → REVERSED
```

Reconciliation evidence MUST be appended to the decision chain rather than replacing earlier observations, preserving the temporal record of what was known at execution time and what became known later. [BEAP-L3-EFF-26]

```text
12:01:31   authority claimed
12:01:31   request transmitted
12:01:36   timeout → INDETERMINATE
12:03:14   provider queried
12:03:15   transaction located
12:03:15   effect verified → CONFIRMED
```

### 22.10 Asynchronous banking effects

Many banking operations are asynchronous: payment clearing, cross-border payments, disbursement processing, account activation, sanctions or manual review, batch processing, downstream posting, settlement. An implementation MUST support an execution being `COMMITTED` while its ultimate effect remains `PENDING`. [BEAP-L3-EFF-27]

The adapter SHOULD capture the strongest available acknowledgement at the initial boundary and subsequently attach authoritative status evidence as it becomes available. A provider status such as `ACCEPTED`, `QUEUED`, `PROCESSING`, or an equivalent MUST NOT be normalized to `CONFIRMED` unless the status semantically proves the protected business effect. [BEAP-L3-EFF-28]

### 22.11 Batch effect evidence

For batch-authorized operations, effect evidence MUST preserve the relationship between the authorized batch and its individual downstream effects, with the structure defined by `batch-effect-evidence.schema.json` (Appendix A). [BEAP-L3-EFF-29] A batch effect record carries the batch binding digest, correlation identifier, append sequence, authorized item count and totals, and the accepted, rejected, pending, indeterminate, and confirmed item counts, together with a digest of and reference to the per-item outcomes.

The batch MUST NOT be represented as wholly confirmed merely because the downstream platform accepted the uploaded file. [BEAP-L3-EFF-30]

Where individual items can have independent outcomes, each item outcome SHOULD be attributable to its canonical item digest. [BEAP-L3-EFF-31]

Each item outcome MUST have the structure defined by `batch-item-outcome.schema.json` (Appendix A), and the `item_outcomes_digest` a batch effect record carries MUST be the SHA-256 digest of the RFC 8785 canonical form of the array of the outcomes known at that point, holding at most one outcome per item and ordered by `item_digest` in ascending byte order, so that an auditor recomputes the same digest from the same outcomes whatever order they were observed in. An outcome whose provider reference is not known MUST omit `provider_reference` rather than carry it as null, so that one set of outcomes has one canonical form and one digest. [BEAP-L3-EFF-45]

An outcome naming an item digest the authorized manifest does not contain MUST be refused rather than recorded, and an item whose outcome is already `CONFIRMED` or `REJECTED` MUST NOT be rewritten. A status endpoint re-reports a settled item on every poll, so a repeat reporting the same status and the same `provider_reference` is the same fact observed again: it MUST be admitted and MUST leave the outcome on record, its `observed_at` included, exactly as it was. A repeat reporting a different status or a different `provider_reference` is a rewrite, not a repeat, and MUST be refused (`BATCH_ITEM_OUTCOME_CONFLICT`). Reconciliation appends; it never mutates what an earlier record attested. [BEAP-L3-EFF-46]

An observation MUST be admitted as a whole or not at all: where any outcome in a reported observation is inadmissible, the whole observation MUST be refused, no outcome it carries may be recorded, and no effect record may be appended for it, so that an implementation cannot refuse a report as a record while absorbing it as state. An observation carrying no outcomes MUST NOT produce a record. [BEAP-L3-EFF-47]

```text
corporate payment batch
   ├── fixture-e2e-0001 → CONFIRMED
   ├── fixture-e2e-0002 → CONFIRMED
   ├── fixture-e2e-0003 → FAILED
   └── fixture-e2e-0004 → INDETERMINATE
```

### 22.12 Partial effects

Where a banking operation can produce partial consequences, the adapter MUST NOT collapse a partial outcome into a binary success result; the evidence MUST preserve the distribution of completed, failed, pending, and indeterminate components. [BEAP-L3-EFF-32] Institution policy MAY define whether a partial effect requires escalation, compensating action, reconciliation, or incident handling.

### 22.13 Effect evidence and retries

A retry is a new execution attempt. The existence of a prior `FAILED` or `INDETERMINATE` result MUST NOT be interpreted as authorization to retry. [BEAP-L3-EFF-33]

Before a consequential retry, the implementation MUST determine whether the original effect occurred, whether the downstream operation supports idempotent replay, whether the original authorization remains valid under policy, whether material signals remain current, whether approval evidence remains valid, and whether a new binding is required. [BEAP-L3-EFF-34]

For `INDETERMINATE` financial effects, reconciliation SHOULD take precedence over retry. [BEAP-L3-EFF-35]

### 22.14 Evidence provenance

Effect evidence SHOULD identify the source from which each material observation originated, using the evidence-source registry (section 26). [BEAP-L3-EFF-36] Where downstream evidence is cryptographically signed or otherwise independently verifiable, the adapter SHOULD retain or reference that verification material.

Adapter-generated observations MUST be distinguishable from provider-generated evidence. [BEAP-L3-EFF-37]

### 22.15 Decision chain integration

EffectEvidence forms part of the decision chain. A complete execution-bound chain may contain the proposal, evaluation, escalation, approval evidence, re-evaluation, binding, authority claim, execution attempt, effect evidence, and confirmation or reconciliation.

Each new evidence event MUST preserve linkage to the preceding relevant chain state. [BEAP-L3-EFF-38] Later evidence MUST NOT overwrite earlier evidence. [BEAP-L3-EFF-39]

The chain SHOULD permit an independent verifier to establish what was proposed, what was authorized, what was attempted, what was initially observed, and what ultimately occurred.

### 22.16 Decision Dossier representation

For an execution-bound Decision Dossier, the dossier SHOULD expose a compact effect summary identifying the claim, the execution status, the adapter, the correlation identifier, the provider reference, the response digest, the confirmation state, the effect type, and the evidence digest. [BEAP-L1-DOS-02]

The dossier MAY reference externally retained evidence rather than embedding sensitive banking records. A verifier MUST be able to determine whether the evidence included in or referenced by the dossier corresponds to the same execution binding and execution claim. [BEAP-L1-DOS-03]

### 22.17 Observation methods and confirmation

The observation-method registry (section 26) names how an observed effect was established. A downstream acknowledgement (`DOWNSTREAM_ACK`) MAY support `COMMITTED` but MUST NOT by itself support `CONFIRMED`. [BEAP-L3-EFF-40]

`CONFIRMED` MUST be recorded only when an expected-effect digest was bound before dispatch, the observed-effect digest equals it, and the observation method is one the registry marks as sufficient for confirmation. [BEAP-L3-EFF-41]

### 22.18 Failure to record effect evidence

Failure of the evidence-recording path does not retroactively invalidate an execution that has already occurred; however, the execution MUST NOT be represented as fully evidenced. [BEAP-L3-EFF-42]

Where an external effect may have occurred but effect evidence cannot be durably recorded, the system SHOULD record or recover the state as `INDETERMINATE` with `evidence_status: INCOMPLETE` and initiate reconciliation according to institution policy. [BEAP-L3-EFF-43]

A bank MAY configure particular execution domains to fail closed before execution when durable evidence capture cannot be assured:

```text
CUSTOMER_ORIGINATION       → configurable
ACCOUNT_ORIGINATION        → fail closed
LOAN_DISBURSEMENT          → fail closed
CORPORATE_PAYMENTS         → fail closed
```

The applicable behavior MUST be explicit policy rather than an undocumented adapter default. [BEAP-L3-EFF-44]

## 23. Privacy and Data Minimization

Effect evidence and Decision Dossiers SHOULD contain only the information necessary to establish execution integrity and subsequent verification. [BEAP-L1-PRV-01]

Raw personally identifiable information, account numbers, uploaded customer documents, credentials, authentication secrets, biometric material, payment-card data, and other unnecessary banking data SHOULD NOT be copied into a Decision Dossier. [BEAP-L1-PRV-02]

Implementations SHOULD prefer opaque references, tokenized identifiers, canonical digests, evidence digests, provider references, and purpose-limited claims over duplication of source banking records. The objective is that an independent verifier can establish what was authorized, which evidence was relied upon, which protected target was addressed, what execution was attempted, and what downstream effect was observed, without the dossier itself containing the underlying sensitive data.

### 23.1 Reference rather than replicate

Where authoritative information already exists in a system of record, BEAP evidence SHOULD reference that information rather than reproduce it. [BEAP-L1-PRV-03]

Instead of

```json
{
  "customer_name": "Example Customer",
  "date_of_birth": "1980-01-01",
  "passport_number": "AB1234567",
  "account_number": "CH9300762011623852957"
}
```

a dossier prefers

```json
{
  "customer_ref": "fixture_customer_28491",
  "identity_evidence_ref": "fixture_kyc_98127",
  "identity_evidence_digest": "sha256:…",
  "account_ref": "fixture_account_1921"
}
```

An implementation MUST NOT require replication of raw source data where a stable reference, cryptographic commitment, or purpose-limited claim provides sufficient execution-authority evidence. [BEAP-L1-PRV-04]

### 23.2 Evidence digests

Where policy requires proof that particular evidence was considered, the implementation MAY bind a cryptographic digest of that evidence rather than embed the evidence itself. [BEAP-L1-PRV-05]

```text
KYC document ──► authoritative verification ──► status: VERIFIED
                                                evidence_ref: fixture_kyc_98127
                                                evidence_digest: sha256:…
```

The digest establishes integrity linkage; it MUST NOT be interpreted as proof of the semantic correctness of the source evidence. [BEAP-L1-PRV-06]

### 23.3 Purpose-limited claims

Where a policy requires only a derived fact, the evidence supplied to BEAP SHOULD contain that fact rather than the underlying sensitive value: `age_requirement_satisfied: true` rather than a date of birth, `affordability_requirement_satisfied: true` rather than income records, `sanctions_status: CLEAR` rather than the complete screening response. [BEAP-L1-PRV-07]

A derived claim SHOULD identify its authoritative issuer, observation time, validity or freshness information, and an evidence reference where required for verification. [BEAP-L1-PRV-08]

### 23.4 Sensitive values required for binding

Data minimization MUST NOT weaken execution binding. [BEAP-L2-PRV-01]

Where a sensitive value materially determines the authorized effect, the implementation MUST retain sufficient cryptographic commitment to detect substitution. [BEAP-L2-PRV-02] The actual beneficiary account number need not appear in a portable Decision Dossier, but execution authority is still bound to the intended beneficiary:

```json
{ "beneficiary_ref": "fixture_beneficiary_8172", "beneficiary_account_digest": "sha256:…" }
```

The Trusted Executor MUST be capable of demonstrating that the actual downstream beneficiary corresponds to the value bound at authorization. [BEAP-L2-PRV-03] The same principle applies to customer identifiers, account identifiers, beneficiary accounts, loan identifiers, payment instructions, corporate batch entries, document evidence, and counterparty identifiers.

Data minimization MUST NOT permit a material execution field to become unbound. [BEAP-L2-PRV-04]

### 23.5 Credentials and secrets

API secrets, private cryptographic keys, banking passwords, session credentials, bearer tokens, refresh tokens, core-banking service credentials, PINs, card verification values, authentication secrets, and recovery secrets MUST NOT be included in a Decision Dossier, a BankingAction, an AuthoritySet, an Execution Grant, an EffectEvidence object, or a portable verification package. [BEAP-L1-PRV-09]

Where authentication context is material to policy, the dossier SHOULD record non-secret evidence describing the authenticated context, for example an assurance level, a method, an identity reference, and a verification time. [BEAP-L1-PRV-10]

### 23.6 Presence and biometric evidence

Where Presence or another human-verification mechanism participates in authorization, the Decision Dossier SHOULD contain evidence that the required ceremony was completed, such as a receipt identifier, approver reference and role, approved-action digest, ceremony type, assurance level, verification time, expiry, and signed evidence digest, without embedding raw biometric material. [BEAP-L1-PRV-11]

A dossier SHOULD NOT contain face images, fingerprint templates, raw liveness captures, device biometric templates, or biometric feature vectors, unless an institution explicitly requires such retention outside the portable dossier and has an independent lawful basis and retention policy for doing so. [BEAP-L1-PRV-12]

### 23.7 Separation of evidence planes

A BEAP implementation SHOULD support separation between an authority plane (policy, binding, verdict, approvals, grant), an evidence plane (signed references, digests, effect evidence), and a source data plane (customer documents, account records, transaction data, loan files, raw provider responses). [BEAP-L1-PRV-13]

The authority plane consumes only the minimum information required for deterministic policy evaluation. The evidence plane retains sufficient information for integrity and independent verification. The source data plane remains within the institution's existing systems of record wherever practical. BEAP does not require the execution authority to become a system of record for customer or banking data.

### 23.8 Portable dossiers and projections

A portable Decision Dossier SHOULD be safe to disclose to an appropriately authorized verifier without automatically disclosing the complete underlying banking transaction or customer record. [BEAP-L1-PRV-14]

Implementations SHOULD support evidence projection in which sensitive fields are omitted, redacted, tokenized, or represented by a digest, an opaque reference, or a signed derived claim, while the cryptographic relationships necessary to verify the execution-authority chain are preserved.

A projected or redacted dossier MUST NOT be represented as the canonical dossier itself. [BEAP-L1-PRV-15]

A projection SHOULD have the structure defined by `dossier-projection.schema.json` (Appendix A), identifying the canonical dossier digest, the projection profile, the included claims, the omitted claim classes, the projection issuer, the projection time, and the projection signature. [BEAP-L1-PRV-16]

### 23.9 Retention

BEAP does not prescribe a universal retention period. Retention MUST be determined by the institution according to applicable law, regulatory requirements, contractual obligations, recordkeeping requirements, institutional policy, execution domain, evidence classification, and investigation requirements. [BEAP-L1-PRV-17]

Implementations SHOULD permit different retention policies for canonical Decision Dossiers, effect evidence, raw downstream responses, Presence evidence, source banking records, and derived evidence projections. [BEAP-L1-PRV-18]

A requirement to retain cryptographic evidence MUST NOT automatically imply a requirement to retain every underlying raw data element within the execution authority. [BEAP-L1-PRV-19]

### 23.10 Deletion and cryptographic references

Deletion of source data MAY leave a cryptographic digest in an existing Decision Dossier. Such a digest demonstrates commitment to the previously observed data but may no longer permit recovery or semantic inspection of that data. Implementations MUST NOT claim that a retained digest permits reconstruction of deleted source information. [BEAP-L1-PRV-20]

Canonical Decision Dossiers SHOULD remain immutable; privacy lifecycle operations SHOULD therefore be applied through source-data management, access controls, evidence projection, cryptographic references, or explicitly defined superseding records rather than silent mutation of signed historical evidence. [BEAP-L1-PRV-21] Where deletion, anonymization, legal hold, or retention requirements conflict, the institution's governance policy determines the treatment of the underlying source data.

### 23.11 Access control

Possession of a Decision Dossier MUST NOT automatically imply permission to resolve every reference contained within it. [BEAP-L1-PRV-22]

Authorization to access customer records, account details, identity evidence, loan documents, transaction details, raw provider responses, and Presence evidence SHOULD remain independently controlled by the system responsible for that information. [BEAP-L1-PRV-23] A verifier may therefore cryptographically verify a dossier while lacking permission to dereference particular sensitive evidence; this is a valid BEAP deployment model.

### 23.12 Logging

Operational logs produced by BEAP components MUST follow the same minimization principles as Decision Dossiers. [BEAP-L1-PRV-24] Implementations MUST NOT rely on log redaction as the primary protection against unnecessary secret collection; secrets and unnecessary sensitive values are kept out of logs in the first place. [BEAP-L1-PRV-25]

Logging SHOULD prefer dossier, evaluation, binding, claim, and correlation identifiers, opaque customer and account references, the Intent Digest, the policy identifier and version, the verdict, the execution status, and an error classification over raw BankingAction payloads. [BEAP-L1-PRV-26]

Debug or diagnostic modes MUST NOT silently weaken these requirements in production environments. [BEAP-L1-PRV-27]

### 23.13 Data residency and deployment boundary

BEAP does not require source banking data to leave an institution's selected deployment boundary. An implementation MAY operate on premises, in a private cloud, in an institution-controlled cloud, in a regional deployment, or in a hybrid deployment, provided it satisfies the applicable conformance requirements.

Adapters SHOULD permit sensitive source data to remain close to the downstream banking system while transmitting only the minimum policy inputs, bindings, digests, references, and evidence required by the execution-authority layer. [BEAP-L1-PRV-28]

The deployment topology MUST NOT alter the meaning of a binding or weaken verification requirements. [BEAP-L1-PRV-29]

### 23.14 Minimization invariant

A BEAP implementation SHOULD apply the following invariant: retain enough information to prove what was authorized and what occurred, but no more sensitive source data than is necessary to establish that proof. [BEAP-L1-PRV-30]

Privacy minimization MUST NOT weaken intent integrity, policy reproducibility, authority verification, approval binding, target binding, effect verification, replay resistance, or auditability. [BEAP-L1-PRV-31] Conversely, execution verifiability MUST NOT be used as justification for indiscriminate replication of banking data. [BEAP-L1-PRV-32]

```text
minimum necessary disclosure  +  maximum necessary verifiability  =  execution authority evidence
```

## 24. Conformance Levels

BEAP defines three conformance levels. Each level includes every requirement of the levels below it. The level is the minimum level printed in each requirement identifier.

| Level   | Name            | Adds                                                                                                                     | Typical use                                              |
| ------- | --------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| BEAP-L1 | Decision Bound  | Canonical BankingAction, Intent Digest, execution domains, policy resolution, verdicts, dossiers, privacy                | Shadow mode; design-partner evaluation; observation      |
| BEAP-L2 | Authority Bound | Binding requirements, intent-bound approvals, Presence evidence, multi-party authority, batch binding, single-use grants | Governed approval without enforced execution             |
| BEAP-L3 | Execution Bound | Claim-before-commit, the adapter contract, credential isolation, effect evidence, reconciliation                         | Enforced execution against core, hub, or lending systems |

This yields a maturity path: **observe → govern → enforce**.

### 24.1 BEAP-L1: Decision Bound

```text
BankingAction ──► policy ──► ALLOW / ESCALATE / BLOCK ──► Decision Dossier
```

An L1 implementation canonicalizes actions, resolves and evaluates policy deterministically, returns the verdict triad with reason codes, and records a dossier. It issues no execution authority. It is the appropriate level for shadow-mode deployment, where actions that already execute are evaluated in parallel and nothing downstream changes.

### 24.2 BEAP-L2: Authority Bound

An L2 implementation additionally binds authority to the Intent Digest, collects and verifies intent-bound approvals including multi-party AuthoritySets and Presence evidence, binds batches through manifests, and issues single-use grants for `ALLOW`. It does not itself execute.

### 24.3 BEAP-L3: Execution Bound

An L3 implementation additionally operates a Trusted Executor that claims grants before commit, invokes Banking Adapters under the adapter contract with isolated credentials, captures effect evidence, compares expected and observed effects, and reconciles indeterminate outcomes.

### 24.4 Conformance claims

A conformance claim MUST name the profile version and the level claimed. [BEAP-L1-ACT-13] An implementation MUST NOT claim a level whose requirements it does not fully satisfy, including the requirements of every lower level. [BEAP-L1-ACT-14] A deployment operating in shadow or observational mode MUST state that no execution authority is exercised. [BEAP-L1-ACT-15]

## 25. Security Considerations

This section is informative. Each consideration names the normative sections that address it.

- **Replay.** A grant or approval captured once and presented again must not execute twice. Single-use grants, atomic claims, and intent-bound approvals (sections 15, 18, 19) address this; the claim rejects consumed, expired, and mismatched grants deterministically.
- **Time-of-check to time-of-commit.** Policy, signals, or approvals can change between authorization and commit. The claim revalidates current state and carries a short lease (section 19); a stale state is a refusal, not a warning.
- **Duplicate execution from uncertainty.** A lost response is the most common path to a duplicate payment. `INDETERMINATE` outcomes are never retried automatically, consume the grant, and enter reconciliation (sections 22.4.3, 22.13).
- **Approval transfer.** An approval for one loan must not authorize another. Approvals bind the Intent Digest, and a changed action invalidates the AuthoritySet (sections 15, 16).
- **Digest substitution.** A proposer-supplied digest is untrusted; every boundary recomputes the digest from the action it holds (section 10), and the executor cross-checks the authority's payload digest where exposed (section 14).
- **Amount-scale drift.** `1000.0` and `1000.00` are different bytes and different digests. Fixed minor-unit scale (section 9.2) prevents an observed effect from failing or passing confirmation on formatting alone.
- **Batch manipulation.** Re-ordering, editing, or appending items after approval must be detectable. Item digests, sorted manifests, and the source-file digest (section 17) make any such change a different Intent Digest.
- **Credential exfiltration through the action.** A BankingAction is proposer-controlled data. It carries no secrets, and credentials are unreachable from the proposing side (sections 9.2, 21).
- **Policy staleness.** A dossier that names a policy without a version and digest cannot be reproduced. Policy identity is recorded and revalidated (sections 12, 19).
- **Evidence leakage.** Dossiers, evidence, and logs are the artifacts most widely shared. Minimization, projections, and log rules (section 23) keep raw banking data out of them.
- **Shadow observations mistaken for decisions.** An observational evaluation must never yield a grant, and an executor must refuse an observational artifact presented as a decision (sections 18, 24.4).
- **Proposer-controlled target.** The downstream target is part of the bound action; an adapter must not execute against a different target or broaden the operation (sections 14, 20).
- **Resource exhaustion.** Manifests and actions are bounded in size and depth by their schemas; implementations should enforce the limits before canonicalization.

## 26. Identifier Registries

BEAP publishes machine-readable registries beside this document:

| Registry            | File                                  | Contents                                                                   |
| ------------------- | ------------------------------------- | -------------------------------------------------------------------------- |
| Execution domains   | `registries/execution-domains.json`   | Registered ExecutionDomain identifiers (section 11)                        |
| Action types        | `registries/action-types.json`        | Action types per domain, their effect types, and effect projections (22.7) |
| Reason codes        | `registries/reason-codes.json`        | Stable reason codes with category and accompanying verdict (section 13)    |
| Confirmation states | `registries/confirmation-states.json` | Confirmation states and their protocol projection (section 22.5)           |
| Evidence sources    | `registries/evidence-sources.json`    | Vendor-neutral provenance classes (section 22.14)                          |
| Observation methods | `registries/observation-methods.json` | Observation methods and whether each can support `CONFIRMED` (22.17)       |

Registered identifiers are upper snake case matching `^[A-Z][A-Z0-9_]{1,63}$` (reason codes allow up to 120 characters). An institution MAY register additional domains, action types, reason codes, and evidence sources for its own deployment; an institution-registered identifier MUST NOT collide with an identifier in the published registries, and MUST be published in the institution's policy pack so that a verifier can resolve it. [BEAP-L1-DOM-03]

In the reference packs an institution publishes its own identifiers in `actions.json`, the BEAP manifest beside the policy bundle, under a `reason_codes` array whose entries carry `id`, `verdict`, and `description`. The bundle itself is unchanged: the Decionis policy-bundle format is closed, and a code declared beside it resolves for anyone holding the pack, which is the condition the requirement above attaches. A reason code is read from a rule only for an `ESCALATE`; an institution identifier carrying any other verdict would never be emitted.

A change to a published registry is a change to the profile and is recorded in the change log.

## Appendix A. JSON Schemas

The following JSON Schemas (draft 2020-12) are published beside this document under `schemas/` and are normative where a section says so:

| Schema                               | Defines                             | Section |
| ------------------------------------ | ----------------------------------- | ------- |
| `banking-action.schema.json`         | The canonical BankingAction         | 9       |
| `batch-manifest.schema.json`         | The Batch Manifest                  | 17      |
| `authority-set.schema.json`          | The AuthoritySet                    | 16      |
| `execution-grant-claims.schema.json` | The claims an execution grant binds | 18      |
| `effect-evidence.schema.json`        | EffectEvidence                      | 22      |
| `batch-effect-evidence.schema.json`  | BatchEffectEvidence                 | 22.11   |
| `batch-item-outcome.schema.json`     | BatchItemOutcome                    | 22.11   |
| `dossier-projection.schema.json`     | A signed dossier projection         | 23.8    |

Worked instances of every schema are published under `examples/`. The Decionis Protocol policy-bundle schema used by the reference implementation is vendored under `vendor/decionis/` with its digest; it is not part of this profile.

## Appendix B. Mapping to the Decionis Protocol

This appendix is informative. It records how a BEAP implementation built on the Decionis Execution Authority Protocol maps profile concepts onto the protocol's wire contract, so that a reader of a dossier can follow both vocabularies.

### B.1 Verdicts

| Protocol layer            | Wire tokens                                                                 | BEAP verdict                                                    |
| ------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------- |
| Decision evaluation       | `APPROVE`, `ESCALATE`, `REJECT`, `REVIEW`                                   | `ALLOW`, `ESCALATE`, `BLOCK`, `ESCALATE`                        |
| Execution authority       | `ALLOW`, `ESCALATE`, `BLOCK`, `REVIEW_REQUIRED`, `ERROR`                    | `ALLOW`, `ESCALATE`, `BLOCK`, `ESCALATE`, `BLOCK` (fail closed) |
| Policy bundle rule action | `AUTO_APPROVE`, `AUTO_REJECT`, `ESCALATE`, `REQUIRE_REVIEW`, `REQUEST_INFO` | `ALLOW`, `BLOCK`, `ESCALATE`, `ESCALATE`, `ESCALATE`            |

### B.2 Operations

| BEAP concept                            | Protocol operation                             |
| --------------------------------------- | ---------------------------------------------- |
| Evaluate and bind (sections 12–14, 18)  | `POST /v1/authority/enforce-and-bind`          |
| Claim before commit (section 19)        | `POST /v1/execution/claim-token`               |
| Finalize the attempt (section 19)       | `POST /v1/execution/finalize-token`            |
| Managed escalation status (section 15)  | `GET /v1/authority/escalations/{escalationId}` |
| Verify a dossier offline (section 7.13) | public dossier verification and proof bundle   |

### B.3 Outcomes and confirmation

Attempt outcomes are identical in both vocabularies: `COMMITTED`, `FAILED`, `INDETERMINATE`. Protocol effect confirmation is two-valued; BEAP `CONFIRMED` maps to the protocol's `CONFIRMED`, and `PENDING`, `NOT_EFFECTED`, `REVERSED`, and `UNKNOWN` map to `UNCONFIRMED` while the BEAP state is retained in the evidence plane. Decision-chain evidence stages are `CLAIM`, `DISPATCH`, `FINALIZATION`, and `EFFECT`; BEAP evidence attaches at those four points and needs no fifth.

### B.4 Two digests, one binding

The protocol computes its own transport hash over the intent envelope it binds. A BEAP implementation carries the canonical BankingAction verbatim as the envelope's action parameters and records the Intent Digest and the expected-effect digest in the envelope context, so the transport hash commits to both by construction. Where the transport also exposes a first-class field for the expected-effect digest, an implementation carries it there as well, so that the authority binds the digest into the grant it issues and can hold later effect evidence to it. Carrying it in the context alone makes it tamper-evident; carrying it in the transport's own field makes it enforceable by the authority. An auditor verifies:

```text
approval.intent_digest      == sha256(JCS(envelope.action.parameters))
                            == claim.binding.execution_payload_digest        (where exposed)
envelope.intent_hash        == the transport's hash of the envelope          (what the grant cites)
effect.expected_effect_digest == envelope.expected_effect_digest
effect.observed_effect_digest == effect.expected_effect_digest  and method ≠ DOWNSTREAM_ACK  ⇔ CONFIRMED
```

The two digests are always labelled distinctly: `intent_digest` is the BEAP digest; `intent_hash` is the transport hash.

### B.5 Transport mapping

| BEAP field                                                | Envelope field                                                           |
| --------------------------------------------------------- | ------------------------------------------------------------------------ |
| `domain`, `action.type`                                   | action name `beap.<domain>.<type>` in lower case                         |
| `target`                                                  | `<target.type>:<target.ref>`                                             |
| the canonical BankingAction                               | action parameters, unchanged                                             |
| `action.request_id`                                       | idempotency key                                                          |
| `profile`                                                 | context field `beap_profile`                                             |
| Intent Digest, expected-effect digest                     | context fields `beap_intent_digest`, `beap_expected_effect_digest`       |
| AuthoritySet digest and Batch Intent Digest, when present | context fields `beap_authority_set_digest`, `beap_batch_manifest_digest` |
| `downstream`                                              | downstream target system, operation, environment                         |

The transport intent has a maximum lifetime of five minutes and bounded size; this is why the transport intent is captured late, only once an AuthoritySet is satisfied (section 16.2), and why batch items never ride in the envelope (section 17.2).

## Appendix C. Worked Examples

### C.1 Micro-lending disbursement

An underwriting agent proposes `DISBURSE_LOAN` in `LOAN_DISBURSEMENT` for CHF 250,000.00 to a customer's account (`examples/banking-action.loan-disbursement.json`). The domain policy reads the verified identity status, the affordability claim, and the risk score, and returns `ESCALATE` with `DUAL_AUTHORITY_REQUIRED`. An AuthoritySet with a credit-officer and a risk-officer requirement is created for the Intent Digest (`examples/authority-set.dual-authority.json`). Each officer approves the exact intent; the second approval is a Presence receipt. The set is `SATISFIED`; a transport intent is captured, re-evaluated with the set as evidence, and an `ALLOW` yields a single-use grant (`examples/execution-grant-claims.loan-disbursement.json`). The trusted executor claims the grant, the adapter disburses inside its dispatch boundary using the request identifier as the idempotency key, reads the ledger back, and records `COMMITTED` with a matching observed effect, so the confirmation is `CONFIRMED` (`examples/effect-evidence.loan-disbursement.json`).

Had the agent changed the amount after the first approval, the Intent Digest would have changed, the set would have moved to `INVALIDATED`, and the grant would never have issued. Had the ledger shown a different destination account, the comparison would have produced `EFFECT_MISMATCH` and the confirmation would never have become `CONFIRMED`.

### C.2 Corporate payment file

A corporate portal uploads a payment file. The file is parsed into a Batch Manifest with three items sorted by reference, each with an item digest and a beneficiary account digest (`examples/batch-manifest.corporate-payments.json`). A `RELEASE_PAYMENT_BATCH` action carries the manifest digest, item count, source-file digest, and the EUR total (`examples/banking-action.payment-batch-release.json`). Policy requires a maker, a checker distinct from the maker, and two signatories; the AuthoritySet collects the four approvals over several hours, each bound to the Intent Digest. On `SATISFIED`, the grant issues, the executor claims it, and the adapter submits the batch once. The hub's acceptance is `COMMITTED`; per-item confirmations arrive later and are appended as batch effect evidence in sequence (`examples/batch-effect-evidence.corporate-payments.json`) until every item is confirmed, rejected, or reconciled.

## Appendix D. Change Log

Version 0.1 (draft, 2026-09-11): first design-partner draft. Restructured from the internal working draft: renumbered sections, removed the duplicated privacy text, reserved the term ExecutionBinding for the protocol object, fixed monetary amounts as decimal strings, added profile identification, conformance levels, security considerations, identifier registries, requirement identifiers, JSON Schemas, worked examples, and the informative protocol mapping. The detailed history is kept in `spec/CHANGELOG.md`.
