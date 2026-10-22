# Business Central API v2.0

**Profile:** `businesscentral/api/v2` · **Contract:** [`agent-safe.profile.api/1`](../../../../spec/profiles/api/v1/README.md) ·
**Platform:** `business-central` · **Definition:** [`profile.json`](./profile.json) ·
**Vectors:** [`vectors/`](./vectors) · **Manifest:** [`MANIFEST.sha256`](./MANIFEST.sha256)

The postings and master-data writes an agent can make through Business Central's standard API
v2.0, as intents. Calls are matched under the online endpoint's paths
(`/v2.0/{tenantId}/{environment}/api/v2.0`, `/v2.0/{environment}/api/v2.0`) or bare, when the
gateway's upstream already carries the API base. An OData key may be quoted or not.

| Operation                    | Call (after the prefix)                                               | Action            | Facts beyond `company_id`, `environment`                                           |
| ---------------------------- | --------------------------------------------------------------------- | ----------------- | ---------------------------------------------------------------------------------- |
| `salesInvoices.post`         | `POST /companies({companyId})/salesInvoices({id})/Microsoft.NAV.post` | `sales.post`      | `document_id`                                                                      |
| `salesInvoices.postAndSend`  | `POST …/salesInvoices({id})/Microsoft.NAV.postAndSend`                | `sales.post`      | `document_id`                                                                      |
| `salesInvoices.cancel`       | `POST …/salesInvoices({id})/Microsoft.NAV.cancel`                     | `sales.cancel`    | `document_id`                                                                      |
| `salesOrders.shipAndInvoice` | `POST …/salesOrders({id})/Microsoft.NAV.shipAndInvoice`               | `sales.post`      | `document_id`                                                                      |
| `salesOrders.create`         | `POST …/salesOrders`                                                  | `sales.create`    | `customer_number`, `currency_code`, `external_document_number`                     |
| `purchaseInvoices.post`      | `POST …/purchaseInvoices({id})/Microsoft.NAV.post`                    | `purchase.post`   | `document_id`                                                                      |
| `journals.post`              | `POST …/journals({journalId})/Microsoft.NAV.post`                     | `journal.post`    | `journal_id`                                                                       |
| `vendorPayments.create`      | `POST …/vendorPaymentJournals({journalId})/vendorPayments`            | `payment.create`  | `journal_id`, `vendor_number`, `payment_amount`, `posting_date`, `document_number` |
| `vendors.update`             | `PATCH …/vendors({vendorId})`                                         | `vendor.update`   | `vendor_id`                                                                        |
| `customers.update`           | `PATCH …/customers({customerId})`                                     | `customer.update` | `customer_id`, `blocked`                                                           |

- `sales.post` is the action type Commerce's Business Central executors decide a posting under, so
  an agent's posting and an in-app posting meet the same rules.
- The profile states no policy path: Business Central's rules are keyed on these action types.
- Any write not listed is no operation of this profile.

## Customer-scoped reads

The subject is the customer's number (`number` on a customer, `customerNumber` on a document or a
ledger entry), which is what an identity provider or a CRM names a customer by. Each read below is
checked against the session's customer and never sent to the authority
([subjects](../../../../spec/profiles/api/v1/README.md#7-subjects)). A list read must carry exactly
one filter, the profile's: `$filter=number eq 'C-10000'` for customers and
`$filter=customerNumber eq 'C-10000'` for documents and ledger entries, with the session's number
and no second predicate. Besides it a list may carry `$select`, `$top`, `$skip`, `$orderby`,
`$expand` and `$skiptoken`, and a read by id `$select` and `$expand`; any other option, `$count`,
`$search` and `$apply` among them, is refused. A list's answer may carry `@odata.context` and
`@odata.nextLink` beside `value`, and nothing else:

| Operation                            | Call (after the prefix)                                        | Action          | Subject in each item of the answer |
| ------------------------------------ | -------------------------------------------------------------- | --------------- | ---------------------------------- |
| `customers.list`                     | `GET /companies({companyId})/customers`                        | `customer.read` | `/body/value/*/number`             |
| `customers.get`                      | `GET …/customers({customerId})`                                | `customer.read` | `/body/number`                     |
| `salesInvoices.list`, `.get`         | `GET …/salesInvoices`, `…/salesInvoices({id})`                 | `sales.read`    | `customerNumber`                   |
| `salesOrders.list`, `.get`           | `GET …/salesOrders`, `…/salesOrders({id})`                     | `sales.read`    | `customerNumber`                   |
| `salesQuotes.list`, `.get`           | `GET …/salesQuotes`, `…/salesQuotes({id})`                     | `sales.read`    | `customerNumber`                   |
| `salesCreditMemos.list`, `.get`      | `GET …/salesCreditMemos`, `…/salesCreditMemos({id})`           | `sales.read`    | `customerNumber`                   |
| `customerLedgerEntries.list`, `.get` | `GET …/customerLedgerEntries`, `…/customerLedgerEntries({id})` | `ledger.read`   | `customerNumber`                   |

`salesOrders.create` names its subject in the call and in its answer (`customerNumber`), and
`customers.update` in its answer (`number`). Writes are decided by the authority: the gateway
states the session's customer as the fact `session.subject`, beside the operation's
`customer_number`, so a write policy can compare the two (`customer_number EQ_FACT session.subject`)
where the authority's policy core has fact-to-fact operators. Either write needs a session, and its
successful answer is withheld when it names another customer.

What this does not cover, so an operator knows where the edge is:

- A read by id (`customers({id})`, `salesInvoices({id})`) carries a GUID, not a number, so it is
  checked by its answer only: the record is fetched and, when it is another customer's, refused
  whole before any of it is relayed.
- An answer is checked only when it carries the number. A `$select` that leaves it out is refused
  (`RESPONSE_SUBJECT_ABSENT`); select `number` or `customerNumber` too.
- A list cannot be narrowed further by the filter (`and open eq true`, `and amount gt 5000`): a second
  predicate is refused, so filter what comes back instead.
- Document lines (`salesInvoiceLines`, `salesOrderLines`, …), attachments, PDFs, counts and
  navigation below a record name no customer, so they are no read operation of this profile and
  `refuseUnknownReads` refuses them. It is on by default with `subject`; with it off, a read the
  profile does not name passes unchecked, though a count or a navigation below a listed read is
  still refused.
- `$batch` is a `POST` the profile does not name, so `refuseUnknownReads` refuses it, whatever
  `unmatched` says; its parts could not be checked. With it off, `$batch` goes to the authority as
  `http.post` and its answer is not checked.
- The writes by id (postings, `customers.update`, `vendors.update`) carry a GUID and no customer
  number, so no fact compares them with the session: block or escalate them in policy when
  `session.subject` is present. The answer of `customers.update` is checked, so another customer's
  record is withheld, but the change has been made if policy allowed it.
- Customer ledger entries are served by Business Central's finance reports API, which Microsoft has
  announced as deprecated from Business Central 2026 release wave 2. Where an environment serves
  them under another route, they are no read operation of this profile.

An operator turns customer scoping on with one profile and one identity provider:

```yaml
interception:
  profile: businesscentral/api/v2
  privacy: facts # optional: the authority receives the operation and facts only
  # refuseUnknownReads: true is the default with subject: calls this profile cannot check are refused
subject:
  issuer: https://login.example.com/
  audience: agentsafe-gateway
  jwksFile: /etc/agentsafe/idp-jwks.json # or jwksUrl, refreshed through the guarded egress
  claim: customer_number # the token claim holding the Business Central customer number
```
