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
- Reads, and any write not listed, are no operation of this profile.
