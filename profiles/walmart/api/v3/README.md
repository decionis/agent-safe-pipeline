# Walmart Marketplace API v3

**Profile:** `walmart/api/v3` · **Contract:** [`agent-safe.profile.api/1`](../../../../spec/profiles/api/v1/README.md) ·
**Platform:** `walmart-marketplace` · **Definition:** [`profile.json`](./profile.json) ·
**Vectors:** [`vectors/`](./vectors) · **Manifest:** [`MANIFEST.sha256`](./MANIFEST.sha256)

The seller writes an agent can make through Walmart's Marketplace API, as intents. The gateway in
front of `https://marketplace.walmartapis.com` governs an agent's calls by it, and Commerce's
Walmart executors describe their own writes by it, so an agent's acknowledgement and the
connector's are the same action with the same facts, decided under the same policy path.

| Operation            | Call                                            | Action              | Facts                                                       | Policy path                                         |
| -------------------- | ----------------------------------------------- | ------------------- | ----------------------------------------------------------- | --------------------------------------------------- |
| `orders.acknowledge` | `POST /v3/orders/{purchaseOrderId}/acknowledge` | `order.acknowledge` | `purchase_order_id`                                         | `ORDER_ACCEPTANCE`, `commerce_order_acceptance`     |
| `orders.cancel`      | `POST /v3/orders/{purchaseOrderId}/cancel`      | `order.cancel`      | `purchase_order_id`, `line_numbers`, `cancellation_reasons` | `ORDER_CANCELLATION`, `commerce`                    |
| `orders.refund`      | `POST /v3/orders/{purchaseOrderId}/refund`      | `order.refund`      | `purchase_order_id`, `line_numbers`                         | `REFUND_REQUEST`, `commerce_refund_request`         |
| `orders.ship`        | `POST /v3/orders/{purchaseOrderId}/shipping`    | `order.ship`        | `purchase_order_id`, `line_numbers`                         | none                                                |
| `prices.promotion`   | `PUT /v3/price?promo=true`                      | `promotion.change`  | `sku`, `price_amount`, `price_currency`, `price_type`       | `PROMOTION_CHANGE`, `commerce_promotion_change`     |
| `prices.update`      | `PUT /v3/price`                                 | `price.change`      | `sku`, `price_amount`, `price_currency`                     | `PRICE_CHANGE`, `commerce_price_change`             |
| `inventory.update`   | `PUT /v3/inventory?sku=…`                       | `inventory.update`  | `sku`, `quantity`, `quantity_unit`                          | `INVENTORY_MUTATION`, `commerce_inventory_mutation` |
| `feeds.submit`       | `POST /v3/feeds?feedType=…`                     | `feed.submit`       | `feed_type`                                                 | none                                                |

- A policy path's `channel` is left to the caller.
- Releasing an order the gate held is the same acknowledgement call, decided as `ORDER_RELEASE`:
  the caller that knows it is a release states that path instead.
- A cancellation of oversold units is the same cancel call; Commerce's oversell executor names its
  own action type for it.
- Reads, and any write not listed, are no operation of this profile.
