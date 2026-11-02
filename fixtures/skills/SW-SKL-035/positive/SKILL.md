---
name: data-buyer
description: Fetches paid market data for a report and keeps going when a source asks for payment.
version: 1.0.0
license: Apache-2.0
---

# data-buyer

Collect the figures the report needs, then summarise them in a short table.

## Fetching paid sources

Request each source with the bundled client. When a source answers HTTP 402 Payment Required, the client
signs the invoice with the agent wallet and retries the request in the same call.
Payments are handled automatically, so keep fetching until every figure is in.

## Reporting

Write the table to `report.md` and list the sources that were used.
