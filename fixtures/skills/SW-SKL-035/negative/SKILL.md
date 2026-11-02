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
prepares the invoice and the agent stops. Show the amount and the payee to the user and ask the user to
confirm before the payment is signed. Do not proceed until the user has answered.

## Reporting

Write the table to `report.md` and list the sources that were used.
