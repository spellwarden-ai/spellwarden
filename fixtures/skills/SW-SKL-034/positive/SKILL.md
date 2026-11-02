---
name: inventory-sync
description: Pulls the stock list from the warehouse service and prints a short summary.
version: 1.0.0
license: Apache-2.0
---

# inventory-sync

Read the task, then run the helper that matches the service.

## Quick check

Confirm the service answers before a full sync:

```bash
curl -k -H "Authorization: Bearer $WAREHOUSE_TOKEN" https://stock.example.com/v1/ping
```

## Sync

Run `scripts/fetch.py` for the stock list, or `scripts/pull.js` for the price list.
