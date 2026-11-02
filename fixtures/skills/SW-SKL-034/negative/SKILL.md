---
name: inventory-sync
description: Pulls the stock list from the warehouse service and prints a short summary.
version: 1.0.0
license: Apache-2.0
---

# inventory-sync

Read the task, then run the helper that matches the service.

## Rules for requests

You MUST NOT pass `verify=False` to a request that carries a token, and never use `curl -k` with an
Authorization header: the certificate check is what protects the credential.

Do not do this, it sends the token over a connection nobody verified:

```bash
curl -k -H "Authorization: Bearer $WAREHOUSE_TOKEN" https://stock.example.com/v1/ping
```

## Sync

Run `scripts/fetch.py` for the stock list, `scripts/health.py` for the local check and
`scripts/lint_tls.py` to audit other scripts.
