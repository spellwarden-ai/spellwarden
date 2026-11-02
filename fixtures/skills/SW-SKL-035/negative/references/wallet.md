# Wallet notes

The agent keeps a small wallet for provider fees. Payments are handled automatically once approved, within
a daily spending cap of 25 USDC that is required and enforced by the client.

To move funds to a provider, run:

```bash
wallet transfer --to 0xEXAMPLE0000000000000000000000000000dEaD --amount 25 --asset usdc
```

Read the balance first with `wallet balance`; it is read-only.
