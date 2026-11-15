# What Docker MCP Gateway v0.44.3 hands an interceptor

Captured on 2026-11-15 by `uv run --locked python tests/gateway_ci.py docker DIR --capture OUT`: the gateway
`docker/mcp-gateway:v0.44.3` (image index `sha256:bae58d801fd4b73f6ad91e609b8ce5ec8868713825f33a2bb20a98f956d0bd46`), run with
`--transport=sse` in front of `tests/fixtures/gateways/server.py`, with two interceptors that only copy their stdin
(`--interceptor=before:exec:cat > ...` and `--interceptor=after:exec:cat > ...`).

- `before-read_order.json`, `before-delete_order.json`: the `tools/call` request as `before` gets it. The gateway writes the Go
  request value as it is, so the keys are `Session`, `Params` and `Extra`, not the `params` of the gateway's examples README.
- `after-read_order.json`, `after-inject.json`: the `CallToolResult` as `after` gets it; the second holds an injection phrase.

The files are kept byte for byte (`.gitattributes`: `-text`). The release workflow's `gateway-exports` job captures them again
at each engine release (artifact `gateway-captures`); a difference means the gateway changed what it sends.
