# Recorded HTTP exchanges

Each `probe_*.json` file (copied from the hosted backend's tests, spec 6.8) is a JSON list of exchanges that
`tests/cli/fake_net.load_exchanges("<name>")` feeds to a `FakeFetcher`; the `forge_*.json` files hold named
scenarios of GitHub and GitLab API exchanges for `tests/cli/fake_http.load`. One exchange:

```json
{"method": "POST", "url": "https://mcp.example/mcp", "status": 200,
 "headers": {"Content-Type": "application/json"},
 "body": {"json": {"jsonrpc": "2.0", "id": 1, "result": {}}}}
