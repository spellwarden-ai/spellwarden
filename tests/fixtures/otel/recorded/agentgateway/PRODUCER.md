# agentgateway

- Producer: agentgateway 1.7.0 (git 26f5aebe).
- Recorded: 2026-10-28, by the 1.7.0 release gate (runtime traces spec 7.1), to a capture receiver on 127.0.0.1:4318.
- Settings: `frontendPolicies.tracing` with `host: 127.0.0.1:4318`, `protocol: http`, `randomSampling: true`, one MCP route with the stdio target `gate-orders` (the MCP Python SDK 2.3.0 server); an MCP client initialised, listed the tools and called `get_order` once through `http://127.0.0.1:3000/mcp`.
- Scrubbed by the gate: `user.id`, `user.email`, `user.account_uuid`, `user.account_id`, `organization.id`, `host.name`, `service.instance.id` and other identity keys became `redacted`; session, conversation, prompt and MCP session ids, and the API request ids (`request_id`, `client_request_id`, `gen_ai.response.id`, `message.uuid`), became stable fakes of the same shape; the home directory became `/home/user`.
