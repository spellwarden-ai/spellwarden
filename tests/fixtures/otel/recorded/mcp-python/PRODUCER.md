# mcp-python

- Producer: MCP Python SDK 2.3.0, server and client.
- Recorded: 2026-10-28, by the 1.7.0 release gate (runtime traces spec 7.1), to a capture receiver on 127.0.0.1:4318.
- Settings: A stdio server `gate-orders` (service `gate-mcp-server`) with one tool `get_order`, and a client (service `gate-mcp-client`) that initialises, lists the tools and calls the tool twice, once failing; both with OpenTelemetry Python SDK 1.45.1 with `opentelemetry-exporter-otlp-proto-http` 1.45.1 (protobuf over HTTP, no compression). The SDK traces once a tracer provider is set.
- Scrubbed by the gate: `user.id`, `user.email`, `user.account_uuid`, `user.account_id`, `organization.id`, `host.name`, `service.instance.id` and other identity keys became `redacted`; session, conversation, prompt and MCP session ids, and the API request ids (`request_id`, `client_request_id`, `gen_ai.response.id`, `message.uuid`), became stable fakes of the same shape; the home directory became `/home/user`.
