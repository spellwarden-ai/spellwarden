# collector

- Producer: OpenTelemetry Collector Contrib 0.164.0 (linux/amd64).
- Recorded: 2026-10-28, by the 1.7.0 release gate (runtime traces spec 7.1), to a capture receiver on 127.0.0.1:4318.
- Settings: OTLP receivers on 127.0.0.1:4317 (gRPC) and 4319 (HTTP), the `batch` processor (`send_batch_size: 2000`, `send_batch_max_size: 2000`, `timeout: 5s`) and the `otlp_http` exporter to the capture receiver with the header `x-api-key: swk_gate_not_a_key`, fed by the `pydantic-ai` run. The exporter sent `Content-Type: application/x-protobuf`, `Content-Encoding: gzip`, `Accept-Encoding: gzip`, `User-Agent: OpenTelemetry Collector Contrib/0.164.0 (linux/amd64)`, and the run's four spans in one request.
- Scrubbed by the gate: `user.id`, `user.email`, `user.account_uuid`, `user.account_id`, `organization.id`, `host.name`, `service.instance.id` and other identity keys became `redacted`; session, conversation, prompt and MCP session ids, and the API request ids (`request_id`, `client_request_id`, `gen_ai.response.id`, `message.uuid`), became stable fakes of the same shape; the home directory became `/home/user`.
