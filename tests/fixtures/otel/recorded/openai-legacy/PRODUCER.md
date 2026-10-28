# openai-legacy

- Producer: `opentelemetry-instrumentation-openai-v2` 2.4b0 with `opentelemetry-util-genai` 0.4b0 and `openai` 3.40.0.
- Recorded: 2026-10-28, by the 1.7.0 release gate (runtime traces spec 7.1), to a capture receiver on 127.0.0.1:4318.
- Settings: `OTEL_SEMCONV_STABILITY_OPT_IN` unset (v1.30 conventions: `gen_ai.system`, one log event per message), `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`, one chat completion with a tool call against a local fake OpenAI endpoint, service `gate-openai-legacy`, OpenTelemetry Python SDK 1.45.1 with `opentelemetry-exporter-otlp-proto-http` 1.45.1 (protobuf over HTTP, no compression); traces and logs both recorded. (The latest `opentelemetry-util-genai`, 1.3b0, lacks the module 2.4b0 imports.)
- Scrubbed by the gate: `user.id`, `user.email`, `user.account_uuid`, `user.account_id`, `organization.id`, `host.name`, `service.instance.id` and other identity keys became `redacted`; session, conversation, prompt and MCP session ids, and the API request ids (`request_id`, `client_request_id`, `gen_ai.response.id`, `message.uuid`), became stable fakes of the same shape; the home directory became `/home/user`.
