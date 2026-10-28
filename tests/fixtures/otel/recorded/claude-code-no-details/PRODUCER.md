# claude-code-no-details

- Producer: Claude Code 2.1.312.
- Recorded: 2026-10-28, by the 1.7.0 release gate (runtime traces spec 7.1), to a capture receiver on 127.0.0.1:4318.
- Settings: As `claude-code-no-content` with `OTEL_LOG_TOOL_DETAILS` unset too (tool and skill names as placeholders). The HTTP server `gate-search` came up after the session started: its first connection failed and a later one served the call.
- Scrubbed by the gate: `user.id`, `user.email`, `user.account_uuid`, `user.account_id`, `organization.id`, `host.name`, `service.instance.id` and other identity keys became `redacted`; session, conversation, prompt and MCP session ids, and the API request ids (`request_id`, `client_request_id`, `gen_ai.response.id`, `message.uuid`), became stable fakes of the same shape; the home directory became `/home/user`.
