"""The dialects of agent telemetry and what each one's names mean, as data (runtime traces spec 4.4 to 4.6). No
producer's convention is stable (spec section 1), so a new attribute generation changes these tables, not the code."""
from __future__ import annotations

DIALECTS = ("claude_code", "claude_platform", "openinference", "genai_legacy", "genai", "mcp")
RECORD_KINDS = ("agent", "model", "tool", "mcp", "decision", "connection", "skill", "content", "other")
CONTENT_KINDS = ("system", "input", "output", "tool_arguments", "tool_result", "prompt", "response")
COUNTED_KINDS = frozenset({"agent", "model", "tool", "mcp", "decision", "connection", "skill"})

CLAUDE_CODE_SERVICES = frozenset({"claude-code", "claude-code-desktop"})
CLAUDE_PLATFORM_SERVICE = "claude-platform"

# 4.4: GenAI `gen_ai.operation.name` (dialects genai, genai_legacy, claude_platform); any other value is `other`.
GENAI_OPERATION_KINDS = {
    "chat": "model", "text_completion": "model", "generate_content": "model", "embeddings": "model",
    "execute_tool": "tool",
    "invoke_agent": "agent", "create_agent": "agent", "invoke_workflow": "agent",
}
# 4.4: OpenInference `openinference.span.kind`; any other value is `other`.
OPENINFERENCE_KINDS = {"LLM": "model", "EMBEDDING": "model", "TOOL": "tool", "AGENT": "agent"}
OPENINFERENCE_CONTENT_SPANS = frozenset({"LLM", "AGENT", "CHAIN"})
# 4.4: Claude Code's beta spans (P6: stored, never counted).
CLAUDE_CODE_SPAN_KINDS = {
    "claude_code.interaction": "agent", "claude_code.llm_request": "model", "claude_code.tool": "tool",
    "claude_code.tool.blocked_on_user": "decision",
}
# 4.4: Claude Code's log events, by the name after `claude_code.`; `safety_event` is folded (normalise.py).
CLAUDE_CODE_EVENT_KINDS = {
    "api_request": "model", "api_error": "model", "tool_result": "tool", "tool_decision": "decision",
    "safety_event": "decision", "skill_activated": "skill", "mcp_server_connection": "connection",
    "user_prompt": "content", "assistant_response": "content",
}
# 4.4: GenAI log events that carry content, with the content kind of the deprecated per-message ones.
GENAI_CONTENT_EVENTS = {
    "gen_ai.client.inference.operation.details": None,
    "gen_ai.system.message": "system", "gen_ai.user.message": "input", "gen_ai.tool.message": "input",
    "gen_ai.assistant.message": "output", "gen_ai.choice": "output",
}
# 4.5: legacy `gen_ai.system` values spelled differently from `gen_ai.provider.name`.
LEGACY_PROVIDERS = {"mistral_ai": "mistral", "xai": "x_ai"}
# 4.5: the names Claude Code reports instead of a real one (`mcp_other` appears in spans' `tool_name_safe` only).
CLAUDE_CODE_PLACEHOLDERS = frozenset({"mcp_tool", "custom", "custom_skill", "skill_tool", "dynamic_tool", "other_tool",
                                      "third-party"})
SPAN_SAFE_PLACEHOLDERS = CLAUDE_CODE_PLACEHOLDERS | {"mcp_other"}
UNKNOWN_SERVICE = "unknown_service"

# 4.6: content attributes, as (attribute, kind). The GenAI ones apply to every dialect but Claude Code.
GENAI_CONTENT_ATTRIBUTES = (
    ("gen_ai.system_instructions", "system"),
    ("gen_ai.input.messages", "input"),
    ("gen_ai.prompt", "input"),
    ("gen_ai.output.messages", "output"),
    ("gen_ai.completion", "output"),
    ("gen_ai.tool.call.arguments", "tool_arguments"),
    ("tool_call.function.arguments", "tool_arguments"),
    ("gen_ai.tool.call.result", "tool_result"),
)
# 4.6: flattened families (`gen_ai.prompt.0.content`): every attribute under the prefix, rendered as one JSON object.
GENAI_CONTENT_PREFIXES = (
    ("gen_ai.prompt.", "input"),
    ("llm.input_messages.", "input"),
    ("gen_ai.completion.", "output"),
    ("llm.output_messages.", "output"),
)
# 4.6: OpenInference's `input.value` and `output.value`, whose kind depends on the span kind.
OPENINFERENCE_VALUE_ATTRIBUTES = ("input.value", "output.value")
CLAUDE_CODE_CONTENT_ATTRIBUTES = (
    ("prompt", "prompt"), ("prompt_text", "prompt"), ("user_prompt", "prompt"),
    ("response", "response"),
    ("tool_parameters", "tool_arguments"), ("tool_input", "tool_arguments"),
)
# 4.6: span events read as content of their span (never records).
CLAUDE_CODE_CONTENT_EVENTS = {"tool.output": "tool_result"}
# 4.6: the parts of `gen_ai.client.inference.operation.details`.
OPERATION_DETAILS_PARTS = (
    ("gen_ai.system_instructions", "system"), ("gen_ai.input.messages", "input"), ("gen_ai.output.messages", "output"),
)

CONTENT_ITEM_BYTES = 32 * 1024
CONTENT_RECORD_BYTES = 128 * 1024
OTHER_FLOOR = 100
