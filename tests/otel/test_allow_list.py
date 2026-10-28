"""Invariants 1 and 2, claims E5 and E6: an allow-list, never a deny-list. 1,000 generated spans and log records of
every dialect carry extra attributes, resource attributes and events whose values are unique sentinels; with content
off no sentinel reaches the output, and with content on only the sentinels of the content attributes of 4.6 do, as
content items."""
from __future__ import annotations

import json
import random

from otel_support import build_request, json_bytes
from spellwarden_scan.otel import decode, normalise

# 4.6, every named content attribute (the flattened families by one member each).
CONTENT_ATTRIBUTES = (
    "gen_ai.system_instructions", "gen_ai.input.messages", "gen_ai.prompt", "gen_ai.prompt.0.content", "llm.input_messages.0.content",
    "input.value", "gen_ai.output.messages", "gen_ai.completion", "gen_ai.completion.0.content", "llm.output_messages.0.content",
    "output.value", "gen_ai.tool.call.arguments", "tool_call.function.arguments", "tool_parameters", "tool_input",
    "gen_ai.tool.call.result", "prompt", "prompt_text", "user_prompt", "response",
)
# Invariant 2: never on the allow-list.
IDENTITY_ATTRIBUTES = ("user.id", "user.email", "user.account_uuid", "enduser.id", "organization.id", "client.address",
                       "client.port", "host.name", "host.id", "host.ip", "host.arch", "os.type", "process.owner")
OTHER_ATTRIBUTES = ("gen_ai.tool.definitions", "gen_ai.request.temperature", "http.request.header.authorization",
                    "db.statement", "exception.stacktrace", "mcp.session.id", "jsonrpc.request.id", "prompt.id",
                    "event.sequence", "terminal.type", "gen_ai.response.id", "mcp.resource.uri", "classifier_verdict")
DIALECT_SPANS = (
    ("claude-code", "claude_code.tool", {"tool_name": "Read"}),
    ("claude-code", "claude_code.interaction", {}),
    ("claude-platform", "anthropic.messages", {"gen_ai.operation.name": "chat", "gen_ai.provider.name": "anthropic"}),
    ("oi-app", "llm", {"openinference.span.kind": "LLM"}),
    ("oi-app", "tool", {"openinference.span.kind": "TOOL"}),
    ("oi-app", "chain", {"openinference.span.kind": "CHAIN"}),
    ("legacy", "chat", {"gen_ai.system": "openai", "gen_ai.operation.name": "chat"}),
    ("genai", "execute_tool x", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "x"}),
    ("genai", "invoke_agent", {"gen_ai.operation.name": "invoke_agent"}),
    ("mcp-server", "tools/call y", {"mcp.method.name": "tools/call"}),
)
DIALECT_LOGS = (
    ("claude-code", "claude_code.tool_result", {"tool_name": "Bash"}),
    ("claude-code", "claude_code.user_prompt", {}),
    ("claude-code", "claude_code.tool_decision", {"decision": "reject", "source": "hook"}),
    ("legacy", "gen_ai.user.message", {}),
    ("genai", "gen_ai.client.inference.operation.details", {}),
)


def _generate(seed: int) -> tuple[list[tuple[dict, str]], set[str], set[str]]:
    """`(requests, every sentinel, the sentinels placed under a content attribute)`."""
    rng = random.Random(seed)
    counter = iter(range(10**9))
    every: set[str] = set()
    content: set[str] = set()

    def sentinel(is_content: bool = False) -> str:
        value = f"xtra-{next(counter)}-{rng.getrandbits(48):012x}"
        every.add(value)
        if is_content:
            content.add(value)
        return value

    def extras() -> dict:
        values = {name: sentinel(True) for name in rng.sample(CONTENT_ATTRIBUTES, 6)}
        values.update({name: sentinel() for name in rng.sample(IDENTITY_ATTRIBUTES, 4)})
        values.update({name: sentinel() for name in rng.sample(OTHER_ATTRIBUTES, 3)})
        values[f"x.custom.{next(counter)}"] = sentinel()
        values[f"x.nested.{next(counter)}"] = {"inner": [sentinel(), {"deep": sentinel()}]}
        return values

    requests = []
    for _ in range(100):
        service, name, base = rng.choice(DIALECT_SPANS)
        items = []
        for _ in range(8):
            events = [{"name": "exception", "attributes": {"exception.message": sentinel()}},
                      {"name": f"custom.{next(counter)}", "attributes": {"k": sentinel()}}]
            items.append({"name": name, "kind": rng.choice([1, 2, 3]), "attributes": {**base, **extras()}, "events": events})
        resource = {"service.name": service, **{attribute: sentinel() for attribute in IDENTITY_ATTRIBUTES}}
        requests.append((build_request({"signal": "traces", "resource": resource, "items": items}), "traces"))
    for _ in range(25):
        service, event, base = rng.choice(DIALECT_LOGS)
        # The body of a deprecated GenAI message event is that message (4.6); every other body is dropped.
        items = [{"event_name": event, "attributes": {**base, **extras()}, "body": sentinel(event.startswith("gen_ai."))}
                 for _ in range(8)]
        resource = {"service.name": service, "host.name": sentinel()}
        requests.append((build_request({"signal": "logs", "resource": resource, "items": items}), "logs"))
    return requests, every, content


def _found(text: str, sentinels: set[str]) -> set[str]:
    return {value for value in sentinels if value in text}


def test_no_sentinel_reaches_the_output_with_content_off():
    requests, every, _ = _generate(1)
    assert sum(len(doc["resourceSpans" if signal == "traces" else "resourceLogs"][0]["scopeSpans" if signal == "traces" else "scopeLogs"][0]
                   ["spans" if signal == "traces" else "logRecords"]) for doc, signal in requests) == 1000
    for document, signal in requests:
        result = normalise(decode(json_bytes(document), signal=signal, encoding="json"), content=False)
        assert result.records or signal == "logs"
        assert _found(json.dumps(result.to_dict(content=True)), every) == set()


def test_with_content_on_only_content_sentinels_appear_and_only_as_content():
    requests, every, content = _generate(2)
    seen: set[str] = set()
    for document, signal in requests:
        result = normalise(decode(json_bytes(document), signal=signal, encoding="json"), content=True)
        fields_only = json.dumps(result.to_dict(content=False))
        assert _found(fields_only, every) == set()
        items = " ".join(item.text for record in result.records for item in record.content)
        found = _found(items, every)
        assert found <= content
        seen |= found
    assert seen, "some content sentinels must be kept"
